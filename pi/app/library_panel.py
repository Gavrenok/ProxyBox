"""Proxy-library import and rendering. No network calls, persistence or apply.

Integration: call import_batch while holding geobox.lib_lock, then save the
library once. Keep its sanitized result in the session for the next page.
render_library returns cards for the existing proxies tab. Existing /lib actions
are retained. /lib/meta updates metadata through library.set_metadata.
GET filters: q, tag and favorite; all forms carry tab=proxies.
"""
import html
import time
import urllib.parse

import library as libmod
import failover_policy
import proxy_checks

MAX_IMPORT_BYTES = 128 * 1024
MAX_IMPORT_LINES = 200
MAX_LINE_LENGTH = 8192
DEFAULT_KINDS = ('socks5', 'http', 'socks4', 'https')
PAGE_SIZE = 15
KIND_NAMES = {'socks5': 'SOCKS5', 'socks4': 'SOCKS4', 'http': 'HTTP',
              'https': 'HTTPS', 'ss': 'Shadowsocks', 'vless': 'VLESS',
              'vmess': 'VMess', 'trojan': 'Trojan', 'hysteria2': 'Hysteria2'}


def import_batch(lib, text, parse_proxy, default_kind='socks5', tags=''):
    """Add parseable lines, retaining originals and distinguishing credentials.

    Error details intentionally never echo input or parser exceptions: either
    can contain credentials. Whole-batch validation happens before mutations.
    Explicit protocol URLs win; bare lines use the visible protocol selector.
    """
    result = {'added': 0, 'duplicates': 0, 'failed': 0, 'rows': [], 'error': ''}
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_IMPORT_BYTES:
        result['error'] = 'Импорт не выполнен: текст больше 128 КБ.'
        return result
    if default_kind not in DEFAULT_KINDS:
        result['error'] = 'Импорт не выполнен: выбери тип для строк без схемы.'
        return result
    try:
        clean_tags = libmod.normalize_tags(tags)
    except ValueError as exc:
        result['error'] = str(exc)
        return result
    lines = [(i, line.strip()) for i, line in enumerate(text.splitlines(), 1)
             if line.strip()]
    if not lines:
        result['error'] = 'Вставь хотя бы один прокси: по одному на строку.'
        return result
    if len(lines) > MAX_IMPORT_LINES:
        result['error'] = 'Импорт не выполнен: за один раз можно добавить до 200 строк.'
        return result
    known = {libmod.identity(item) for item in lib['items']}
    for number, line in lines:
        try:
            if len(line) > MAX_LINE_LENGTH:
                raise ValueError('line too long')
            parsed = parse_proxy(line)
            cands = parsed['cands']
            kind, outbound = (cands[0] if len(cands) == 1 else
                              next(c for c in cands if c[0] == default_kind))
            proxy = {'kind': kind, 'server': parsed['server'], 'port': parsed['port'],
                     'name': parsed.get('name', ''), 'login': parsed.get('login', False),
                     'secrets': parsed.get('secrets', []), 'outbound': outbound}
            key = libmod.identity(proxy)
        except (ValueError, TypeError, KeyError, IndexError, StopIteration, OverflowError, AttributeError):
            result['failed'] += 1
            result['rows'].append({'line': number, 'status': 'error',
                                   'message': 'Не распознано: проверь формат, адрес, порт и тип.'})
            continue
        if key in known:
            result['duplicates'] += 1
            result['rows'].append({'line': number, 'status': 'duplicate',
                                   'message': 'Уже есть в библиотеке; сохранён без изменений.'})
            continue
        item = libmod.add_or_update(lib, proxy)
        item['tags'] = list(clean_tags)
        known.add(key)
        result['added'] += 1
        result['rows'].append({'line': number, 'status': 'added',
                               'message': 'Добавлен; соединение ещё не проверено.'})
    return result


def _text(value):
    return str(value) if value is not None else ''


def _esc(value):
    return html.escape(_text(value), quote=True)


def _tags(item):
    tags = item.get('tags')
    return [tag for tag in tags if isinstance(tag, str)] if isinstance(tags, list) else []


def filter_items(lib, filters=None):
    """Search only visible non-secret fields, never passwords or raw outbounds."""
    filters = filters or {}
    query = _text(filters.get('q', '')).strip().casefold()[:200]
    tag = _text(filters.get('tag', '')).casefold()[:MAX_LINE_LENGTH]
    favorite = filters.get('favorite') in (True, '1')
    found = []
    for item in lib['items']:
        tags = _tags(item)
        if favorite and not item.get('favorite'):
            continue
        if tag and tag not in [value.casefold() for value in tags]:
            continue
        check = item.get('check') or {}
        searchable = ' '.join(_text(value) for value in (
            item.get('name'), item.get('server'), item.get('port'),
            item.get('kind'), check.get('ip'), check.get('country'),
            check.get('city'), check.get('org'), *tags)).casefold()
        if query and query not in searchable:
            continue
        found.append(item)
    # Keep existing library order within favorite/nonfavorite groups.
    return sorted(found, key=lambda item: not bool(item.get('favorite')))


def _label(item):
    address = '%s:%s' % (_text(item.get('server')), _text(item.get('port')))
    kind = KIND_NAMES.get(item.get('kind'), _text(item.get('kind')))
    return '%s %s' % (kind, address)


def _age(timestamp):
    try:
        seconds = max(0, time.time() - float(timestamp or 0))
    except (ValueError, TypeError, OverflowError):
        return 'время неизвестно'
    if seconds < 60:
        return 'только что'
    if seconds < 3600:
        return '%d мин назад' % (seconds // 60)
    if seconds < 86400:
        return '%d ч назад' % (seconds // 3600)
    return '%d дн назад' % (seconds // 86400)


def render_import_result(result):
    if not result:
        return ''
    if result.get('error'):
        return '<div class="msg err" role="status">%s</div>' % _esc(result['error'])
    summary = 'Добавлено: %d · уже были: %d · ошибок: %d' % (
        result.get('added', 0), result.get('duplicates', 0), result.get('failed', 0))
    rows = ''.join('<li class="%s">Строка %d: %s</li>' % (
        'err' if row['status'] == 'error' else 'k', row['line'], _esc(row['message']))
        for row in result.get('rows', []))
    return ('<div class="c" role="status"><h2>Результат импорта</h2><p>%s</p>'
            '<details%s><summary>По строкам</summary><ul>%s</ul></details>'
            '<div class="hint">Активный прокси и подключения устройств не менялись.</div></div>'
            % (_esc(summary), ' open' if result.get('failed') else '', rows))


def page_items(items, requested='1'):
    pages = max(1, (len(items) + PAGE_SIZE - 1) // PAGE_SIZE)
    try:
        number = max(1, min(pages, int(str(requested)[:10])))
    except (ValueError, TypeError):
        number = 1
    start = (number - 1) * PAGE_SIZE
    return items[start:start + PAGE_SIZE], number, pages, start


def view_url(filters=None, **changes):
    values = dict(filters or {}, **changes)
    params = {'tab': 'proxies'}
    for key, limit in (('q', 200), ('tag', 208), ('favorite', 1), ('p', 10), ('selected', 80)):
        value = _text(values.get(key, ''))[:limit]
        if value:
            params[key] = value
    return '/?' + urllib.parse.urlencode(params)


def view_fields(filters):
    return ''.join('<input type="hidden" name="%s" value="%s">' % (key, _esc(filters[key]))
                   for key in ('q', 'tag', 'favorite', 'p', 'selected') if filters.get(key))


def render_library(lib, current_id='', devices=None, import_result=None, filters=None):
    devices, filters = devices or {}, filters or {}
    items = filter_items(lib, filters)
    all_tags = sorted({tag for item in lib['items'] for tag in _tags(item)}, key=str.casefold)
    q = _text(filters.get('q', ''))[:200]
    selected_tag = _text(filters.get('tag', ''))
    favorites = filters.get('favorite') in (True, '1')
    options = ''.join('<option value="%s"%s>%s</option>' % (
        _esc(tag), ' selected' if tag == selected_tag else '', _esc(tag)) for tag in all_tags)
    parts = [render_import_result(import_result),
        '<details class="c compact-import"><summary>Импорт списка прокси</summary><form method="post" action="/lib/import">'
        '<label for="lib-import">Прокси — по одному на строку</label>'
        '<textarea id="lib-import" name="proxies" rows="5" autocomplete="off" '
        'autocapitalize="off" spellcheck="false" placeholder="socks5://user:password@host:port"></textarea>'
        '<div class="f"><label style="flex:1;min-width:180px">Тип строк без схемы'
        '<select name="default_kind"><option value="socks5">SOCKS5</option>'
        '<option value="http">HTTP</option><option value="https">HTTPS</option>'
        '<option value="socks4">SOCKS4</option></select></label>'
        '<label style="flex:1;min-width:180px">Метки для новых записей'
        '<input type="text" name="tags" maxlength="208" placeholder="работа, Европа"></label></div>'
        '<div class="f"><button>Добавить в библиотеку</button></div></form>'
        '<div class="hint">До 200 строк за раз, до 128 КБ. Схема в ссылке имеет приоритет над выбранным типом. '
        'Импорт сохраняет записи без проверки соединения и без переключения. '
        'Полные дубликаты пропускаются; разные логины и пароли считаются разными прокси.</div></details>',
        '<div class="c"><h2>Библиотека прокси (%d)</h2>' % len(lib['items']),
        '<form method="get" action="/" role="search" class="library-search"><input type="hidden" name="tab" value="proxies">'
        '<label for="lib-search">Поиск по названию, адресу, IP выхода, стране или метке</label>'
        '<input type="text" id="lib-search" name="q" value="%s" maxlength="200" placeholder="Например: работа или DE">'
        '<div class="f"><label style="flex:1;min-width:180px">Группа'
        '<select name="tag"><option value="">Все метки</option>%s</select></label>'
        '<label class="cb" style="align-self:end"><input type="checkbox" name="favorite" value="1"%s> '
        'Только избранные</label></div><div class="f"><button class="g">Найти</button>'
        '<a href="/?tab=proxies" style="align-self:center">Сбросить</a></div></form>'
        % (_esc(q), options, ' checked' if favorites else '')]
    visible, number, pages, start = page_items(items, filters.get('p', '1'))
    selected = next((it for it in visible if it['id'] == filters.get('selected')), None)
    if selected is None:
        selected = next((it for it in visible if it['id'] == current_id), visible[0] if visible else None)
    filters = dict(filters, p=str(number), selected=selected['id'] if selected else '')
    context = view_fields(filters)
    parts.append('<div class="list-meta"><span>%d–%d из %d · всего %d</span><span>Избранные сверху</span></div>' % (
        start + 1 if items else 0, start + len(visible), len(items), len(lib['items'])))
    parts.append('<div class="library-workspace"><div id="proxy-list"><div class="t"><table class="proxy-table">'
                 '<thead><tr><th scope="col">Прокси</th><th scope="col">Выход</th>'
                 '<th scope="col">Проверка</th></tr></thead><tbody>')
    for item in visible:
        check = item.get('check') or {}
        state = 'Работает' if check.get('ok') else 'Ошибка' if check else 'Не проверен'
        tone = 'ok' if check.get('ok') else 'err' if check else 'k'
        active = ' <span class="badge">Активен</span>' if item['id'] == current_id else ''
        chosen = selected and item['id'] == selected['id']
        parts.append('<tr%s><td><a translate="no" class="proxy-title" href="%s"%s>%s%s</a>%s'
                     '<small>%s</small></td><td>%s<small>%s</small></td>'
                     '<td><span class="%s">%s</span><small>%s</small></td></tr>' % (
            ' class="selected"' if chosen else '', _esc(view_url(filters, selected=item['id']) + '#proxy-details'),
            ' aria-current="true"' if chosen else '', '★ ' if item.get('favorite') else '',
            _esc(item.get('name') or _label(item)), active, _esc(_label(item)),
            _esc(' '.join(str(check.get(k) or '') for k in ('country', 'city')).strip() or '—'),
            _esc(check.get('ip') or ''), tone, state, _esc(_age(check.get('time'))) if check else ''))
    parts.append('</tbody></table></div><nav class="pagination" aria-label="Страницы прокси">')
    if number > 1:
        parts.append('<a class="btn" href="%s">← Назад</a>' % _esc(view_url(filters, p=number - 1, selected='')))
    parts.append('<span>Страница %d из %d</span>' % (number, pages))
    if number < pages:
        parts.append('<a class="btn" href="%s">Далее →</a>' % _esc(view_url(filters, p=number + 1, selected='')))
    parts.append('</nav></div><aside id="proxy-details" class="proxy-inspector" aria-label="Выбранный прокси">'
                 '<p class="hint"><a href="#proxy-list">Back to list</a></p>')
    for item in ([selected] if selected else []):
        item_id = item['id']
        check = item.get('check') or {}
        users = [d.get('name') or mac for mac, d in devices.items()
                 if d.get('mode') == 'proxy' and d.get('item') == item_id]
        if check.get('ok'):
            status = '<span class="ok">Последняя проверка: работает</span> · <span>%s</span>' % _esc(_age(check.get('time')))
            detail = '%s · %s %s' % (_text(check.get('ip')), _text(check.get('country')), _text(check.get('city')))
        elif check:
            status = '<span class="err">Последняя проверка: ошибка</span> · <span>%s</span>' % _esc(_age(check.get('time')))
            detail = 'Проверь соединение заново перед применением.'
        else:
            status = '<span class="k">Соединение ещё не проверено</span>'
            detail = ''
        title = item.get('name') or _label(item)
        mark = ' <span class="ok">· общий прокси</span>' if item_id == current_id else ''
        favorite_mark = '★ ' if item.get('favorite') else ''
        tags = _tags(item)
        buttons = ''.join(
            '<form class="i" method="post" action="/lib"><input type="hidden" name="id" value="%s">'
            '<input type="hidden" name="op" value="%s"><button class="%s">%s</button></form>'
            % (_esc(item_id), op, cls, label)
            for op, cls, label in (('apply', '', 'Применить'), ('check', 'g', 'Проверить'),
                                   ('capabilities', 'g', 'Проверить возможности'),
                                   ('speed', 'g', 'Скорость'), ('delete', 'g', 'Удалить')))
        parts.append('<div class="li"><div><b translate="no">%s%s</b>%s</div><div class="k" translate="no">%s%s</div>'
                     '<div>%s</div><div>%s</div>' % (
                         favorite_mark, _esc(title), mark, _esc(_label(item)),
                         ' · с авторизацией' if item.get('login') else '', status, _esc(detail)))
        if tags:
            parts.append('<div class="hint"><span>Метки:</span> <span translate="no">%s</span></div>' % _esc(' · '.join(tags)))
        if users:
            parts.append('<div class="hint">Устройства: %s</div>' % _esc(', '.join(users)))
        speed = item.get('speed') or {}
        if isinstance(speed.get('mbps'), (float, int)) and speed.get('method') == 'download-v2':
            parts.append('<div class="hint">Последний замер: %.1f Мбит/с · %s · %s</div>' % (
                speed['mbps'], _esc(speed.get('source', '')), _esc(_age(speed.get('time')))))
        elif speed:
            parts.append('<div class="hint">Старый замер требует повторной проверки.</div>')
        parts.append(proxy_checks.render(item))
        buttons = buttons.replace('</form>', context + '</form>')
        parts.append('<div class="f">%s</div><details style="margin-top:10px"><summary>Название, метки, избранное</summary>'
                     '<form method="post" action="/lib/meta"><input type="hidden" name="id" value="%s">'
                     '<label>Название<input type="text" name="name" maxlength="60" value="%s"></label>'
                     '<label>Метки через запятую<input type="text" name="tags" maxlength="208" value="%s"></label>'
                     '<label class="cb"><input type="checkbox" name="favorite" value="1"%s> В избранном</label>'
                     '<div class="f"><button class="g">Сохранить</button></div>%s</form></details></div>' % (
                         buttons, _esc(item_id), _esc(item.get('name', '')), _esc(', '.join(tags)),
                         ' checked' if item.get('favorite') else '', context))
    if not items:
        parts.append('<p class="k">%s</p>' % ('Ничего не найдено. Измени фильтры.' if lib['items']
                                             else 'Библиотека пока пуста. Добавь список выше или проверь один прокси.'))
    parts.append('</aside></div></div><details class="c"><summary>Автозамена и резервные прокси</summary>')
    failover = bool(lib.get('failover'))
    rules = failover_policy.policy(lib)
    if rules is None:
        parts.append('<p class="err">Ограничения автозамены повреждены: переключения заблокированы. Сохрани их заново.</p>')
        rules = failover_policy.validate()
    parts.append('<h2>Резервные прокси</h2><form class="failover-settings" method="post" action="/lib/failover">'
                 '<label>Метка группы (пусто — вся библиотека)<input type="text" name="tag" maxlength="24" value="%s"></label>'
                 '<label>Страна выхода (пусто — любая)<input type="text" name="country" maxlength="2" placeholder="DE" value="%s"></label>'
                 '<label>Минимальная пауза между автозаменами, секунд<input name="cooldown" type="number" '
                 'min="60" max="86400" required value="%d"></label>'
                 '<div class="f"><button class="g">Сохранить ограничения</button></div></form>'
                 '<p class="hint">Страна проверяется перед переключением и при подтверждении нового выхода. '
                 'Если подходящего резерва нет, прямой выход не включается. '
                 'Провайдер может изменить IP и страну позже — эта настройка не фиксирует географию ротирующего прокси. '
                 'За один цикл проверяется до 6 резервов.</p>' % (_esc(rules['tag']), _esc(rules['country']), rules['cooldown']))
    history = lib.get('failover_history') or []
    history = [event for event in history if isinstance(event, dict)] if isinstance(history, list) else []
    if history:
        parts.append('<details><summary>Последние автозамены</summary><ul>')
        for event in reversed(history[-25:]):
            old = libmod.get(lib, event.get('from')) or {}
            new = libmod.get(lib, event.get('to')) or {}
            parts.append('<li>%s: %s → %s · %s</li>' % (_esc(_age(event.get('time'))),
                _esc(old.get('name') or event.get('from') or '—'),
                _esc(new.get('name') or event.get('to') or '—'), _esc(event.get('country'))))
        parts.append('</ul></details>')
    parts.append('<form method="post" action="/lib"><input type="hidden" name="op" value="%s">'
                 '<input type="hidden" name="id" value=""><div class="f"><button class="g">%s</button></div></form>'
                 '<div class="hint">Записи хранятся до явного удаления. Метки ограничивают резерв, если группа выбрана выше. '
                 'Автозамена относится к общему прокси и может сменить IP во время работы. '
                 'Резерв проверяется перед применением; сам импорт её не запускает.</div></details>' % (
                     'failover_off' if failover else 'failover_on',
                     'Автозамена включена — выключить' if failover else 'Автозамена выключена — включить'))
    return ''.join(parts)
