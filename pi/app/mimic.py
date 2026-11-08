"""Client diagnostics UI. No requests, settings changes or credential output.

The caller authenticates /mimic.js and supplies the actual socket peer address.
build_context deliberately exports an allowlist, never a proxy configuration.
"""
import html
import ipaddress
import json
import math
from pathlib import Path


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value or '')))
    except ValueError:
        return ''


def _time(value):
    try:
        value = float(value)
        return value if math.isfinite(value) and value > 0 else 0
    except (ValueError, TypeError):
        return 0


def _text(value, limit=120):
    return str(value or '')[:limit]


def _reference(info, timestamp):
    """Only observed IP metadata; never reflect arbitrary provider fields."""
    info = info if isinstance(info, dict) else {}
    addr = _ip(info.get('ip'))
    if not addr:
        return None
    return {'ip': addr, 'country': _text(info.get('country'), 60),
            'city': _text(info.get('city')), 'org': _text(info.get('org')),
            'time': _time(timestamp)}


def _label(proxy):
    if not proxy:
        return ''
    return _text(proxy.get('name')) or _text(proxy.get('kind'), 30).upper() or 'Прокси'


def build_context(client_ip, devices, items, current_proxy, router_exit=None,
                  router_exit_time=0, clients=None):
    """Resolve predicted policy by source IP, just as sing-box routing does.

    items can be library['items'] or an ID -> item mapping. The source IP must
    come from client_address, never X-Forwarded-For or browser input. Results
    describe configured policy, not proof of actual traffic routing.
    """
    source = _ip(client_ip)
    library = list(items.values()) if isinstance(items, dict) else list(items or [])
    library = [it for it in library if isinstance(it, dict)]
    by_id = {it.get('id'): it for it in library if it.get('id')}
    router = _reference(router_exit, router_exit_time)
    result = {'client_ip': source or 'не определён', 'device_name': '',
              'policy': 'unknown', 'profile': '', 'reference': None,
              'router_exit': router, 'reason': '', 'scope': 'outside'}
    for client in clients or []:
        if isinstance(client, dict) and _ip(client.get('ip')) == source and source:
            result['device_name'] = _text(client.get('name'), 60)
            break
    if not source or ipaddress.ip_address(source) not in ipaddress.ip_network('10.77.0.0/24'):
        result['reason'] = ('Панель открыта вне клиентской сети GeoBox. Правило Wi-Fi '
                            'для этого браузера определить нельзя; тесты проверят его текущий маршрут.')
        return result
    result['scope'] = 'wifi'
    matches = [d for d in (devices or {}).values()
               if isinstance(d, dict) and _ip(d.get('ip')) == source]
    if len(matches) > 1:
        result['reason'] = 'Для адреса найдено несколько назначений. Проверь вкладку «Устройства».'
        return result
    device = matches[0] if matches else {}
    result['device_name'] = _text(device.get('name'), 60) or result['device_name']
    mode = device.get('mode', 'default')
    if mode == 'block':
        result.update(policy='blocked', profile='Без интернета',
                      reason='Для этого адреса задана блокировка. Успешный внешний тест требует проверки маршрута устройства.')
        return result
    if mode == 'proxy':
        proxy = by_id.get(device.get('item'))
        if not proxy or not proxy.get('outbound'):
            result.update(policy='blocked', profile='Назначенный прокси недоступен',
                          reason='Профиля нет в библиотеке. Конфигурация должна блокировать выход этого устройства.')
            return result
        check = proxy.get('check') or {}
        result.update(policy='device', profile=_label(proxy),
                      reference=_reference(check, check.get('time')) if check.get('ok') else None,
                      reason='Отдельный прокси устройства. Эталон ниже — последняя проверка профиля с малины.')
        return result
    if mode != 'default':
        result['reason'] = 'Неизвестный режим устройства. Проверь назначение во вкладке «Устройства».'
        return result
    if not current_proxy:
        result.update(policy='blocked', profile='Общий прокси не задан',
                      reason='Для этого адреса интернет должен быть заблокирован до выбора общего прокси.')
        return result
    reference = router
    if not reference:
        for item in library:
            if item.get('outbound') == current_proxy.get('outbound'):
                check = item.get('check') or {}
                if check.get('ok'):
                    reference = _reference(check, check.get('time'))
                break
    result.update(policy='default', profile=_label(current_proxy), reference=reference,
                  reason='Общий прокси. Эталон ниже — последняя проверка с малины, а не измерение этого браузера.')
    return result


def audit_context(value):
    """Keep only bounded presentation fields, never commands/config objects."""
    if not isinstance(value, dict) or value.get('scope') != 'router':
        return None
    statuses = ('pass', 'warn', 'unknown')
    ids = {'config_dns_capture', 'config_ipv6', 'config_udp', 'config_private', 'config_egress',
           'config_dns_egress', 'config_devices', 'firewall_forward', 'routing_policy',
           'routing_table', 'tunnel', 'selector'}
    result = {'scope': 'router', 'status': value.get('status') if value.get('status') in statuses else 'unknown',
              'checked_at': _time(value.get('checked_at')), 'stale': value.get('stale') is True,
              'checks': [], 'limitations': []}
    for item in value.get('checks', [])[:20] if isinstance(value.get('checks'), list) else []:
        if not isinstance(item, dict):
            continue
        ident = item.get('id')
        if not isinstance(ident, str) or ident not in ids:
            continue
        result['checks'].append({'id': ident,
                                'title': _text(item.get('title'), 100) if isinstance(item.get('title'), str) else ident,
                                'status': item.get('status') if item.get('status') in statuses else 'unknown',
                                'detail': _text(item.get('detail'), 500) if isinstance(item.get('detail'), str) else ''})
    for line in value.get('limitations', [])[:8] if isinstance(value.get('limitations'), list) else []:
        if isinstance(line, str):
            result['limitations'].append(_text(line, 400))
    return result


def udp_context(value):
    if not isinstance(value, dict):
        return None
    return {'status': value.get('status') if value.get('status') in ('pass', 'warn', 'unknown', 'unsupported') else 'unknown',
            'code': value.get('code') if value.get('code') in ('command_rejected', 'unsupported_proxy') else '',
            'checked_at': _time(value.get('checked_at')), 'stale': value.get('stale') is True,
            'scope': value.get('scope') if value.get('scope') in ('device_proxy', 'global_proxy', 'blocked', 'outside') else 'outside',
            'detail': _text(value.get('detail'), 500) if isinstance(value.get('detail'), str) else '',
            'mapped_ip': _ip(value.get('mapped_ip'))}


def render(context, audit_result=None):
    """Return tab cards; values are escaped even inside the JSON data attribute."""
    e = html.escape
    ctx = dict(context)
    ctx['router_audit'] = audit_context(audit_result if audit_result is not None else ctx.get('router_audit'))
    ctx['udp_probe_result'] = udp_context(ctx.get('udp_probe_result'))
    payload = e(json.dumps(ctx, ensure_ascii=False, allow_nan=False), quote=True)
    reference = ctx.get('reference')
    router = ctx.get('router_exit')

    def row(label, value, css=''):
        return '<div class="row"><span class="k">%s</span><span class="v %s">%s</span></div>' % (
            e(label), e(css), e(str(value)))

    def observed(info):
        if not info:
            return 'Нет результата'
        region = ' · '.join(x for x in (info.get('country'), info.get('city')) if x)
        return info['ip'] + (' · ' + region if region else '')

    audit = ctx['router_audit']
    audit_html = '<div class="k">Ещё не проверено</div>'
    status_labels = {'pass': 'Проверка пройдена', 'warn': 'Нужно проверить', 'unknown': 'Не определено',
                     'fail': 'Обнаружено несоответствие', 'skipped': 'Не проверено'}
    if audit:
        audit_html = '<div id="mimic-audit-time" class="hint"></div>'
        counts = {status: sum(check['status'] == status for check in audit['checks'])
                  for status in ('pass', 'warn', 'unknown')}
        summary_css = 'ok' if audit['status'] == 'pass' and not audit['stale'] else 'warn'
        audit_html += '<div class="%s">%s</div>' % (summary_css, e(status_labels[audit['status']]))
        audit_html += '<div class="hint">Пройдено: %d · Нужно проверить: %d · Не определено: %d</div>' % (
            counts['pass'], counts['warn'], counts['unknown'])
        if audit['stale']:
            audit_html += '<div class="warn">Результат устарел. Повтори проверку для текущего подключения.</div>'
        audit_html += '<details style="margin-top:10px"><summary>Результаты %d проверок</summary>' % len(audit['checks'])
        for check in audit['checks']:
            css = 'ok' if check['status'] == 'pass' and not audit['stale'] else 'warn'
            audit_html += row(check['title'], status_labels[check['status']], css)
            if check['detail']:
                audit_html += '<div class="hint">%s</div>' % e(check['detail'])
        for limitation in audit['limitations']:
            audit_html += '<div class="hint">%s</div>' % e(limitation)
        audit_html += '</details>'
    audit_html = ('<div class="c"><h2>Защита на малине</h2>%s'
                  '<form method="post" action="/diagnostics"><div class="f">'
                  '<button type="submit" class="g">Проверить малину</button></div></form>'
                  '<div class="hint">Отдельная проверка настроек и состояния маршрутизатора на момент запуска. '
                  'Она не подтверждает маршрут браузера, DNS всех приложений или отсутствие утечек. '
                  'Кнопка обновляет страницу; сначала дождись завершения браузерных тестов.</div></div>') % audit_html

    udp = ctx['udp_probe_result']
    udp_html = '<div class="k">Ещё не проверено</div>'
    if udp:
        labels = {'pass': 'UDP-ответ получен', 'warn': 'Нужно проверить', 'unknown': 'Результат не определён',
                  'unsupported': {'command_rejected': 'Сервер отклонил UDP',
                                  'unsupported_proxy': 'Этот тип прокси не поддерживается тестом'}.get(udp['code'], 'UDP не подтверждён')}
        scopes = {'device_proxy': 'Отдельный прокси устройства', 'global_proxy': 'Общий прокси',
                  'blocked': 'Устройство заблокировано', 'outside': 'Вне клиентской сети GeoBox'}
        udp_html = row('Проверялся', scopes[udp['scope']])
        udp_html += row('Результат', labels[udp['status']], 'ok' if udp['status'] == 'pass' and not udp['stale'] else 'warn')
        udp_html += '<div id="mimic-udp-time" class="hint"></div>'
        if udp['stale']:
            udp_html += '<div class="warn">Результат устарел. Повтори проверку для текущего подключения.</div>'
        if udp['detail']:
            udp_html += '<div class="hint">%s</div>' % e(udp['detail'])
        if udp['mapped_ip']:
            udp_html += row('IP в ответе STUN', udp['mapped_ip'])
    udp_html = ('<div class="c"><h2>UDP у прокси</h2>%s'
                '<form method="post" action="/diagnostics/udp"><div class="f">'
                '<button type="submit" class="g">Проверить UDP прокси</button></div></form>'
                '<div class="hint">Явный STUN-запрос с малины через назначенный этому устройству SOCKS5. '
                'Вне Wi-Fi GeoBox проверяется общий прокси. Внешний STUN-сервис увидит адрес выхода. '
                'Это проверка возможности прокси, а не WebRTC телефона. Она не включает UDP в настройках '
                'и не доказывает отсутствие утечек. Кнопка обновляет страницу.</div></div>') % udp_html

    browser_start_html = (
        '<div class="c"><h2>Проверить устройство</h2>'
        '<p class="hint">Сначала измерим IPv4 и IPv6 по HTTPS, затем соберём WebRTC-адреса. '
        'Браузер обратится к api.ipify.org, api6.ipify.org и STUN Google '
        '(stun.l.google.com:19302); эти сервисы увидят источник запросов. '
        'Камера и микрофон не используются. Автоматических внешних запросов нет.</p>'
        '<div class="f"><button type="button" id="mimic-run-button">Проверить устройство</button>'
        '<button type="button" id="mimic-cancel-button" class="g" disabled>Отменить</button>'
        '<button type="button" id="mimic-copy-button" class="g">Копировать отчёт</button></div>'
        '<div id="mimic-summary" class="hint" aria-live="polite">Проверки ещё не запускались.</div>'
        '<div id="mimic-copy-status" class="hint" aria-live="polite"></div>'
        '<textarea id="mimic-report" readonly hidden aria-label="Диагностический отчёт" '
        'style="width:100%;min-height:180px"></textarea>'
        '<div class="hint">Отчёт содержит результаты и IP-адреса, но не пароль прокси, название профиля, '
        'точные координаты или данные сессии. Проверь содержимое перед отправкой.</div></div>')

    return (
        '<section id="mimic" data-context="%s">'
        '<div class="c"><h2>Mimic · диагностика этого устройства</h2>'
        '<p style="margin:0 0 10px">Сравниваем настройки GeoBox с тем, что фактически видит внешний сервис. '
        'Проверки не меняют сетевые настройки.</p>%s%s%s'
        '<div class="hint">%s</div>'
        '<div class="hint">Профиль определяется по адресу подключения к панели. VPN на устройстве, '
        'Private Relay или мобильная сеть могут дать другой путь для внешнего запроса.</div></div>'
        '%s'
        '<div class="c"><h2>Профиль и последнее измерение</h2>%s'
        '<div class="hint" id="mimic-reference-time"></div>'
        '<div class="hint">Совпадение IP — только совпадение с прошлой проверкой. У вращающегося прокси IP может '
        'измениться; несовпадение само по себе не доказывает утечку. Страна и город относятся к IP, не к GPS.</div>'
        '<details style="margin-top:10px"><summary>Общий выход малины</summary>%s'
        '<div class="hint" id="mimic-router-time"></div>'
        '<div class="hint">Измерение из процесса малины. Оно не подтверждает выход отдельного устройства.</div>'
        '</details></div>'
        '%s%s'
        '<div class="c"><h2>IP и IPv6 из браузера</h2>'
        '<div id="mimic-ip4" class="row" aria-live="polite">IPv4: не проверено</div>'
        '<div id="mimic-ip6" class="row" aria-live="polite">IPv6: не проверено</div>'
        '<div id="mimic-compare" class="hint" aria-live="polite"></div>'
        '<div class="f"><button type="button" id="mimic-ip-button">Проверить IP и IPv6</button></div>'
        '<div class="hint">По нажатию браузер обратится к api.ipify.org и api6.ipify.org. '
        'Сервисы увидят адрес источника запроса. Результаты остаются на этой странице.</div></div>'
        '<div class="c"><h2>WebRTC</h2><div id="mimic-rtc" aria-live="polite">Не проверено</div>'
        '<div class="f"><button type="button" id="mimic-rtc-button" class="g">Проверить WebRTC</button></div>'
        '<div class="hint">По нажатию браузер запросит STUN-сервер Google: stun.l.google.com:19302. '
        'Сервер увидит адрес источника запроса. Камера и микрофон не используются. Проверка одного STUN-сервера '
        'не гарантирует поведение всех приложений.</div></div>'
        '<div class="c"><h2>DNS</h2><div class="warn">Не проверено с устройства</div>'
        '<div class="hint">В конфигурации GeoBox DNS клиентов направлен через прокси, но это не результат теста. '
        'Для определения фактического резолвера нужен внешний DNS-тест с уникальными запросами. '
        'Обычная проверка IP этого не показывает; браузер или приложение могут использовать собственный DNS.</div></div>'
        '<div class="c"><h2>Браузер и геолокация</h2>'
        '<div id="mimic-browser" class="hint"></div>'
        '<div id="mimic-geo" aria-live="polite">Геолокация не запрошена</div>'
        '<div class="f"><button type="button" id="mimic-geo-button" class="g">Проверить геолокацию</button></div>'
        '<div class="hint">Только по нажатию и с разрешения браузера. Координаты не сохраняются на малине и '
        'не отправляются этой страницей внешнему сервису; системная служба геолокации может обращаться к своему '
        'провайдеру. Прокси не меняет GPS, часовой пояс или разрешения браузера.</div></div>'
        '<noscript><div class="msg warn">Для клиентских тестов включи JavaScript. Внешние проверки сами не запускаются.</div></noscript>'
        '</section><script src="/mimic.js" defer></script>'
    ) % (payload,
         row('Адрес подключения к панели', ctx.get('client_ip', 'не определён')),
         row('Устройство', ctx.get('device_name') or 'не задано имя'),
         row('Настроенный профиль', ctx.get('profile') or 'не определён'),
         e(ctx.get('reason', '')), browser_start_html, row('Последний IP профиля', observed(reference)),
         row('IP общего выхода', observed(router)), audit_html, udp_html)


def javascript():
    return Path(__file__).with_name('mimic.js').read_text(encoding='utf-8')
