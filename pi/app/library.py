"""GeoBox: библиотека сохранённых прокси и выбор живого прокси для автозамены.

Файл <etc>/library.json: {"items": [...], "failover": false}
Каждый элемент - прокси в формате geobox ('kind','server','port','name','login','secrets','outbound')
плюс 'id', 'added', 'check' (последняя проверка) и 'speed' (последний замер скорости).
"""
import json
import os
import secrets
import time

# Entries are retained until explicitly deleted. Never evict a proxy: devices
# may still reference its id, and its last check need not reflect current health.
MAX_TAGS = 8
MAX_TAG_LENGTH = 24
PROXY_KEYS = ('kind', 'server', 'port', 'name', 'login', 'secrets', 'outbound')


def _path(etc):
    return os.path.join(etc, 'library.json')


def _empty():
    return {'items': [], 'failover': False}


def load(etc):
    """Нет файла или он битый - пустая библиотека."""
    try:
        with open(_path(etc), encoding='utf-8') as f:
            lib = json.load(f)
    except (OSError, ValueError):
        return _empty()
    if not isinstance(lib, dict) or not isinstance(lib.get('items'), list):
        return _empty()
    lib['items'] = [it for it in lib['items'] if isinstance(it, dict) and it.get('id') and isinstance(it.get('outbound'), dict)]
    lib['failover'] = bool(lib.get('failover', False))
    return lib


def save(etc, lib):
    """Атомарная запись, читать может только root (внутри пароли прокси)."""
    path = _path(etc)
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(lib, f, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def identity(proxy):
    """Ключ дубликатов: одинаковые настройки подключения = один и тот же прокси."""
    return json.dumps(proxy.get('outbound') or {}, sort_keys=True)


def as_proxy(item):
    """Только поля прокси geobox - без служебных полей библиотеки."""
    return {k: item[k] for k in PROXY_KEYS if k in item}


def get(lib, item_id):
    for it in lib['items']:
        if it.get('id') == item_id:
            return it
    return None


def items_by_id(lib):
    return {it['id']: it for it in lib['items']}


def remove(lib, item_id):
    n = len(lib['items'])
    lib['items'] = [it for it in lib['items'] if it.get('id') != item_id]
    return len(lib['items']) != n


def normalize_tags(tags):
    """Validate tags before mutating stored metadata. Commas separate tags."""
    if isinstance(tags, str):
        tags = tags.split(',')
    if not isinstance(tags, (list, tuple)):
        raise ValueError('Метки должны быть строкой через запятую.')
    result, seen = [], set()
    for tag in tags:
        if not isinstance(tag, str):
            raise ValueError('Каждая метка должна быть текстом.')
        tag = ' '.join(tag.split())
        if not tag:
            continue
        if len(tag) > MAX_TAG_LENGTH:
            raise ValueError('Метка должна быть не длиннее 24 символов.')
        if tag.casefold() not in seen:
            seen.add(tag.casefold())
            result.append(tag)
    if len(result) > MAX_TAGS:
        raise ValueError('Можно задать не больше 8 меток.')
    return result


def set_metadata(lib, item_id, name='', tags='', favorite=False):
    """Edit labels only; leave connection, health and device ids unchanged."""
    item = get(lib, item_id)
    if item is None:
        raise ValueError('Такого прокси в списке нет.')
    if not isinstance(name, str) or len(name.strip()) > 60:
        raise ValueError('Название должно быть не длиннее 60 символов.')
    clean_tags = normalize_tags(tags)
    item.update(name=name.strip(), tags=clean_tags,
                favorite=favorite is True or favorite == '1')
    return item


def add_or_update(lib, proxy):
    key = identity(proxy)
    for it in lib['items']:
        if identity(it) == key:
            if proxy.get('name') and not it.get('name'):
                it['name'] = proxy['name']
            return it
    item = as_proxy(proxy)
    used = {it['id'] for it in lib['items']}
    item_id = secrets.token_hex(4)
    while item_id in used:
        item_id = secrets.token_hex(4)
    item.update(id=item_id, added=time.time(), check=None, speed=None,
                tags=[], favorite=False)
    lib['items'].insert(0, item)
    return item


def set_check(lib, item_id, info, err=''):
    it = get(lib, item_id)
    if not it:
        return None
    if info:
        it['check'] = {'ok': True, 'ip': info.get('ip', ''), 'country': info.get('country', ''),
                       'city': info.get('city', ''), 'org': info.get('org', ''), 'ms': int(info.get('ms') or 0),
                       'time': time.time(), 'err': ''}
    else:
        it['check'] = {'ok': False, 'ip': '', 'country': '', 'city': '', 'org': '', 'ms': 0,
                       'time': time.time(), 'err': err or 'не отвечает'}
    return it


def set_speed(lib, item_id, res):
    it = get(lib, item_id)
    if not it or not res or not res.get('ok'):
        return None
    it['speed'] = {'mbps': float(res.get('mbps', 0)), 'latency_ms': int(res.get('latency_ms') or 0), 'time': time.time(),
                   'method': res.get('method'), 'source': res.get('source', ''),
                   'streams': res.get('streams', 1), 'requested_streams': res.get('requested_streams', 1)}
    return it


def pick_failover(lib, exclude_ids, max_age=900):
    """Лучший живой прокси для автозамены: недавно проверен успешно, не из исключённых, с минимальным откликом."""
    now = time.time()
    exclude = set(exclude_ids or ())
    cands = []
    for it in lib['items']:
        c = it.get('check') or {}
        if it['id'] in exclude or not c.get('ok'):
            continue
        if now - float(c.get('time') or 0) > max_age:
            continue
        cands.append(it)
    if not cands:
        return None
    return min(cands, key=lambda it: (it['check'].get('ms') or 10 ** 9))
