"""GeoBox DIY: трафик по устройствам.

Фаервол считает байты по IPv4 (tx/rx) и IPv6 (tx6/rx6) адресам клиентов Wi-Fi.
Здесь эти счётчики раз в пару минут переводятся в итоги по устройствам (по MAC) за день и за всё время.
Счётчики фаервола обнуляются при перезагрузке - это учитывается: если число стало меньше, считаем с нуля.
"""
import json
import ipaddress
import os
import re
import threading
import time

STATE_FILE = os.environ.get('GEOBOX_TRAFFIC', '/var/lib/geobox/traffic.json')
KEEP_DAYS = 31
LAN6 = ipaddress.IPv6Network('fd77:6765:6f62:1::/64')
MAC_RE = re.compile(r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$')
lock = threading.Lock()


def _empty():
    return {'last': {}, 'days': {}, 'total': {}}


def load():
    try:
        with open(STATE_FILE) as f:
            d = json.load(f)
        if isinstance(d, dict) and all(k in d for k in ('last', 'days', 'total')):
            return d
    except (OSError, ValueError):
        pass
    return _empty()


def _save(d):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(d, f)
    os.replace(tmp, STATE_FILE)


def read_counters(run):
    """{ip: [отправлено, получено]} из фаервола."""
    res = {}
    for idx, name, version in ((0, 'tx', 4), (1, 'rx', 4), (0, 'tx6', 6), (1, 'rx6', 6)):
        rc, out, _ = run(['nft', '-j', 'list', 'set', 'inet', 'geobox', name], timeout=10)
        if rc != 0:
            continue
        try:
            data = json.loads(out)
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        for obj in data.get('nftables', []):
            if not isinstance(obj, dict) or not isinstance(obj.get('set'), dict):
                continue
            for el in (obj.get('set') or {}).get('elem', []) or []:
                e = el.get('elem') if isinstance(el, dict) else None
                if not isinstance(e, dict) or not isinstance(e.get('val'), str):
                    continue
                try:
                    address = ipaddress.ip_address(e['val'])
                except ValueError:
                    continue
                if address.version != version or not isinstance(e.get('counter'), dict):
                    continue
                b = e['counter'].get('bytes', 0)
                if isinstance(b, bool) or not isinstance(b, int) or b < 0:
                    continue
                res.setdefault(str(address), [0, 0])[idx] = b
    return res


def ipv6_neighbors(run):
    """Best-effort attribution for statistics ONLY; never used for routing/security.

    SLAAC privacy addresses are grouped using the current neighbor table. Missing
    or unverifiable neighbors retain their ip: bucket rather than guessing a MAC.
    """
    rc, out, _ = run(['ip', '-j', '-6', 'neigh', 'show', 'dev', 'wlan0'], timeout=10)
    if rc != 0:
        return {}
    try:
        rows = json.loads(out)
    except (ValueError, TypeError):
        return {}
    if not isinstance(rows, list):
        return {}
    result = {}
    for row in rows:
        if not isinstance(row, dict) or row.get('dev', 'wlan0') != 'wlan0':
            continue
        mac = row.get('lladdr')
        if not isinstance(mac, str):
            continue
        mac = mac.lower()
        if not MAC_RE.fullmatch(mac) or mac == '00:00:00:00:00:00' or int(mac[:2], 16) & 1:
            continue
        states = row.get('state', [])
        if isinstance(states, str):
            states = [states]
        if not isinstance(states, list) or any(s in ('FAILED', 'INCOMPLETE') for s in states):
            continue
        try:
            address = ipaddress.IPv6Address(row.get('dst', ''))
        except (ValueError, TypeError):
            continue
        if address not in LAN6 or address == LAN6.network_address or address == LAN6.network_address + 1:
            continue
        result[str(address)] = mac
    return result


def update(run, ip2mac):
    """Добавить прирост с прошлого раза к итогам. ip2mac - {ip: mac} из аренд dnsmasq."""
    with lock:
        d = load()
        # Do not mutate DHCP's mapping; IPv6 neighbor data is only a stats hint.
        attribution = dict(ip2mac)
        attribution.update(ipv6_neighbors(run))
        cur = read_counters(run)
        day = time.strftime('%Y-%m-%d')
        today = d['days'].setdefault(day, {})
        for ip, (tx, rx) in cur.items():
            ltx, lrx = d['last'].get(ip, [0, 0])
            dtx = tx - ltx if tx >= ltx else tx      # меньше, чем было - счётчик обнулился
            drx = rx - lrx if rx >= lrx else rx
            if dtx or drx:
                key = attribution.get(ip) or ('ip:' + ip)
                for bucket in (today, d['total']):
                    v = bucket.setdefault(key, [0, 0])
                    v[0] += dtx
                    v[1] += drx
        d['last'] = cur
        for old in sorted(d['days'])[:-KEEP_DAYS]:
            del d['days'][old]
        _save(d)
        return d


def summary():
    """{mac: {'today': [tx, rx], 'total': [tx, rx]}}"""
    with lock:
        d = load()
    today = d['days'].get(time.strftime('%Y-%m-%d'), {})
    keys = set(today) | set(d['total'])
    return {k: {'today': today.get(k, [0, 0]), 'total': d['total'].get(k, [0, 0])} for k in keys}


def reset():
    with lock:
        d = load()
        _save({'last': d['last'], 'days': {}, 'total': {}})   # last оставляем, чтобы не посчитать старое заново


def fmt(n):
    n = float(n)
    for unit in ('Б', 'КБ', 'МБ', 'ГБ'):
        if n < 1024 or unit == 'ГБ':
            return ('%d %s' if unit == 'Б' else '%.1f %s') % (n, unit)
        n /= 1024
