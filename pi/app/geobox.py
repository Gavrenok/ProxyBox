#!/usr/bin/env python3
"""GeoBox DIY: настройки sing-box и веб-панель управления прокси.

Команды:
  geobox.py serve          веб-панель (порт 80)
  geobox.py render         собрать настройки sing-box из /etc/geobox/proxy.json (без перезапуска)
  geobox.py set-password   задать пароль панели (читает его из stdin)
  geobox.py status         состояние в консоль
"""
import base64
import email.parser
import email.policy
import hashlib
import hmac
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import devices as devmod      # noqa: E402  прокси на отдельное устройство
import library as libmod      # noqa: E402  сохранённые прокси и автозамена
import speedtest as spdmod    # noqa: E402  замер скорости
import notify as tgmod        # noqa: E402  уведомления в Telegram
import traffic as trmod       # noqa: E402  трафик по устройствам
import switching as swmod    # noqa: E402  переключение с журналом и откатом
import mimic as mimicmod     # noqa: E402  клиентская диагностика
import library_panel as libpanel  # noqa: E402  импорт и библиотека
import panel_runtime as runtime  # noqa: E402  быстрые проверки
import fastswitch as fastmod  # noqa: E402  переключение без перезапуска движка
import network_audit as auditmod  # noqa: E402  проверка защиты на малине
import udp_probe as udpmod  # noqa: E402  возможности SOCKS5 UDP
import ipv6_probe as ip6probe  # noqa: E402
import ipv6_policy as ip6policy  # noqa: E402
import ios_location as iosmod  # noqa: E402
import ios_location_panel as iospanel  # noqa: E402
import ios_pairing as iospair  # noqa: E402
import connectivity as connmod  # noqa: E402

ETC = os.environ.get('GEOBOX_ETC', '/etc/geobox')
PROXY_FILE = os.path.join(ETC, 'proxy.json')
PANEL_FILE = os.path.join(ETC, 'panel.json')
SETTINGS_FILE = os.path.join(ETC, 'settings.json')
SB_CONFIG = os.path.join(ETC, 'sing-box.json')
SB_BIN = os.environ.get('GEOBOX_SB', '/usr/bin/sing-box')
RUN_DIR = os.environ.get('GEOBOX_RUN', '/run/geobox')
SB_UNIT = 'geobox-singbox.service'
AP_CON = 'geobox-ap'
LEASES = '/var/lib/misc/dnsmasq.leases'
CHECK_PROXY = 'http://127.0.0.1:2080'   # вход sing-box только для самой малины: «что видят клиенты Wi-Fi»
PORT = int(os.environ.get('GEOBOX_PORT', '80'))
SESSION_TTL = 7 * 24 * 3600
MAX_BACKUP_BYTES = 32 * 1024 * 1024

apply_lock = threading.Lock()
sess_lock = threading.Lock()
sessions = {}
fails = []
state = {'exit': None, 'exit_time': 0.0, 'down_since': None, 'wifi_error': None,
         'fails': 0, 'failover_note': None, 'speed': None, 'notified_down': False,
         'switch': None}
lib_lock = threading.RLock()   # library.json и devices.json меняют несколько потоков
WATCH_EVERY = 120   # раз в сколько секунд панель сама проверяет выход через прокси
TELEMETRY_EVERY = 5
telemetry = {'singbox': 'проверяется', 'wifi': None, 'clients': [], 'traffic': {}, 'time': 0}
telemetry_wake = threading.Event()
job_slots = threading.BoundedSemaphore(3)
ios_manager = None
ios_pairing_manager = None


def ios_geo_for_device(address):
    """Resolve the authenticated phone's configured exit, without changing it."""
    with apply_lock:
        expected = iosmod.guards(ETC, ('proxy.json', 'devices.json', 'library.json'))
        matches = [d for d in devmod.load(ETC).values() if d.get('ip') == address]
        if len(matches) > 1:
            return {'ok': False, 'message': 'Для iPhone найдено несколько сетевых назначений.'}
        device = matches[0] if matches else {}
        mode = device.get('mode', 'default')
        if mode == 'default':
            proxy = load_proxy()
        elif mode == 'proxy':
            proxy = libmod.get(libmod.load(ETC), device.get('item'))
        else:
            proxy = None
        if not proxy or not proxy.get('outbound'):
            return {'ok': False, 'message': 'У iPhone нет действующего назначения прокси.'}
        # A private snapshot prevents a concurrent library edit changing the probe.
        proxy = json.loads(json.dumps(proxy))

    def locate(url):
        cfg = 'proxy = %s\n' % _curl_quote(url)
        rc, out, _ = run(['curl', '-s', '--fail', '-m', '20', '-K', '-',
                          'https://ipinfo.io/json'], data=cfg, timeout=25)
        if rc:
            return None
        try:
            data = json.loads(out)
            ipaddress.ip_address(data['ip'])
            parts = data['loc'].split(',')
            if len(parts) != 2:
                return None
            lat, lon = float(parts[0]), float(parts[1])
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                return None
            return {'ok': True, 'latitude': lat, 'longitude': lon,
                    'city': str(data.get('city', ''))[:120], 'guards': expected}
        except (ValueError, TypeError, KeyError, AttributeError):
            return None

    if mode == 'default':
        result = locate(CHECK_PROXY)
    else:
        result, _ = with_temp_proxy(proxy['outbound'], proxy.get('secrets'), locate)
    return result or {'ok': False, 'message': 'Прокси не ответил или сервис не вернул координаты. Старую точку не меняли.'}


def get_ios_manager():
    global ios_manager
    if ios_manager is None:
        ios_manager = iosmod.Controller(ETC, ios_geo_for_device,
                                       pause_when=lambda: get_ios_pairing_manager().active)
    return ios_manager


def get_ios_pairing_manager():
    global ios_pairing_manager
    if ios_pairing_manager is None:
        def paired():
            manager = get_ios_manager()
            manager.refresh_devices()
            manager.wake.set()
        ios_pairing_manager = iospair.PairingController(on_paired=paired)
    return ios_pairing_manager


# ---------------------------------------------------------------- общее
def run(cmd, data=None, timeout=30):
    try:
        p = subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or '', p.stderr or ''
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, '', str(e)


def write_private(path, text):
    """Атомарная запись файла, читать может только root."""
    swmod.private_write(path, text)


def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


# ---------------------------------------------------------------- разбор прокси
# Понимает почти любую запись и сам определяет формат:
#   ip:порт  ip:порт:логин:пароль  логин:пароль:ip:порт  логин:пароль@ip:порт  ip:порт@логин:пароль
#   те же с разделителями | ; , пробел  и со схемами socks5:// socks4:// http:// https://
#   ссылки ss:// vless:// vmess:// trojan:// hysteria2:// hy2://
IPV4_RE = re.compile(r'^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}$')
IPV6_RE = re.compile(r'^[0-9A-Fa-f:]{2,39}$')

PLAIN_SCHEMES = {'socks5': 'socks5', 'socks5h': 'socks5', 'socks': 'socks5', 'socks4': 'socks4',
                 'socks4a': 'socks4', 'http': 'http', 'https': 'https'}
KIND_NAMES = {'socks5': 'SOCKS5', 'socks4': 'SOCKS4', 'http': 'HTTP', 'https': 'HTTPS', 'ss': 'Shadowsocks',
              'vless': 'VLESS', 'vmess': 'VMess', 'trojan': 'Trojan', 'hysteria2': 'Hysteria2'}
AUTO_ORDER = ['socks5', 'http', 'socks4', 'https']   # что пробовать, если тип не указан
UTLS_FP = {'chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized'}


def is_host(t):
    return bool(IPV4_RE.match(t) or DOMAIN_RE.match(t))


def is_port(t):
    return t.isdigit() and 1 <= int(t) <= 65535


def _hostport(t):
    host, sep, port = t.rpartition(':')
    host = host.strip('[]')
    if sep and (is_host(host) or (':' in host and IPV6_RE.match(host))) and is_port(port):
        return host, int(port)
    return None


def _b64(s):
    s = urllib.parse.unquote(s.strip()).replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise ValueError('не получилось раскодировать base64')


def plain_outbound(kind, host, port, user, pw):
    if kind in ('socks5', 'socks4'):
        ob = {'type': 'socks', 'server': host, 'server_port': port, 'version': '5' if kind == 'socks5' else '4'}
        if user:
            ob['username'] = user
            if kind == 'socks5':
                ob['password'] = pw
    else:
        ob = {'type': 'http', 'server': host, 'server_port': port}
        if user:
            ob.update(username=user, password=pw)
        if kind == 'https':
            ob['tls'] = {'enabled': True, 'server_name': host}
    return ob


def _parse_plain(s, kind):
    s = s.strip().rstrip('/')
    if '@' in s:
        left, right = s.rsplit('@', 1)
        hp = _hostport(right)
        cred = left
        if not hp:
            hp, cred = _hostport(left), right
        if not hp:
            raise ValueError('не нашёл адрес:порт')
        user, _, pw = cred.partition(':')
        user, pw = urllib.parse.unquote(user), urllib.parse.unquote(pw)
        host, port = hp
    else:
        if re.search(r'[|;,\s]', s):
            toks, joiner = [], ''
            for t in re.split(r'[|;,\s]+', s):
                if not t:
                    continue
                hp = _hostport(t)
                toks.extend([hp[0], str(hp[1])] if hp else [t])
        else:
            toks, joiner = s.split(':'), ':'
        n = len(toks)
        idx = [i for i in range(n - 1) if is_host(toks[i]) and is_port(toks[i + 1])]
        if not idx:
            raise ValueError('не нашёл адрес и порт')
        if 0 in idx:
            i, rest = 0, toks[2:]
        elif n - 2 in idx:
            i, rest = n - 2, toks[:n - 2]
        else:
            raise ValueError('не понял, где логин, а где адрес')
        host, port = toks[i], int(toks[i + 1])
        user = rest[0] if rest else ''
        pw = (joiner or ':').join(rest[1:]) if len(rest) > 1 else ''
    kinds = [kind] if kind else AUTO_ORDER
    return {'server': host, 'port': port, 'name': '', 'secrets': [x for x in (pw,) if x],
            'cands': [(k, plain_outbound(k, host, port, user, pw)) for k in kinds],
            'login': bool(user)}


def _url(s):
    u = urllib.parse.urlsplit(s)
    q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    try:
        port = u.port
    except ValueError:
        raise ValueError('странный порт')
    host = u.hostname
    if not host or not port:
        raise ValueError('нет адреса или порта')
    return u, q, host, port, urllib.parse.unquote(u.fragment)


def _tls(q, host, sec):
    sec = (sec or '').lower()
    if sec not in ('tls', 'reality', 'xtls'):
        return None
    t = {'enabled': True, 'server_name': q.get('sni') or q.get('peer') or host}
    if q.get('alpn'):
        t['alpn'] = [a for a in q['alpn'].split(',') if a]
    if str(q.get('allowInsecure', q.get('insecure', ''))).lower() in ('1', 'true'):
        t['insecure'] = True
    fp = str(q.get('fp', '')).lower()
    if sec == 'reality':
        if not q.get('pbk'):
            raise ValueError('у reality нет pbk (публичного ключа)')
        t['reality'] = {'enabled': True, 'public_key': q['pbk'], 'short_id': q.get('sid', '')}
        fp = fp or 'chrome'
    if fp:
        t['utls'] = {'enabled': True, 'fingerprint': fp if fp in UTLS_FP else 'chrome'}
    return t


def _transport(net, host_hdr='', path='', service=''):
    net = (net or 'tcp').lower()
    if net in ('tcp', 'raw', 'none'):
        return None
    if net == 'ws':
        tr = {'type': 'ws', 'path': path or '/'}
        m = re.search(r'[?&]ed=(\d+)', tr['path'])
        if m:
            tr['path'] = re.sub(r'[?&]ed=\d+', '', tr['path']) or '/'
            tr['max_early_data'] = int(m.group(1))
            tr['early_data_header_name'] = 'Sec-WebSocket-Protocol'
        if host_hdr:
            tr['headers'] = {'Host': host_hdr}
        return tr
    if net == 'grpc':
        return {'type': 'grpc', 'service_name': service or path.strip('/') or ''}
    if net in ('http', 'h2'):
        tr = {'type': 'http', 'path': path or '/'}
        if host_hdr:
            tr['host'] = [h for h in host_hdr.split(',') if h]
        return tr
    if net == 'httpupgrade':
        tr = {'type': 'httpupgrade', 'path': path or '/'}
        if host_hdr:
            tr['host'] = host_hdr
        return tr
    raise ValueError('транспорт %s sing-box не поддерживает' % net)


def _link(kind, ob, name, secrets_):
    return {'server': ob['server'], 'port': ob['server_port'], 'name': name[:60],
            'secrets': [x for x in secrets_ if x], 'cands': [(kind, ob)], 'login': False}


def _parse_vless(s):
    u, q, host, port, name = _url(s)
    uuid = urllib.parse.unquote(u.username or '')
    if not uuid:
        raise ValueError('в ссылке нет UUID')
    ob = {'type': 'vless', 'server': host, 'server_port': port, 'uuid': uuid}
    if q.get('flow'):
        ob['flow'] = q['flow']
    tls = _tls(q, host, q.get('security', 'none'))
    if tls:
        ob['tls'] = tls
    tr = _transport(q.get('type'), q.get('host', ''), q.get('path', ''), q.get('serviceName', ''))
    if tr:
        ob['transport'] = tr
    return _link('vless', ob, name, [uuid])


def _parse_trojan(s):
    u, q, host, port, name = _url(s)
    pw = urllib.parse.unquote(u.username or '')
    if u.password:
        pw += ':' + urllib.parse.unquote(u.password)
    if not pw:
        raise ValueError('в ссылке нет пароля')
    ob = {'type': 'trojan', 'server': host, 'server_port': port, 'password': pw}
    tls = _tls(q, host, q.get('security') or 'tls')
    if tls:
        ob['tls'] = tls
    tr = _transport(q.get('type'), q.get('host', ''), q.get('path', ''), q.get('serviceName', ''))
    if tr:
        ob['transport'] = tr
    return _link('trojan', ob, name, [pw])


def _parse_vmess(s):
    body = s.split('://', 1)[1].split('#')[0]
    try:
        d = json.loads(_b64(body))
    except ValueError:
        raise ValueError('ссылка vmess не похожа на правильную')
    host = str(d.get('add', '')).strip()
    port = str(d.get('port', '')).strip()
    if not host or not is_port(port) or not d.get('id'):
        raise ValueError('в ссылке vmess нет адреса, порта или id')
    ob = {'type': 'vmess', 'server': host, 'server_port': int(port), 'uuid': str(d['id']),
          'security': str(d.get('scy') or 'auto'), 'alter_id': int(d.get('aid') or 0)}
    q = {'sni': d.get('sni', ''), 'alpn': d.get('alpn', ''), 'fp': d.get('fp', ''),
         'allowInsecure': str(d.get('allowInsecure', ''))}
    tls = _tls(q, host, 'tls' if str(d.get('tls', '')).lower() == 'tls' else 'none')
    if tls:
        ob['tls'] = tls
    net = str(d.get('net', 'tcp'))
    path = str(d.get('path', ''))
    tr = _transport(net, str(d.get('host', '')), path, path if net == 'grpc' else '')
    if tr:
        ob['transport'] = tr
    return _link('vmess', ob, str(d.get('ps', '')), [str(d['id'])])


def _parse_ss(s):
    body = s.split('://', 1)[1]
    body, _, frag = body.partition('#')
    name = urllib.parse.unquote(frag)
    if '@' in body:
        userinfo, hp = body.rsplit('@', 1)
        hp, _, qs = hp.partition('?')
        if 'plugin=' in qs:
            raise ValueError('Shadowsocks с плагином пока не умею')
        userinfo = urllib.parse.unquote(userinfo)
        if ':' not in userinfo:
            userinfo = _b64(userinfo)
    else:
        dec = _b64(body.split('?')[0].rstrip('/'))
        if '@' not in dec:
            raise ValueError('ссылка ss не похожа на правильную')
        userinfo, hp = dec.rsplit('@', 1)
    method, _, pw = userinfo.partition(':')
    hpp = _hostport(hp.rstrip('/'))
    if not hpp or not method:
        raise ValueError('в ссылке ss нет адреса, порта или метода')
    ob = {'type': 'shadowsocks', 'server': hpp[0], 'server_port': hpp[1], 'method': method, 'password': pw}
    return _link('ss', ob, name, [pw])


def _parse_hy2(s):
    s = re.sub(r'^hy2://', 'hysteria2://', s, flags=re.I)
    u = urllib.parse.urlsplit(s)
    q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    auth, _, hp = u.netloc.rpartition('@')
    host, _, port = hp.rpartition(':')
    host = host.strip('[]')
    if not port.isdigit():
        raise ValueError('диапазоны портов в Hysteria2 пока не умею')
    if not host or not is_port(port):
        raise ValueError('в ссылке нет адреса или порта')
    auth = urllib.parse.unquote(auth)
    ob = {'type': 'hysteria2', 'server': host, 'server_port': int(port), 'password': auth,
          'tls': {'enabled': True, 'server_name': q.get('sni') or host}}
    if str(q.get('insecure', '')).lower() in ('1', 'true'):
        ob['tls']['insecure'] = True
    if q.get('alpn'):
        ob['tls']['alpn'] = [a for a in q['alpn'].split(',') if a]
    if q.get('obfs'):
        if q['obfs'] != 'salamander':
            raise ValueError('обфускацию %s не знаю' % q['obfs'])
        ob['obfs'] = {'type': 'salamander', 'password': q.get('obfs-password', '')}
    return _link('hysteria2', ob, urllib.parse.unquote(u.fragment), [auth, q.get('obfs-password', '')])


LINK_PARSERS = {'vless': _parse_vless, 'vmess': _parse_vmess, 'trojan': _parse_trojan, 'ss': _parse_ss,
                'hysteria2': _parse_hy2, 'hy2': _parse_hy2}


def parse_proxy(text):
    """Возвращает {'server','port','name','secrets','cands':[(тип, outbound sing-box)],'login'}."""
    lines = [l.strip() for l in (text or '').strip().splitlines() if l.strip()]
    if not lines:
        raise ValueError('пустая строка')
    s = lines[0].strip('\'"<>`')
    m = re.match(r'^([A-Za-z0-9]+)://', s)
    if m:
        scheme = m.group(1).lower()
        if scheme in LINK_PARSERS:
            return LINK_PARSERS[scheme](s)
        if scheme in PLAIN_SCHEMES:
            return _parse_plain(s[m.end():], PLAIN_SCHEMES[scheme])
        raise ValueError('тип %s пока не умею' % scheme)
    return _parse_plain(s, None)


def migrate_proxy(p):
    """Старый формат proxy.json (первая версия панели) -> новый."""
    if not p or 'outbound' in p:
        return p
    kind = 'socks5' if p.get('type') == 'socks' else ('https' if p.get('tls') else 'http')
    return {'kind': kind, 'server': p['server'], 'port': p['port'], 'name': '', 'login': bool(p.get('username')),
            'secrets': [p['password']] if p.get('password') else [],
            'outbound': plain_outbound(kind, p['server'], int(p['port']), p.get('username', ''), p.get('password', ''))}


def proxy_label(p):
    if not p:
        return ''
    s = '%s %s:%s' % (KIND_NAMES.get(p.get('kind'), p.get('kind', '?')), p['server'], p['port'])
    if p.get('name'):
        s += ' «%s»' % p['name']
    if p.get('login'):
        s += ', с логином'
    return s


def _mask(text, secrets_):
    for x in secrets_ or []:
        if x and len(x) >= 3:
            text = text.replace(x, '***')
    return text


# ---------------------------------------------------------------- проверка прокси (без применения)
def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _wait_port(port, secs, scope=None):
    end = time.time() + secs
    while time.time() < end:
        if scope and scope.cancelled.is_set():
            return False
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def with_temp_proxy(ob, secrets_, fn, scope=None):
    """Поднимает временный sing-box только с этим прокси и вызывает fn('http://127.0.0.1:порт').
    Так проверка идёт ровно тем же движком, что и раздача - если тут работает, будет работать и там.
    Возвращает (результат fn, ошибка)."""
    os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
    port = _free_port()
    cfg = {'log': {'level': 'error'},
           'dns': {'servers': [{'type': 'udp', 'tag': 'bootstrap', 'server': '1.1.1.1'}]},
           'inbounds': [{'type': 'mixed', 'tag': 'in', 'listen': '127.0.0.1', 'listen_port': port}],
           'outbounds': [dict(ob, tag='p')],
           'route': {'final': 'p', 'default_domain_resolver': 'bootstrap'}}
    path = os.path.join(RUN_DIR, 'probe-%d.json' % port)
    write_private(path, json.dumps(cfg))
    try:
        if scope and scope.cancelled.is_set():
            return None, 'проверка отменена'
        rc, out, err = run([SB_BIN, 'check', '-c', path])
        if rc != 0:
            return None, 'sing-box не принял: ' + _mask((err or out).strip(), secrets_)[:300]
        proc = subprocess.Popen([SB_BIN, 'run', '-c', path, '-D', RUN_DIR],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if scope:
            scope.register(proc)
        try:
            if not _wait_port(port, 5, scope=scope):
                return None, 'sing-box не запустился'
            return fn('http://127.0.0.1:%d' % port), None
        finally:
            if scope:
                scope.discard(proc)
            try:
                proc.terminate()
            except OSError:
                pass
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def probe_outbound(ob, secrets_, timeout=12, scope=None):
    def measure(url):
        t0 = time.time()
        info = exit_info(url, timeout=timeout, scope=scope)
        if info:
            info['ms'] = int((time.time() - t0) * 1000)
        return info
    info, err = with_temp_proxy(ob, secrets_, measure, scope=scope)
    if err:
        return None, err
    if not info:
        return None, 'через прокси нет ответа'
    return info, None


def probe(parsed):
    return runtime.first_success(parsed['cands'], lambda ob, scope:
                                 probe_outbound(ob, parsed['secrets'], scope=scope))


def _curl_quote(v):
    return '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'


def exit_info(proxy_url, user=None, pw=None, timeout=15, scope=None):
    """IP и страна выхода через указанный прокси. Логин/пароль идут curl через stdin, не через командную строку."""
    cfg = 'proxy = %s\n' % _curl_quote(proxy_url)
    if scope and scope.cancelled.is_set():
        return None
    if user:
        cfg += 'proxy-user = %s\n' % _curl_quote(user + ':' + (pw or ''))
    rc, out, _ = run(['curl', '-s', '-m', str(timeout), '-K', '-', 'https://ipinfo.io/json'], data=cfg, timeout=timeout + 5)
    if rc == 0:
        try:
            j = json.loads(out)
            if isinstance(j, dict) and j.get('ip'):
                return {k: str(j.get(k, '')) for k in ('ip', 'country', 'city', 'org')}
        except ValueError:
            pass
    if scope and scope.cancelled.is_set():
        return None
    rc, out, _ = run(['curl', '-s', '-m', str(timeout), '-K', '-', 'https://api.ipify.org?format=json'], data=cfg, timeout=timeout + 5)
    if rc == 0:
        try:
            j = json.loads(out)
            if isinstance(j, dict) and j.get('ip'):
                return {'ip': str(j['ip']), 'country': '?', 'city': '', 'org': ''}
        except ValueError:
            pass
    return None


# ---------------------------------------------------------------- sing-box
def build_config(proxy, ext=None, ipv6=False):
    """Логика:
    - всё, что приходит из Wi-Fi (через sbtun), уходит ТОЛЬКО в прокси;
    - DNS клиентов перехватывается и идёт через прокси (DoH 1.1.1.1), провайдер не светится;
    - IPv6 закрыт по умолчанию; через прокси разрешается после проверки;
    - UDP и обращения в домашнюю сеть режутся;
    - нет прокси - нет интернета (kill switch).
    ext - дополнения для отдельных устройств (модуль devices.py):
      {'outbounds': [...], 'dns_servers': [...], 'dns_rules': [...], 'route_rules': [...]}
      правила устройств встают ПОСЛЕ общих запретов (UDP/IPv6/домашняя сеть) и ДО общего прокси / общего запрета."""
    ext = ext or {}
    # Until device identities are carried through the IPv6 tunnel, never let a
    # privacy address bypass a per-device proxy or block rule.
    ipv6 = bool(ipv6 and proxy and not ext.get('route_rules') and not ext.get('has_overrides'))
    inbounds = [
        {'type': 'tun', 'tag': 'tun-in', 'interface_name': 'sbtun',
         'address': ['172.19.0.1/30'], 'mtu': 1500, 'stack': 'gvisor'},
        {'type': 'direct', 'tag': 'dns-in', 'listen': '0.0.0.0', 'listen_port': 53},
        {'type': 'mixed', 'tag': 'check-in', 'listen': '127.0.0.1', 'listen_port': 2080},
    ]
    inbounds[0]['address'].append(ip6policy.TUN)
    bootstrap = {'type': 'udp', 'tag': 'bootstrap', 'server': '1.1.1.1'}
    rules = [
        {'action': 'sniff'},
        {'inbound': ['dns-in'], 'action': 'hijack-dns'},
        {'protocol': 'dns', 'action': 'hijack-dns'},
        {'network': 'udp', 'action': 'reject'},
        {'ip_is_private': True, 'action': 'reject'},
    ]
    if not ipv6:
        rules.insert(0, {'ip_version': 6, 'action': 'reject'})
    rules += list(ext.get('route_rules', []))
    dns_servers = [bootstrap] + list(ext.get('dns_servers', []))
    dns_rules = [] if ipv6 else [{'query_type': ['AAAA'], 'action': 'predefined'}]
    dns_rules += list(ext.get('dns_rules', []))
    outbounds = [{'type': 'direct', 'tag': 'direct'}] + list(ext.get('outbounds', []))
    if proxy:
        outbounds.insert(0, dict(proxy['outbound'], tag='proxy'))
        dns_servers.insert(0, {'type': 'https', 'tag': 'remote', 'server': '1.1.1.1', 'detour': 'proxy'})
        dns_final, final = 'remote', 'proxy'
    else:
        dns_rules.append({'action': 'reject'})
        rules.append({'action': 'reject'})
        dns_final, final = 'bootstrap', 'direct'
    return {
        'log': {'level': 'warn', 'timestamp': True},
        'dns': {'servers': dns_servers, 'rules': dns_rules, 'final': dns_final},
        'inbounds': inbounds,
        'outbounds': outbounds,
        'route': {'rules': rules, 'final': final, 'auto_detect_interface': True,
                  'default_domain_resolver': 'bootstrap'},
    }


def load_proxy():
    return migrate_proxy(load_json(PROXY_FILE))


def devices_ext():
    with lib_lock:
        devices = devmod.load(ETC)
        result = devmod.config_ext(devices, libmod.items_by_id(libmod.load(ETC)))
        result['has_overrides'] = any(not isinstance(d, dict) or d.get('mode') != 'default' for d in devices.values())
        return result


def ipv6_path():
    return os.path.join(ETC, 'ipv6-policy.json')


def load_ipv6():
    value = load_json(ipv6_path(), {})
    return value if isinstance(value, dict) else {}


def ipv6_candidate(proxy, mode=None):
    """Run under apply_lock; probe an isolated outbound, never change live routing."""
    policy = load_ipv6()
    mode = mode or policy.get('mode', 'block')
    candidate = {'mode': mode if mode in ('block', 'proxy') else 'block'}
    with lib_lock:
        devices = devmod.load(ETC)
    if (candidate['mode'] == 'proxy' and proxy and
            not any(not isinstance(d, dict) or d.get('mode') != 'default' for d in devices.values())):
        candidate['proof'] = ip6probe.probe(proxy['outbound'], timeout=15)
        candidate['proof']['fingerprint'] = ip6probe.fingerprint(proxy['outbound'])
    return candidate


def write_config(proxy, path):
    with lib_lock:
        ipv6 = ip6policy.evaluate(load_ipv6(), proxy, devmod.load(ETC))['enabled']
        base = build_config(proxy, devices_ext(), ipv6=ipv6)
        items = libmod.load(ETC)['items']
    secret = fastmod.controller(load_json(SB_CONFIG, {})) or secrets.token_hex(32)
    # A bad unused imported node must not prevent a valid current proxy from working.
    pools = [items, []] if items else [[]]
    for pool in pools:
        config = fastmod.configure(base, proxy, pool, secret)
        write_private(path, json.dumps(config, ensure_ascii=False, indent=2))
        rc, _, _ = run([SB_BIN, 'check', '-c', path])
        if rc == 0:
            return True, ''
    return False, 'проверь параметры прокси и назначений устройств'


def apply(proxy):
    old = load_json(SB_CONFIG, {})
    tmp = SB_CONFIG + '.new'
    ok, msg = write_config(proxy, tmp)
    if not ok:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False, 'sing-box не принял настройку: ' + msg
    candidate = load_json(tmp, {})
    client = fastmod.Client(old) if fastmod.compatible(old, candidate) else None
    fast = client is not None and client.matches(old)
    os.replace(tmp, SB_CONFIG)
    swmod.sync_parent(SB_CONFIG)
    if fast:
        try:
            client.select(candidate)
            return True, 'selector'
        except fastmod.ControllerError:
            # The PUT may have succeeded: the surrounding transaction restores
            # disk and runtime together instead of guessing the active route.
            return False, 'не удалось подтвердить переключение'
    rc, out, err = run(['systemctl', 'restart', SB_UNIT], timeout=60)
    if rc != 0:
        return False, 'не удалось перезапустить sing-box: ' + (err or out).strip()[:300]
    return True, 'restart'


def verify_switch_exit():
    """Verify installed route through localhost inbound; not a browser leak test."""
    for attempt in range(2):
        info = exit_info(CHECK_PROXY, timeout=8)
        if info:
            try:
                ipaddress.ip_address(info['ip'])
                return info
            except (ValueError, KeyError):
                pass
        if attempt == 0:
            time.sleep(1)
    return None


def _restart_tunnel():
    rc, _, _ = run(['systemctl', 'restart', SB_UNIT], timeout=60)
    return rc == 0 and run(['systemctl', 'is-active', '--quiet', SB_UNIT])[0] == 0


def _stop_tunnel():
    rc, _, _ = run(['systemctl', 'stop', SB_UNIT], timeout=30)
    _, status, _ = run(['systemctl', 'is-active', SB_UNIT])
    return rc == 0 and status.strip() in ('inactive', 'failed')


def switcher():
    return swmod.Switcher(SB_CONFIG, PROXY_FILE, os.path.join(ETC, 'switch-pending.json'),
                         apply, verify_switch_exit, _restart_tunnel, _stop_tunnel,
                         (os.path.join(ETC, 'devices.json'), devmod.HOSTS_FILE,
                          os.path.join(ETC, 'library.json'), SETTINGS_FILE, ipv6_path()),
                         lambda: run(['systemctl', 'reload', 'dnsmasq'])[0] == 0)


def switch_proxy(proxy):
    """Caller holds apply_lock. Persist selection only after installed exit responds."""
    state['switch'] = {'status': 'applying', 'message': 'Переключаю и проверяю выход…', 'time': time.time()}
    policy = ipv6_candidate(proxy)
    prepare = (lambda: write_private(ipv6_path(), json.dumps(policy))) if policy['mode'] == 'proxy' else None
    result = switcher().switch(proxy, prepare=prepare)
    state['switch'] = result
    if result['status'] != 'unchanged':
        state['exit'], state['exit_time'] = result.get('exit'), time.time()
        state['speed'] = None
    if result['ok'] or result.get('exit'):
        state['down_since'], state['fails'], state['notified_down'] = None, 0, False
    return result


def action_ipv6(mode):
    if mode not in ('block', 'proxy'):
        return ('err', 'Неизвестный режим IPv6.')
    with apply_lock:
        recovery = recover_before_mutation()
        if recovery:
            return ('err', recovery)
        proxy = load_proxy()
        policy = ipv6_candidate(proxy, mode)
        with lib_lock:
            value = ip6policy.evaluate(policy, proxy, devmod.load(ETC))
        # Closing IPv6 must still succeed when the rented proxy has expired.
        result = switcher().switch(proxy, prepare=lambda: write_private(ipv6_path(), json.dumps(policy)),
                                   verify=value['enabled'])
        state['switch'] = result
        if not result['ok']:
            return ('err', result['message'])
        telemetry_wake.set()
        return ('ok' if mode == 'block' or value['enabled'] else 'warn', value['message'])


def recover_before_mutation():
    result = switcher().recover()
    if result:
        state['switch'] = result
        state['exit'], state['exit_time'] = result.get('exit'), time.time()
        if result['status'] in ('blocked', 'attention'):
            return result['message']
    return ''


def check_exit(tries=3):
    with apply_lock:
        return _check_exit(tries)


def _check_exit(tries=3):
    info = None
    for i in range(tries):
        info = exit_info(CHECK_PROXY, timeout=12)
        if info:
            break
        if i < tries - 1:
            time.sleep(2)
    now = time.time()
    state['exit'], state['exit_time'] = info, now
    proxy = load_proxy()
    if info or not proxy:
        if info and state['notified_down']:
            mins = int((now - (state['down_since'] or now)) // 60)
            tg_event('up', 'прокси снова работает (простой ~%d мин). Выход: %s %s %s' % (
                mins, info['ip'], info['country'], info['city']))
        state['down_since'], state['fails'], state['notified_down'] = None, 0, False
    else:
        state['fails'] += 1
        if not state['down_since']:
            state['down_since'] = now
        if state['fails'] >= 2 and not state['notified_down']:
            state['notified_down'] = True
            tg_event('down', 'прокси %s не отвечает с %s. Клиенты Wi-Fi без интернета.' % (
                proxy_label(proxy), time.strftime('%H:%M', time.localtime(state['down_since']))))
    return info


# ---------------------------------------------------------------- настройки и уведомления
TG_EVENTS = {'down': 'прокси перестал отвечать', 'up': 'прокси снова работает',
             'failover': 'сработала автозамена', 'device': 'новое устройство в Wi-Fi'}


def load_settings():
    s = load_json(SETTINGS_FILE, {}) or {}
    s.setdefault('tg', {})
    s['tg'].setdefault('events', {k: True for k in TG_EVENTS})
    return s


def save_settings(s):
    write_private(SETTINGS_FILE, json.dumps(s, ensure_ascii=False))


def tg_event(kind, text):
    """Отправить уведомление, если Telegram настроен и событие включено."""
    tg = load_settings()['tg']
    if tg.get('token') and tg.get('chat_id') and tg['events'].get(kind, True):
        tgmod.send_async(tg['token'], tg['chat_id'], 'GeoBox: ' + text)


def _leases():
    res = {}
    try:
        with open(LEASES) as f:
            for line in f:
                p = line.split()
                if len(p) >= 4:
                    res[p[2]] = (p[1].lower(), '' if p[3] == '*' else p[3])
    except OSError:
        pass
    return res


def watch_tick():
    """Раз в пару минут: трафик, новые устройства."""
    if not telemetry['time']:
        return
    s = load_settings()
    known = set(s.get('known_macs', []))
    first = 'known_macs' not in s
    cur = {c['mac']: c for c in telemetry['clients']}
    new = [m for m in cur if m not in known]
    if new:
        if not first:
            for m in new:
                c = cur[m]
                tg_event('device', 'новое устройство в Wi-Fi: %s (%s, %s)' % (c['name'] or 'без имени', c['ip'] or 'ещё без адреса', m))
        s['known_macs'] = sorted(known | set(new))[-500:]
        save_settings(s)
    elif first:
        s['known_macs'] = []
        save_settings(s)


def watchdog():
    """Слежение за прокси: раз в WATCH_EVERY секунд проверяет выход. Пока идёт смена прокси - не мешает."""
    while True:
        try:
            if load_proxy() and not apply_lock.locked():
                check_exit(tries=2)
                if state['fails'] >= 2:
                    failover()
            watch_tick()
        except Exception:
            pass
        time.sleep(WATCH_EVERY)


def _lib_item_for(proxy):
    """Элемент библиотеки, совпадающий с прокси (или None)."""
    if not proxy:
        return None
    key = libmod.identity(proxy)
    with lib_lock:
        for it in libmod.load(ETC)['items']:
            if libmod.identity(it) == key:
                return it
    return None


def _remember(proxy, info=None, err=''):
    """Сохранить прокси в библиотеку вместе с результатом проверки."""
    with lib_lock:
        lib = libmod.load(ETC)
        it = libmod.add_or_update(lib, proxy)
        if info or err:
            libmod.set_check(lib, it['id'], info, err)
        libmod.save(ETC, lib)
        return it['id']


def failover():
    """Текущий прокси лежит: если включена автозамена - переключиться на живой из библиотеки."""
    with lib_lock:
        lib = libmod.load(ETC)
    if not lib.get('failover'):
        return
    original = load_proxy()
    cur = _lib_item_for(original)
    exclude = [cur['id']] if cur else []
    best = libmod.pick_failover(lib, exclude)
    order = ([best] if best else []) + [it for it in lib['items'] if it['id'] not in exclude and (not best or it['id'] != best['id'])]
    for it in order[:6]:
        info, err = probe_outbound(it['outbound'], it.get('secrets'))
        with lib_lock:
            lib2 = libmod.load(ETC)
            libmod.set_check(lib2, it['id'], info, err or '')
            libmod.save(ETC, lib2)
        if not info:
            continue
        with apply_lock:
            # A user's switch wins over a watchdog probe that started earlier.
            if load_proxy() != original or state['fails'] < 2 or not libmod.load(ETC).get('failover'):
                return
            p = libmod.as_proxy(it)
            result = switch_proxy(p)
            if not result['ok']:
                if result['status'] in ('blocked', 'attention'):
                    return
                continue
        state['failover_note'] = 'Автозамена в %s: %s не отвечал, переключил на %s.' % (
            time.strftime('%H:%M'), proxy_label(cur) if cur else 'прокси', proxy_label(it))
        tg_event('failover', state['failover_note'])
        return
    note = 'Автозамена в %s: живых прокси в библиотеке не нашлось.' % time.strftime('%H:%M')
    if state['failover_note'] != note:
        tg_event('failover', note)
    state['failover_note'] = note


def _info_text(info):
    t = '%s · %s %s · %s' % (info['ip'], info['country'], info['city'], info['org'])
    if info.get('ms'):
        t += ' · отклик %d мс' % info['ms']
    return t


def action_check_proxy(text):
    """Только проверка: что за прокси и кем через него выходим. Ничего не меняет."""
    try:
        parsed = parse_proxy(text)
    except ValueError as e:
        return {'ok': False, 'text': text, 'msg': 'Не понял прокси: %s' % e}
    kind, ob, info, errors = probe(parsed)
    if not kind:
        return {'ok': False, 'text': text, 'msg': 'Прокси не работает. ' + '; '.join(errors)}
    p = {'kind': kind, 'server': parsed['server'], 'port': parsed['port'], 'name': parsed['name'],
         'login': parsed['login'], 'secrets': parsed['secrets'], 'outbound': ob}
    _remember(p, info)
    return {'ok': True, 'text': text, 'label': proxy_label(p), 'info': info}


def action_set_proxy(text):
    try:
        parsed = parse_proxy(text)
    except ValueError as e:
        return ('err', 'Не понял прокси: %s' % e)
    with apply_lock:
        kind, ob, info, errors = probe(parsed)
        if not kind:
            return ('err', 'Прокси не работает, ничего не менял. ' + '; '.join(errors))
        p = {'kind': kind, 'server': parsed['server'], 'port': parsed['port'], 'name': parsed['name'],
             'login': parsed['login'], 'secrets': parsed['secrets'], 'outbound': ob}
        result = switch_proxy(p)
        if not result['ok']:
            return ('err', result['message'])
    ex = result['exit']
    _remember(p, ex)
    state['failover_note'] = None
    return ('ok', 'Прокси применён: %s. Выход проверен: %s' % (proxy_label(p), _info_text(ex)))


def action_speed_current():
    with apply_lock:
        return _action_speed_current_locked()


def _speed_text(res):
    return ('%.1f Мбит/с · %s · %d/%d потоков · первый ответ %d мс%s' % (
        res['mbps'], res.get('source', 'сервер'), res.get('streams', 1), res.get('requested_streams', 1),
        res['latency_ms'], ' · неполный замер' if res.get('partial') else ''))


def _action_speed_current_locked():
    proxy = load_proxy()
    if not proxy:
        return ('err', 'Прокси не задан - мерить нечего.')
    res = spdmod.speed_test(CHECK_PROXY, seconds=10)
    if not res.get('ok'):
        state['speed'] = None
        return ('err', 'Замер не удался: %s' % res.get('err', ''))
    state['speed'] = dict(res, time=time.time())
    it = _lib_item_for(proxy)
    if it:
        with lib_lock:
            lib = libmod.load(ETC)
            libmod.set_speed(lib, it['id'], res)
            libmod.save(ETC, lib)
    return ('warn' if res.get('partial') else 'ok', 'Скачивание через текущий прокси: ' + _speed_text(res))


def _devices_using(item_id):
    devs = devmod.load(ETC)
    return [(d.get('name') or m) for m, d in devs.items() if d.get('item') == item_id]


def action_lib(op, item_id):
    with lib_lock:
        lib = libmod.load(ETC)
        if op in ('failover_on', 'failover_off'):
            lib['failover'] = op == 'failover_on'
            libmod.save(ETC, lib)
            return ('ok', 'Автозамена включена.' if lib['failover'] else 'Автозамена выключена.')
        it = libmod.get(lib, item_id)
    if not it:
        return ('err', 'Такого прокси в списке нет.')
    label = proxy_label(it)
    if op == 'check':
        info, err = probe_outbound(it['outbound'], it.get('secrets'))
        with lib_lock:
            lib = libmod.load(ETC)
            libmod.set_check(lib, it['id'], info, err or '')
            libmod.save(ETC, lib)
        return ('ok', 'Работает: %s. Выход: %s' % (label, _info_text(info))) if info else ('err', 'Не работает: %s - %s' % (label, err))
    if op == 'speed':
        res, err = with_temp_proxy(it['outbound'], it.get('secrets'), lambda url: spdmod.speed_test(url, seconds=10))
        if err or not res or not res.get('ok'):
            return ('err', 'Замер %s не удался: %s' % (label, err or (res or {}).get('err', '')))
        with lib_lock:
            lib = libmod.load(ETC)
            libmod.set_speed(lib, it['id'], res)
            libmod.save(ETC, lib)
        return ('warn' if res.get('partial') else 'ok', 'Скачивание через %s: %s' % (label, _speed_text(res)))
    if op == 'apply':
        with apply_lock:
            with lib_lock:
                it = libmod.get(libmod.load(ETC), item_id)
            if not it:
                return ('err', 'Прокси уже удалён из библиотеки.')
            info, err = probe_outbound(it['outbound'], it.get('secrets'))
            with lib_lock:
                lib = libmod.load(ETC)
                libmod.set_check(lib, it['id'], info, err or '')
                libmod.save(ETC, lib)
            if not info:
                return ('err', 'Не работает, ничего не менял: %s - %s' % (label, err))
            p = libmod.as_proxy(it)
            result = switch_proxy(p)
            if not result['ok']:
                return ('err', result['message'])
            ex = result['exit']
            _remember(p, ex)
        state['failover_note'] = None
        return ('ok', 'Применён: %s. Выход проверен: %s' % (label, _info_text(ex)))
    if op == 'delete':
        with apply_lock:
            with lib_lock:
                used = _devices_using(it['id'])
                if used:
                    return ('err', 'Этот прокси закреплён за устройствами: %s. Сначала переключи их.' % ', '.join(used))
                cur = _lib_item_for(load_proxy())
                lib = libmod.load(ETC)
                libmod.remove(lib, it['id'])
                libmod.save(ETC, lib)
        note = ' Он сейчас применён - работать продолжит, просто пропал из списка.' if cur and cur['id'] == it['id'] else ''
        return ('ok', 'Удалил из списка: %s.%s' % (label, note))
    return ('err', 'Не понял действие.')


def action_device(mac, ip, choice, name):
    with apply_lock:
        err = recover_before_mutation()
        if err:
            return ('err', err)
        return _action_device_locked(mac, ip, choice, name)


def _action_device_locked(mac, ip, choice, name):
    if choice == 'default':
        mode, item = 'default', None
    elif choice == 'block':
        mode, item = 'block', None
    else:
        mode, item = 'proxy', choice
    with lib_lock:
        lib = libmod.load(ETC)
        if mode == 'proxy' and not libmod.get(lib, item):
            return ('err', 'Такого прокси в списке нет.')
        if mode == 'proxy':
            selected = libmod.get(lib, item)
            checked, error = probe_outbound(selected['outbound'], selected.get('secrets'))
            libmod.set_check(lib, item, checked, error or '')
            libmod.save(ETC, lib)
            if not checked:
                return ('err', 'Прокси устройства не прошёл проверку. Назначение не менял.')
        devs = devmod.load(ETC)
        try:
            devmod.set_mode(devs, (mac or '').lower(), ip, mode, item, (name or '')[:40])
        except ValueError as e:
            return ('err', str(e))
        def prepare():
            devmod.save(ETC, devs)
            ok, _ = devmod.write_hosts(ETC, devs, run)
            if not ok:
                raise RuntimeError('DHCP apply failed')
        result = switcher().switch(load_proxy(), prepare=prepare, verify=False)
        state['switch'] = result
        state['exit'], state['exit_time'], state['speed'] = result.get('exit'), time.time(), None
        if not result['ok']:
            return ('err', result['message'])
    what = {'default': 'как все', 'block': 'без интернета'}.get(mode) or ('через ' + proxy_label(libmod.get(lib, item)))
    ipv6_note = (' IPv6 закрыт для всех: отдельные назначения пока поддерживают только IPv4.'
                 if load_ipv6().get('mode') == 'proxy' and devs else '')
    return ('ok', 'Устройство %s теперь %s. Соединения перезапущены. Выход самого устройства проверь во вкладке Mimic.%s' % (name or mac, what, ipv6_note))


def action_tg(op, f):
    s = load_settings()
    tg = s['tg']
    if op == 'save':
        token = (f.get('token') or '').strip()
        chat = (f.get('chat_id') or '').strip()
        if token:
            if not tgmod.TOKEN_RE.match(token):
                return ('err', 'Токен не похож на токен бота (вида 123456789:AA...). Ничего не менял.')
            tg['token'] = token
        if chat and not tgmod.CHAT_RE.match(chat):
            return ('err', 'Chat id - это число (у групп с минусом) или @имя канала.')
        tg['chat_id'] = chat
        tg['events'] = {k: f.get('ev_' + k) == '1' for k in TG_EVENTS}
        save_settings(s)
        return ('ok', 'Настройки Telegram сохранены.')
    if op == 'off':
        s['tg'] = {'events': tg.get('events', {})}
        save_settings(s)
        return ('ok', 'Telegram отключён, токен удалён.')
    if not tg.get('token'):
        return ('err', 'Сначала вставь токен бота и сохрани.')
    if op == 'find':
        chats, err = tgmod.find_chats(tg['token'])
        if err:
            return ('err', 'Telegram ответил: %s' % err)
        if not chats:
            return ('warn', 'Боту ещё никто не писал. Открой своего бота в Telegram, нажми Start или напиши любое сообщение, потом снова «Найти chat id».')
        if len(chats) == 1:
            tg['chat_id'] = chats[0][0]
            save_settings(s)
            return ('ok', 'Нашёл и сохранил chat id: %s (%s). Нажми «Отправить тест».' % chats[0])
        return ('ok', 'Боту писали несколько чатов, впиши нужный id: ' + '; '.join('%s - %s' % c for c in chats))
    if op == 'test':
        ok, err = tgmod.send(tg['token'], tg.get('chat_id'), 'GeoBox: тестовое сообщение. Уведомления работают.')
        return ('ok', 'Отправил тестовое сообщение - проверь Telegram.') if ok else ('err', 'Не отправилось: %s' % err)
    return ('err', 'Не понял действие.')


BACKUP_VERSION = 1


def export_backup():
    with lib_lock:
        data = {'geobox_backup': BACKUP_VERSION, 'created': time.strftime('%Y-%m-%d %H:%M:%S'),
                'proxy': load_proxy(), 'library': libmod.load(ETC), 'devices': devmod.load(ETC),
                'wifi': wifi_settings(with_secret=True), 'settings': load_settings(),
                'ipv6': {'mode': load_ipv6().get('mode', 'block')}}
    data['settings'].pop('known_macs', None)
    return json.dumps(data, ensure_ascii=False, indent=1)


def action_restore(raw, with_wifi):
    with apply_lock:
        err = recover_before_mutation()
        if err:
            return ('err', err)
        return _action_restore_locked(raw, with_wifi)


def _action_restore_locked(raw, with_wifi):
    if len(raw) > MAX_BACKUP_BYTES:
        return ('err', 'Резервная копия больше 32 МБ.')
    try:
        d = json.loads(raw.decode('utf-8-sig'))
    except (ValueError, UnicodeDecodeError):
        return ('err', 'Это не файл настроек GeoBox (не JSON).')
    if not isinstance(d, dict) or d.get('geobox_backup') != BACKUP_VERSION:
        return ('err', 'Это не файл настроек GeoBox или он от другой версии.')
    lib = d.get('library') or {}
    if not isinstance(lib, dict) or not isinstance(lib.get('items', []), list):
        return ('err', 'В файле испорчен список прокси.')
    items = lib.get('items', [])
    if any(not isinstance(it, dict) or not isinstance(it.get('id'), str)
           or not devmod.ITEM_RE.fullmatch(it['id']) or not isinstance(it.get('outbound'), dict)
           or not it.get('outbound') for it in items):
        return ('err', 'В файле испорчен профиль прокси.')
    if len({it['id'] for it in items}) != len(items):
        return ('err', 'В файле повторяются идентификаторы прокси.')
    devs_in = d.get('devices') or {}
    devs = {}
    try:
        for mac, v in devs_in.items():
            devmod.set_mode(devs, mac, v.get('ip'), v.get('mode'), v.get('item'), v.get('name', ''))
    except (ValueError, AttributeError) as e:
        return ('err', 'В файле испорчен список устройств: %s' % e)
    try:
        proxy = migrate_proxy(d.get('proxy'))
        if proxy is not None and (not isinstance(proxy, dict) or not isinstance(proxy.get('outbound'), dict)
                                  or not proxy.get('outbound')):
            raise ValueError('invalid proxy')
    except (ValueError, TypeError, KeyError, AttributeError):
        return ('err', 'В файле испорчен общий прокси.')
    with lib_lock:
        def prepare():
            libmod.save(ETC, {'items': items, 'failover': bool(lib.get('failover'))})
            devmod.save(ETC, devs)
            ok, _ = devmod.write_hosts(ETC, devs, run)
            if not ok:
                raise RuntimeError('DHCP restore failed')
            st = d.get('settings') or {}
            # A backup is not proof that a rented/rotating proxy still has IPv6.
            restored_ipv6 = d.get('ipv6') or {}
            mode = restored_ipv6.get('mode') if isinstance(restored_ipv6, dict) else 'block'
            write_private(ipv6_path(), json.dumps({'mode': mode if mode in ('block', 'proxy') else 'block'}))
            if isinstance(st, dict) and isinstance(st.get('tg'), dict):
                s = load_settings()
                s['tg'] = st['tg']
                save_settings(s)
        result = switcher().switch(proxy, prepare=prepare)
        state['switch'] = result
        state['exit'], state['exit_time'], state['speed'] = result.get('exit'), time.time(), None
        if not result['ok']:
            return ('err', result['message'])
    note = ''
    w = d.get('wifi')
    if with_wifi and isinstance(w, dict) and w.get('ssid'):
        old = wifi_settings(with_secret=True)
        ok2, msg2 = _nm_modify(w['ssid'], w.get('band') or 'a', w.get('channel') or '36', w.get('psk') or '')
        if ok2:
            threading.Thread(target=_restart_ap, args=(old,), daemon=True).start()
            note = ' Wi-Fi перезапускается с настройками из файла (сеть «%s»).' % w['ssid']
        else:
            note = ' Wi-Fi из файла не применился: %s' % msg2
    return ('ok', 'Настройки восстановлены: прокси, список (%d), устройства (%d), Telegram. Для IPv6 через прокси повтори проверку в Настройках.%s'
            % (len(lib.get('items', [])), len(devs), note))


def action_proxy_off():
    with apply_lock:
        result = switch_proxy(None)
        if not result['ok']:
            return ('err', result['message'])
    return ('ok', 'Общий прокси выключен. Устройства со своим прокси продолжают работать; остальные без интернета.')


# ---------------------------------------------------------------- Wi-Fi
def _nm_unescape(v):
    return v.replace('\\:', ':').replace('\\\\', '\\')


def wifi_settings(with_secret=False):
    fields = '802-11-wireless.ssid,802-11-wireless.band,802-11-wireless.channel'
    if with_secret:
        fields += ',802-11-wireless-security.psk'
    cmd = ['nmcli'] + (['-s'] if with_secret else []) + ['-g', fields, 'connection', 'show', AP_CON]
    rc, out, _ = run(cmd, timeout=10)
    if rc != 0:
        return None
    lines = out.rstrip('\n').split('\n')
    lines += [''] * (4 - len(lines))
    return {'ssid': _nm_unescape(lines[0]), 'band': lines[1], 'channel': lines[2] or ('36' if lines[1] == 'a' else '6'),
            'psk': _nm_unescape(lines[3]) if with_secret else ''}


def _nm_modify(ssid, band, channel, psk):
    args = ['nmcli', 'connection', 'modify', AP_CON, '802-11-wireless.ssid', ssid,
            '802-11-wireless.band', band, '802-11-wireless.channel', channel]
    if psk:
        args += ['wifi-sec.psk', psk]
    rc, out, err = run(args, timeout=20)
    return rc == 0, _mask((err or out).strip(), [psk])[:300]


def _restart_ap(old):
    """Перезапуск точки уже после ответа браузеру. Не поднялась - возвращаем старые настройки."""
    time.sleep(2)
    rc, _, _ = run(['nmcli', '--wait', '40', 'connection', 'up', AP_CON], timeout=60)
    if rc == 0:
        state['wifi_error'] = None
        return
    if old:
        _nm_modify(old['ssid'], old['band'], old['channel'], old['psk'])
        run(['nmcli', '--wait', '40', 'connection', 'up', AP_CON], timeout=60)
    state['wifi_error'] = 'Новые настройки Wi-Fi не поднялись (%s) - вернул старые.' % time.strftime('%H:%M')


def action_wifi(ssid, pw, pw2, band):
    ssid = (ssid or '').strip()
    if not ssid or len(ssid.encode('utf-8')) > 32 or any(ord(c) < 32 for c in ssid):
        return ('err', 'Имя сети: от 1 до 32 символов (кириллица считается за 2).')
    if band not in ('a', 'bg'):
        return ('err', 'Не понял диапазон Wi-Fi.')
    if pw or pw2:
        if pw != pw2:
            return ('err', 'Пароли Wi-Fi не совпали, ничего не менял.')
        if not 8 <= len(pw) <= 63 or not all(32 <= ord(c) < 127 for c in pw):
            return ('err', 'Пароль Wi-Fi: 8-63 символа, только латиница, цифры и знаки.')
    old = wifi_settings(with_secret=True)
    if not old:
        return ('err', 'Не нашёл настройки точки Wi-Fi (geobox-ap).')
    if ssid == old['ssid'] and band == old['band'] and not pw:
        return ('ok', 'Ничего не изменилось.')
    ok, msg = _nm_modify(ssid, band, '36' if band == 'a' else '6', pw)
    if not ok:
        return ('err', 'NetworkManager не принял настройки: ' + msg)
    state['wifi_error'] = None
    threading.Thread(target=_restart_ap, args=(old,), daemon=True).start()
    return ('ok', 'Wi-Fi перезапускается (секунд 10-20). Подключись заново к сети «%s»%s. '
                  'Если новые настройки не поднимутся, панель сама вернёт старые.'
            % (ssid, ' с новым паролем' if pw else ''))


# ---------------------------------------------------------------- состояние
def _dur(sec):
    try:
        sec = int(sec)
    except ValueError:
        return ''
    h, m = sec // 3600, (sec % 3600) // 60
    if h:
        return '%d ч %d мин' % (h, m)
    if m:
        return '%d мин' % m
    return '%d с' % sec


def clients():
    _, out, _ = run(['iw', 'dev', 'wlan0', 'station', 'dump'], timeout=10)
    st, cur = {}, None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('Station '):
            cur = line.split()[1].lower()
            st[cur] = {}
        elif cur and line.startswith('signal:'):
            st[cur]['signal'] = line.split(':', 1)[1].strip().split('[')[0].strip()
        elif cur and line.startswith('connected time:'):
            st[cur]['time'] = _dur(line.split(':', 1)[1].strip().split()[0])
    leases = {}
    try:
        with open(LEASES) as f:
            for line in f:
                p = line.split()
                if len(p) >= 4:
                    leases[p[1].lower()] = (p[2], '' if p[3] == '*' else p[3])
    except OSError:
        pass
    res = []
    for mac, d in st.items():
        ip, name = leases.get(mac, ('', ''))
        res.append({'mac': mac, 'ip': ip, 'name': name, 'signal': d.get('signal', ''), 'time': d.get('time', '')})
    return res


def wifi_info():
    w = wifi_settings()
    if not w:
        return '?'
    return '%s (%s)' % (w['ssid'], {'a': '5 ГГц', 'bg': '2.4 ГГц'}.get(w['band'], w['band'] or '?'))


def status_dict():
    snapshot = telemetry
    w = snapshot.get('wifi')
    wifi = ('%s (%s)' % (w['ssid'], {'a': '5 ГГц', 'bg': '2.4 ГГц'}.get(w['band'], '?'))) if w else 'получаем состояние…'
    return {
        'singbox': snapshot['singbox'],
        'wifi': wifi,
        'proxy': proxy_label(load_proxy()),
        'exit': state['exit'],
        'exit_age': int(time.time() - state['exit_time']) if state['exit_time'] else None,
        'clients': snapshot['clients'],
        'down_since': state['down_since'],
        'wifi_error': state['wifi_error'],
        'switch': state['switch'],
        'sample_age': int(time.time() - snapshot['time']) if snapshot['time'] else None,
    }


def refresh_telemetry():
    """Only the sampler runs OS commands; GET handlers read its last snapshot."""
    global telemetry
    _, out, _ = run(['systemctl', 'is-active', SB_UNIT], timeout=3)
    snapshot = {'singbox': out.strip() or 'unknown', 'wifi': wifi_settings(),
                'clients': clients(), 'traffic': telemetry['traffic'], 'time': time.time()}
    # Publish station/service state before potentially slow counter collection.
    telemetry = snapshot
    try:
        trmod.update(run, {ip: v[0] for ip, v in _leases().items()})
        telemetry = dict(snapshot, traffic=trmod.summary())
    except Exception:
        pass


def telemetry_loop():
    while True:
        try:
            refresh_telemetry()
        except Exception:
            pass
        telemetry_wake.wait(TELEMETRY_EVERY)
        telemetry_wake.clear()


def audit_signature():
    """Cheap change marker for the last report; never exported to the browser."""
    result = []
    for path in (SB_CONFIG, PROXY_FILE, os.path.join(ETC, 'devices.json'), os.path.join(ETC, 'library.json')):
        try:
            info = os.stat(path)
            result.append((info.st_ino, info.st_size, info.st_mtime_ns))
        except OSError:
            result.append(None)
    return tuple(result)


def action_diagnostics(session):
    if not apply_lock.acquire(blocking=False):
        return ('warn', 'Сейчас меняется подключение или проверяется выход. Повтори проверку защиты после завершения операции.')
    try:
        with lib_lock:
            before = audit_signature()
            config = load_json(SB_CONFIG, {})
            devices = devmod.load(ETC)
        report = auditmod.audit(config, devices=devices, run=run,
                               selector_read=lambda cfg: fastmod.Client(cfg).request('GET', '/proxies/proxy'))
        after = audit_signature()
        report['stale'] = before != after
        with sess_lock:
            session['router_audit'] = {'report': report, 'signature': after}
        if report['stale']:
            return ('warn', 'Настройки изменились во время проверки. Повтори её для новых настроек.')
        return ('ok' if report.get('status') == 'pass' else 'warn',
                'Проверка правил на малине завершена. Результат — во вкладке Mimic; проверки самого устройства запускаются отдельно.')
    finally:
        apply_lock.release()


def session_audit(session):
    """A dated snapshot, invalidated after settings changes or five minutes."""
    with sess_lock:
        saved = session.get('router_audit')
        if not saved:
            return None
        report = dict(saved['report'])
        signature = saved['signature']
    report['stale'] = (report.get('stale', False) or signature != audit_signature()
                       or time.time() - report.get('checked_at', 0) > 300)
    return report


def client_proxy(client_ip):
    """Choose the configured route from the socket peer, never a form field."""
    try:
        wifi = ipaddress.ip_address(client_ip) in ipaddress.ip_network('10.77.0.0/24')
    except ValueError:
        wifi = False
    if not wifi:
        return load_proxy(), 'outside'
    matches = [d for d in devmod.load(ETC).values() if d.get('ip') == client_ip]
    if len(matches) > 1:
        return None, 'blocked'
    device = matches[0] if matches else {}
    if device.get('mode', 'default') == 'default':
        return load_proxy(), 'global_proxy'
    if device.get('mode') == 'proxy':
        item = libmod.get(libmod.load(ETC), device.get('item'))
        return (libmod.as_proxy(item), 'device_proxy') if item else (None, 'blocked')
    return None, 'blocked'


def action_udp_diagnostics(session, client_ip):
    if not apply_lock.acquire(blocking=False):
        return ('warn', 'Подключение занято другой операцией. Повтори UDP-проверку после её завершения.')
    try:
        with lib_lock:
            before = audit_signature()
            proxy, scope = client_proxy(client_ip)
        report = udpmod.probe(proxy)
        after = audit_signature()
        report.update(scope=scope, stale=before != after)
        with sess_lock:
            session['udp_probe'] = {'report': report, 'signature': after, 'client_ip': client_ip}
        return ('ok' if report['status'] == 'pass' and not report['stale'] else 'warn',
                'UDP-проверка завершена. Результат — во вкладке Mimic; правила сети не изменены.')
    finally:
        apply_lock.release()


def session_udp_probe(session, client_ip):
    with sess_lock:
        saved = session.get('udp_probe')
        if not saved:
            return None
        report = dict(saved['report'])
        signature, previous_client = saved['signature'], saved['client_ip']
    report['stale'] = (report.get('stale', False) or signature != audit_signature() or previous_client != client_ip
                       or time.time() - report.get('checked_at', 0) > 300)
    return report


def action_connection_diagnostics(session, client_ip):
    """Read-only diagnosis scoped to the authenticated request's socket peer."""
    if not apply_lock.acquire(blocking=False):
        return ('warn', 'Подключение занято другой операцией. Повтори диагностику после её завершения.')
    try:
        with lib_lock:
            before = audit_signature()
            config = load_json(SB_CONFIG, {})
            devices = devmod.load(ETC)
            proxy, scope = client_proxy(client_ip)
        def probe_exit():
            if scope == 'device_proxy':
                result, error = with_temp_proxy(proxy['outbound'], proxy.get('secrets'),
                    lambda url: connmod.probe_https(url, run))
                return result if not error else 'unknown'
            return connmod.probe_https(CHECK_PROXY, run)
        report = connmod.diagnose(config, devices, scope, bool(proxy and proxy.get('outbound')),
                                  run, lambda cfg: fastmod.Client(cfg).request('GET', '/proxies/proxy'),
                                  probe_exit)
        after = audit_signature()
        report['stale'] = before != after
        with sess_lock:
            session['connection_diagnosis'] = {'report': report, 'signature': after, 'client_ip': client_ip}
        return ('ok' if report['status'] == 'pass' and not report['stale'] else 'warn',
                'Диагностика завершена. Результат — в «Обзоре»; настройки не менялись.')
    finally:
        apply_lock.release()


def session_connection_diagnosis(session, client_ip):
    with sess_lock:
        saved = session.get('connection_diagnosis')
        if not saved:
            return None
        report = dict(saved['report'])
        signature, previous_client = saved['signature'], saved['client_ip']
    report['stale'] = (report.get('stale', False) or signature != audit_signature()
                       or previous_client != client_ip or time.time() - report.get('checked_at', 0) > 300)
    return report


def queue_action(session, label, action, probe_result=False):
    """Respond immediately, execute slow actions off the HTTP request thread."""
    with sess_lock:
        existing = session.get('job')
        if existing and existing['status'] == 'running':
            return existing['id']
        if not job_slots.acquire(blocking=False):
            session['flash'] = ('warn', 'Панель уже выполняет несколько операций. Попробуй чуть позже.')
            return None
        job = {'id': secrets.token_hex(12), 'status': 'running', 'label': label, 'started': time.time()}
        session['job'] = job

    def work():
        try:
            result = action()
            with sess_lock:
                if probe_result:
                    session['probe'] = result
                    ok = result.get('ok', False)
                else:
                    session['flash'] = result
                    ok = result[0] != 'err'
                job['status'] = 'done' if ok else 'error'
        except Exception:
            with sess_lock:
                session['flash'] = ('err', 'Операция завершилась с ошибкой. Проверь текущее состояние подключения.')
                job['status'] = 'error'
        finally:
            job_slots.release()
            telemetry_wake.set()
    threading.Thread(target=work, daemon=True).start()
    return job['id']


# ---------------------------------------------------------------- пароль панели
def _hash(pw, salt, it):
    return hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, it).hex()


def set_password(pw):
    salt = secrets.token_bytes(16)
    write_private(PANEL_FILE, json.dumps({'salt': salt.hex(), 'iter': 200000, 'hash': _hash(pw, salt, 200000)}))


def check_password(pw):
    d = load_json(PANEL_FILE)
    if not d:
        return False
    return hmac.compare_digest(_hash(pw, bytes.fromhex(d['salt']), int(d['iter'])), d['hash'])


# ---------------------------------------------------------------- страницы
CSS = """
body{margin:0;background:#0f1115;color:#e6e6e6;font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.w{max-width:720px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:6px 0 16px}
.c{background:#181b22;border:1px solid #262b36;border-radius:10px;padding:14px 16px;margin:0 0 14px}
.c h2{font-size:14px;margin:0 0 10px;color:#9aa4b2;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.row{display:flex;justify-content:space-between;gap:12px;padding:4px 0;flex-wrap:wrap}
.k{color:#9aa4b2}
.v{text-align:right;word-break:break-word}
select,textarea,input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #333a48;background:#0f1115;color:#e6e6e6;font:inherit}
button{padding:9px 14px;border-radius:8px;border:0;background:#3b82f6;color:#fff;font:inherit;cursor:pointer}
button.g{background:#2a2f3a}
form.i{display:inline}
.f{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.ok{color:#4ade80}.err{color:#f87171}.warn{color:#fbbf24}
.msg{padding:10px 12px;border-radius:8px;margin:0 0 14px;background:#181b22;border:1px solid #262b36}
.t{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{text-align:left;padding:5px 6px;border-bottom:1px solid #262b36;white-space:nowrap}
th{color:#9aa4b2;font-weight:600}
.hint{color:#9aa4b2;font-size:13px;margin-top:8px}
code{background:#0f1115;padding:1px 5px;border-radius:4px}
a{color:#93c5fd}
label.cb{display:block;padding:3px 0}
a.btn{display:inline-block;padding:9px 14px;border-radius:8px;background:#2a2f3a;color:#fff;text-decoration:none}
input[type=file]{margin:6px 0;color:#e6e6e6}
nav.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 14px}
nav.tabs a{padding:8px 14px;border-radius:8px;background:#181b22;border:1px solid #262b36;color:#e6e6e6;text-decoration:none}
nav.tabs a.on{background:#3b82f6;border-color:#3b82f6;color:#fff}
nav.tabs .n{display:inline-block;min-width:18px;padding:0 5px;border-radius:9px;background:#0f1115;color:#9aa4b2;font-size:12px;text-align:center}
nav.tabs a.on .n{background:#1d4ed8;color:#fff}
.li{border-top:1px solid #262b36;padding:10px 0}
.li:first-of-type{border-top:0}
.li button{padding:6px 10px;font-size:14px}
form.dv{display:flex;gap:6px}
form.dv select{min-width:160px;padding:6px}
form.dv button{padding:6px 10px}
textarea{resize:vertical;min-height:44px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.res{border-color:#3b82f6}
"""


def page(title, body):
    return ('<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>%s</title><style>%s</style></head><body><div class="w">%s</div></body></html>'
            % (html.escape(title), CSS, body))


def login_page(msg=''):
    m = '<div class="msg err">%s</div>' % html.escape(msg) if msg else ''
    return page('GeoBox', '<h1>GeoBox</h1>%s<div class="c"><form method="post" action="/login">'
                '<input type="password" name="password" placeholder="пароль панели" autofocus autocomplete="current-password">'
                '<div class="f"><button>Войти</button></div></form></div>' % m)


def _row(k, v):
    return '<div class="row"><span class="k">%s</span><span class="v">%s</span></div>' % (k, v)


def _age(sec):
    if sec is None:
        return ''
    if sec < 60:
        return 'только что'
    if sec < 3600:
        return '%d мин назад' % (sec // 60)
    return '%d ч назад' % (sec // 3600)


TAB_NAMES = {'status': 'Обзор', 'proxies': 'Прокси', 'devices': 'Устройства', 'mimic': 'Mimic', 'wifi': 'Wi-Fi', 'settings': 'Настройки'}
TAB_OF_PATH = {'/ipv6': 'settings', '/check': 'status', '/speed': 'status', '/proxy': 'proxies', '/proxy/check': 'proxies',
               '/proxy/off': 'proxies', '/lib': 'proxies', '/device': 'devices', '/wifi': 'wifi',
               '/tg': 'settings', '/restore': 'settings', '/traffic/reset': 'devices',
               '/lib/import': 'proxies', '/lib/meta': 'proxies', '/diagnostics': 'mimic', '/diagnostics/udp': 'mimic',
               '/ios/location': 'mimic'}


def main_page(flash, probe_res=None, tab='status', client_ip='', library_filters=None, import_result=None, job=None, audit_result=None, udp_result=None, pairing_owner='', connection_report=None):
    if tab not in TAB_NAMES:
        tab = 'status'
    e = html.escape
    st = status_dict()
    out = ['<h1>GeoBox</h1>']
    if job and job.get('status') == 'running':
        out.append('<div class="c" id="panel-job" data-job="%s"><b>%s</b>'
                   '<div class="hint" id="panel-job-message">Выполняется. Можно переходить между вкладками.</div>'
                   '</div><script src="/panel.js" defer></script>' % (e(job['id']), e(job['label'])))
    if flash:
        lvl, text = flash
        out.append('<div class="msg %s">%s</div>' % (e(lvl), e(text)))
    if st['down_since']:
        mins = int((time.time() - st['down_since']) // 60)
        out.append('<div class="msg err">Прокси не отвечает с %s%s. Клиенты Wi-Fi сейчас без интернета. '
                   'Проверь прокси или вставь другой.</div>'
                   % (time.strftime('%H:%M', time.localtime(st['down_since'])), ' (уже %d мин)' % mins if mins else ''))
    if st['wifi_error']:
        out.append('<div class="msg warn">%s</div>' % e(st['wifi_error']))
    if state['failover_note']:
        out.append('<div class="msg warn">%s</div>' % e(state['failover_note']))
    sw = state.get('switch')
    if sw and tab in ('status', 'proxies'):
        out.append('<div class="msg %s">%s</div>' % (
            'ok' if sw.get('ok') else 'warn', e(sw.get('message', ''))))
    # Writers replace JSON atomically. Read-only rendering must never wait for
    # a writer's network probe or recovery lock.
    lib = libmod.load(ETC)
    devs = devmod.load(ETC)
    current = load_proxy()
    cur_item = next((it for it in lib['items'] if current and libmod.identity(it) == libmod.identity(current)), None)
    cards = {k: [] for k in TAB_NAMES}
    if tab == 'mimic':
        ios_snapshot = get_ios_manager().snapshot()
        ios_snapshot['pairing'] = get_ios_pairing_manager().snapshot(pairing_owner)
        cards['mimic'].append(iospanel.render(ios_snapshot))
        context = mimicmod.build_context(
            client_ip, devs, lib['items'], load_proxy(), state.get('exit'),
            state.get('exit_time', 0), st['clients'])
        context['router_audit'] = audit_result
        context['udp_probe_result'] = udp_result
        cards['mimic'].append(mimicmod.render(context))
    if tab == 'status':
        sb_ok = st['singbox'] == 'active'
        ex = st['exit']
        if ex:
            exit_html = '<span class="ok">%s</span> · %s %s<br><span class="k">%s · %s</span>' % (
                e(ex['ip']), e(ex['country']), e(ex['city']), e(ex['org']), e(_age(st['exit_age'])))
        elif st['proxy']:
            exit_html = ('<span class="err">не отвечает</span>' if state['exit_time'] else
                         '<span class="k">ещё не проверен</span>')
        else:
            exit_html = '<span class="k">-</span>'
        cards['status'].append('<div class="c"><h2>Состояние</h2>'
                   + _row('sing-box', '<span class="%s">%s</span>' % ('ok' if sb_ok else 'err',
                                                                      'работает' if sb_ok else e(st['singbox'])))
                   + _row('Wi-Fi', e(st['wifi']))
                   + _row('Общий прокси', e(st['proxy']) if st['proxy'] else '<span class="warn">не задан — работают только отдельные прокси устройств</span>')
                   + _row('Выход', exit_html)
                   + (_row('Скачивание', '%s <span class="k">· %s</span>' % (
                       e(_speed_text(state['speed'])), e(_age(int(time.time() - state['speed']['time'])))))
                      if state['speed'] else '')
                   + '<div class="f"><form class="i" method="post" action="/check"><button class="g">Проверить выход</button></form>'
                   + '<form class="i" method="post" action="/speed"><button class="g">Замерить скорость</button></form>'
                   + '<a href="/?tab=status" style="align-self:center">обновить</a></div>'
                   + '<div class="hint">Замер скачивания с малины через прокси к указанному серверу, до 4 соединений. '
                     'Скорость Wi-Fi устройства он не измеряет. «Первый ответ» включает подключение и ответ сервера, это не пинг.</div></div>')
        cards['status'].append(connmod.render(connection_report))
        age = st.get('sample_age')
        if age is None:
            cards['status'].append('<div class="hint">Собираем состояние служб и Wi-Fi в фоне. Обнови страницу через несколько секунд.</div>')
        elif age > 15:
            cards['status'].append('<div class="msg warn">Системный статус обновлён %d с назад; сбор данных задерживается.</div>' % age)
    if tab == 'proxies':
        prefill = probe_res['text'] if probe_res else ''
        if probe_res:
            if probe_res['ok']:
                info = probe_res['info']
                res = ('<div class="c res"><h2>Проверка: прокси работает</h2>'
                       + _row('Тип', e(probe_res['label']))
                       + _row('Выход', '<span class="ok">%s</span>' % e(info['ip']))
                       + _row('Страна, город', e('%s %s' % (info['country'], info['city'])))
                       + _row('Провайдер', e(info['org']))
                       + _row('Отклик', '%d мс' % info.get('ms', 0))
                       + '<form method="post" action="/proxy"><input type="hidden" name="proxy" value="%s">'
                         '<div class="f"><button>Применить этот прокси</button></div></form></div>' % e(prefill))
            else:
                res = '<div class="c res"><h2>Проверка</h2><div class="err">%s</div></div>' % e(probe_res['msg'])
            cards['proxies'].append(res)
        cards['proxies'].append('<div class="c"><h2>Прокси</h2><form method="post" action="/proxy">'
                   '<textarea name="proxy" rows="2" placeholder="вставь прокси в любом формате" autocomplete="off" '
                   'autocapitalize="off" spellcheck="false">%s</textarea>'
                   '<div class="f"><button class="g" formaction="/proxy/check">Проверить</button>'
                   '<button>Применить</button></div></form>'
                   '<div class="hint">Понимаю почти любую запись: <code>ip:порт:логин:пароль</code>, <code>логин:пароль:ip:порт</code>, '
                   '<code>логин:пароль@ip:порт</code>, <code>ip:порт</code>, с разделителями <code>|</code> <code>;</code> или пробелом, '
                   'со схемами <code>socks5://</code> <code>socks4://</code> <code>http://</code> <code>https://</code>, '
                   'а также ссылки <code>vless://</code> <code>vmess://</code> <code>trojan://</code> <code>ss://</code> '
                   '<code>hysteria2://</code>. Если тип не указан, SOCKS5/HTTP/SOCKS4/HTTPS определяется сам.<br>'
                   '<b>Проверить</b> - покажет IP, страну и провайдера, ничего не меняя. '
                   '<b>Применить</b> — проверит до и после переключения. При ошибке вернёт прежние настройки. '
                   'Загруженные прокси переключаются без перезапуска движка; соединения через прежний общий прокси закрываются. '
                   'Новый адрес или изменение правил могут потребовать перезапуска и кратко прервать соединения устройств. '
                   'Проверка может занять до минуты.</div>'
                   '<div class="f"><form class="i" method="post" action="/proxy/off">'
                   '<button class="g">Выключить прокси</button></form></div></div>' % e(prefill))
    cl = st['clients']
    if tab == 'devices':
        online = {c['mac'] for c in cl}
        rows_src = [dict(c, online=True) for c in cl]
        for mac, d in sorted(devs.items()):
            if mac not in online:
                rows_src.append({'mac': mac, 'ip': d.get('ip', ''), 'name': d.get('name', ''), 'signal': '', 'time': '', 'online': False})

        def dev_form(c):
            if not c['ip']:
                return '<span class="k">ждёт адрес</span>'
            d = devs.get(c['mac'], {})
            cur = 'block' if d.get('mode') == 'block' else (d.get('item') if d.get('mode') == 'proxy' else 'default')
            opts = [('default', 'как все')] + [(it['id'], proxy_label(it)) for it in lib['items']] + [('block', 'без интернета')]
            sel = ''.join('<option value="%s"%s>%s</option>' % (e(v), ' selected' if v == cur else '', e(l)) for v, l in opts)
            return ('<form method="post" action="/device" class="dv"><input type="hidden" name="mac" value="%s">'
                    '<input type="hidden" name="ip" value="%s"><input type="hidden" name="name" value="%s">'
                    '<select name="choice">%s</select><button class="g">OK</button></form>'
                    % (e(c['mac']), e(c['ip']), e(c['name'] or ''), sel))

        traf = telemetry['traffic']

        def tr_cell(mac, key):
            v = (traf.get(mac) or {}).get(key) or [0, 0]
            return '↓ %s<br><span class="k">↑ %s</span>' % (trmod.fmt(v[1]), trmod.fmt(v[0])) if (v[0] or v[1]) else '<span class="k">-</span>'

        if rows_src:
            rows = ''.join('<tr><td>%s%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                e(c['name'] or c['mac']), '' if c['online'] else ' <span class="k">(не в сети)</span>',
                e(c['ip']), e(c['time']), tr_cell(c['mac'], 'today'), tr_cell(c['mac'], 'total'), dev_form(c)) for c in rows_src)
            tbl = ('<div class="t"><table><tr><th>Устройство</th><th>IP</th><th>В сети</th><th>Сегодня</th><th>Всего</th><th>Прокси</th></tr>%s</table></div>'
                   '<div class="hint">«как все» - через общий прокси. Можно дать устройству свой прокси из списка ниже '
                   'или оставить его без интернета. При смене интернет у всех моргает на пару секунд. '
                   '↓ скачано, ↑ отправлено; счёт идёт через прокси, обновляется раз в пару минут.</div>'
                   '<form method="post" action="/traffic/reset"><div class="f"><button class="g">Обнулить счётчики трафика</button></div></form>' % rows)
        else:
            tbl = '<div class="k">никого</div>'
        cards['devices'].append('<div class="c"><h2>Подключены к Wi-Fi (%d)</h2>%s</div>' % (len(cl), tbl))

    if tab == 'proxies':
        # --- библиотека: импорт, фильтры, избранное
        cards['proxies'].append(libpanel.render_library(
            lib, cur_item['id'] if cur_item else '', devs, import_result, library_filters))
    if tab == 'wifi':
        w = telemetry.get('wifi') or {'ssid': '', 'band': 'a'}
        cards['wifi'].append('<div class="c"><h2>Wi-Fi</h2><form method="post" action="/wifi">'
                   '<div class="k">Имя сети</div><input type="text" name="ssid" value="%s" maxlength="32" autocomplete="off">'
                   '<div class="k" style="margin-top:8px">Новый пароль (пусто - оставить старый)</div>'
                   '<input type="password" name="pw" autocomplete="new-password">'
                   '<div class="k" style="margin-top:8px">Новый пароль ещё раз</div>'
                   '<input type="password" name="pw2" autocomplete="new-password">'
                   '<div class="k" style="margin-top:8px">Диапазон</div>'
                   '<select name="band"><option value="a"%s>5 ГГц - быстрее, бьёт ближе</option>'
                   '<option value="bg"%s>2.4 ГГц - медленнее, бьёт дальше</option></select>'
                   '<div class="f"><button>Сохранить Wi-Fi</button></div></form>'
                   '<div class="hint">После сохранения Wi-Fi перезапустится, все устройства отключатся на 10-20 секунд. '
                   'Если меняешь имя или пароль - подключайся заново уже к новой сети. '
                   'Если новые настройки не поднимутся, панель вернёт старые сама.</div></div>'
                   % (e(w['ssid']), ' selected' if w['band'] != 'bg' else '', ' selected' if w['band'] == 'bg' else ''))
    if tab == 'settings':
        cards['settings'].append(ip6policy.card(load_ipv6(), load_proxy(), devmod.load(ETC), load_json(SB_CONFIG, {})))
        tg = load_settings()['tg']
        tok = tg.get('token') or ''
        evs = ''.join('<label class="cb"><input type="checkbox" name="ev_%s" value="1"%s> %s</label>' % (
            k, ' checked' if tg['events'].get(k, True) else '', e(v)) for k, v in TG_EVENTS.items())
        cards['settings'].append(
            '<div class="c"><h2>Уведомления в Telegram</h2><form method="post" action="/tg">'
            '<input type="hidden" name="op" value="save">'
            '<div class="k">Токен бота%s</div><input type="password" name="token" autocomplete="off" placeholder="%s">'
            '<div class="k" style="margin-top:8px">Chat id</div><input type="text" name="chat_id" value="%s" autocomplete="off" placeholder="например 123456789">'
            '<div class="k" style="margin-top:8px">О чём писать</div><div>%s</div>'
            '<div class="f"><button>Сохранить</button></div></form>'
            '<div class="f">%s</div>'
            '<div class="hint">Как подключить: в Telegram открой @BotFather, команда /newbot, придумай имя - он пришлёт токен, вставь его сюда и сохрани. '
            'Потом открой своего бота, нажми Start и здесь нажми «Найти chat id» - панель сама найдёт тебя. В конце - «Отправить тест». '
            'Токен хранится только на этой малине и в панели не показывается.</div></div>'
            % (' (задан, ...%s - оставь пустым, чтобы не менять)' % e(tok[-4:]) if tok else '',
               'оставь пустым, чтобы не менять' if tok else '123456789:AA...',
               e(tg.get('chat_id', '')), evs,
               ''.join('<form class="i" method="post" action="/tg"><input type="hidden" name="op" value="%s"><button class="g">%s</button></form>' % (o, l)
                       for o, l in (('find', 'Найти chat id'), ('test', 'Отправить тест'), ('off', 'Отключить Telegram')))
               if tok else ''))
        cards['settings'].append(
            '<div class="c"><h2>Резервная копия</h2>'
            '<div class="f"><a class="btn" href="/backup">Скачать настройки</a></div>'
            '<div class="hint">В файле: прокси с паролями, список, устройства, Wi-Fi с паролем и токен Telegram. '
            'Храни его как пароль. Пароля панели в файле нет. Размер копии — до 32 МБ.</div>'
            '<form method="post" action="/restore" enctype="multipart/form-data" style="margin-top:12px">'
            '<div class="k">Восстановить из файла</div><input type="file" name="file" accept=".json,application/json">'
            '<label class="cb"><input type="checkbox" name="wifi" value="1"> и настройки Wi-Fi тоже (имя, пароль, диапазон)</label>'
            '<div class="f"><button class="g">Восстановить</button></div></form>'
            '<div class="hint">Восстановление заменяет прокси, список, устройства и Telegram на те, что в файле. '
            'Интернет у всех моргнёт на пару секунд.</div></div>')
    counts = {'proxies': len(lib['items']), 'devices': len(cl)}
    nav = ''.join('<a href="/?tab=%s" class="%s">%s%s</a>' % (
        k, 'on' if k == tab else '', TAB_NAMES[k], (' <span class="n">%d</span>' % counts[k]) if counts.get(k) else '')
        for k in TAB_NAMES)
    out.insert(1, '<nav class="tabs">%s</nav>' % nav)
    out.extend(cards[tab])
    out.append('<form method="post" action="/logout"><button class="g">Выйти</button></form>')
    return page('GeoBox', ''.join(out))


# ---------------------------------------------------------------- веб-сервер
class Handler(BaseHTTPRequestHandler):
    server_version = 'GeoBox'
    sys_version = ''

    def log_message(self, fmt, *args):
        pass

    def _session(self):
        for part in self.headers.get('Cookie', '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'gbs' and v:
                with sess_lock:
                    s = sessions.get(v)
                    if s and s['exp'] > time.time():
                        return v, s
        return None, None

    def _send(self, code, body, ctype='text/html; charset=utf-8', headers=()):
        b = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Cache-Control', 'no-store')
        if hasattr(self, '_request_started'):
            self.send_header('Server-Timing', 'app;dur=%.2f' % ((time.monotonic()-self._request_started)*1000))
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self' https://api.ipify.org https://api6.ipify.org; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _redirect(self, to='/', headers=()):
        self.send_response(303)
        self.send_header('Location', to)
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-store')
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()

    def _form(self, limit=16384):
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            return None
        if n < 0 or n > limit:
            return None
        data = self.rfile.read(n).decode('utf-8', 'replace')
        return {k: v[0] for k, v in urllib.parse.parse_qs(data, keep_blank_values=True).items()}

    def _multipart(self, limit):
        ctype = self.headers.get('Content-Type', '')
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            return None
        if not ctype.startswith('multipart/form-data') or n <= 0 or n > limit:
            return None
        body = self.rfile.read(n)
        msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            b'Content-Type: ' + ctype.encode('latin-1') + b'\r\nMIME-Version: 1.0\r\n\r\n' + body)
        fields = {}
        for part in msg.iter_parts():
            name = part.get_param('name', header='content-disposition')
            if name:
                fields[name] = part.get_payload(decode=True) or b''
        return fields

    def _same_origin(self):
        o = self.headers.get('Origin')
        if not o or o == 'null':
            return True     # куки SameSite=Strict и так не уходят с чужих сайтов
        return urllib.parse.urlsplit(o).netloc == self.headers.get('Host', '')

    def do_GET(self):
        self._request_started = time.monotonic()
        path = urllib.parse.urlsplit(self.path).path
        tok, s = self._session()
        if path == '/ios_location.js':
            if not s:
                return self._send(401, '', 'application/javascript; charset=utf-8')
            return self._send(200, Path(__file__).with_name('ios_location.js').read_text(encoding='utf-8'),
                              'application/javascript; charset=utf-8')
        if path == '/api/ios/pairing':
            if not s:
                return self._send(401, '{}', 'application/json')
            return self._send(200, json.dumps(get_ios_pairing_manager().snapshot(tok), ensure_ascii=False),
                              'application/json; charset=utf-8')
        if path == '/panel.js':
            if not s:
                return self._send(401, '', 'application/javascript; charset=utf-8')
            return self._send(200, Path(__file__).with_name('panel.js').read_text(encoding='utf-8'),
                              'application/javascript; charset=utf-8')
        if path == '/api/job':
            if not s:
                return self._send(401, '{}', 'application/json')
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            with sess_lock:
                job = dict(s.get('job') or {})
            if not job or query.get('id', [''])[0] != job['id']:
                return self._send(404, '{}', 'application/json')
            public = {k: job[k] for k in ('id', 'status', 'label')}
            public['seconds'] = max(0, int(time.time() - job['started']))
            return self._send(200, json.dumps(public, ensure_ascii=False), 'application/json; charset=utf-8')
        if path == '/mimic.js':
            if not s:
                return self._send(401, '', 'application/javascript; charset=utf-8')
            return self._send(200, mimicmod.javascript(), 'application/javascript; charset=utf-8')
        if path == '/backup':
            if not s:
                return self._redirect('/')
            backup = export_backup()
            if len(backup.encode('utf-8')) > MAX_BACKUP_BYTES:
                return self._send(413, page('GeoBox', '<p>Копия больше 32 МБ. Уменьши библиотеку перед экспортом; настройки не изменены.</p>'))
            return self._send(200, backup, 'application/json; charset=utf-8',
                              [('Content-Disposition', 'attachment; filename="geobox-backup-%s.json"' % time.strftime('%Y%m%d'))])
        if path == '/api/status':
            if not s:
                return self._send(401, '{}', 'application/json')
            return self._send(200, json.dumps(status_dict(), ensure_ascii=False), 'application/json; charset=utf-8')
        if path != '/':
            return self._send(404, page('GeoBox', '<p>Нет такой страницы. <a href="/">На главную</a></p>'))
        if not s:
            return self._send(200, login_page())
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        tab = query.get('tab', ['status'])[0]
        with sess_lock:
            flash = s.pop('flash', None)
            probe_res = s.pop('probe', None) if tab == 'proxies' else None
            import_result = s.pop('library_import', None) if tab == 'proxies' else None
            job = dict(s.get('job') or {})
        filters = {k: query.get(k, [''])[0] for k in ('q', 'tag', 'favorite')}
        audit_result = session_audit(s) if tab == 'mimic' else None
        udp_result = session_udp_probe(s, self.client_address[0]) if tab == 'mimic' else None
        connection_report = session_connection_diagnosis(s, self.client_address[0]) if tab == 'status' else None
        return self._send(200, main_page(flash, probe_res, tab, self.client_address[0], filters, import_result, job, audit_result, udp_result, tok, connection_report))

    def do_POST(self):
        self._request_started = time.monotonic()
        path = urllib.parse.urlsplit(self.path).path
        if not self._same_origin():
            return self._send(403, page('GeoBox', '<p>Чужой запрос.</p>'))
        if path == '/restore':
            tok, s = self._session()
            if not s:
                return self._redirect('/')
            fields = self._multipart(MAX_BACKUP_BYTES + 65536)
            if fields is None:
                msg = ('err', 'Не получил файл (или он больше 32 МБ).')
            else:
                queue_action(s, 'Восстановление настроек',
                             lambda: action_restore(fields.get('file', b''), fields.get('wifi') == b'1'))
                return self._redirect('/?tab=settings')
            with sess_lock:
                s['flash'] = msg
            return self._redirect('/?tab=settings')
        f = self._form(512 * 1024 if path == '/lib/import' else 16384)
        if f is None:
            return self._send(413, page('GeoBox', '<p>Слишком большой запрос.</p>'))
        if path == '/login':
            return self._login(f)
        tok, s = self._session()
        if not s:
            return self._redirect('/')
        if path == '/logout':
            get_ios_pairing_manager().stop(tok)
            with sess_lock:
                sessions.pop(tok, None)
            return self._redirect('/', [('Set-Cookie', 'gbs=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict')])
        if path == '/proxy/check':
            queue_action(s, 'Проверка прокси', lambda: action_check_proxy(f.get('proxy', '')), probe_result=True)
            return self._redirect('/?tab=proxies')
        if path == '/ios/location':
            action, device_id = f.get('action', ''), f.get('device_id', '')
            manager = get_ios_manager()
            if action == 'sync':
                queue_action(s, 'Геолокация iPhone по прокси', lambda: manager.action(action, device_id))
            else:
                msg = manager.action(action, device_id)
                with sess_lock:
                    s['flash'] = msg
            return self._redirect('/?tab=mimic')
        if path == '/ios/pairing':
            action = f.get('action', '')
            if action == 'start':
                if get_ios_manager().operation.locked():
                    msg = ('warn', 'Дождись завершения текущей команды iPhone.')
                else:
                    msg = get_ios_pairing_manager().start(tok)
            elif action == 'stop':
                msg = get_ios_pairing_manager().stop(tok)
            else:
                msg = ('err', 'Неизвестная команда сопряжения.')
            with sess_lock:
                s['flash'] = msg
            return self._redirect('/?tab=mimic')
        if path == '/lib/import':
            with lib_lock:
                lib = libmod.load(ETC)
                result = libpanel.import_batch(lib, f.get('proxies', ''), parse_proxy,
                                               f.get('default_kind', 'socks5'), f.get('tags', ''))
                if result['added']:
                    libmod.save(ETC, lib)
            with sess_lock:
                s['library_import'] = result
            return self._redirect('/?tab=proxies')
        slow = {
            '/ipv6': ('Проверка и применение IPv6', lambda: action_ipv6(f.get('mode', ''))),
            '/diagnostics': ('Проверка защиты на малине', lambda: action_diagnostics(s)),
            '/diagnostics/connection': ('Поиск причины отсутствия интернета', lambda: action_connection_diagnostics(s, self.client_address[0])),
            '/diagnostics/udp': ('Проверка UDP у прокси', lambda: action_udp_diagnostics(s, self.client_address[0])),
            '/proxy': ('Переключение прокси', lambda: action_set_proxy(f.get('proxy', ''))),
            '/proxy/off': ('Отключение общего прокси', action_proxy_off),
            '/speed': ('Измерение скорости', action_speed_current),
            '/check': ('Проверка выхода', lambda: ('ok', 'Выход проверен') if check_exit() else ('err', 'Выход не отвечает: прокси недоступен или не задан')),
            '/device': ('Применение настроек устройства', lambda: action_device(f.get('mac', ''), f.get('ip', ''), f.get('choice', ''), f.get('name', ''))),
        }
        if path == '/lib' and f.get('op') in ('apply', 'check', 'speed'):
            slow['/lib'] = ('Операция с прокси из библиотеки', lambda: action_lib(f.get('op', ''), f.get('id', '')))
        if path in slow:
            label, action = slow[path]
            queue_action(s, label, action)
            return self._redirect('/?tab=' + TAB_OF_PATH.get(path, 'status'))
        if path == '/lib':
            msg = action_lib(f.get('op', ''), f.get('id', ''))
        elif path == '/lib/meta':
            try:
                with lib_lock:
                    lib = libmod.load(ETC)
                    libmod.set_metadata(lib, f.get('id', ''), f.get('name', ''),
                                        f.get('tags', ''), f.get('favorite') == '1')
                    libmod.save(ETC, lib)
                msg = ('ok', 'Название, метки и избранное сохранены.')
            except ValueError as exc:
                msg = ('err', str(exc))
        elif path == '/tg':
            msg = action_tg(f.get('op', ''), f)
        elif path == '/traffic/reset':
            trmod.reset()
            msg = ('ok', 'Счётчики трафика обнулены.')
        elif path == '/wifi':
            msg = action_wifi(f.get('ssid', ''), f.get('pw', ''), f.get('pw2', ''), f.get('band', ''))
        else:
            return self._send(404, page('GeoBox', '<p>Нет такой страницы.</p>'))
        with sess_lock:
            s['flash'] = msg
        return self._redirect('/?tab=' + TAB_OF_PATH.get(path, 'status'))

    def _login(self, f):
        now = time.time()
        with sess_lock:
            fails[:] = [t for t in fails if now - t < 600]
            blocked = len(fails) >= 10
        if blocked:
            return self._send(429, login_page('Слишком много неверных попыток. Подожди 10 минут.'))
        if check_password(f.get('password', '')):
            tok = secrets.token_urlsafe(32)
            with sess_lock:
                for k in [k for k, v in sessions.items() if v['exp'] < now]:
                    sessions.pop(k, None)
                sessions[tok] = {'exp': now + SESSION_TTL}
            return self._redirect('/', [('Set-Cookie', 'gbs=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict'
                                         % (tok, SESSION_TTL))])
        with sess_lock:
            fails.append(now)
        time.sleep(1)
        return self._send(200, login_page('Неверный пароль'))


def serve():
    if not os.path.exists(PANEL_FILE):
        print('нет пароля панели: geobox.py set-password', file=sys.stderr)
        sys.exit(1)
    with apply_lock:
        recovered = switcher().recover()
        if recovered:
            state['switch'] = recovered
            state['exit'], state['exit_time'] = recovered.get('exit'), time.time()
    srv = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    srv.daemon_threads = True
    threading.Thread(target=telemetry_loop, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()
    get_ios_manager().start()
    srv.serve_forever()


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'serve':
        serve()
    elif cmd == 'render':
        proxy = load_proxy()
        ok, msg = write_config(proxy, SB_CONFIG)
        if not ok:
            print('sing-box не принял настройку: ' + msg)
            sys.exit(1)
        print('ok: ' + (proxy_label(proxy) or 'без прокси (интернета в Wi-Fi нет)'))
    elif cmd == 'set-password':
        pw = sys.stdin.read().rstrip('\r\n')
        if len(pw) < 6:
            print('пароль короче 6 символов')
            sys.exit(1)
        set_password(pw)
        print('ok')
    elif cmd == 'lib-add-current':
        proxy = load_proxy()
        if proxy:
            _remember(proxy)
            print('ok: ' + proxy_label(proxy))
        else:
            print('прокси не задан')
    elif cmd == 'status':
        print(json.dumps(status_dict(), ensure_ascii=False, indent=2))
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == '__main__':
    main()
