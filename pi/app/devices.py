"""GeoBox DIY: прокси на отдельное устройство.

Устройство узнаём по MAC. Чтобы правило не слетело, малина всегда выдаёт ему тот же IP
(dnsmasq dhcp-hostsfile), а sing-box направляет этот IP в нужный прокси.
Режимы:
  default - как все (записи в devices.json нет);
  proxy   - через конкретный прокси из библиотеки;
  block   - без интернета.
Мимо прокси (direct) устройство не пускается никогда: если его прокси удалили из библиотеки,
оно ведёт себя как block.
"""
import json
import os
import re

MODES = ('default', 'proxy', 'block')
MAC_RE = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')
ITEM_RE = re.compile(r'^[0-9a-f]{8}$')
NET_PREFIX = '10.77.0.'
# Файл адресов для dnsmasq. Не в /etc/geobox (там 0700): dnsmasq перечитывает его по SIGHUP уже
# от своего пользователя dnsmasq, а не от root.
HOSTS_FILE = os.environ.get('GEOBOX_DHCP_HOSTS', '/var/lib/misc/geobox-dhcp-hosts')


def _path(etc):
    return os.path.join(etc, 'devices.json')


def _write_atomic(path, text, mode):
    """Атомарная запись: сначала временный файл с нужными правами, потом переименование."""
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def load(etc):
    try:
        with open(_path(etc)) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save(etc, devices):
    _write_atomic(_path(etc), json.dumps(devices, ensure_ascii=False, indent=1), 0o600)


def _check_ip(ip):
    if not isinstance(ip, str) or not ip.startswith(NET_PREFIX):
        raise ValueError('адрес устройства должен быть из сети Wi-Fi малины (10.77.0.x)')
    last = ip[len(NET_PREFIX):]
    if not last.isdigit() or str(int(last)) != last or not 2 <= int(last) <= 254:
        raise ValueError('адрес устройства должен быть от 10.77.0.2 до 10.77.0.254')


def set_mode(devices, mac, ip, mode, item=None, name=''):
    mac = (mac or '').strip().lower()
    if not MAC_RE.match(mac):
        raise ValueError('странный MAC-адрес устройства')
    if mode not in MODES:
        raise ValueError('неизвестный режим устройства')
    if mode == 'default':
        devices.pop(mac, None)
        return devices
    ip = (ip or '').strip()
    _check_ip(ip)
    for other_mac, d in devices.items():
        if other_mac != mac and d.get('ip') == ip:
            raise ValueError('адрес %s уже закреплён за другим устройством' % ip)
    if mode == 'proxy':
        if not isinstance(item, str) or not ITEM_RE.match(item):
            raise ValueError('не выбран прокси для устройства')
    else:
        item = None
    name = (name or '').strip()[:40]
    devices[mac] = {'ip': ip, 'mode': mode, 'item': item, 'name': name}
    return devices


def hosts_file_text(devices):
    lines = sorted('%s,%s' % (mac, d['ip']) for mac, d in devices.items()
                   if MAC_RE.match(mac) and d.get('ip'))
    return ''.join(l + '\n' for l in lines)


def write_hosts(etc, devices, run):
    path = HOSTS_FILE
    try:
        _write_atomic(path, hosts_file_text(devices), 0o644)
    except OSError as e:
        return False, 'не записался файл адресов устройств: %s' % e
    rc, out, err = run(['systemctl', 'reload', 'dnsmasq'])
    if rc != 0:
        rc, out, err = run(['systemctl', 'restart', 'dnsmasq'])
    if rc != 0:
        return False, 'dnsmasq не перечитал адреса: ' + (err or out).strip()[:200]
    return True, 'ok'


def config_ext(devices, items):
    """Дополнения к настройке sing-box для geobox.build_config(proxy, ext)."""
    by_item, blocked, missing = {}, [], []
    for mac in sorted(devices):
        d = devices[mac]
        ip = d.get('ip')
        if not ip:
            continue
        cidr = ip + '/32'
        if d.get('mode') == 'proxy':
            it = items.get(d.get('item')) if d.get('item') else None
            if it and it.get('outbound'):
                by_item.setdefault(d['item'], []).append(cidr)
            else:
                missing.append(mac)
                blocked.append(cidr)
        elif d.get('mode') == 'block':
            blocked.append(cidr)
    ext = {'outbounds': [], 'dns_servers': [], 'dns_rules': [], 'route_rules': [], 'missing': missing}
    if blocked:
        ext['route_rules'].append({'source_ip_cidr': blocked, 'action': 'reject'})
        ext['dns_rules'].append({'source_ip_cidr': blocked, 'action': 'reject'})
    for item_id in sorted(by_item):
        cidrs = by_item[item_id]
        ob = dict(items[item_id]['outbound'])
        ob.pop('tag', None)
        ob['tag'] = 'dev-%s' % item_id
        ext['outbounds'].append(ob)
        ext['dns_servers'].append({'type': 'https', 'tag': 'remote-%s' % item_id,
                                   'server': '1.1.1.1', 'detour': 'dev-%s' % item_id})
        ext['dns_rules'].append({'source_ip_cidr': cidrs, 'action': 'route', 'server': 'remote-%s' % item_id})
        ext['route_rules'].append({'source_ip_cidr': cidrs, 'outbound': 'dev-%s' % item_id})
    return ext
