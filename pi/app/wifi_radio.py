"""Supervised USB AP switching and bounded, opt-in beacon experiments.

No location databases, pairing records or phone commands. Submitted frames are
not evidence of reception or of a change in the client's system location.
"""
from contextlib import contextmanager
import configparser
import html
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import struct
import time

import lan

ROOT = Path('/var/lib/geobox/wifi-transition')
AP_UNIT = 'proxybox-wifi-adapter'
RF_UNIT = 'proxybox-wifi-beacons'
HELPER = Path(__file__).resolve()
MAC = re.compile(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}')


def read(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def save(path, data):
    lan.write(path, json.dumps(data, ensure_ascii=False))


@contextmanager
def radio_lock():
    import fcntl
    with open('/run/proxybox-usb-radio.lock', 'a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def channels(text):
    found = {}
    for line in text.splitlines():
        match = re.search(r'\* (\d+(?:\.\d+)?) MHz \[(\d+)\]', line)
        if match and not any(word in line.lower() for word in ('disabled', 'no ir', 'radar')):
            found[int(match[2])] = int(float(match[1]))
    return found


def inventory():
    devices = []
    for path in sorted(Path('/sys/class/net').glob('wl*')):
        try:
            name = lan.interface(path.name)
            info = lan.command(['iw', 'dev', name, 'info'], timeout=3)
            phy = 'phy' + re.search(r'wiphy (\d+)', info).group(1)
            caps = lan.command(['iw', 'phy', phy, 'info'], timeout=3)
            mode = re.search(r'^\s*type (\S+)', info, re.M).group(1)
            allowed = channels(caps)
            driver = (path / 'device/driver').resolve().name
            device = (path / 'device').resolve()
            usb = any((parent / 'idVendor').exists() for parent in (device, *device.parents))
            nm = lan.command(['nmcli', '-g', 'GENERAL.STATE', 'device', 'show', name], timeout=3)
            devices.append({'interface': name, 'phy': phy, 'driver': driver, 'usb': usb,
                'address': (path / 'address').read_text().strip().lower(), 'mode': mode,
                'idle': mode == 'managed' and nm.startswith('30 '),
                'ap': bool(re.search(r'^\s*\* AP\s*$', caps, re.M)),
                'monitor': bool(re.search(r'^\s*\* monitor\s*$', caps, re.M)),
                'channels': allowed, 'bands': [b for b, c in (('bg', 6), ('a', 36)) if c in allowed]})
        except (OSError, RuntimeError, AttributeError, ValueError):
            continue
    return devices


def select_device(items, name, role, band='bg', channel=1):
    name = lan.interface(name)
    target = next((item for item in items if item['interface'] == name), None)
    current = next((item for item in items if item['interface'] == lan.ap_interface()), None)
    if not target or not current:
        raise ValueError('Не удалось определить оба адаптера / Radio inventory unavailable')
    if role == 'ap':
        if not target['ap'] or band not in target['bands']:
            raise ValueError('Адаптер не поддерживает выбранный диапазон AP / Unsupported AP band')
    else:
        if (not target['usb'] or not target['monitor'] or channel not in target['channels']
                or name == current['interface'] or target['phy'] == current['phy']):
            raise ValueError('Нужен отдельный USB-адаптер с monitor / Separate USB monitor radio required')
    if name != current['interface'] and not target['idle']:
        raise ValueError('Адаптер занят / Adapter is not idle')
    return target


def validate_dataset(raw):
    value = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(value, list) or not 1 <= len(value) <= 40:
        raise ValueError('Нужен JSON-массив из 1–40 сетей / Expected 1–40 networks')
    result, used = [], set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {'bssid', 'ssid'}:
            raise ValueError('Каждая сеть: только bssid и ssid / Only bssid and ssid fields allowed')
        mac, ssid = item['bssid'], item['ssid']
        if not isinstance(mac, str) or not MAC.fullmatch(mac.lower()):
            raise ValueError('Invalid BSSID')
        mac = mac.lower()
        if mac in used or mac == '00:00:00:00:00:00' or int(mac[:2], 16) & 1:
            raise ValueError('Duplicate, multicast or zero BSSID')
        if not isinstance(ssid, str) or not 1 <= len(ssid.encode()) <= 32 or any(ord(c) < 32 for c in ssid):
            raise ValueError('SSID must contain 1–32 UTF-8 bytes without controls')
        used.add(mac)
        result.append({'bssid': mac, 'ssid': ssid})
    return result


def beacon(item, channel, sequence, microseconds):
    """Build an ordinary open ESS beacon; no association/authentication service."""
    mac = bytes.fromhex(item['bssid'].replace(':', ''))
    ssid = item['ssid'].encode()
    radiotap = struct.pack('<BBHIB', 0, 0, 9, 4, 2)  # rate 1 Mbps
    header = struct.pack('<HH', 0x80, 0) + b'\xff' * 6 + mac + mac
    header += struct.pack('<H', (sequence % 4096) << 4)
    fixed = struct.pack('<QHH', microseconds, 100, 1)
    ies = bytes((0, len(ssid))) + ssid
    ies += b'\x01\x04\x82\x84\x8b\x96'  # supported 1/2/5.5/11 Mbps rates
    ies += bytes((3, 1, channel)) + b'\x05\x04\x00\x01\x00\x00'
    return radiotap + header + fixed + ies


def active(unit):
    return lan.command(['systemctl', 'is-active', '--quiet', unit], check=False, timeout=3).returncode == 0


def busy():
    # Cheap file check used by panel actions, not an OS command on each GET.
    return bool(read(lan.RUN / 'wifi-job.json', {}).get('busy'))


def status():
    return read(lan.RUN / 'wifi-job.json', {'phase': 'off', 'busy': False})


def publish(phase, **kwargs):
    value = status()
    value.update(phase=phase, time=time.time(), **kwargs)
    save(lan.RUN / 'wifi-job.json', value)


def start(kind, fields):
    with radio_lock():
        if busy() or active(AP_UNIT) or active(RF_UNIT):
            raise ValueError('Дождись завершения радиооперации / Radio operation is busy')
        if Path('/run/geobox-ios-pairing-worker.json').exists():
            raise ValueError('Сначала заверши сопряжение iPhone / Finish iPhone pairing first')
        pending = read(ROOT / 'journal.json')
        if pending and not pending['committed'] and not pending['restored']:
            raise ValueError('Предыдущий откат не завершён / Previous rollback needs recovery')
        items = inventory()
        name = fields.get('interface', '')
        if kind == 'ap':
            band = fields.get('band', '')
            target = select_device(items, name, 'ap', band=band)
            if 'eth0' not in [r.get('dev') for r in json.loads(lan.command(['ip', '-j', 'route', 'show', 'default']))]:
                raise ValueError('Для переключения нужен Ethernet / Keep Ethernet upstream connected')
            request = {'interface': name, 'band': band, 'address': target['address']}
        elif kind == 'beacons':
            seconds, channel = int(fields.get('seconds', '120')), int(fields.get('channel', '1'))
            if not 10 <= seconds <= 300 or not 1 <= channel <= 11:
                raise ValueError('Duration: 10–300 s; channel: 1–11')
            select_device(items, name, 'beacons', channel=channel)
            dataset = validate_dataset(fields.get('networks', ''))
            if any(n['bssid'] in {r['address'] for r in items} for n in dataset):
                raise ValueError('BSSID conflicts with a local adapter')
            request = {'interface': name, 'seconds': seconds, 'channel': channel, 'networks': dataset}
        else:
            raise ValueError('Unknown operation')
        token = secrets.token_hex(16)
        save(lan.RUN / 'wifi-request.json', dict(request, token=token, kind=kind))
        publish('starting', busy=True, kind=kind, token=token, interface=name, submitted=0,
                location_success='not_tested', deadline=None, error=None)
        unit = AP_UNIT if kind == 'ap' else RF_UNIT
        limit = 210 if kind == 'ap' else request['seconds'] + 40
        try:
            lan.command(['systemd-run', '--quiet', '--collect', '--unit=' + unit,
                '--property=RuntimeMaxSec=' + str(limit), '--property=TimeoutStopSec=90',
                '--property=ExecStopPost=/usr/bin/python3 ' + str(HELPER) + ' cleanup-' + kind,
                '/usr/bin/python3', str(HELPER), 'worker-' + kind], timeout=8)
        except Exception:
            publish('failed_to_start', busy=False)
            raise
    return ('ok', 'Запущено. Обнови страницу Wi-Fi / Started; refresh the Wi-Fi tab.')


def ap_snapshot(request):
    # Only a persistent, unique NM profile is supported. Never export its PSK.
    uuid = lan.command(['nmcli', '-g', 'connection.uuid', 'connection', 'show', 'geobox-ap'])
    paths = []
    for path in Path('/etc/NetworkManager/system-connections').glob('*.nmconnection'):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read(path)
        if cp.get('connection', 'uuid', fallback=None) == uuid:
            paths.append(path)
    if len(paths) != 1 or paths[0].is_symlink():
        raise RuntimeError('A unique persistent geobox-ap profile is required')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    lan.write(ROOT / 'profile.before', paths[0].read_bytes())
    conf = lan.ETC / 'wifi-radio.json'
    old_config = conf.read_bytes() if conf.exists() else b''
    lan.write(ROOT / 'config.before', old_config)
    meta = {'boot': boot_id(), 'profile': str(paths[0]), 'committed': False,
            'restored': False, 'token': request['token']}
    save(ROOT / 'journal.json', meta)  # complete journal BEFORE any mutation


def restore_files(meta):
    target = Path(meta['profile'])
    if target.parent != Path('/etc/NetworkManager/system-connections') or target.suffix != '.nmconnection':
        raise RuntimeError('Invalid saved profile path')
    lan.write(target, (ROOT / 'profile.before').read_bytes())
    data = (ROOT / 'config.before').read_bytes()
    if data:
        lan.write(lan.ETC / 'wifi-radio.json', data)
    else:
        (lan.ETC / 'wifi-radio.json').unlink(missing_ok=True)


def recover_boot():
    meta = read(ROOT / 'journal.json')
    if meta and not meta['committed'] and not meta['restored'] and meta['boot'] != boot_id():
        restore_files(meta)
        save(ROOT / 'journal.json', dict(meta, restored=True))


def cleanup_ap():
    meta = read(ROOT / 'journal.json')
    if not meta or meta.get('token') != status().get('token') or meta['committed'] or meta['restored']:
        if status().get('kind') == 'ap':
            phase = ('error' if status().get('error') else 'saved' if meta and meta['committed']
                     else 'rolled_back' if meta and meta['restored'] else 'stopped')
            publish(phase, busy=False, deadline=None)
        return
    lan.command(['nmcli', '--wait', '10', 'connection', 'down', 'geobox-ap'], check=False)
    restore_files(meta)
    lan.configure()
    lan.command(['nmcli', 'connection', 'reload'])
    lan.command(['nmcli', '--wait', '35', 'connection', 'up', 'geobox-ap'])
    lan.command(['systemctl', 'restart', 'dnsmasq'])
    save(ROOT / 'journal.json', dict(meta, restored=True))
    publish('rolled_back', busy=False)


def worker_ap():
    req = read(lan.RUN / 'wifi-request.json')
    select_device(inventory(), req['interface'], 'ap', band=req['band'])
    ap_snapshot(req)
    lan.command(['nmcli', '--wait', '10', 'connection', 'down', 'geobox-ap'])
    save(lan.ETC / 'wifi-radio.json', {'interface': req['interface']})
    lan.configure()  # protection precedes activation on the new interface
    lan.command(['nmcli', 'connection', 'modify', 'geobox-ap',
        'connection.interface-name', req['interface'], '802-11-wireless.mac-address', req['address'],
        '802-11-wireless.cloned-mac-address', 'permanent',
        '802-11-wireless.band', req['band'], '802-11-wireless.channel', '36' if req['band'] == 'a' else '6'])
    lan.command(['nmcli', '--wait', '35', 'connection', 'up', 'geobox-ap'])
    lan.command(['dnsmasq', '--test'])
    lan.command(['systemctl', 'restart', 'dnsmasq'])
    deadline = time.monotonic() + 120
    publish('awaiting_confirmation', deadline=time.time() + 120)
    while time.monotonic() < deadline:
        if read(lan.RUN / 'wifi-confirm.json', {}).get('token') == req['token']:
            # A browser on the LAN demonstrated connectivity; NM is already persistent.
            meta = read(ROOT / 'journal.json')
            save(ROOT / 'journal.json', dict(meta, committed=True))
            publish('saved', busy=False)
            return
        time.sleep(.5)
    cleanup_ap()


def cleanup_beacons():
    saved = read(lan.RUN / 'wifi-rf-restore.json')
    if saved and not saved.get('restored'):
        name = lan.interface(saved['interface'])
        # Do not reconfigure a replacement USB device with a recycled name.
        if Path('/sys/class/net', name).exists():
            path = Path('/sys/class/net', name)
            if str((path / 'device').resolve()) != saved['device']:
                raise RuntimeError('USB identity changed; cleanup requires inspection')
            lan.command(['ip', 'link', 'set', name, 'down'])
            lan.command(['iw', 'dev', name, 'set', 'type', 'managed'])
            lan.command(['ip', 'link', 'set', name, 'up' if saved['up'] else 'down'])
            lan.command(['nmcli', 'device', 'set', name, 'managed', 'yes'])
            lan.command(['nmcli', 'device', 'set', name, 'autoconnect', saved['autoconnect']])
        save(lan.RUN / 'wifi-rf-restore.json', dict(saved, restored=True))
    publish('error' if status().get('error') else 'stopped', busy=False, deadline=None)


def worker_beacons():
    req = read(lan.RUN / 'wifi-request.json')
    target = select_device(inventory(), req['interface'], 'beacons', channel=req['channel'])
    networks = validate_dataset(req['networks'])
    path = Path('/sys/class/net', target['interface'])
    name = target['interface']
    saved = {'interface': name, 'device': str((path / 'device').resolve()),
        'up': bool(int((path / 'flags').read_text(), 16) & 1), 'restored': False,
        'autoconnect': lan.command(['nmcli', '-g', 'GENERAL.AUTOCONNECT', 'device', 'show', name])}
    if saved['autoconnect'] not in ('yes', 'no'):
        raise RuntimeError('Cannot snapshot NetworkManager device state')
    save(lan.RUN / 'wifi-rf-restore.json', saved)
    lan.command(['nmcli', 'device', 'set', name, 'autoconnect', 'no'])
    lan.command(['nmcli', 'device', 'set', name, 'managed', 'no'])
    lan.command(['ip', 'link', 'set', name, 'down'])
    lan.command(['iw', 'dev', name, 'set', 'type', 'monitor'])
    lan.command(['ip', 'link', 'set', name, 'up'])
    lan.command(['iw', 'dev', name, 'set', 'channel', str(req['channel'])])
    start_time = time.monotonic()
    deadline = start_time + req['seconds']
    sent, sequence, next_round, next_report = 0, 0, start_time, start_time
    publish('transmitting_unverified', deadline=time.time() + req['seconds'])
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sender:
        sender.bind((name, 0))
        sender.settimeout(1)
        while time.monotonic() < deadline:
            for item in networks:
                if time.monotonic() >= deadline:
                    break
                packet = beacon(item, req['channel'], sequence, int((time.monotonic() - start_time) * 1e6))
                if sender.send(packet) != len(packet):
                    raise RuntimeError('Short frame write')
                sent += 1
            sequence += 1
            now = time.monotonic()
            if now >= next_report:
                publish('transmitting_unverified', submitted=sent)
                next_report = now + 2
            # No catch-up bursts when the driver stalls.
            next_round = max(next_round + .1024, now)
            time.sleep(max(0, min(next_round, deadline) - now))
    publish('finishing', submitted=sent)


def action(operation, fields, peer):
    try:
        if operation in ('ap', 'beacons'):
            return start(operation, fields)
        current = status()
        if operation == 'confirm':
            import ipaddress
            if (current.get('phase') != 'awaiting_confirmation'
                    or fields.get('token') != current.get('token')
                    or ipaddress.ip_address(peer) not in ipaddress.ip_network('10.77.0.0/24')):
                raise ValueError('Подтверди с устройства на новом Wi-Fi / Confirm from the new Wi-Fi LAN')
            save(lan.RUN / 'wifi-confirm.json', {'token': current['token']})
            return ('ok', 'Связь подтверждена / Connection confirmed')
        if operation == 'stop':
            unit = AP_UNIT if current.get('kind') == 'ap' else RF_UNIT
            lan.command(['systemctl', 'stop', '--no-block', unit], timeout=5)
            return ('ok', 'Остановка запрошена; обнови страницу / Stop requested; refresh the page')
        raise ValueError('Unknown operation')
    except (OSError, ValueError, RuntimeError) as exc:
        return ('err', str(exc))


def card(items):
    e = html.escape
    value = status()
    rows = ''.join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        e(r['interface']), e(r['driver']), 'USB' if r['usb'] else 'built-in',
        e(r['mode']) + (' — Internet AP' if r['interface'] == lan.ap_interface() else '')) for r in items)
    options = ''.join('<option value="%s">%s · %s · %s</option>' % (
        e(r['interface']), e(r['interface']), e(r['driver']), '/'.join(r['bands'])) for r in items if r['ap'])
    rf_options = ''.join('<option value="%s">%s · %s</option>' % (
        e(r['interface']), e(r['interface']), e(r['driver'])) for r in items
        if r['usb'] and r['monitor'] and r['interface'] != lan.ap_interface())
    out = '<div class="c"><h2>Адаптеры / Wi-Fi adapters</h2><table>' + rows + '</table>'
    out += '<p class="hint">USB не гарантирует большую скорость или дальность. AP и маячки используют разные радиомодули. / USB does not guarantee higher speed or range. AP and beacons use separate radios.</p>'
    out += '<p>Состояние / State: <b>' + e(str(value['phase'])) + '</b>; submitted: ' + str(int(value.get('submitted', 0))) + '</p>'
    if value.get('error'):
        out += '<p class="hint">' + e(str(value['error'])) + '</p>'
    if value.get('deadline'):
        out += '<p>Осталось / Remaining: ' + str(max(0, int(value['deadline'] - time.time()))) + ' s</p>'
    if value.get('busy'):
        if value['phase'] == 'awaiting_confirmation':
            out += '<p>Подключись к сети с прежним именем и паролем и подтверди в течение 120 секунд. Иначе настройки вернутся. / Rejoin your existing SSID and confirm within 120 seconds, or the change rolls back.</p>'
            out += '<form method="post" action="/wifi/radio"><input type="hidden" name="op" value="confirm"><input type="hidden" name="token" value="' + e(value['token']) + '"><button>Связь работает / Keep adapter</button></form>'
        out += '<form method="post" action="/wifi/radio"><input type="hidden" name="op" value="stop"><button>Остановить / Stop and restore</button></form>'
    else:
        out += '<form method="post" action="/wifi/radio"><input type="hidden" name="op" value="ap"><label>Раздавать интернет через / Internet AP<select name="interface">' + options + '</select></label><select name="band"><option value="a">5 GHz</option><option value="bg">2.4 GHz</option></select><button>Проверить адаптер / Try adapter</button></form>'
        out += '<p class="hint">Wi-Fi кратко отключится. Ethernet должен оставаться подключённым. / Wi-Fi briefly disconnects; keep Ethernet connected.</p>'
    out += '<p><a href="/?tab=wifi">Обновить состояние / Refresh status</a></p></div>'
    out += '<div class="c"><h2>Маячки / Experimental Wi-Fi beacons</h2><p>По умолчанию выключены. Передача не означает смену геолокации. iPhone: маячки приняты, системная подмена не подтверждена. Android / Windows / macOS: не проверено.</p><p class="hint">Off by default. Transmission does not prove location change. iPhone received beacons but system spoofing was not demonstrated. Android / Windows / macOS are untested. No automatic proxy-to-location mapping.</p>'
    if not value.get('busy'):
        out += '<form method="post" action="/wifi/radio"><input type="hidden" name="op" value="beacons"><label>Отдельный USB / Separate USB<select name="interface">' + rf_options + '</select></label><label>Канал / Channel<input name="channel" type="number" min="1" max="11" value="1"></label><label>Секунды / Seconds<input name="seconds" type="number" min="10" max="300" value="120"></label><label>Свой JSON / Your dataset<textarea name="networks" rows="5" required placeholder=\'[ {"bssid":"02:00:00:00:00:01", "ssid":"PB-Test"} ]\'></textarea></label><p class="hint">1–40 сетей. Пример — синтетический адрес, не привязан к городу. К маячкам подключаться не нужно. / 1–40 networks. Example is synthetic, with no city mapping. Do not join the beacon SSIDs.</p><button>Включить на заданное время / Start timed experiment</button></form>'
    return out + '</div>'


if __name__ == '__main__':
    import sys
    os.umask(0o077)
    operation = sys.argv[1] if len(sys.argv) == 2 else ''
    def stop(signum, frame):
        raise InterruptedError('Stopped')
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    try:
        with radio_lock():
            if operation == 'worker-ap':
                worker_ap()
            elif operation == 'worker-beacons':
                worker_beacons()
            elif operation == 'cleanup-ap':
                cleanup_ap()
            elif operation == 'cleanup-beacons':
                cleanup_beacons()
            else:
                raise ValueError('Unknown worker mode')
    except Exception as exc:
        publish('error', error=str(exc))
        raise SystemExit(1)
