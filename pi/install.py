#!/usr/bin/env python3
"""Install a reviewed extracted GeoBox release; default is a read-only preflight.

The release manifest detects corruption, not publisher identity. Only run a
release obtained from a trusted source. No personal data belongs in a release.
"""
import argparse
import configparser
from contextlib import contextmanager
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

APP = Path('/opt/geobox')
ETC = Path('/etc/geobox')
STATE = Path('/var/lib/geobox')
BACKUPS = Path('/var/lib/geobox-installer')
RECEIPT = STATE / 'release.json'
SB_VERSION = '1.14.4'
IOS_VERSION = '11.49.0'
GUIDE_ASSETS = {'docs/images/' + name for name in
                ('setup-en.png', 'setup-ru.png', 'iphone-en.png', 'iphone-ru.png')}
NETWORK = {'geobox.nft', 'net-up.sh', 'tun-route.sh', 'ipv6-network-setup.sh'}
SYSTEM = {'geobox-net.service', 'geobox-singbox.service', 'geobox-panel.service',
          'geobox.conf', 'geobox-ipv6.conf'}
UNITS = ['geobox-panel.service', 'geobox-singbox.service', 'geobox-net.service']
SYSCTLS = ('net.ipv4.ip_forward', 'net.ipv4.conf.all.rp_filter',
           'net.ipv4.conf.default.rp_filter', 'net.ipv6.conf.all.forwarding',
           'net.ipv6.conf.wlan0.accept_ra', 'net.ipv6.conf.wlan0.autoconf')


def run(args, *, data=None, env=None, timeout=45, check=True):
    p = subprocess.run(args, input=data, text=True, capture_output=True,
                       timeout=timeout, env=env)
    if check and p.returncode:
        # NetworkManager and config validators can echo credentials in stderr.
        raise RuntimeError(f'{Path(args[0]).name} failed (exit {p.returncode}); no credentials logged')
    return p.stdout.strip() if check else p


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_release(root):
    manifest = json.loads((root / 'manifest.json').read_text())
    files = manifest.get('files', {})
    if manifest.get('format') != 1 or not isinstance(files, dict) or not files:
        raise ValueError('Invalid release manifest')
    required = {'install.py', 'README.md', 'app/geobox.py', 'app/ios_device_bridge.py',
                'app/ios_pairing_worker.py', *('system/' + n for n in SYSTEM),
                *('app/' + n for n in NETWORK)}
    if not required <= files.keys():
        raise ValueError('Release is incomplete')
    for name, expected in files.items():
        if name not in GUIDE_ASSETS and not re.fullmatch(r'(?:app/[a-z0-9_-]+\.(?:py|js|sh|nft)|system/[a-z0-9.-]+|install\.py|README(?:\.ru)?\.md)', name):
            raise ValueError('Unexpected release path')
        if name.startswith('system/') and name.split('/')[1] not in SYSTEM:
            raise ValueError('Unexpected system file')
        path = root / name
        cursor = path
        linked = False
        while cursor != root:
            linked = linked or cursor.is_symlink()
            cursor = cursor.parent
        if linked or not path.is_file():
            raise ValueError('Release contains a missing file or symbolic link')
        if not isinstance(expected, str) or not re.fullmatch('[a-f0-9]{64}', expected) or digest(path) != expected:
            raise ValueError('Release checksum mismatch: ' + name)
    return manifest


def copy_verified(root, stage):
    manifest = verify_release(root)
    for name in manifest['files']:
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, target)
    (stage / 'manifest.json').write_text(json.dumps(manifest))
    verify_release(stage)
    return manifest


def environment(etc, temporary):
    return {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8',
            'PYTHONNOUSERSITE': '1', 'GEOBOX_ETC': str(etc),
            'GEOBOX_RUN': str(temporary / 'run'),
            'GEOBOX_TRAFFIC': str(temporary / 'traffic.json'),
            'GEOBOX_DHCP_HOSTS': str(temporary / 'dhcp-hosts')}


def validate_code(stage, current=False):
    for path in (stage / 'app').glob('*.py'):
        compile(path.read_bytes(), path.name, 'exec')
    with tempfile.TemporaryDirectory(prefix='geobox-config-', dir='/run') as directory:
        temp = Path(directory)
        etc = temp / 'etc'
        etc.mkdir(mode=0o700)
        if current:
            for name in ('proxy.json', 'devices.json', 'library.json', 'settings.json',
                         'ipv6-policy.json', 'sing-box.json'):
                source = ETC / name
                if source.is_symlink():
                    raise RuntimeError('Unexpected config symlink')
                if source.is_file():
                    shutil.copyfile(source, etc / name)
        run(['/usr/bin/python3', '-I', '-B', str(stage / 'app/geobox.py'), 'render'],
            env=environment(etc, temp), timeout=45)
    run(['/usr/sbin/nft', '--check', '--file', str(stage / 'app/geobox.nft')])


def preflight(stage):
    if platform.system() != 'Linux' or platform.machine() not in ('aarch64', 'arm64'):
        raise RuntimeError('Supported target: Raspberry Pi 5, 64-bit Debian 13/Raspberry Pi OS')
    if sys.version_info < (3, 13):
        raise RuntimeError('Python 3.13 or newer is required for the tested runtime')
    for executable in ('nmcli', 'nft', 'ip', 'iw', 'curl', 'dnsmasq', 'sing-box',
                       'systemctl', 'systemd-run', 'sysctl', 'ss'):
        if not shutil.which(executable):
            raise RuntimeError('Missing dependency: ' + executable)
    version = run(['/usr/bin/sing-box', 'version'])
    if version.splitlines()[0] != 'sing-box version ' + SB_VERSION or 'with_clash_api' not in version:
        raise RuntimeError('Install sing-box ' + SB_VERSION + ' with Clash API support')
    run(['systemctl', 'is-active', 'NetworkManager'])
    run(['ip', 'link', 'show', 'wlan0'])
    if not Path('/dev/net/tun').exists():
        raise RuntimeError('/dev/net/tun is unavailable')
    for interface in ('all', 'default', 'wlan0'):
        if run(['sysctl', '-n', f'net.ipv6.conf.{interface}.disable_ipv6']) != '0':
            raise RuntimeError('IPv6 must be enabled locally; GeoBox filters client IPv6 separately')
    validate_code(stage, current=ETC.exists())


def clean_preflight():
    if APP.exists() or ETC.exists() or RECEIPT.exists():
        raise RuntimeError('Existing GeoBox detected: do not use --install')
    if run(['nmcli', '-g', 'UUID', 'connection', 'show', 'geobox-ap'], check=False).returncode == 0:
        raise RuntimeError('geobox-ap already exists')
    addresses = json.loads(run(['ip', '-j', 'address']))
    lan = ipaddress.ip_network('10.77.0.0/24')
    for interface in addresses:
        for address in interface.get('addr_info', []):
            if address.get('family') == 'inet' and ipaddress.ip_network(
                    f"{address['local']}/{address['prefixlen']}", strict=False).overlaps(lan):
                raise RuntimeError('Existing network overlaps 10.77.0.0/24')
    if 'eth0' not in [r.get('dev') for r in json.loads(run(['ip', '-j', 'route', 'show', 'default']))]:
        raise RuntimeError('Connect the Pi upstream by Ethernet (eth0) before installation')
    if run(['nmcli', '-g', 'GENERAL.STATE', 'device', 'show', 'wlan0']).startswith('100'):
        raise RuntimeError('wlan0 is already connected; disconnect it before a clean install')
    if run(['nmcli', 'radio', 'wifi']) != 'enabled':
        raise RuntimeError('Enable Wi-Fi radio with nmcli radio wifi on first')
    if not re.search(r'^\s+\* AP\s*$', run(['iw', 'list']), re.M):
        raise RuntimeError('Wi-Fi adapter does not report AP support')
    if not re.search(r'country (?!00:)[A-Z]{2}:', run(['iw', 'reg', 'get'])):
        raise RuntimeError('Set the actual Wi-Fi country using raspi-config first')
    if run(['nft', 'list', 'table', 'inet', 'geobox'], check=False).returncode == 0:
        raise RuntimeError('Existing GeoBox firewall table')
    for family in ('-4', '-6'):
        routes = run(['ip', family, 'route', 'show', 'table', '100'], check=False)
        if routes.stdout.strip() or re.search(r'lookup (?:100|geobox)\b', run(['ip', family, 'rule'])):
            raise RuntimeError('Routing table 100 is already in use')
    for name in SYSTEM:
        if destination('system/' + name).exists():
            raise RuntimeError('Existing system configuration: ' + name)
    if Path('/var/lib/misc/geobox-dhcp-hosts').exists():
        raise RuntimeError('Existing GeoBox DHCP assignments')
    if Path('/etc/NetworkManager/system-connections/geobox-ap.nmconnection').exists():
        raise RuntimeError('Existing GeoBox network profile file')
    # No occupied server port may be stolen. Stop the stock empty dnsmasq after
    # package preparation; never stop an existing DNS service implicitly here.
    if re.search(r':(?:53|67|80|2080|9091)\s', run(['ss', '-H', '-lntu'])):
        raise RuntimeError('Required local port is occupied (53/67/80/2080/9091)')


def destination(name):
    if name.startswith('app/'):
        return APP / name.split('/')[1]
    if name.startswith('system/'):
        leaf = name.split('/')[1]
        return Path('/etc/systemd/system' if leaf.endswith('.service') else '/etc/dnsmasq.d') / leaf
    raise ValueError('Not an installable path')


def atomic_write(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.install-new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    temporary.chmod(mode)
    os.replace(temporary, path)


def update_plan(manifest, previous):
    old = previous.get('files', {})
    new = manifest['files']
    old_app = {n for n in old if n.startswith('app/')}
    new_app = {n for n in new if n.startswith('app/')}
    if not old_app <= new_app:
        raise RuntimeError('Removing installed modules requires a dedicated migration')
    for name in new_app - old_app:
        if destination(name).exists() or destination(name).is_symlink():
            raise RuntimeError('New module would overwrite an untracked file: ' + name)
    for name in new:
        if name.startswith('system/') or name.removeprefix('app/') in NETWORK:
            if old.get(name) != new[name]:
                raise RuntimeError('Network/system changes require a dedicated migration: ' + name)
    for name in old_app | {n for n in old if n.startswith('system/')}:
        target = destination(name)
        if target.is_symlink() or not target.is_file() or digest(target) != old[name]:
            raise RuntimeError('Installed code/config was edited locally: ' + name)
    return sorted(new_app - {'app/' + n for n in NETWORK})


def assert_no_pairing():
    if Path('/run/geobox-ios-pairing-worker.json').exists():
        raise RuntimeError('Finish or cancel iPhone pairing before updating')
    names = {'ios_pairing_worker.py', 'iphone_pair_host.py', 'iphone_pairing_window.py'}
    for process in Path('/proc').iterdir():
        if process.name.isdigit():
            try:
                args = (process / 'cmdline').read_bytes().split(b'\0')
            except (FileNotFoundError, ProcessLookupError):
                continue
            if any(os.fsdecode(a).rsplit('/', 1)[-1] in names for a in args):
                raise RuntimeError('An iPhone pairing process is still active')


@contextmanager
def mutation_guard():
    import fcntl
    assert_no_pairing()
    folder = STATE / 'ios'
    if not folder.exists():
        yield
        return
    fd = os.open(folder / 'bridge.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError:
        raise RuntimeError('iPhone location operation is active; retry after it finishes') from None
    finally:
        os.close(fd)


def health():
    run(['systemctl', 'is-active', 'geobox-panel', 'geobox-singbox'])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(30):
        try:
            with opener.open('http://127.0.0.1/', timeout=2) as response:
                if response.status == 200 and b'/login' in response.read(100000):
                    return
        except OSError:
            pass
        time.sleep(.25)
    raise RuntimeError('Panel health check failed')


def make_backup(stage, payload, fresh, profile):
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix='release-', dir=BACKUPS))
    (backup / 'files').mkdir(mode=0o700)
    before = {}
    for index, (target, data) in enumerate(payload.items()):
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise RuntimeError('Unexpected target type: ' + str(target))
        old = None
        if target.exists():
            shutil.copy2(target, backup / 'files' / str(index))
            old = digest(target)
        before[str(target)] = {'slot': str(index), 'before': old,
                               'after': hashlib.sha256(data).hexdigest(),
                               'mode': target.stat().st_mode & 0o777 if old else 0o600}
    meta = {'fresh': fresh, 'profile': profile, 'files': before,
            'installer_pid': os.getpid(), 'installer_stamp': process_stamp(os.getpid()),
            'dnsmasq_enabled': run(['systemctl', 'is-enabled', 'dnsmasq'], check=False).stdout.strip() if fresh else None,
            'dnsmasq_active': run(['systemctl', 'is-active', 'dnsmasq'], check=False).returncode == 0 if fresh else False,
            'sysctls': {key: run(['sysctl', '-n', key]) for key in SYSCTLS} if fresh else {}}
    (backup / 'state.json').write_text(json.dumps(meta))
    shutil.copyfile(stage / 'install.py', backup / 'install.py')
    unit = 'geobox-release-recover-' + backup.name
    run(['systemd-run', '--quiet', '--unit=' + unit, '--on-active=5min',
         '--property=Restart=on-failure', '--property=RestartSec=15s',
         '/usr/bin/python3', str(backup / 'install.py'), '--recover', str(backup)])
    run(['systemctl', 'is-active', unit + '.timer'])
    return backup


def process_stamp(pid):
    try:
        return Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def recover_stalled_installer(backup):
    backup = backup.resolve(strict=True)
    if backup.parent != BACKUPS or not backup.name.startswith('release-'):
        raise RuntimeError('Invalid recovery directory')
    if (backup / 'COMMITTED').exists() or (backup / 'ROLLED_BACK').exists():
        return
    meta = json.loads((backup / 'state.json').read_text())
    pid, stamp = meta.get('installer_pid'), meta.get('installer_stamp')
    if not isinstance(pid, int) or pid <= 1 or pid == os.getpid() or not stamp:
        return
    if process_stamp(pid) != stamp:
        return
    # The installer's handler interrupts subprocess.run, which kills and reaps
    # its child before rollback. PID start time prevents terminating a reused PID.
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 20
    while process_stamp(pid) == stamp and time.monotonic() < deadline:
        time.sleep(.2)
    if process_stamp(pid) == stamp:
        raise RuntimeError('Installer has not exited; recovery will retry without concurrent writes')


def profile_bytes(profile, ssid, wifi, band):
    # NetworkManager keyfile GKeyFile escapes; SSID uses the documented byte list.
    # The secret is written only to a root-only file, never a command argument.
    escaped = wifi.replace('\\', '\\\\').replace(' ', '\\s')
    octets = ''.join(str(byte) + ';' for byte in ssid.encode('utf-8'))
    return (f'[connection]\nid=geobox-ap\nuuid={profile}\ntype=wifi\ninterface-name=wlan0\nautoconnect=false\n'
            f'[wifi]\nmode=ap\nband={band}\nssid={octets}\n'
            f'[wifi-security]\nkey-mgmt=wpa-psk\npsk={escaped}\n'
            '[ipv4]\nmethod=manual\naddress1=10.77.0.1/24\nnever-default=true\n'
            '[ipv6]\nmethod=manual\naddress1=fd77:6765:6f62:1::1/64\nnever-default=true\n'
            'ignore-auto-routes=true\nignore-auto-dns=true\n').encode()


def restore(backup, automatic=False):
    backup = backup.resolve(strict=True)
    if backup.parent != BACKUPS or not backup.name.startswith('release-'):
        raise RuntimeError('Invalid release backup path')
    if (backup / 'ROLLED_BACK').exists() or (automatic and (backup / 'COMMITTED').exists()):
        return
    meta = json.loads((backup / 'state.json').read_text())
    if meta['fresh'] and (backup / 'COMMITTED').exists():
        raise RuntimeError('A completed clean installation cannot be uninstalled with rollback')
    for name, entry in meta['files'].items():
        path = Path(name)
        current = digest(path) if path.is_file() and not path.is_symlink() else None
        if (meta['fresh'] and path.name == 'geobox-ap.nmconnection' and path.is_file()
                and not path.is_symlink()):
            profile = configparser.ConfigParser(interpolation=None)
            profile.read(path)
            if profile.get('connection', 'uuid', fallback='') != meta['profile']:
                raise RuntimeError('AP profile identity changed; refusing removal')
            # NetworkManager rewrites this newly owned profile on activation /
            # enabling autoconnect. It is removed by exact UUID below.
            continue
        if path.is_symlink() or current not in {entry['before'], entry['after']}:
            raise RuntimeError('File changed after installation; refusing overwrite: ' + name)
        if entry['before'] and digest(backup / 'files' / entry['slot']) != entry['before']:
            raise RuntimeError('Backup integrity check failed')
    run(['systemctl', 'stop', 'geobox-panel.service'], check=False)
    if meta['fresh']:
        # Stop the AP before removing any fail-closed policy.
        run(['nmcli', 'connection', 'delete', 'uuid', meta['profile']], check=False)
        profiles = run(['nmcli', '-g', 'UUID', 'connection', 'show'])
        if meta['profile'] in profiles.splitlines():
            raise RuntimeError('AP profile remains registered; firewall deliberately retained')
        run(['systemctl', 'disable', '--now', *UNITS], check=False)
        run(['systemctl', 'stop', 'dnsmasq'], check=False)
    for name, entry in meta['files'].items():
        path = Path(name)
        if entry['before']:
            atomic_write(path, (backup / 'files' / entry['slot']).read_bytes(), entry['mode'])
        else:
            path.unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    if meta['fresh']:
        for family in ('-4', '-6'):
            run(['ip', family, 'rule', 'del', 'iif', 'wlan0', 'lookup', '100', 'priority', '100'], check=False)
            run(['ip', family, 'route', 'flush', 'table', '100'], check=False)
        for key, value in meta['sysctls'].items():
            run(['sysctl', '-q', '-w', key + '=' + value])
        run(['nft', 'delete', 'table', 'inet', 'geobox'], check=False)
        enabled = meta.get('dnsmasq_enabled')
        if enabled in ('enabled', 'disabled'):
            run(['systemctl', 'enable' if enabled == 'enabled' else 'disable', 'dnsmasq'])
        if meta.get('dnsmasq_active'):
            run(['systemctl', 'start', 'dnsmasq'])
        for directory in (APP, ETC):
            # Preserve unexpected files, including any concurrent user changes.
            try:
                directory.rmdir()
            except OSError:
                pass
    else:
        run(['systemctl', 'restart', 'geobox-panel'])
        health()
    (backup / 'ROLLED_BACK').write_text('ok\n')
    run(['systemctl', 'stop', 'geobox-release-recover-' + backup.name + '.timer'], check=False)


def apply_release(stage, manifest, *, fresh=False, ssid=None, band='bg'):
    if fresh:
        clean_preflight()
        if not ssid or not 1 <= len(ssid.encode('utf-8')) <= 32 or any(ord(c) < 32 for c in ssid):
            raise RuntimeError('SSID must be 1–32 UTF-8 bytes without control characters')
        wifi = getpass.getpass('Wi-Fi password (8–63 printable ASCII characters): ')
        if not 8 <= len(wifi) <= 63 or any(not 32 <= ord(c) <= 126 for c in wifi):
            raise RuntimeError('Invalid Wi-Fi password')
        if wifi != getpass.getpass('Repeat Wi-Fi password: '):
            raise RuntimeError('Passwords differ')
        password = getpass.getpass('Panel password (at least 12 characters): ')
        if len(password) < 12 or password != getpass.getpass('Repeat panel password: '):
            raise RuntimeError('Panel passwords differ or are too short')
        names = [n for n in manifest['files'] if n.startswith(('app/', 'system/'))]
    else:
        if not RECEIPT.is_file():
            raise RuntimeError('No release receipt: legacy installations need a reviewed migration')
        names = update_plan(manifest, json.loads(RECEIPT.read_text()))
    payload = {destination(n): (stage / n).read_bytes() for n in names}
    payload[RECEIPT] = json.dumps(manifest, sort_keys=True).encode()
    profile = str(uuid.uuid4()) if fresh else None
    if fresh:
        with tempfile.TemporaryDirectory(dir='/run') as temporary:
            temp = Path(temporary)
            generated = temp / 'etc'
            generated.mkdir(mode=0o700)
            env = environment(generated, temp)
            run(['/usr/bin/python3', '-I', '-B', str(stage / 'app/geobox.py'), 'set-password'], data=password, env=env)
            run(['/usr/bin/python3', '-I', '-B', str(stage / 'app/geobox.py'), 'render'], env=env)
            payload[ETC / 'panel.json'] = (generated / 'panel.json').read_bytes()
            payload[ETC / 'sing-box.json'] = (generated / 'sing-box.json').read_bytes()
        payload[Path('/var/lib/misc/geobox-dhcp-hosts')] = b''
        payload[Path('/etc/NetworkManager/system-connections/geobox-ap.nmconnection')] = profile_bytes(profile, ssid, wifi, band)
    backup = make_backup(stage, payload, fresh, profile)
    print(json.dumps({'backup': str(backup), 'mode': 'install' if fresh else 'update'}), flush=True)
    entered = False
    try:
        with mutation_guard():
            entered = True
            if not fresh:
                run(['systemctl', 'stop', 'geobox-panel'])
                # Recheck after requests/background tasks have stopped.
                update_plan(manifest, json.loads(RECEIPT.read_text()))
                validate_code(stage, current=True)
            else:
                APP.mkdir(mode=0o755)
                ETC.mkdir(mode=0o700)
                STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
            for target, data in payload.items():
                mode = 0o600 if target.parent in (ETC, STATE) or target.suffix == '.nmconnection' else 0o644
                if target.suffix == '.sh':
                    mode = 0o755
                atomic_write(target, data, mode)
            if fresh:
                run(['systemctl', 'daemon-reload'])
                run(['systemctl', 'start', 'geobox-net'])
                run(['dnsmasq', '--test'])
                # No automatic AP activation until firewall and routes exist.
                run(['nmcli', 'connection', 'load', '/etc/NetworkManager/system-connections/geobox-ap.nmconnection'])
                run(['nmcli', '--wait', '40', 'connection', 'up', 'uuid', profile], timeout=45)
                run(['sysctl', '-q', '-w', 'net.ipv6.conf.wlan0.accept_ra=0', 'net.ipv6.conf.wlan0.autoconf=0'])
                run(['systemctl', 'restart', 'dnsmasq', 'geobox-singbox'])
            run(['systemctl', 'restart', 'geobox-panel'])
            health()
            if fresh:
                run(['systemctl', 'enable', *UNITS, 'dnsmasq'])
                run(['nmcli', 'connection', 'modify', 'uuid', profile, 'connection.autoconnect', 'yes'])
            (backup / 'COMMITTED').write_text('ok\n')
    except BaseException:
        if not entered:
            # A busy phone prevented us from touching any installed file or
            # service. Do not let rollback interrupt that operation either.
            (backup / 'ROLLED_BACK').write_text('no changes\n')
            run(['systemctl', 'stop', 'geobox-release-recover-' + backup.name + '.timer'], check=False)
            raise
        try:
            restore(backup)
        except BaseException:
            if not fresh:
                run(['systemctl', 'restart', 'geobox-panel'], check=False)
            raise
        raise
    finally:
        if (backup / 'COMMITTED').exists():
            run(['systemctl', 'stop', 'geobox-release-recover-' + backup.name + '.timer'], check=False)
    print(json.dumps({'installed': True, 'mode': 'install' if fresh else 'update', 'backup': str(backup)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--install', action='store_true')
    mode.add_argument('--update', action='store_true')
    mode.add_argument('--rollback', type=Path)
    mode.add_argument('--recover', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--ssid')
    parser.add_argument('--band', choices=('bg', 'a'), default='bg')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo on the target Pi')
    os.umask(0o077)
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    import fcntl
    if args.recover:
        recover_stalled_installer(args.recover)
    def interrupted(signum, frame):
        raise RuntimeError('Installation interrupted; rolling back')
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, interrupted)
    with open('/run/geobox-release.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.rollback or args.recover:
            with mutation_guard():
                restore(args.rollback or args.recover, automatic=bool(args.recover))
            return
        with tempfile.TemporaryDirectory(prefix='geobox-release-', dir='/run') as directory:
            stage = Path(directory)
            manifest = copy_verified(Path(__file__).resolve().parent, stage)
            preflight(stage)
            if args.install or args.update:
                apply_release(stage, manifest, fresh=args.install, ssid=args.ssid, band=args.band)
            else:
                print(json.dumps({'preflight': 'passed', 'configuration_valid': True,
                                  'existing_installation': ETC.exists(), 'changes': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('STOP: ' + str(exc), file=sys.stderr)
        sys.exit(1)
