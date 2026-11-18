"""Remote Ubuntu/Debian bootstrap, sent over authenticated SSH.

Only our instance's config/unit are managed. No default routes, NAT, SSH or
existing firewall policy is changed. Cloud/host firewalls may need a port rule.
"""
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys


def save_private(path, value):
    temporary = path.with_suffix(path.suffix + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(value, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def owned(data):
    owner = data.get('owner', '')
    if not re.fullmatch('[a-f0-9]{24}', owner):
        raise RuntimeError('invalid_instance')
    root = Path('/etc/geobox-egress')
    config = root / (owner + '.json')
    receipt = root / (owner + '.receipt')
    backup = root / (owner + '.udp-backup')
    unit = Path('/etc/systemd/system') / ('geobox-egress-' + owner + '.service')
    if (any(p.is_symlink() for p in (root, config, receipt, backup, unit))
            or not config.is_file() or not unit.is_file()):
        raise RuntimeError('ownership_not_confirmed')
    previous = json.loads(config.read_text())
    if previous.get('password') != data.get('secret') or str(config) not in unit.read_text():
        raise RuntimeError('ownership_not_confirmed')
    metadata = json.loads(receipt.read_text()) if receipt.is_file() else {}
    if metadata and metadata.get('owner') != owner:
        raise RuntimeError('ownership_not_confirmed')
    return config, receipt, backup, unit, previous, metadata


def remove_rule(owner, port, protocol):
    status = command(['ufw', 'status'], check=False).stdout
    if any(re.search(r'^' + str(port) + '/' + protocol + r'\s', line)
           and '# geobox-' + owner in line for line in status.splitlines()):
        command(['ufw', '--force', 'delete', 'allow', str(port) + '/' + protocol])


def rollback_udp(data):
    config, receipt, backup, unit, previous, metadata = owned(data)
    if not backup.is_file():
        return {'ok': True, 'restored': False}
    snapshot = json.loads(backup.read_text())
    if (snapshot.get('owner') != data['owner']
            or snapshot.get('config', {}).get('password') != data.get('secret')):
        raise RuntimeError('ownership_not_confirmed')
    if snapshot.get('added_udp_rule'):
        remove_rule(data['owner'], previous['server_port'], 'udp')
    save_private(config, snapshot['config'])
    if snapshot['receipt']:
        save_private(receipt, snapshot['receipt'])
    else:
        receipt.unlink(missing_ok=True)
    command(['systemctl', 'restart', unit.name])
    command(['systemctl', 'is-active', '--quiet', unit.name])
    backup.unlink()
    return {'ok': True, 'restored': True}


def commit_udp(data):
    _, _, backup, _, _, _ = owned(data)
    backup.unlink(missing_ok=True)
    return {'ok': True, 'committed': True}


def upgrade_udp(data):
    config, receipt, backup, unit, previous, metadata = owned(data)
    port = previous['server_port']
    if previous.get('mode') == 'tcp_and_udp':
        return {'ok': True, 'created': False, 'port': port, 'udp': True, 'unit': unit.name}
    if previous.get('mode', 'tcp_only') != 'tcp_only':
        raise RuntimeError('existing_instance_mismatch')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind(('0.0.0.0', port))
        except OSError:
            raise RuntimeError('udp_port_in_use') from None
    status = command(['ufw', 'status'], check=False).stdout if shutil.which('ufw') else ''
    active = status.startswith('Status: active')
    if active and any(re.search(r'^' + str(port) + r'/udp\s', line) for line in status.splitlines()):
        raise RuntimeError('udp_firewall_rule_exists')
    save_private(backup, {'owner': data['owner'], 'config': previous, 'receipt': metadata,
                          'added_udp_rule': active})
    try:
        save_private(config, dict(previous, mode='tcp_and_udp'))
        if active:
            command(['ufw', 'allow', str(port) + '/udp', 'comment', 'geobox-' + data['owner']])
        save_private(receipt, dict(metadata, owner=data['owner'], port=port, ufw_udp=active))
        command(['systemctl', 'restart', unit.name])
        command(['systemctl', 'is-active', '--quiet', unit.name])
    except Exception:
        rollback_udp(data)
        raise
    # Keep the snapshot until the Pi verifies a real UDP round trip.
    return {'ok': True, 'created': False, 'port': port, 'udp': True,
            'udp_changed': True, 'unit': unit.name}


def command(args, timeout=30, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                            env=dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l', LC_ALL='C'))
    if check and result.returncode:
        raise RuntimeError('command_failed:' + args[0])
    return result


def install(data):
    if os.geteuid() != 0:
        raise RuntimeError('root_required')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') not in ('debian', 'ubuntu'):
        raise RuntimeError('unsupported_os')
    owner = data.get('owner', '')
    if not re.fullmatch('[a-f0-9]{24}', owner):
        raise RuntimeError('invalid_instance')
    root = Path('/etc/geobox-egress')
    config = root / (owner + '.json')
    receipt = root / (owner + '.receipt')
    unit_name = 'geobox-egress-' + owner + '.service'
    unit = Path('/etc/systemd/system') / unit_name
    if root.is_symlink() or config.is_symlink() or unit.is_symlink() or receipt.is_symlink():
        raise RuntimeError('unexpected_symlink')
    if config.exists() or unit.exists() or receipt.exists():
        # An incomplete/existing installation must not be overwritten blindly.
        if not (config.is_file() and unit.is_file()):
            raise RuntimeError('incomplete_existing_installation')
        previous = json.loads(config.read_text())
        if previous.get('password') != data.get('secret') or str(config) not in unit.read_text():
            raise RuntimeError('existing_instance_mismatch')
        if config.with_suffix('.udp-backup').exists():
            rollback_udp(data)  # Recover an interrupted, uncommitted upgrade.
        command(['systemctl', 'is-active', '--quiet', unit_name])
        if data.get('udp') is True:
            return upgrade_udp(data)
        return {'ok': True, 'created': False, 'port': previous['server_port'], 'unit': unit_name}
    secret = data.get('secret', '')
    if not re.fullmatch('[A-Za-z0-9_-]{40,100}', secret):
        raise RuntimeError('invalid_secret')
    requested = int(data.get('port', 0))
    if requested and not 1024 <= requested <= 65535:
        raise RuntimeError('invalid_port')
    ufw_status = command(['ufw', 'status'], check=False).stdout if shutil.which('ufw') else ''
    ufw_active = ufw_status.startswith('Status: active')
    port = 0
    for candidate in ([requested] if requested else range(32180, 32280)):
        if ufw_active and re.search(r'\b' + str(candidate) + r'\b', ufw_status):
            continue  # Leave any pre-existing rule for this port untouched.
        with socket.socket() as sock, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            try:
                sock.bind(('0.0.0.0', candidate))
                if data.get('udp') is True:
                    udp_sock.bind(('0.0.0.0', candidate))
                port = candidate
                break
            except OSError:
                continue
    if not port:
        raise RuntimeError('port_in_use')
    if not shutil.which('ss-server'):
        # Prevent the newly installed distribution default instance from starting.
        default = 'shadowsocks-libev.service'
        before = command(['systemctl', 'is-enabled', default], check=False).stdout.strip()
        if before not in ('', 'not-found', 'disabled'):
            raise RuntimeError('existing_shadowsocks_unit')
        command(['systemctl', 'mask', '--runtime', default])
        try:
            command(['apt-get', 'update', '-qq'], timeout=120)
            planned = command(['apt-get', '-s', 'install', '--no-install-recommends', '--no-upgrade',
                               '--no-remove', 'shadowsocks-libev'], timeout=60).stdout
            if re.search(r'^Inst \S+ \[', planned, re.M) or re.search(r'^Remv ', planned, re.M):
                raise RuntimeError('package_changes_require_review')
            command(['apt-get', 'install', '-y', '--no-install-recommends', '--no-upgrade', '--no-remove',
                     'shadowsocks-libev'], timeout=180)
        finally:
            command(['systemctl', 'disable', default], check=False)
            command(['systemctl', 'unmask', '--runtime', default], check=False)
    root.mkdir(mode=0o700, exist_ok=True)
    contents = {'server': '0.0.0.0', 'server_port': port, 'password': secret,
                'timeout': 60, 'method': 'chacha20-ietf-poly1305',
                'mode': 'tcp_and_udp' if data.get('udp') is True else 'tcp_only',
                'nameserver': '1.1.1.1', 'no_delay': True}
    # Create exclusively: another panel/administrator may have acted since preflight.
    made_config = made_unit = made_firewall = made_udp_firewall = False
    try:
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        made_config = True
        with os.fdopen(fd, 'w') as handle:
            json.dump(contents, handle)
        service = ('[Unit]\nDescription=GeoBox private server exit\nAfter=network-online.target\n'
                   '[Service]\nExecStart=/usr/bin/ss-server -c %s -a nobody\nRestart=on-failure\n'
                   'RestartSec=3\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n'
                   'ProtectHome=yes\n[Install]\nWantedBy=multi-user.target\n') % config
        with unit.open('x') as handle:
            made_unit = True
            handle.write(service)
        command(['systemctl', 'daemon-reload'])
        command(['systemctl', 'enable', '--now', unit_name])
        command(['systemctl', 'is-active', '--quiet', unit_name])
        if ufw_active:
            command(['ufw', 'allow', str(port) + '/tcp', 'comment', 'geobox-' + owner])
            made_firewall = True
            if data.get('udp') is True:
                made_udp_firewall = True
                command(['ufw', 'allow', str(port) + '/udp', 'comment', 'geobox-' + owner])
        with receipt.open('x') as handle:
            json.dump({'owner': owner, 'ufw': made_firewall, 'ufw_udp': made_udp_firewall, 'port': port}, handle)
    except Exception:
        if made_udp_firewall:
            remove_rule(owner, port, 'udp')
        if made_firewall:
            command(['ufw', '--force', 'delete', 'allow', str(port) + '/tcp'], check=False)
        if made_unit:
            command(['systemctl', 'disable', '--now', unit_name], check=False)
            unit.unlink(missing_ok=True)
        if made_config:
            config.unlink(missing_ok=True)
        command(['systemctl', 'daemon-reload'], check=False)
        raise
    return {'ok': True, 'created': True, 'port': port, 'unit': unit_name, 'udp': data.get('udp') is True}


def remove(data):
    # Validate all ownership records before stopping any service.
    owned(data)
    owner = data.get('owner', '')
    if not re.fullmatch('[a-f0-9]{24}', owner):
        raise RuntimeError('invalid_instance')
    config = Path('/etc/geobox-egress') / (owner + '.json')
    receipt = config.with_suffix('.receipt')
    unit_name = 'geobox-egress-' + owner + '.service'
    unit = Path('/etc/systemd/system') / unit_name
    if config.is_symlink() or unit.is_symlink() or receipt.is_symlink() or not config.is_file() or not unit.is_file():
        raise RuntimeError('ownership_not_confirmed')
    if json.loads(config.read_text()).get('password') != data.get('secret') or str(config) not in unit.read_text():
        raise RuntimeError('ownership_not_confirmed')
    command(['systemctl', 'disable', '--now', unit_name])
    if receipt.is_file():
        metadata = json.loads(receipt.read_text())
        if metadata.get('owner') != owner:
            raise RuntimeError('ownership_not_confirmed')
        if metadata.get('ufw'):
            remove_rule(owner, int(metadata['port']), 'tcp')
        if metadata.get('ufw_udp'):
            remove_rule(owner, int(metadata['port']), 'udp')
        receipt.unlink()
    unit.unlink()
    config.unlink()
    config.with_suffix('.udp-backup').unlink(missing_ok=True)
    command(['systemctl', 'daemon-reload'])
    return {'ok': True, 'removed': True}


if __name__ == '__main__':
    try:
        request = json.loads(sys.stdin.buffer.readline(16385))
        operations = {'install': install, 'remove': remove, 'rollback_udp': rollback_udp, 'commit_udp': commit_udp}
        result = operations[request.get('op', 'install')](request)
    except Exception as exc:
        # Only fixed errors, never commands, input, secrets or host diagnostics.
        message = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        result = {'ok': False, 'error': message}
    print(json.dumps(result), flush=True)
