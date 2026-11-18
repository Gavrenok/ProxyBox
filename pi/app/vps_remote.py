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
        command(['systemctl', 'is-active', '--quiet', unit_name])
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
        with socket.socket() as sock:
            try:
                sock.bind(('0.0.0.0', candidate))
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
                'timeout': 60, 'method': 'chacha20-ietf-poly1305', 'mode': 'tcp_only',
                'nameserver': '1.1.1.1', 'no_delay': True}
    # Create exclusively: another panel/administrator may have acted since preflight.
    made_config = made_unit = made_firewall = False
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
        with receipt.open('x') as handle:
            json.dump({'owner': owner, 'ufw': made_firewall, 'port': port}, handle)
    except Exception:
        if made_firewall:
            command(['ufw', '--force', 'delete', 'allow', str(port) + '/tcp'], check=False)
        if made_unit:
            command(['systemctl', 'disable', '--now', unit_name], check=False)
            unit.unlink(missing_ok=True)
        if made_config:
            config.unlink(missing_ok=True)
        command(['systemctl', 'daemon-reload'], check=False)
        raise
    return {'ok': True, 'created': True, 'port': port, 'unit': unit_name}


def remove(data):
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
            status = command(['ufw', 'status'], check=False).stdout
            # Only remove a rule still carrying our instance marker.
            if 'geobox-' + owner in status:
                command(['ufw', '--force', 'delete', 'allow', str(int(metadata['port'])) + '/tcp'])
        receipt.unlink()
    unit.unlink()
    config.unlink()
    command(['systemctl', 'daemon-reload'])
    return {'ok': True, 'removed': True}


if __name__ == '__main__':
    try:
        request = json.loads(sys.stdin.buffer.readline(16385))
        result = remove(request) if request.get('op') == 'remove' else install(request)
    except Exception as exc:
        # Only fixed errors, never commands, input, secrets or host diagnostics.
        message = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        result = {'ok': False, 'error': message}
    print(json.dumps(result), flush=True)
