"""One-time SSH bootstrap and a durable, independent default server profile."""
import base64
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shlex
import socket
import os
import importlib
import subprocess
import time
import vps_udp


class SetupError(Exception):
    pass


def ssh_module():
    try:
        return importlib.import_module('paramiko')
    except ModuleNotFoundError as exc:
        if exc.name != 'paramiko':
            raise SetupError('The Pi SSH dependency is damaged. Reinstall python3-paramiko.') from None
    if os.name != 'posix' or os.geteuid() != 0:
        raise SetupError('Install python3-paramiko on the Pi, then retry server setup.')
    for args in (['apt-get', 'update', '-qq'],
                 ['apt-get', 'install', '-y', '--no-install-recommends', '--no-upgrade', 'python3-paramiko']):
        try:
            completed = subprocess.run(args, capture_output=True, timeout=180,
                env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'))
            if completed.returncode:
                raise SetupError('Could not install the Pi SSH dependency. Check its internet connection and package manager.')
        except (OSError, subprocess.TimeoutExpired):
            raise SetupError('Installing the Pi SSH dependency timed out or failed.') from None
    importlib.invalidate_caches()
    return importlib.import_module('paramiko')


def validate(fields):
    try:
        host = str(ipaddress.IPv4Address(fields.get('host', '').strip()))
        if not ipaddress.ip_address(host).is_global:
            raise ValueError()
        ssh_port = int(fields.get('ssh_port', '22'))
        port = int(fields.get('port') or '0')
        user = fields.get('user', 'root').strip()
        if not 1 <= ssh_port <= 65535 or (port and not 1024 <= port <= 65535):
            raise ValueError()
        if not re.fullmatch('[a-z_][a-z0-9_-]{0,31}', user):
            raise ValueError()
        if not fields.get('ssh_password') or len(fields['ssh_password']) > 1024:
            raise ValueError()
        return host, ssh_port, user, port
    except (ValueError, TypeError, AttributeError):
        raise SetupError('Check the public IPv4 address, SSH port, user and password.') from None


def profile(value):
    """Validate saved/backup data and rebuild the narrow supported outbound."""
    if value == {} or value is None:
        return {}
    try:
        host = str(ipaddress.IPv4Address(value['host']))
        ssh_port, user = value['ssh_port'], value['user']
        owner, identity = value['owner'], value['fingerprint']
        proxy = value['proxy']
        outbound = proxy['outbound']
        port, secret = outbound['server_port'], outbound['password']
        if (not ipaddress.ip_address(host).is_global
                or type(ssh_port) is not int or not 1 <= ssh_port <= 65535
                or type(port) is not int or not 1024 <= port <= 65535
                or not re.fullmatch('[a-z_][a-z0-9_-]{0,31}', user)
                or not re.fullmatch('[a-f0-9]{24}', owner)
                or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', identity)
                or not re.fullmatch('[A-Za-z0-9_-]{40,100}', secret)
                or outbound.get('type') != 'shadowsocks'
                or outbound.get('method') != 'chacha20-ietf-poly1305'
                or outbound.get('server') != host or proxy.get('origin') != 'vps'):
            raise ValueError()
        result = {'host': host, 'ssh_port': ssh_port, 'user': user,
                'owner': owner, 'fingerprint': identity,
                'proxy': {'kind': 'ss', 'server': host, 'port': port, 'name': 'VPS',
                          'origin': 'vps', 'login': True, 'secrets': [secret],
                          'outbound': {'type': 'shadowsocks', 'server': host, 'server_port': port,
                                       'method': 'chacha20-ietf-poly1305', 'password': secret}}}
        if vps_udp.valid_proof(value.get('udp'), result['proxy']['outbound']):
            result['udp'] = {key: value['udp'][key] for key in ('status', 'fingerprint', 'mapped_ip', 'checked_at')}
        return result
    except (ValueError, TypeError, KeyError, AttributeError):
        raise SetupError('Invalid saved server profile.') from None


def load(directory):
    try:
        value = json.loads((Path(directory) / 'vps.json').read_text(encoding='utf-8'))
        return profile(value)
    except (OSError, ValueError, TypeError, AttributeError, SetupError):
        pass
    return {}


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def remote(client, user, data):
    source = Path(__file__).with_name('vps_remote.py').read_text(encoding='utf-8')
    command = ('' if user == 'root' else 'sudo -n ') + 'python3 -u -c ' + shlex.quote(source)
    channel = client.get_transport().open_session(timeout=15)
    try:
        channel.settimeout(15)
        channel.exec_command(command)
        channel.sendall(json.dumps(data).encode() + b'\n')
        channel.shutdown_write()
        result = bytearray()
        deadline = time.monotonic() + 350
        while time.monotonic() < deadline:
            if channel.recv_ready():
                result.extend(channel.recv(16384))
                if len(result) > 65536:
                    raise SetupError('Unexpected server response.')
            if channel.recv_stderr_ready():
                channel.recv_stderr(16384)  # Never retain/echo remote diagnostics.
            if channel.exit_status_ready() and not channel.recv_ready():
                break
            time.sleep(.1)
        else:
            raise SetupError('Server setup timed out. Check the server before retrying.')
        try:
            response = json.loads(result)
        except (ValueError, UnicodeDecodeError):
            raise SetupError('Server setup could not run. Python 3 and root or passwordless sudo are required.') from None
        if not response.get('ok'):
            allowed = {'root_required', 'unsupported_os', 'port_in_use', 'existing_instance_mismatch',
                       'incomplete_existing_installation', 'existing_shadowsocks_unit', 'ownership_not_confirmed',
                       'package_changes_require_review', 'udp_port_in_use', 'udp_firewall_rule_exists'}
            code = response.get('error', '')
            raise SetupError('Server setup failed: ' + (code if code in allowed else 'installation did not complete'))
        return response
    finally:
        channel.close()


def provision(fields, previous, verify, pins=None, remember=None, verify_udp=None):
    try:
        return _provision(fields, previous, verify, pins, remember, verify_udp)
    finally:
        fields['ssh_password'] = ''


def _provision(fields, previous, verify, pins=None, remember=None, verify_udp=None):
    """Password stays in this job only. Pin SSH identity before authenticating.

    On first use, the observed identity is trusted and returned for persistence.
    Existing pins must match; a changed key is never silently accepted.
    """
    host, ssh_port, user, port = validate(fields)
    paramiko = ssh_module()
    identity = '%s:%d' % (host, ssh_port)
    pins = pins or {}
    old = previous if previous.get('host') == host and previous.get('ssh_port') == ssh_port else {}
    sock = transport = None
    try:
        sock = socket.create_connection((host, ssh_port), timeout=10)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=15)
        actual = fingerprint(transport.get_remote_server_key())
        expected = pins.get(identity) or old.get('fingerprint')
        if expected and actual != expected:
            raise SetupError('The SSH host key changed. Check the server identity before reconnecting.')
        transport.auth_password(user, fields['ssh_password'], fallback=False)
        client = paramiko.SSHClient()
        client._transport = transport
        owner = old.get('owner') or secrets.token_hex(12)
        secret = (old.get('proxy', {}).get('outbound') or {}).get('password') or secrets.token_urlsafe(32)
        if remember:
            remember({'host': host, 'ssh_port': ssh_port, 'user': user, 'fingerprint': actual,
                      'owner': owner, 'proxy': {'outbound': {'password': secret}}})
        data = {'owner': owner, 'secret': secret, 'port': port, 'udp': verify_udp is not None}
        result = remote(client, user, data)
        port = int(result['port'])
        outbound = {'type': 'shadowsocks', 'server': host, 'server_port': port,
                    'method': 'chacha20-ietf-poly1305', 'password': secret}
        proxy = {'kind': 'ss', 'server': host, 'port': port, 'name': 'VPS', 'origin': 'vps',
                 'login': True, 'secrets': [secret], 'outbound': outbound}
        proof = None
        try:
            tcp_ok = bool(verify(proxy))
            if tcp_ok and verify_udp is not None and result.get('udp') is True:
                proof = verify_udp(outbound)
        except Exception:
            tcp_ok = False
        udp_ok = verify_udp is None or vps_udp.valid_proof(proof, outbound)
        if not tcp_ok or not udp_ok:
            cleanup = 'Existing server service was left unchanged.'
            if result.get('created'):
                try:
                    remote(client, user, dict(data, op='remove'))
                    cleanup = 'The new service was removed.'
                except Exception:
                    cleanup = 'The new service could not be removed; inspect the GeoBox service on the server.'
            elif result.get('udp_changed'):
                try:
                    remote(client, user, dict(data, op='rollback_udp'))
                    cleanup = 'The existing TCP service was restored.'
                except Exception:
                    cleanup = 'Server rollback could not be confirmed. Retry setup to recover the saved TCP configuration.'
            if tcp_ok and not udp_ok:
                raise SetupError('UDP exit was not verified. Check UDP port %d in the server/cloud firewall. Client UDP stays blocked. %s' % (port, cleanup))
            raise SetupError('The server exit did not respond. Allow TCP port %d in the server/cloud firewall and retry. %s' % (port, cleanup))
        if result.get('udp_changed'):
            remote(client, user, dict(data, op='commit_udp'))
        return {'host': host, 'ssh_port': ssh_port, 'user': user, 'fingerprint': actual,
                'owner': owner, 'proxy': proxy, 'configured_at': time.time(), 'udp': proof}
    except SetupError:
        raise
    except Exception:
        raise SetupError('SSH connection or authentication failed. Check the server, port and credentials.') from None
    finally:
        if transport is not None:
            transport.close()
        if sock is not None:
            sock.close()
        fields['ssh_password'] = ''


def card(saved, active):
    esc = lambda v: html.escape(str(v), quote=True)
    current = bool(active and active.get('origin') == 'vps')
    intro = ('<div class="c"><h2>Server exit</h2><p>Proxy on → selected proxy. Proxy off → your server.</p>'
             '<p class="hint">This changes your public IP. Device location shared with apps and websites is separate: Windows needs a local location component; iPhone needs pairing and location synchronization. Server setup does not enable these features. Deny location permission to websites if you do not want to share device coordinates.</p>')
    if saved:
        ready = vps_udp.enabled(saved, saved.get('proxy'))
        intro += '<p translate="no"><b>%s</b> · %s %s</p><p>%s</p>' % (
            esc(saved['host']), 'TCP + UDP' if ready else 'TCP', esc(saved['proxy']['port']), 'Server exit is active.' if current else 'Server is ready. The selected proxy remains active.')
        intro += '<p class="hint">%s</p>' % ('UDP exit verified. Games can use the server when it is selected. Devices with a separate proxy or block assignment keep UDP blocked.' if ready
            else 'UDP is not enabled. Submit the server setup form again with the SSH password to upgrade and verify the existing service.')
        intro += '<p class="hint" translate="no">SSH %s</p><form method="post" action="/vps/use"><button>Use server now</button></form>' % esc(saved.get('fingerprint', ''))
    else:
        intro += '<p>No server configured.</p>'
    intro += '</div><div class="c"><h2>Set up a server</h2><form class="setup" method="post" action="/vps/setup" autocomplete="off">'
    for key, label, value, kind, placeholder in (
        ('host', 'Server IPv4 address', saved.get('host', ''), 'text', '203.0.113.10'),
        ('ssh_port', 'SSH port', saved.get('ssh_port', 22), 'number', '22'),
        ('user', 'SSH user', saved.get('user', 'root'), 'text', 'root'),
        ('ssh_password', 'SSH password (used once)', '', 'password', ''),
        ('port', 'Service TCP/UDP port (blank: keep existing or choose a free port)', '', 'number', '32180')):
        intro += '<label>%s<input name="%s" type="%s" value="%s" placeholder="%s"%s></label>' % (
            label, key, kind, esc(value), placeholder, ' required' if key != 'port' else '')
    intro += ('<div class="f"><button>Set up server</button></div></form>'
              '<p class="hint">Ubuntu/Debian with Python 3. Root or passwordless sudo. Installs or upgrades the isolated GeoBox Shadowsocks service and verifies TCP and UDP exits. SSH, routes and other services are preserved. Active UFW gets rules only for this service port. Cloud firewalls must allow this port over TCP and UDP. Setup can take several minutes.</p>'
              '<p class="hint">The SSH password is never saved. On first connection the SSH host key is trusted and pinned. Future key changes stop setup. Use this form only over a trusted management connection.</p>'
              '<p class="hint">When the verified server is selected, IPv4 TCP, UDP and DNS use it. Selecting a regular proxy blocks client UDP again. A failed exit never falls back to your home IP. Internet speed is still limited by your WAN connection.</p></div>')
    return intro
