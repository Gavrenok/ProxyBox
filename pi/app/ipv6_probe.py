"""Check one proxy's IPv6 HTTPS egress without changing the live router.

All test requests, including the AAAA lookup, go through an isolated loopback
sing-box. An available result requires both a hostname and an IPv6-literal
CONNECT to the same TLS-verified service. Timeouts are inconclusive. This is a
point-in-time TCP test, not proof about UDP, every destination or client leaks.
"""
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


HOST = 'api6.ipify.org'
URL = 'https://' + HOST + '?format=json'
DNS_URL = 'https://cloudflare-dns.com/dns-query?name=' + HOST + '&type=AAAA'
PROXY_TYPES = frozenset(('http', 'socks', 'shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria2'))
MAX_BODY = 16384


class ProbeError(Exception):
    pass


def fingerprint(outbound):
    """Bind evidence to all outbound options, including credentials, except tag."""
    if not isinstance(outbound, dict) or not outbound:
        raise ValueError('outbound must be a nonempty object')
    canonical = json.dumps({k: v for k, v in outbound.items() if k != 'tag'},
                           sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                           allow_nan=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise ProbeError()
    return left


def _global6(value):
    if not isinstance(value, str) or '%' in value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if (address.version != 6 or not address.is_global or address.is_multicast
            or address.ipv4_mapped is not None):
        return None
    return str(address)


def _config(outbound, port):
    return {
        'log': {'disabled': True},
        'dns': {'servers': [
            {'type': 'udp', 'tag': 'bootstrap', 'server': '1.1.1.1'},
            {'type': 'https', 'tag': 'remote', 'server': '1.1.1.1', 'detour': 'p'}],
            'final': 'remote'},
        'inbounds': [{'type': 'mixed', 'tag': 'probe', 'listen': '127.0.0.1', 'listen_port': port}],
        'outbounds': [dict(outbound, tag='p')],
        'route': {'final': 'p', 'default_domain_resolver': 'bootstrap'},
    }


def _wait_port(process, port, deadline):
    startup_end = min(deadline, time.monotonic() + 3)
    while time.monotonic() < startup_end:
        if process.poll() is not None:
            raise ProbeError()
        try:
            with socket.create_connection(('127.0.0.1', port),
                                          timeout=min(.15, _remaining(startup_end))):
                return
        except OSError:
            time.sleep(min(.05, _remaining(startup_end)))
    raise ProbeError()


def _request(port, url, deadline, *, literal=None, budget=None):
    left = _remaining(deadline)
    if budget is not None:
        left = min(left, budget)
    # -q must be first: ignore ~/.curlrc, redirects, environment proxy bypasses
    # and TLS-insecure settings. The URL and local proxy contain no credentials.
    args = ['curl', '-q', '--silent', '--fail', '--proxy', 'http://127.0.0.1:%d' % port,
            '--noproxy', '', '--proto', '=https', '--max-time', str(left),
            '--connect-timeout', str(min(4, left)), '--max-filesize', str(MAX_BODY),
            '--write-out', '\n%{http_code}',
            '--header', 'Accept: application/dns-json' if url == DNS_URL else 'Accept: application/json']
    if literal is not None:
        if not _global6(literal):
            raise ProbeError()
        # --connect-to changes CONNECT's destination, preserving hostname, SNI
        # and certificate verification. --resolve alone is insufficient here.
        args += ['--connect-to', '%s:443:[%s]:443' % (HOST, literal)]
    args += [url]
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=left, check=False)
    if result.returncode != 0 or len(result.stdout) > MAX_BODY + 4:
        raise ProbeError()
    body, separator, status = result.stdout.rpartition(b'\n')
    if not separator or status != b'200' or len(body) > MAX_BODY:
        raise ProbeError()
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError):
        raise ProbeError() from None
    if not isinstance(payload, dict):
        raise ProbeError()
    return payload


def _measure(port, deadline):
    first = _request(port, URL, deadline, budget=min(6, _remaining(deadline) * .4))
    if not _global6(first.get('ip')):
        raise ProbeError()
    dns = _request(port, DNS_URL, deadline, budget=min(4, _remaining(deadline) * .4))
    if dns.get('Status') != 0 or dns.get('TC') is True:
        raise ProbeError()
    answers = dns.get('Answer')
    if not isinstance(answers, list):
        raise ProbeError()
    addresses = [_global6(a.get('data')) for a in answers
                 if isinstance(a, dict) and a.get('type') == 28]
    literal = next((a for a in addresses if a), None)
    if literal is None:
        raise ProbeError()
    second = _request(port, URL, deadline, literal=literal)
    address = _global6(second.get('ip'))
    if address is None:
        raise ProbeError()
    # Rotating proxies may use different exits for the two connections.
    return address


def _stop(process):
    if process is None:
        return
    try:
        process.terminate()
        process.wait(timeout=.5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=.5)
    except OSError:
        pass


def probe(outbound, timeout=18):
    """Return status/address/time/message/fingerprint; never raw errors or secrets.

    ``available`` requires two successful HTTPS checks, including a literal
    IPv6 destination. ``unavailable`` is reserved for an absent proxy. Unsupported
    probe formats and network failures are unknown, not proof about the service.
    The network/process budget is clamped to 1..30 seconds plus up to 1 second
    for terminating the isolated worker. No router settings are changed.
    """
    started = time.monotonic()
    result = {'status': 'unknown', 'address': None, 'time': time.time(), 'fingerprint': None,
              'message': 'Поддержку IPv6 подтвердить не удалось. Это не доказывает её отсутствие.'}
    process = None
    try:
        if outbound is None:
            result.update(status='unavailable', message='Прокси для IPv6 не задан.')
            return result
        result['fingerprint'] = fingerprint(outbound)
        budget = float(timeout)
        if not math.isfinite(budget):
            raise ProbeError()
        deadline = started + min(30, max(1, budget))
        if outbound.get('type') not in PROXY_TYPES or outbound.get('detour'):
            return result
        if outbound.get('type') == 'socks' and str(outbound.get('version', '5')) in ('4', '4a'):
            result.update(message='Эта проверка не подтверждает IPv6 для SOCKS4/4a; нужен другой формат прокси.')
            return result
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix='geobox-ipv6-') as directory:
            os.chmod(directory, 0o700)
            path = Path(directory) / 'config.json'
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as config_file:
                json.dump(_config(outbound, port), config_file, allow_nan=False)
            binary = os.environ.get('GEOBOX_SB', '/usr/bin/sing-box')
            checked = subprocess.run([binary, 'check', '-c', str(path)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=min(3, _remaining(deadline)), check=False)
            if checked.returncode != 0:
                raise ProbeError()
            try:
                process = subprocess.Popen([binary, 'run', '-c', str(path), '-D', directory],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                _wait_port(process, port, deadline)
                address = _measure(port, deadline)
            finally:
                _stop(process)
                process = None
            result.update(status='available', address=address,
                          message='IPv6 HTTPS подтверждён через этот прокси по имени и IPv6-адресу. Это разовый TCP-тест.')
    except (ProbeError, OSError, ValueError, TypeError, OverflowError, subprocess.SubprocessError):
        pass
    finally:
        result['time'] = time.time()
        result['checked_at'] = result['time']
        result['duration_ms'] = max(0, round((time.monotonic() - started) * 1000))
    return result
