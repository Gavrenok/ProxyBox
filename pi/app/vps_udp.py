"""Verified IPv4 UDP for the managed VPS; no direct or alternate exit.

The dedicated outbound avoids selector changes sending UDP through a different
node. Per-device overrides remain UDP-blocked. The audit recognizes only the
exact generated exception, after DNS/private guards and before the UDP deny.
"""
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

import ipv6_probe
import udp_probe

TAG = 'vps-udp'
ALLOW = {'network': 'udp', 'ip_version': 4, 'outbound': TAG}
DENY = {'network': 'udp', 'action': 'reject'}


def exclusions(devices):
    if not isinstance(devices, dict):
        return None
    addresses = set()
    try:
        for device in devices.values():
            if not isinstance(device, dict):
                return None
            if device.get('mode') == 'default':
                continue
            if device.get('mode') not in ('proxy', 'block'):
                return None
            addresses.add(str(ipaddress.IPv4Address(device['ip'])) + '/32')
    except (ValueError, KeyError, TypeError):
        return None
    return sorted(addresses)


def exception_rules(excluded):
    if excluded is None:
        return []
    guards = ([{'network': 'udp', 'source_ip_cidr': excluded, 'action': 'reject'}]
              if excluded else [])
    return guards + [dict(ALLOW)]


def valid_proof(proof, outbound):
    try:
        when = proof['checked_at']
        return (proof.get('status') == 'pass'
                and proof.get('fingerprint') == ipv6_probe.fingerprint(outbound)
                and proof.get('mapped_ip') == outbound['server']
                and ipaddress.IPv4Address(proof['mapped_ip']).is_global
                and type(when) in (int, float) and math.isfinite(when) and when > 0)
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def enabled(saved, proxy):
    if not saved or not proxy or proxy.get('origin') != 'vps':
        return False
    return (proxy.get('outbound') == saved.get('proxy', {}).get('outbound')
            and valid_proof(saved.get('udp'), proxy.get('outbound')))


def audited_exceptions(config, devices):
    """Return only proven-safe rule indexes; an unknown shape gets no exemption."""
    try:
        excluded = exclusions(devices)
        if excluded is None:
            return set()
        rules = config['route']['rules']
        expected = exception_rules(excluded)
        start = rules.index(expected[0])
        end = start + len(expected)
        if rules[start:end + 1] != expected + [DENY]:
            return set()
        # No early outbound, altered DNS capture, or missing private guard.
        prefix = [{'action': 'sniff'}, {'inbound': ['dns-in'], 'action': 'hijack-dns'},
                  {'protocol': 'dns', 'action': 'hijack-dns'},
                  {'ip_is_private': True, 'action': 'reject'}]
        if rules[:start] not in (prefix, [{'ip_version': 6, 'action': 'reject'}] + prefix):
            return set()
        obs = config['outbounds']
        by_tag = {ob['tag']: ob for ob in obs}
        if len(by_tag) != len(obs):
            return set()
        target = dict(by_tag[TAG]); target.pop('tag')
        if (set(target) != {'type', 'server', 'server_port', 'method', 'password'}
                or target['type'] != 'shadowsocks'
                or target['method'] != 'chacha20-ietf-poly1305'
                or not ipaddress.IPv4Address(target['server']).is_global):
            return set()
        active = by_tag[config['route']['final']]
        if active['type'] == 'selector':
            if active.get('default') not in active.get('outbounds', []):
                return set()
            active = by_tag[active['default']]
        if {k: v for k, v in active.items() if k != 'tag'} != target:
            return set()
        return set(range(start, end))
    except (KeyError, ValueError, TypeError, AttributeError):
        return set()


def probe(outbound, timeout=14):
    """Real STUN over a temporary loopback SOCKS -> Shadowsocks relay."""
    result = {'status': 'unknown', 'code': 'probe_failed', 'checked_at': time.time()}
    process = None
    deadline = time.monotonic() + timeout
    try:
        result['fingerprint'] = ipv6_probe.fingerprint(outbound)
        if (outbound.get('type') != 'shadowsocks' or outbound.get('detour')
                or not ipaddress.IPv4Address(outbound['server']).is_global):
            return result
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix='geobox-vps-udp-') as directory:
            os.chmod(directory, 0o700)
            path = Path(directory) / 'config.json'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump(ipv6_probe._config(outbound, port), handle, allow_nan=False)
            binary = os.environ.get('GEOBOX_SB', '/usr/bin/sing-box')
            checked = subprocess.run([binary, 'check', '-c', str(path)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            if checked.returncode:
                return result
            process = subprocess.Popen([binary, 'run', '-c', str(path)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                ipv6_probe._wait_port(process, port, deadline)
                measured = udp_probe.probe({'outbound': {'type': 'socks', 'server': '127.0.0.1',
                                                       'server_port': port}},
                                           timeout=max(.1, deadline - time.monotonic()))
                result['code'] = measured.get('code', 'probe_failed')
                if measured.get('status') == 'pass' and measured.get('mapped_ip') == outbound['server']:
                    result.update(status='pass', mapped_ip=measured['mapped_ip'])
                elif measured.get('status') == 'pass':
                    result.update(code='exit_mismatch')
            finally:
                ipv6_probe._stop(process)
                process = None
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, ipv6_probe.ProbeError):
        pass
    finally:
        ipv6_probe._stop(process)
    return result
