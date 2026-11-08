"""Explicit SOCKS5 UDP capability check; never sends STUN directly.

Uses RFC 1928 UDP ASSOCIATE, RFC 1929 authentication, and an RFC 8489 Binding
request. It does not enable client UDP, change firewall rules, or emulate an IP.
Only fixed diagnostic text and the observed mapped IP leave this module.
"""
import ipaddress
import queue
import secrets
import socket
import struct
import threading
import time

STUN_HOST = 'stun.l.google.com'
STUN_PORT = 19302
COOKIE = 0x2112A442
DETAILS = {
    'supported': 'Получен STUN-ответ через SOCKS5 UDP. Прокси передал тестовую UDP-датаграмму; это не проверка WebRTC самого устройства.',
    'unsupported_proxy': 'Эта проверка поддерживает обычный SOCKS5 UDP. Возможности других протоколов этим тестом не определяются.',
    'no_proxy': 'Для этого маршрута прокси не задан или доступ заблокирован.',
    'command_rejected': 'Сервер SOCKS5 явно отклонил команду UDP ASSOCIATE как неподдерживаемую.',
    'auth_failed': 'Сервер не принял аутентификацию для UDP-проверки.',
    'connection_failed': 'Не удалось завершить соединение с прокси. Поддержка UDP не определена.',
    'timeout': 'Ответ не получен за отведённое время. Возможны ограничения прокси, сети или STUN-сервиса; поддержка UDP не определена.',
    'invalid_reply': 'Получен некорректный ответ SOCKS5/STUN. Поддержка UDP не подтверждена.',
    'unsafe_relay': 'Прокси указал недопустимый локальный адрес UDP-реле. Запрос к нему не отправлен.',
    'private_mapping': 'STUN вернул неглобальный адрес. Публичный UDP-выход не подтверждён.',
}


class ProbeFailure(Exception):
    pass


def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise ProbeFailure('timeout')
    return left


def resolve(host, port, socktype, deadline):
    # The OS resolver can exceed socket timeouts; bound the caller's wait too.
    answers = queue.Queue(maxsize=1)
    def work():
        try:
            answers.put(socket.getaddrinfo(host, port, socket.AF_UNSPEC, socktype))
        except (OSError, ValueError, TypeError, UnicodeError):
            answers.put(None)
    threading.Thread(target=work, daemon=True).start()
    try:
        result = answers.get(timeout=remaining(deadline))
    except queue.Empty:
        raise ProbeFailure('timeout') from None
    if not result:
        raise ProbeFailure('connection_failed')
    return result


def connect_tcp(host, port, deadline):
    for family, socktype, proto, _, address in resolve(host, port, socket.SOCK_STREAM, deadline):
        wait = min(3, remaining(deadline))
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(wait)
            sock.connect(address)
            return sock
        except OSError:
            sock.close()
    raise ProbeFailure('connection_failed')


def exact(sock, size, deadline):
    data = b''
    while len(data) < size:
        sock.settimeout(remaining(deadline))
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProbeFailure('invalid_reply')
        data += chunk
    return data


def address(read, atyp):
    if atyp == 1:
        return str(ipaddress.ip_address(read(4)))
    if atyp == 4:
        return str(ipaddress.ip_address(read(16)))
    if atyp == 3:
        size = read(1)[0]
        if size == 0:
            raise ProbeFailure('invalid_reply')
        return read(size).decode('ascii')
    raise ProbeFailure('invalid_reply')


def unwrap(packet):
    if len(packet) < 4 or packet[:3] != b'\0\0\0':
        raise ProbeFailure('invalid_reply')
    offset = 4
    def read(size):
        nonlocal offset
        if offset + size > len(packet):
            raise ProbeFailure('invalid_reply')
        value = packet[offset:offset + size]
        offset += size
        return value
    source = address(read, packet[3])
    port = struct.unpack('!H', read(2))[0]
    if port != STUN_PORT:
        raise ProbeFailure('invalid_reply')
    return source, packet[offset:]


def mapped_address(packet, transaction):
    if len(packet) < 20:
        raise ProbeFailure('invalid_reply')
    kind, size, cookie = struct.unpack('!HHI', packet[:8])
    if kind != 0x0101 or cookie != COOKIE or packet[8:20] != transaction or size % 4 or len(packet) != size + 20:
        raise ProbeFailure('invalid_reply')
    offset, fallback, xor_result = 20, None, None
    while offset < len(packet):
        if offset + 4 > len(packet):
            raise ProbeFailure('invalid_reply')
        attr, length = struct.unpack('!HH', packet[offset:offset + 4])
        offset += 4
        if offset + length > len(packet):
            raise ProbeFailure('invalid_reply')
        value = packet[offset:offset + length]
        offset += (length + 3) & ~3
        if offset > len(packet):
            raise ProbeFailure('invalid_reply')
        if attr not in (0x0020, 0x0001):
            continue
        if length not in (8, 20) or value[0] != 0 or value[1] not in (1, 2):
            raise ProbeFailure('invalid_reply')
        if length != (8 if value[1] == 1 else 20):
            raise ProbeFailure('invalid_reply')
        port = struct.unpack('!H', value[2:4])[0]
        raw = value[4:]
        if attr == 0x0020:
            port ^= COOKIE >> 16
            mask = struct.pack('!I', COOKIE) + transaction
            raw = bytes(a ^ b for a, b in zip(raw, mask))
        if port == 0:
            raise ProbeFailure('invalid_reply')
        ip = str(ipaddress.ip_address(raw))
        if attr == 0x0020:
            xor_result = ip
        else:
            fallback = ip
    if not (xor_result or fallback):
        raise ProbeFailure('invalid_reply')
    return xor_result or fallback


def probe(proxy, timeout=10):
    started = time.monotonic()
    deadline = started + timeout
    result = {'scope': 'proxy', 'checked_at': time.time(), 'status': 'unknown'}
    code, mapped = 'connection_failed', None
    ob = (proxy or {}).get('outbound') or {}
    if not proxy:
        code = 'no_proxy'
    elif ob.get('type') != 'socks' or str(ob.get('version', '5')) != '5' or ob.get('udp_over_tcp') or ob.get('detour'):
        code = 'unsupported_proxy'
    else:
        try:
            with connect_tcp(ob['server'], int(ob['server_port']), deadline) as tcp:
                user = str(ob.get('username') or '').encode('utf-8')
                password = str(ob.get('password') or '').encode('utf-8')
                if len(user) > 255 or len(password) > 255:
                    raise ProbeFailure('auth_failed')
                method = 2 if user else 0
                tcp.sendall(bytes((5, 1, method)))
                if exact(tcp, 2, deadline) != bytes((5, method)):
                    raise ProbeFailure('auth_failed')
                if user:
                    tcp.sendall(bytes((1, len(user))) + user + bytes((len(password),)) + password)
                    if exact(tcp, 2, deadline) != b'\x01\x00':
                        raise ProbeFailure('auth_failed')
                tcp.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
                version, reply, reserved, atyp = exact(tcp, 4, deadline)
                if version != 5 or reserved != 0:
                    raise ProbeFailure('invalid_reply')
                if reply:
                    raise ProbeFailure('command_rejected' if reply == 7 else 'connection_failed')
                relay = address(lambda size: exact(tcp, size, deadline), atyp)
                port = struct.unpack('!H', exact(tcp, 2, deadline))[0]
                if port == 0:
                    raise ProbeFailure('invalid_reply')
                peer = tcp.getpeername()[0]
                if relay in ('0.0.0.0', '::'):
                    relay = peer
                targets = resolve(relay, port, socket.SOCK_DGRAM, deadline)
                target = next((item for item in targets if ipaddress.ip_address(item[4][0]).is_global or item[4][0] == peer), None)
                if target is None:
                    raise ProbeFailure('unsafe_relay')
                family, socktype, proto, _, endpoint = target
                transaction = secrets.token_bytes(12)
                request = struct.pack('!HHI', 1, 0, COOKIE) + transaction
                # The STUN hostname is resolved by the SOCKS relay, never by the client.
                host = STUN_HOST.encode('ascii')
                datagram = b'\0\0\0\x03' + bytes((len(host),)) + host + struct.pack('!H', STUN_PORT) + request
                with socket.socket(family, socktype, proto) as udp:
                    udp.connect(endpoint)
                    for wait in (1, 2, 3):
                        udp.settimeout(min(wait, remaining(deadline)))
                        udp.send(datagram)
                        try:
                            _, payload = unwrap(udp.recv(4096))
                            mapped = mapped_address(payload, transaction)
                            break
                        except socket.timeout:
                            continue
                    if not mapped:
                        raise ProbeFailure('timeout')
                    code = 'supported' if ipaddress.ip_address(mapped).is_global else 'private_mapping'
        except ProbeFailure as exc:
            code = str(exc) if str(exc) in DETAILS else 'invalid_reply'
        except (TimeoutError, socket.timeout):
            code = 'timeout'
        except (ValueError, KeyError, TypeError, UnicodeError, struct.error):
            code = 'invalid_reply'
        except OSError:
            code = 'connection_failed'
    result.update(code=code, detail=DETAILS[code], elapsed_ms=round((time.monotonic() - started) * 1000))
    result['status'] = ('pass' if code == 'supported' else 'unsupported' if code in ('unsupported_proxy', 'command_rejected')
                        else 'warn' if code in ('auth_failed', 'private_mapping', 'no_proxy', 'unsafe_relay') else 'unknown')
    if mapped:
        result['mapped_ip'] = mapped
    return result
