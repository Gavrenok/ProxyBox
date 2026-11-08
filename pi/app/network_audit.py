"""Explicit, read-only router audit. Never call this from page rendering.

audit(config, devices, run, selector_read) inspects supplied snapshots and live
local state. run follows geobox.run's (returncode, stdout, stderr) contract;
selector_read(config) returns the local Clash selector JSON. Neither dependency
may mutate state. The default implementations run fixed read-only commands and
an authenticated loopback GET. Reports contain fixed messages/counts, never raw
config, command output, IPs, MACs, node names, credentials or tokens.

This is a conservative audit of the policy our app generates, not a general
sing-box/nftables interpreter. Unsupported policy constructs produce unknown.
"""
import ipaddress
import json
import subprocess
import time

import fastswitch

TITLES = {
    'config_dns_capture': 'Перехват обычного DNS',
    'config_ipv6': 'Политика IPv6',
    'config_udp': 'Политика UDP',
    'config_private': 'Доступ к частным сетям',
    'config_egress': 'Выход клиентского трафика',
    'config_dns_egress': 'Выход DNS-запросов',
    'config_devices': 'Назначения устройств',
    'firewall_forward': 'Живой фаервол пересылки',
    'routing_policy': 'Правило маршрутизации IPv4',
    'routing_table': 'Туннель и резервный запрет маршрута',
    'tunnel': 'Служба и интерфейс туннеля',
    'selector': 'Выбранный узел движка',
    'routing_policy6': 'Правило маршрутизации IPv6',
    'routing_table6': 'Туннель и резервный запрет IPv6',
}
LIMITATIONS = [
    'Это аудит правил малины, а не проверка утечек с телефона, Mac или браузера.',
    'Настройки sing-box проверены по переданному файлу; API подтверждает выбор узла, но не весь работающий конфиг.',
    'Bootstrap DNS для адреса самого прокси отличается от DNS клиентов и может обращаться напрямую.',
    'Назначения проверяются по сохранённым IP устройств; их фактическое подключение и другие сети устройства здесь не проверяются.',
    'Проверка не делает внешних запросов и не подтверждает доступность или геолокацию прокси.',
]
PROXY_TYPES = {'socks', 'http', 'shadowsocks', 'vmess', 'trojan', 'vless', 'hysteria2'}
CMD_NFT = ['/usr/sbin/nft', '-j', 'list', 'ruleset']
CMD_RULES = ['/usr/sbin/ip', '-j', '-4', 'rule', 'show']
CMD_ROUTES = ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', '100']
CMD_RULES6 = ['/usr/sbin/ip', '-j', '-6', 'rule', 'show']
CMD_ROUTES6 = ['/usr/sbin/ip', '-j', '-6', 'route', 'show', 'table', '100']
CMD_LINK = ['/usr/sbin/ip', '-j', 'link', 'show', 'dev', 'sbtun']
CMD_SERVICE = ['systemctl', 'is-active', 'geobox-singbox.service']


def _check(key, status, detail, *evidence):
    return {'id': key, 'title': TITLES[key], 'scope': 'router', 'status': status,
            'detail': detail, 'evidence': list(evidence)}


def _run(args, timeout=6):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.TimeoutExpired):
        return 1, '', ''


def _read(run, command, shape):
    try:
        rc, stdout, _ = run(list(command), timeout=6)
        if rc != 0 or not isinstance(stdout, str) or len(stdout) > 4 * 1024 * 1024:
            return None
        parsed = json.loads(stdout)
        return parsed if isinstance(parsed, shape) else None
    except Exception:
        return None


def _list(value):
    if isinstance(value, str):
        return [value]
    return value if isinstance(value, list) else None


def _exact(rule, **wanted):
    if not isinstance(rule, dict) or set(rule) != set(wanted):
        return False
    for key, value in wanted.items():
        actual = rule[key]
        if isinstance(value, list):
            if _list(actual) != value:
                return False
        elif actual != value:
            return False
    return True


def _position(rules, **wanted):
    return next((i for i, rule in enumerate(rules) if _exact(rule, **wanted)), None)


def _shape(config):
    if not isinstance(config, dict):
        return None
    route, dns = config.get('route'), config.get('dns')
    if not isinstance(route, dict) or not isinstance(dns, dict):
        return None
    rules, dns_rules = route.get('rules'), dns.get('rules')
    outbounds, servers, inbounds = config.get('outbounds'), dns.get('servers'), config.get('inbounds')
    arrays = (rules, dns_rules, outbounds, servers, inbounds)
    if not all(isinstance(a, list) and all(isinstance(v, dict) for v in a) for a in arrays):
        return None
    return route, dns, rules, dns_rules, outbounds, servers, inbounds


def _unique_map(entries):
    result = {}
    for entry in entries:
        tag = entry.get('tag')
        if not isinstance(tag, str) or not tag or tag in result:
            return None
        result[tag] = entry
    return result


def _outbound_status(tag, outbounds, seen=None):
    """Every possible selector/URLTest member must terminate at a proxy/block."""
    if not isinstance(tag, str) or outbounds is None or tag not in outbounds:
        return 'unknown'
    seen = set(seen or ())
    if tag in seen:
        return 'unknown'
    seen.add(tag)
    outbound = outbounds[tag]
    kind = outbound.get('type')
    if kind == 'direct':
        return 'warn'
    if kind == 'block':
        return 'pass'
    if kind in PROXY_TYPES:
        if (not isinstance(outbound.get('server'), str) or not outbound['server']
                or not isinstance(outbound.get('server_port'), int)
                or isinstance(outbound['server_port'], bool)
                or not 1 <= outbound['server_port'] <= 65535):
            return 'unknown'
        # A proxy's transport detour does not imply direct client egress. Complex
        # chained transports are intentionally outside this generated-policy audit.
        return 'unknown' if outbound.get('detour') else 'pass'
    if kind in ('selector', 'urltest'):
        members = outbound.get('outbounds')
        if not isinstance(members, list) or not members or not all(isinstance(v, str) for v in members):
            return 'unknown'
        if kind == 'selector' and outbound.get('default') not in members:
            return 'unknown'
        return _worst(_outbound_status(member, outbounds, seen) for member in members)
    return 'unknown'


def _worst(statuses):
    values = list(statuses)
    return 'warn' if 'warn' in values else 'unknown' if 'unknown' in values else 'pass'


def _safe_rule_prefix(rules):
    """Recognize only app-generated preliminary rules with no early route."""
    allowed = [
        {'action': 'sniff'},
        {'inbound': ['dns-in'], 'action': 'hijack-dns'},
        {'protocol': ['dns'], 'action': 'hijack-dns'},
        {'ip_version': 6, 'action': 'reject'},
        {'network': ['udp'], 'action': 'reject'},
        {'ip_is_private': True, 'action': 'reject'},
    ]
    for rule in rules:
        if any(_exact(rule, **expected) for expected in allowed):
            continue
        if 'outbound' in rule or rule.get('action') in ('route', 'route-options', 'direct', 'hijack-dns'):
            return 'warn'
        return 'unknown'
    return 'pass'


def _ipv6_tun(config):
    """New dual-stack infrastructure also exists while IPv6 is blocked."""
    shaped = _shape(config)
    if shaped is None:
        return False
    for inbound in shaped[-1]:
        if inbound.get('type') != 'tun' or inbound.get('interface_name') != 'sbtun':
            continue
        for address in _list(inbound.get('address')) or []:
            try:
                if ipaddress.ip_interface(address).version == 6:
                    return True
            except (ValueError, TypeError):
                continue
    return False


def _policy_checks(config, devices):
    shaped = _shape(config)
    keys = list(TITLES)[:7]
    if shaped is None:
        return [_check(key, 'unknown', 'Структура конфигурации не распознана.') for key in keys]
    route, dns, rules, dns_rules, outbound_list, server_list, inbounds = shaped
    outbound_map, servers = _unique_map(outbound_list), _unique_map(server_list)
    result = []
    inbound_pos = _position(rules, inbound=['dns-in'], action='hijack-dns')
    protocol_pos = _position(rules, protocol=['dns'], action='hijack-dns')
    sniff_pos = _position(rules, action='sniff')
    dns_listeners = [entry for entry in inbounds if entry.get('tag') == 'dns-in']
    listener_ok = (len(dns_listeners) == 1 and dns_listeners[0].get('type') == 'direct'
                   and dns_listeners[0].get('listen_port') == 53
                   and dns_listeners[0].get('listen') in ('0.0.0.0', '10.77.0.1')
                   and not dns_listeners[0].get('network'))
    tunnel_listeners = [entry for entry in inbounds if entry.get('type') == 'tun']
    tunnel_ok = (len(tunnel_listeners) == 1
                 and tunnel_listeners[0].get('interface_name') == 'sbtun')
    if (inbound_pos is None or protocol_pos is None or not listener_ok or not tunnel_ok
            or sniff_pos is None or sniff_pos >= protocol_pos):
        result.append(_check('config_dns_capture', 'warn', 'Ожидаемый приём и перехват DNS не подтверждены.'))
    else:
        prefix = _safe_rule_prefix(rules[:max(inbound_pos, protocol_pos)])
        # A UDP rejection before the protocol matcher blocks DNS received on TUN;
        # it is fail-closed, but does not meet the expected interception policy.
        udp_at = _position(rules, network=['udp'], action='reject')
        if udp_at is not None and udp_at < protocol_pos:
            prefix = 'warn'
        result.append(_check('config_dns_capture', prefix,
            'Проверены слушатель DNS и порядок перехвата обычных DNS-запросов.' if prefix == 'pass'
            else 'Перед перехватом DNS есть другое или неподдерживаемое правило.',
            'Порт 53, DNS-вход и DNS в туннеле проверены; DoH браузера этим не измеряется.'))
    for key, matcher in [('config_ipv6', {'ip_version': 6}),
                         ('config_udp', {'network': ['udp']}),
                         ('config_private', {'ip_is_private': True})]:
        position = _position(rules, **matcher, action='reject')
        status = 'warn' if position is None else _safe_rule_prefix(rules[:position])
        if key == 'config_ipv6':
            aaaa = _position(dns_rules, query_type=['AAAA'], action='predefined')
            if position is None and _ipv6_tun(config):
                # IPv4 source assignments cannot identify privacy IPv6 addresses.
                # Until L2 classification is implemented this mode is global-only.
                if not isinstance(devices, dict):
                    status = 'unknown'
                elif any(not isinstance(d, dict) or d.get('mode', 'default') != 'default'
                         for d in devices.values()):
                    status = 'warn'
                else:
                    status = _worst([_safe_rule_prefix(rules),
                                     _outbound_status(route.get('final'), outbound_map)])
                if aaaa is not None or dns.get('strategy') == 'ipv4_only':
                    status = _worst([status, 'warn'])
                result.append(_check(key, status,
                    'IPv6 направлен через общий прокси; отдельных назначений устройств нет.'
                    if status == 'pass' else 'IPv6 через общий прокси не соответствует ожидаемой политике.',
                    'Проверен конфиг; IPv6 маршруты и фаервол проверяются отдельно. Доступность прокси здесь не измеряется.'))
                continue
            if aaaa is None or aaaa != 0:
                status = _worst([status, 'warn'])
            if (_ipv6_tun(config) and position is not None
                    and protocol_pos is not None and position > protocol_pos):
                # With IPv6 active on LAN, hijack-dns would consume an IPv6
                # DNS packet before the later block or IPv4 device policy.
                status = _worst([status, 'warn'])
        result.append(_check(key, status,
            'Запрет стоит до правил направления клиентского трафика.' if status == 'pass'
            else 'Ожидаемый запрет отсутствует, ограничен условием или обходится более ранним правилом.'
            if status == 'warn' else 'Порядок правил содержит неподдерживаемую конструкцию.',
            'Проверена конфигурация; это не внешний тест.' if key != 'config_ipv6'
            else 'Проверены IPv6 reject и ранний пустой ответ AAAA.'))

    statuses = []
    closed = False
    for rule in rules:
        if _exact(rule, action='reject'):
            closed = True
            break
        if 'outbound' in rule:
            if rule.get('action', 'route') != 'route':
                statuses.append('unknown')
            else:
                statuses.append(_outbound_status(rule['outbound'], outbound_map))
        elif rule.get('action') not in ('sniff', 'hijack-dns', 'reject'):
            statuses.append('unknown')
    if not closed:
        statuses.append(_outbound_status(route.get('final'), outbound_map))
    status = _worst(statuses)
    result.append(_check('config_egress', status,
        'Доступные направления ведут через прокси либо блокировку; прямой запасной выход не найден в проверенных правилах.'
        if status == 'pass' else 'В доступных направлениях найден прямой выход.' if status == 'warn'
        else 'Не все направления удалось разобрать; отсутствие прямого выхода не подтверждено.'))

    def dns_path(tag):
        if servers is None or not isinstance(tag, str) or tag not in servers:
            return 'unknown'
        server = servers[tag]
        if server.get('type') not in ('https', 'tls', 'quic', 'udp', 'tcp', 'h3'):
            return 'unknown'
        if not server.get('detour'):
            return 'warn'
        return _outbound_status(server['detour'], outbound_map)

    statuses, closed = [], False
    for rule in dns_rules:
        if _exact(rule, action='reject'):
            closed = True
            break
        if rule.get('action') == 'route' and 'server' in rule:
            statuses.append(dns_path(rule['server']))
        elif not (_exact(rule, query_type=['AAAA'], action='predefined') or
                  set(rule) == {'source_ip_cidr', 'action'} and rule.get('action') == 'reject'):
            statuses.append('unknown')
    if not closed:
        statuses.append(dns_path(dns.get('final')))
    status = _worst(statuses)
    result.append(_check('config_dns_egress', status,
        'DNS клиентов направлен через проверенные прокси-направления либо запрещён.' if status == 'pass'
        else 'DNS клиентов может использовать сервер без прокси-detour.' if status == 'warn'
        else 'Не все DNS-направления поддерживаются этим аудитом.',
        'Bootstrap для адреса самого прокси не является проверкой клиентского DNS.'))
    result.append(_device_check(devices, rules, dns_rules, servers, outbound_map))
    return result


def _source_ips(rule):
    values = _list(rule.get('source_ip_cidr'))
    if values is None or not values:
        return None
    parsed = set()
    try:
        for value in values:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4 or network.prefixlen != 32:
                return None
            parsed.add(str(network.network_address))
    except (ValueError, TypeError):
        return None
    return parsed


def _device_check(devices, route_rules, dns_rules, servers, outbounds):
    key = 'config_devices'
    if not isinstance(devices, dict):
        return _check(key, 'unknown', 'Снимок назначений устройств не передан или не распознан.')
    expected = {}
    for device in devices.values():
        if not isinstance(device, dict):
            return _check(key, 'unknown', 'Структура назначений устройств не распознана.')
        mode = device.get('mode')
        if mode == 'default':
            continue
        if mode not in ('proxy', 'block'):
            return _check(key, 'unknown', 'Есть неподдерживаемый режим устройства.')
        try:
            address = str(ipaddress.IPv4Address(device.get('ip')))
        except (ValueError, TypeError):
            return _check(key, 'unknown', 'Не все назначения содержат корректный IPv4-адрес.')
        if address in expected:
            return _check(key, 'warn', 'Один клиентский IP назначен нескольким записям устройств.')
        if mode == 'proxy' and not isinstance(device.get('item'), str):
            return _check(key, 'unknown', 'Назначенный профиль устройства не распознан.')
        expected[address] = ('reject', None) if mode == 'block' else ('proxy', 'dev-' + device['item'])

    # Find first matching generated rule per client, including unconditional
    # catchalls. Unknown constructs cannot be assumed to leave it untouched.
    outcomes = []
    for rules, is_dns in ((route_rules, False), (dns_rules, True)):
        actual = {}
        for rule in rules:
            if 'source_ip_cidr' in rule:
                ips = _source_ips(rule)
                if ips is None:
                    return _check(key, 'unknown', 'Клиентские правила используют неподдерживаемые адресные условия.')
                allowed = ({'source_ip_cidr', 'action'} if rule.get('action') == 'reject' else
                           {'source_ip_cidr', 'action', 'server'} if is_dns else {'source_ip_cidr', 'outbound'})
                if set(rule) != allowed:
                    return _check(key, 'unknown', 'Клиентские правила содержат дополнительные условия.')
                if not ips <= set(expected):
                    outcomes.append('warn')
                for ip in ips:
                    actual.setdefault(ip, rule)
            elif _exact(rule, action='reject') or (not is_dns and _exact(rule, outbound=rule.get('outbound'))):
                for ip in expected:
                    actual.setdefault(ip, rule)
                break
            elif not is_dns and _safe_rule_prefix([rule]) != 'pass':
                return _check(key, 'unknown', 'До назначений есть неподдерживаемые правила трафика.')
            elif is_dns and not _exact(rule, query_type=['AAAA'], action='predefined'):
                return _check(key, 'unknown', 'До назначений есть неподдерживаемые DNS-правила.')
        for ip, (mode, tag) in expected.items():
            rule = actual.get(ip)
            if rule is None:
                outcomes.append('warn')
            elif mode == 'reject':
                outcomes.append('pass' if rule.get('action') == 'reject' else 'warn')
            elif is_dns:
                server = servers.get(rule.get('server'), {}) if servers else {}
                outcomes.append('pass' if rule.get('action') == 'route' and server.get('detour') == tag
                                and _outbound_status(tag, outbounds) == 'pass' else 'warn')
            else:
                outcomes.append('pass' if rule.get('outbound') == tag
                                and _outbound_status(tag, outbounds) == 'pass' else 'warn')
    status = _worst(outcomes)
    return _check(key, status,
        'Правила трафика и DNS соответствуют сохранённым назначениям.' if status == 'pass'
        else 'Назначение трафика или DNS расходится с сохранённым профилем устройства.',
        'Проверено отдельных назначений: %d.' % len(expected))


def _forward_rule(rule):
    expressions = rule.get('expr')
    if not isinstance(expressions, list) or not expressions:
        return 'unknown', None
    interfaces, accept, unknown = {}, False, False
    for index, expression in enumerate(expressions):
        if not isinstance(expression, dict) or len(expression) != 1:
            unknown = True
            continue
        kind, value = next(iter(expression.items()))
        if kind == 'match':
            if not isinstance(value, dict):
                unknown = True
                continue
            left = value.get('left')
            meta = left.get('meta') if isinstance(left, dict) else None
            iface = meta.get('key') if isinstance(meta, dict) else None
            if iface in ('iifname', 'oifname') and value.get('op') == '==' and isinstance(value.get('right'), str):
                if iface in interfaces or accept:
                    unknown = True
                interfaces[iface] = value['right']
            elif (isinstance(left, dict) and left.get('payload') in (
                    {'protocol': 'ip6', 'field': 'saddr'}, {'protocol': 'ip6', 'field': 'daddr'})
                    and value.get('op') == '=='
                    and value.get('right') == {'prefix': {'addr': 'fd77:6765:6f62:1::', 'len': 64}}):
                pass
            else:
                unknown = True
        elif kind == 'accept':
            accept = True
            if index != len(expressions) - 1:
                unknown = True
        elif kind == 'counter':
            pass
        elif kind == 'set':
            allowed = ({'op': 'update', 'elem': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'set': '@tx'},
                       {'op': 'update', 'elem': {'payload': {'protocol': 'ip', 'field': 'daddr'}}, 'set': '@rx'},
                       {'op': 'update', 'elem': {'payload': {'protocol': 'ip6', 'field': 'saddr'}}, 'set': '@tx6'},
                       {'op': 'update', 'elem': {'payload': {'protocol': 'ip6', 'field': 'daddr'}}, 'set': '@rx6'})
            if value not in allowed:
                unknown = True
        else:
            unknown = True
    pair = (interfaces.get('iifname'), interfaces.get('oifname'))
    if accept and pair not in (('wlan0', 'sbtun'), ('sbtun', 'wlan0')):
        return 'warn', None
    if unknown or not accept:
        return 'unknown', None
    return 'pass', pair


def _firewall(nft, ipv6=False):
    key = 'firewall_forward'
    if not isinstance(nft, dict) or not isinstance(nft.get('nftables'), list):
        return _check(key, 'unknown', 'Не удалось получить структуру живого nftables ruleset.')
    entries = nft['nftables']
    if not all(isinstance(entry, dict) for entry in entries):
        return _check(key, 'unknown', 'Формат nftables не распознан.')
    chains = [entry['chain'] for entry in entries if isinstance(entry.get('chain'), dict)]
    targets = [chain for chain in chains if chain.get('family') == 'inet' and chain.get('table') == 'geobox'
               and chain.get('name') == 'forward']
    if len(targets) != 1:
        return _check(key, 'warn', 'Ожидаемая единая цепочка inet/geobox/forward не найдена.')
    chain = targets[0]
    if chain.get('type') != 'filter' or chain.get('hook') != 'forward' or chain.get('policy') != 'drop':
        return _check(key, 'warn', 'Цепочка пересылки не имеет ожидаемого hook forward и политики drop.')
    relevant = [entry['rule'] for entry in entries if isinstance(entry.get('rule'), dict)
                and entry['rule'].get('family') == 'inet' and entry['rule'].get('table') == 'geobox'
                and entry['rule'].get('chain') == 'forward']
    checks = [_forward_rule(rule) for rule in relevant]
    status = _worst(value[0] for value in checks)
    pairs = {pair for _, pair in checks if pair}
    if pairs != {('wlan0', 'sbtun'), ('sbtun', 'wlan0')} and status == 'pass':
        status = 'warn'
    if ipv6:
        ipv6_pairs = set()
        for rule, (rule_status, pair) in zip(relevant, checks):
            # An IPv4 payload counter is also a family match: it cannot carry
            # IPv6. A generic interface-only accept is valid for both families.
            ipv4_only = any(expr.get('set', {}).get('elem', {}).get('payload', {}).get('protocol') == 'ip'
                            for expr in rule.get('expr', []) if isinstance(expr, dict))
            if rule_status == 'pass' and not ipv4_only:
                ipv6_pairs.add(pair)
        if ipv6_pairs != {('wlan0', 'sbtun'), ('sbtun', 'wlan0')}:
            status = _worst([status, 'warn'])
    extra = [other for other in chains if other.get('hook') in ('forward', 'ingress', 'prerouting') and other is not chain]
    if extra or any('flowtable' in entry for entry in entries):
        status = _worst([status, 'unknown'])
    return _check(key, status,
        'Политика drop; разрешены только пары Wi-Fi ↔ туннель.' if status == 'pass'
        else 'Пересылка отличается от ожидаемого закрытого набора разрешений.' if status == 'warn'
        else 'Есть дополнительные цепочки или выражения, которые аудит не интерпретирует.',
        'Проверены живые правила, включая условия каждого accept; одного наличия drop недостаточно.')


def _policy_route(rules, ipv6=False):
    key = 'routing_policy6' if ipv6 else 'routing_policy'
    if rules is None or not all(isinstance(rule, dict) for rule in rules):
        return _check(key, 'unknown', 'Не удалось прочитать правила маршрутизации выбранного семейства IP.')
    candidates = [rule for rule in rules if rule.get('iif') == 'wlan0' and str(rule.get('table')) == '100']
    if not candidates:
        return _check(key, 'warn', 'Нет правила направления входящего Wi-Fi трафика в таблицу 100.')
    safe = []
    for rule in candidates:
        if (isinstance(rule.get('priority'), int) and rule.get('src', 'all') == 'all'
                and rule.get('dst', 'all') == 'all'
                and set(rule) <= {'priority', 'src', 'dst', 'iif', 'table', 'protocol'}):
            safe.append(rule)
    if not safe:
        return _check(key, 'warn', 'Правило таблицы 100 содержит ограничения или исключения.')
    selected = min(safe, key=lambda rule: rule['priority'])
    for rule in rules:
        priority = rule.get('priority')
        if not isinstance(priority, int):
            return _check(key, 'unknown', 'Приоритеты правил маршрутизации не распознаны.')
        if rule is selected or priority > selected['priority']:
            continue
        if (priority == 0 and rule.get('table') == 'local' and rule.get('src', 'all') == 'all'
                and set(rule) <= {'priority', 'src', 'table', 'protocol'}):
            continue
        if isinstance(rule.get('iif'), str) and rule['iif'] != 'wlan0' and 'not' not in rule:
            continue
        # ip-rule(8): oif matches only traffic from local sockets bound to a
        # device, never a forwarded packet arriving on wlan0. sing-box creates
        # this narrow rule for its TUN. Do not generalize to negated, unknown,
        # or additionally qualified constructs.
        if (rule.get('oif') == 'sbtun' and rule.get('src', 'all') == 'all'
                and rule.get('dst', 'all') == 'all'
                and isinstance(rule.get('table'), (str, int))
                and set(rule) <= {'priority', 'src', 'dst', 'oif', 'table', 'protocol'}):
            continue
        return _check(key, 'warn', 'Более раннее правило может перехватить Wi-Fi трафик до таблицы 100.')
    return _check(key, 'pass', 'Безусловное правило для входящего Wi-Fi стоит перед общими таблицами.',
                  'Локальная таблица ядра разрешена; дополнительные ранние правила проверены.')


def _route_table(routes, ipv6=False):
    key = 'routing_table6' if ipv6 else 'routing_table'
    if routes is None or not all(isinstance(route, dict) for route in routes):
        return _check(key, 'unknown', 'Не удалось прочитать таблицу маршрутов 100.')
    tunnel, fallback = [], []
    for route in routes:
        if not isinstance(route.get('flags', []), list):
            return _check(key, 'unknown', 'Флаги маршрутов не распознаны.')
        if any(flag in route.get('flags', []) for flag in ('dead', 'linkdown')):
            return _check(key, 'warn', 'Маршрут помечен ядром как недоступный.')
        if route.get('dst') not in ('default', '::/0' if ipv6 else '0.0.0.0/0'):
            return _check(key, 'unknown', 'В таблице 100 есть дополнительные маршруты; нужен расширенный разбор.')
        if (route.get('type') == 'unreachable' and not route.get('gateway')
                and (not route.get('dev') or ipv6 and route.get('dev') == 'lo')):
            fallback.append(route)
        elif route.get('type', 'unicast') == 'unicast' and route.get('dev') == 'sbtun' and not route.get('gateway'):
            tunnel.append(route)
        else:
            return _check(key, 'warn', 'В таблице 100 найден иной выход или маршрут, допускающий переход к другой таблице.')
        if ipv6 and route.get('pref', 'medium') not in ('low', 'medium', 'high'):
            return _check(key, 'unknown', 'Предпочтение IPv6 маршрута не распознано.')
        if set(route) - ({'dst', 'dev', 'scope', 'metric', 'flags', 'type', 'protocol', 'table'}
                         | ({'pref'} if ipv6 else set())):
            return _check(key, 'unknown', 'Маршруты содержат дополнительные условия, которые аудит не интерпретирует.')
    if not fallback:
        return _check(key, 'warn', 'Отсутствует резервный unreachable default; падение туннеля требует проверки.')
    if not tunnel:
        return _check(key, 'warn', 'Резервный запрет есть, но активный маршрут в туннель не найден.')
    try:
        order_ok = min(int(r.get('metric', 0)) for r in tunnel) < min(int(r.get('metric', 0)) for r in fallback)
    except (ValueError, TypeError):
        return _check(key, 'unknown', 'Метрики маршрутов не распознаны.')
    if not order_ok:
        return _check(key, 'warn', 'Приоритет маршрута в туннель не выше резервного запрета.')
    return _check(key, 'pass', 'Маршрут ведёт в туннель; за ним стоит unreachable default.',
                  'Прямой default или throw в проверенной таблице не найден.')


def _tunnel(link, run):
    try:
        rc, stdout, _ = run(list(CMD_SERVICE), timeout=6)
        state = stdout.strip() if isinstance(stdout, str) else ''
    except Exception:
        rc, state = 1, ''
    if state in ('inactive', 'failed', 'activating', 'deactivating'):
        return _check('tunnel', 'warn', 'Служба туннеля не подтверждена как работающая.')
    if rc != 0 or state != 'active' or link is None:
        return _check('tunnel', 'unknown', 'Не удалось подтвердить состояние службы и интерфейса.')
    if len(link) != 1 or not isinstance(link[0], dict) or link[0].get('ifname') != 'sbtun':
        return _check('tunnel', 'unknown', 'Данные интерфейса туннеля не распознаны.')
    flags = link[0].get('flags')
    if not isinstance(flags, list):
        return _check('tunnel', 'unknown', 'Флаги интерфейса туннеля не распознаны.')
    if 'UP' not in flags:
        return _check('tunnel', 'warn', 'Интерфейс туннеля существует, но не поднят.')
    return _check('tunnel', 'pass', 'Служба активна, интерфейс туннеля поднят.',
                  'Это не подтверждение доступности внешнего прокси.')


def _selector(config, selector_read):
    key = 'selector'
    try:
        if _shape(config) is None:
            return _check(key, 'unknown', 'Структура конфигурации не распознана.')
        selected = fastswitch.selector(config)
        if not selected:
            final = config.get('route', {}).get('final')
            return _check(key, 'pass' if final != 'proxy' else 'unknown',
                          'Общий selector не используется.' if final != 'proxy'
                          else 'Для этого общего прокси выбор через API не подтверждается.')
        if not fastswitch.controller(config):
            return _check(key, 'warn', 'Локальный контроллер не соответствует ожидаемой защищённой настройке.')
        reader = selector_read or (lambda value: fastswitch.Client(value).request('GET', '/proxies/' + fastswitch.TAG))
        actual = reader(config)
        if (not isinstance(actual, dict) or not isinstance(actual.get('all'), list)
                or not all(isinstance(value, str) for value in actual['all'])):
            return _check(key, 'unknown', 'Ответ локального selector API не распознан.')
        if actual.get('now') != selected.get('default') or set(actual['all']) != set(selected.get('outbounds', [])):
            return _check(key, 'warn', 'Живой выбор или состав узлов отличается от сохранённой конфигурации.')
        return _check(key, 'pass', 'Живой выбранный узел и состав группы совпадают со снимком.',
                      'Проверен только локальный authenticated API; токен в отчёт не включён.')
    except Exception:
        return _check(key, 'unknown', 'Не удалось получить подтверждение локального selector API.')


def audit(config, devices=None, run=None, selector_read=None):
    """Run explicitly in a background job; takes up to ~30s on local timeouts."""
    run = run or _run
    checked_at = time.time()
    try:
        checks = _policy_checks(config, devices)
    except Exception:
        # Malformed snapshots are untrusted data. Never echo exceptions/values.
        checks = [_check(key, 'unknown', 'Конфигурация содержит неподдерживаемые или повреждённые значения.')
                  for key in list(TITLES)[:7]]
    nft = _read(run, CMD_NFT, dict)
    rules = _read(run, CMD_RULES, list)
    routes = _read(run, CMD_ROUTES, list)
    link = _read(run, CMD_LINK, list)
    ipv6 = _ipv6_tun(config)
    if ipv6:
        rules6 = _read(run, CMD_RULES6, list)
        routes6 = _read(run, CMD_ROUTES6, list)
        checks.append(_policy_route(rules6, ipv6=True))
        checks.append(_route_table(routes6, ipv6=True))
    for key, function, args in (
        ('firewall_forward', _firewall, (nft, ipv6)),
        ('routing_policy', _policy_route, (rules,)),
        ('routing_table', _route_table, (routes,)),
        ('tunnel', _tunnel, (link, run)),
        ('selector', _selector, (config, selector_read)),
    ):
        try:
            checks.append(function(*args))
        except Exception:
            checks.append(_check(key, 'unknown', 'Локальные данные содержат неподдерживаемые или повреждённые значения.'))
    return {'scope': 'router', 'status': _worst(check['status'] for check in checks),
            'checked_at': checked_at, 'completed_at': time.time(), 'checks': checks,
            'limitations': list(LIMITATIONS)}
