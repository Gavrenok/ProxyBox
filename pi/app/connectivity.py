"""On-demand connection diagnosis. Fixed messages; no settings or service writes.

The caller owns the configuration snapshot/lock and supplies an exit probe.
An exit probe from the Pi is not a test of a phone's actual traffic or DNS leaks.
"""
import html
import ipaddress
import json
import secrets
import socket
import struct
import time

import network_audit

ENDPOINTS = ('https://api.ipify.org?format=json', 'https://ipinfo.io/json')


def _dns_has_address(response, offset, answers):
    for _ in range(min(answers, 100)):
        # Skip a DNS owner name. Compression pointers terminate the name;
        # there is no reason to follow them for this bounded A-answer check.
        for _ in range(128):
            size = response[offset]
            if size & 0xc0 == 0xc0:
                pointer = ((size & 0x3f) << 8) | response[offset + 1]
                if pointer >= len(response):
                    return False
                offset += 2
                break
            offset += 1
            if size == 0:
                break
            if size > 63:
                return False
            offset += size
        else:
            return False
        kind, klass, _, length = struct.unpack('!HHIH', response[offset:offset+10])
        offset += 10
        data = response[offset:offset+length]
        if len(data) != length:
            return False
        if kind == 1 and klass == 1 and length == 4:
            address = ipaddress.ip_address(data)
            if address.is_global and not address.is_multicast:
                return True
        offset += length
    return False


def probe_https(url, run):
    """Only a loopback HTTP proxy is accepted; curl never falls back to direct."""
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
        return 'unknown'
    results = []
    for endpoint in ENDPOINTS:
        rc, body, _ = run(['curl', '-q', '-4', '--silent', '--fail', '--proxy', url,
                          '--noproxy', '', '--connect-timeout', '3', '--max-time', '6',
                          '--max-filesize', '4096', endpoint], timeout=7)
        if rc == 0:
            try:
                value = json.loads(body)
                address = ipaddress.ip_address(value['ip'])
                if address.version == 4 and address.is_global and not address.is_multicast:
                    return 'pass'
            except (ValueError, KeyError, TypeError):
                pass
        results.append(rc)
    # Timeouts and HTTP errors do not identify an expired proxy or bad password.
    return 'unavailable' if any(code != 0 for code in results) else 'unknown'


def dns_query(timeout=2):
    """Ask the local client DNS listener, never the OS resolver or public DNS.

This is the global policy from the Pi, not a per-device source-IP simulation.
An answer may be cached and does not establish the external resolver's identity.
"""
    query_id = secrets.randbelow(65536)
    question = b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
    query = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0) + question
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.settimeout(timeout)
            channel.connect(('10.77.0.1', 53))
            channel.send(query)
            response = channel.recv(4096)
        if len(response) < 12 + len(question):
            return 'unknown'
        ident, flags, questions, answers, _, _ = struct.unpack('!HHHHHH', response[:12])
        if ident != query_id or not flags & 0x8000 or questions != 1 or response[12:12+len(question)] != question:
            return 'unknown'
        if flags & 0x0200:
            return 'unknown'
        if flags & 0x000f:
            return 'unavailable'
        return 'pass' if _dns_has_address(response, 12+len(question), answers) else 'unknown'
    except OSError:
        return 'unavailable'
    except (IndexError, ValueError, struct.error):
        return 'unknown'


def diagnose(config, devices, scope, has_proxy, run, selector_read, exit_probe,
             dns_probe=dns_query, audit=network_audit.audit):
    report = {'checked_at': time.time(), 'scope': scope, 'steps': [], 'status': 'unknown',
              'title': '', 'next': '', 'stale': False}

    def step(label, status, detail):
        report['steps'].append({'label': label, 'status': status, 'detail': detail})

    def finish(status, title, next_action):
        report.update(status=status, title=title, next=next_action, completed_at=time.time())
        return report

    if scope == 'blocked':
        step('Назначение устройства', 'warn', 'Для адреса этого устройства задан запрет или нет назначенного профиля.')
        return finish('warn', 'Доступ ограничен настройками устройства',
                      'Открой «Устройства»: проверь режим и наличие назначенного прокси в библиотеке.')
    if not has_proxy:
        step('Прокси', 'warn', 'Для проверяемого маршрута прокси не выбран.')
        return finish('warn', 'Прокси не задан', 'Выбери прокси во вкладке «Прокси» или назначь его устройству.')
    step('Назначение', 'pass', 'Проверяется отдельный прокси устройства.' if scope == 'device_proxy'
         else 'Проверяется общий прокси. Панель открыта вне Wi-Fi GeoBox.' if scope == 'outside'
         else 'Проверяется общий прокси для этого адреса в Wi-Fi GeoBox.')

    # Bound all audit subprocesses together, instead of multiplying each timeout.
    local_deadline = time.monotonic() + 8
    def bounded_run(args, timeout=6):
        remaining = local_deadline - time.monotonic()
        return run(args, timeout=min(timeout, remaining)) if remaining > 0 else (124, '', '')

    rc, body, _ = bounded_run(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'default'], timeout=2)
    try:
        routes = json.loads(body) if rc == 0 else None
    except (ValueError, TypeError):
        routes = None
    no_ipv4_default = routes == []
    if no_ipv4_default:
        step('Входящий интернет', 'info', 'Основного маршрута IPv4 нет. Прокси может быть доступен по IPv6 или отдельному маршруту; проверим запросом.')
    else:
        step('Входящий интернет', 'pass' if isinstance(routes, list) else 'unknown',
             'Маршрут IPv4 присутствует; доступность провайдера проверяется внешним запросом ниже.'
             if isinstance(routes, list) else 'Не удалось прочитать основной маршрут.')

    rc, state, _ = bounded_run(['nmcli', '-g', 'GENERAL.CONNECTION', 'device', 'show', 'wlan0'], timeout=2)
    if rc == 0 and state.strip() != 'geobox-ap':
        step('Wi-Fi', 'warn', 'Профиль точки доступа GeoBox сейчас не активен на wlan0.')
        return finish('warn', 'Точка доступа GeoBox не активна',
                      'Проверь вкладку «Wi-Fi». Если подключён к домашней сети, перейди на Wi-Fi GeoBox после восстановления точки.')
    step('Wi-Fi', 'pass' if rc == 0 else 'unknown',
         'Профиль точки доступа активен.' if rc == 0 else 'Не удалось подтвердить состояние точки доступа.')
    try:
        audit_result = audit(config, devices=devices, run=bounded_run, selector_read=selector_read)
        checks = {item['id']: item['status'] for item in audit_result['checks']}
    except Exception:
        checks = {}
    # Prioritize the stopped tunnel over the missing active TUN route it causes.
    if checks.get('tunnel') == 'warn':
        step('Туннель', 'warn', 'Служба или интерфейс туннеля не работают нормально.')
        return finish('warn', 'Туннель не готов',
                      'Проверь состояние sing-box в «Обзоре». Не выключай защиту: сначала восстанови службу или её конфигурацию.')
    step('Туннель', checks.get('tunnel', 'unknown'), 'Проверены служба и интерфейс sbtun.')
    policy_keys = set(network_audit.TITLES) - {'tunnel'}
    suspect = [key for key in policy_keys if checks.get(key) == 'warn']
    if suspect:
        step('Правила сети', 'warn', 'Аудит нашёл расхождение в настройках, маршрутах, фаерволе или выборе прокси.')
        return finish('warn', 'Правила сети требуют проверки',
                      'Открой Mimic → «Проверить малину» для подробностей. Это найденное расхождение, а не доказанная причина каждого сбоя.')
    required = {'config_dns_capture', 'config_ipv6', 'config_udp', 'config_private', 'config_egress',
                'config_dns_egress', 'config_devices', 'firewall_forward', 'routing_policy', 'routing_table', 'selector'}
    policy_known = required <= checks.keys() and all(value == 'pass' for value in checks.values())
    step('Правила сети', 'pass' if policy_known else 'unknown',
         'Проверенные правила соответствуют ожидаемой политике.' if policy_known
         else 'Часть правил не удалось подтвердить; это не результат проверки утечек.')
    if not policy_known:
        return finish('unknown', 'Не удалось подтвердить правила сети',
                      'Повтори проверку. Если результат тот же, открой Mimic → «Проверить малину». Внешний запрос не выполнялся.')

    ipv6_blocked = any(isinstance(rule, dict) and rule.get('ip_version') == 6
                      and rule.get('action') == 'reject' for rule in config.get('route', {}).get('rules', []))
    step('IPv6', 'info', 'IPv6 заблокирован политикой. Это не мешает сайтам с IPv4; IPv6-only ресурсы недоступны.'
         if ipv6_blocked else 'IPv6 оценивается аудитом правил; внешний IPv6-запрос этой кнопкой не выполняется.')

    try:
        reachable = exit_probe()
    except Exception:
        reachable = 'unknown'
    step('HTTPS через прокси', 'pass' if reachable == 'pass' else 'warn' if reachable == 'unavailable' else 'unknown',
         'Получен корректный внешний IPv4-ответ с малины через проверяемый прокси.' if reachable == 'pass'
         else 'Внешний запрос не подтвердил выход. Причиной может быть прокси, провайдер или недоступность проверочного сервиса.')
    if reachable != 'pass':
        return finish('warn' if reachable == 'unavailable' else 'unknown', 'Выход через прокси не подтверждён',
                      ('Основного маршрута IPv4 нет: проверь Ethernet и домашний роутер. ' if no_ipv4_default else '')
                      + 'Проверь срок аренды и параметры прокси, затем повтори проверку. По тайм-ауту нельзя определить неверный пароль или истечение аренды.')
    if scope == 'device_proxy':
        step('DNS устройства', 'info', 'Отдельный прокси проверен изолированно. DNS и реальный маршрут телефона этой проверкой не подтверждены.')
    else:
        try:
            dns = dns_probe()
        except Exception:
            dns = 'unknown'
        step('DNS на малине', 'pass' if dns == 'pass' else 'warn' if dns == 'unavailable' else 'unknown',
             'Локальный DNS ответил; ответ может быть из кеша. Внешний резолвер устройства не определялся.'
             if dns == 'pass' else 'Локальный клиентский DNS не подтвердил успешный ответ.')
        if dns != 'pass':
            return finish('warn' if dns == 'unavailable' else 'unknown', 'HTTPS работает, DNS требует проверки',
                          'Проверь DNS в Mimic → «Проверить малину». Отдельный DNS-тест с телефона нужен для проверки его фактического резолвера.')
    uncertain = any(s['status'] == 'unknown' for s in report['steps'])
    return finish('unknown' if uncertain else 'pass',
                  'Выход работает, часть проверок не завершена' if uncertain else 'В проверенной части сбой не обнаружен',
                  'Если сайт всё ещё не открывается, запусти проверки устройства во вкладке Mimic на самом телефоне или Mac. Проверь VPN, Private Relay и подключение к нужной Wi-Fi сети.')


def render(report=None):
    out = ['<div class="c"><h2>Почему нет интернета?</h2>',
           '<form method="post" action="/diagnostics/connection"><button class="g">Найти причину</button></form>',
           '<p class="hint">Проверка с малины: назначение прокси, Wi-Fi, туннель, правила, HTTPS и DNS. '
           'Не переключает прокси и не перезапускает службы. Может занять около минуты. '
           'HTTPS-запросы идут через прокси к api.ipify.org и ipinfo.io.</p>']
    if report:
        escape = lambda value: html.escape(str(value or '')[:700])
        stale = report.get('stale') is True
        out.append('<p class="%s"><b>%s</b></p>' % ('warn' if stale else 'ok' if report.get('status') == 'pass' else 'warn',
                   'Результат устарел — запусти проверку заново' if stale else escape(report.get('title'))))
        if not stale:
            out.append('<p>%s</p>' % escape(report.get('next')))
        out.append('<details><summary>Этапы проверки%s</summary><ul>' % (' — предыдущий снимок' if stale else ''))
        labels = {'pass': 'OK', 'warn': 'Внимание', 'unknown': 'Не подтверждено', 'info': 'Информация'}
        for step in report.get('steps', [])[:12]:
            out.append('<li><b>%s — %s.</b> %s</li>' % (escape(step.get('label')),
                       labels.get(step.get('status'), 'Не подтверждено'), escape(step.get('detail'))))
        out.append('</ul></details>')
    out.append('</div>')
    return ''.join(out)
