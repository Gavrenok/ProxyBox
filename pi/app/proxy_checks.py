"""Explicit capability snapshots: no activation, no policy changes, no secrets."""
import html
import time


def measure(proxy, exit_probe, udp_probe, ipv6_probe):
    started = time.time()
    info, _ = exit_probe(proxy['outbound'], proxy.get('secrets'))
    udp = udp_probe(proxy)
    ipv6 = ipv6_probe(proxy['outbound'])
    return {'time': started, 'https': 'pass' if info else 'unknown',
            'udp': 'pass' if udp.get('code') == 'supported' else
                   'unsupported' if udp.get('code') == 'command_rejected' else
                   'not_tested' if udp.get('code') == 'unsupported_proxy' else 'unknown',
            'ipv6': 'pass' if ipv6.get('status') == 'available' else 'unknown',
            'dns': 'not_tested'}


def render(item, lang='ru', expanded=False):
    en = lang == 'en'
    labels = {'pass': 'Confirmed' if en else 'Подтверждено',
              'unknown': 'Inconclusive' if en else 'Не установлено',
              'unsupported': 'Rejected by proxy' if en else 'Прокси отклонил',
              'not_tested': 'Not tested' if en else 'Не проверено'}
    report = item.get('capabilities') or {}
    if not isinstance(report, dict):
        report = {}
    rows = []
    for key, title in [('https', 'HTTPS'), ('udp', 'SOCKS5 UDP'), ('ipv6', 'IPv6 HTTPS'),
                       ('dns', 'Client DNS' if en else 'DNS устройства')]:
        status = report.get(key, 'not_tested')
        status = status if isinstance(status, str) else 'unknown'
        rows.append('<div class="row"><span>%s</span><span class="%s">%s</span></div>' %
                    (title, 'ok' if status == 'pass' else 'k', labels.get(status, labels['unknown'])))
    if report.get('time'):
        try:
            stamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(float(report['time'])))
        except (ValueError, TypeError, OverflowError, OSError):
            stamp = 'Unknown check time' if en else 'Время проверки неизвестно'
        rows.append('<p class="hint">%s</p>' % html.escape(stamp))
    rows.append('<p class="hint">%s</p>' % (
        'A snapshot from the Pi, not a browser leak test. DNS needs a separate client test. '
        'Timeouts do not prove missing support. These checks do not enable UDP or IPv6.' if en else
        'Разовый замер с малины, не тест утечек браузера. DNS нужно проверять отдельно с устройства. '
        'Таймаут не доказывает отсутствие поддержки. Проверка не включает UDP или IPv6.'))
    return '<details%s><summary>%s</summary>%s</details>' % (
        ' open' if expanded else '', 'Proxy capabilities' if en else 'Возможности прокси', ''.join(rows))
