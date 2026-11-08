"""IPv6 policy: explicit opt-in, proof bound to the exact proxy, no direct fallback."""
import html
import ipaddress
import time

import ipv6_probe

LAN = 'fd77:6765:6f62:1::/64'
TUN = 'fd77:6765:6f62:2::1/126'
MAX_PROOF_AGE = 900


def evaluate(policy, proxy, devices, now=None):
    policy = policy if isinstance(policy, dict) else {}
    mode = policy.get('mode', 'block')
    result = {'mode': mode if mode in ('block', 'proxy') else 'block',
              'enabled': False, 'status': 'blocked', 'message': 'IPv6 заблокирован.'}
    if result['mode'] != 'proxy':
        return result
    if not isinstance(devices, dict) or any(not isinstance(d, dict) or d.get('mode') != 'default'
                                           for d in devices.values()):
        result.update(status='devices', message='IPv6 заблокирован: есть отдельные назначения или блокировки устройств. '
                      'В этой версии IPv6 через прокси доступен только когда все устройства используют общий прокси.')
        return result
    if not proxy or not isinstance(proxy.get('outbound'), dict):
        result.update(status='no_proxy', message='IPv6 заблокирован: общий прокси не задан.')
        return result
    proof = policy.get('proof')
    if not isinstance(proof, dict) or proof.get('fingerprint') != ipv6_probe.fingerprint(proxy['outbound']):
        result.update(status='unchecked', message='IPv6 заблокирован: этот прокси ещё не прошёл проверку IPv6.')
        return result
    if proof.get('status') != 'available':
        result.update(status='unknown', message='IPv6 заблокирован: выход через этот прокси не подтверждён. '
                      'IPv4 продолжает работать. Можно повторить проверку.')
        return result
    try:
        address = ipaddress.ip_address(proof.get('address', ''))
        age = (time.time() if now is None else now) - float(proof['checked_at'])
        if address.version != 6 or not address.is_global or not 0 <= age <= MAX_PROOF_AGE:
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        result.update(status='stale', message='Для включения IPv6 нужна свежая успешная проверка прокси.')
        return result
    result.update(enabled=True, status='available', address=str(address),
                  message='Проверка IPv6 через текущий прокси успешна.')
    return result


def card(policy, proxy, devices, config):
    value = evaluate(policy, proxy, devices)
    rules = config.get('route', {}).get('rules', []) if isinstance(config, dict) else []
    inbounds = config.get('inbounds', []) if isinstance(config, dict) else []
    installed = (any(i.get('type') == 'tun' and TUN in i.get('address', []) for i in inbounds)
                 and not any(r.get('ip_version') == 6 and r.get('action') == 'reject' for r in rules))
    # The proof ages; the installed route remains proxy-only until the next apply.
    status = ('IPv6 направлен через общий прокси. Доступность выхода может меняться.' if installed
              else value['message'])
    proof = policy.get('proof', {}) if isinstance(policy, dict) else {}
    checked = ''
    if isinstance(proof, dict) and isinstance(proof.get('checked_at'), (int, float)):
        age = max(0, int((time.time() - proof['checked_at']) / 60))
        checked = '<div class="hint">Последняя проверка: %d мин. назад. Это проверка с малины; тест с телефона — во вкладке Mimic.</div>' % age
        if value.get('address'):
            checked += '<p>Проверенный IPv6: %s</p>' % html.escape(value['address'])
    return ('<div class="c"><h2>IPv6</h2><p>%s</p><form method="post" action="/ipv6">'
            '<select name="mode"><option value="block"%s>IPv6 заблокирован</option>'
            '<option value="proxy"%s>IPv6 через прокси</option></select>'
            '<div class="f"><button>Применить и проверить</button></div></form>%s'
            '<div class="hint">При выборе режима через прокси сначала проверяется его IPv6-выход. '
            'Если ответа нет, IPv6 остаётся закрыт. При каждой смене общего прокси проверка повторяется. '
            'Прямой выход через провайдера запрещён в обоих режимах. '
            'IPv4 и IPv6 одного прокси могут иметь разную геолокацию. '
            'Пока доступны только общий прокси и TCP: при отдельных назначениях устройств IPv6 блокируется для всех.</div></div>') % (
                html.escape(status), ' selected' if value['mode'] == 'block' else '',
                ' selected' if value['mode'] == 'proxy' else '', checked)
