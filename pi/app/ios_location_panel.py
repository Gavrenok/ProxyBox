"""Render the optional iPhone location card; no device or network operations.

The caller supplies a sanitized snapshot and authenticates/queues POST actions.
Only public display fields and opaque device IDs are rendered, never the whole
snapshot, pairing records, coordinates or proxy configuration.
"""
import datetime
import html
import math
import re

PAIRING_LABELS = {
    'idle': 'Можно подключить iPhone', 'starting': 'Готовим сопряжение',
    'waiting': 'Выбери GeoBox на iPhone', 'pin': 'Введи этот код на iPhone',
    'paired': 'iPhone подключён', 'timeout': 'Время сопряжения истекло',
    'cancelled': 'Сопряжение отменено', 'error': 'Не удалось завершить сопряжение',
    'stopping': 'Закрываем окно сопряжения',
}


def _pairing(snapshot, available, busy):
    value = snapshot if isinstance(snapshot, dict) else {}
    available = available and value.get('available') is not False
    state = _text(value.get('state'))
    state = state if state in PAIRING_LABELS else 'idle'
    active = value.get('active') is True and state in ('starting', 'waiting', 'pin', 'stopping')
    owned = value.get('owned') is not False
    pin = _text(value.get('pin'))
    pin = pin if owned and active and state == 'pin' and re.fullmatch(r'[0-9]{6}', pin) else ''
    seconds = value.get('seconds_left', 0)
    seconds = max(0, min(300, seconds)) if type(seconds) is int else 0
    return (
        '<div id="ios-pairing" data-active="%s" data-available="%s" data-busy="%s" data-owned="%s">'
        '<h3>Подключить iPhone</h3>'
        '<p class="hint">На iOS 27 проверено подключение без USB. На iPhone включи '
        '«Настройки → Конфиденциальность и безопасность → Режим разработчика». '
        'Если телефон перезагрузится, подтверди включение режима после перезапуска.</p>'
        '<p class="hint">Подключи iPhone к Wi-Fi GeoBox и нажми «Подключить iPhone». '
        'В разделе «Режим разработчика» открой «Сопряжённые компьютеры», выбери GeoBox '
        'и введи появившийся здесь код. Окно сопряжения открывается максимум на 5 минут.</p>'
        '<p id="ios-pairing-status" role="status">%s</p>'
        '<p id="ios-pairing-message" class="hint">%s</p>'
        '<output id="ios-pairing-pin" aria-label="Код сопряжения" '
        'style="display:block;font-size:2rem;letter-spacing:.2em;font-variant-numeric:tabular-nums">%s</output>'
        '<p id="ios-pairing-time" class="hint">%s</p><div class="f">'
        '<form id="ios-pairing-start-form" class="i" method="post" action="/ios/pairing"%s>'
        '<input type="hidden" name="action" value="start">'
        '<button id="ios-pairing-start" type="submit"%s>Подключить iPhone</button></form>'
        '<form id="ios-pairing-stop-form" class="i" method="post" action="/ios/pairing"%s>'
        '<input type="hidden" name="action" value="stop">'
        '<button id="ios-pairing-stop" type="submit" class="g"%s>Отменить сопряжение</button></form>'
        '</div></div><script src="/ios_location.js" defer></script>'
    ) % ('1' if active else '0', '1' if available else '0', '1' if busy else '0', '1' if owned else '0',
         _escape(PAIRING_LABELS[state]), _escape(value.get('message')), _escape(pin),
         _escape('Осталось: %d с' % seconds if active else ''),
         ' hidden' if active else '', ' disabled' if active or busy or not available else '',
         '' if active else ' hidden', '' if active and owned and state != 'stopping' else ' disabled')


STATUS_LABELS = {
    'idle': 'Готов к настройке',
    'ready': 'Готов к настройке',
    'queued': 'Команда в очереди',
    'pending': 'Ожидает подключения',
    'syncing': 'Отправляем координаты',
    'running': 'Выполняем команду',
    'accepted': 'Команда координат принята',
    'applied': 'Команда координат принята',
    'cleared': 'Команда возврата принята',
    'pending_clear': 'Возврат ожидает подключения',
    'offline': 'iPhone недоступен',
    'error': 'Не удалось выполнить команду',
    'timeout': 'Ответ не получен — результат неизвестен',
    'needs_pairing': 'Нужно сопряжение с iPhone',
}


def _text(value):
    # Malformed nested values must not accidentally dump a private structure.
    return value if isinstance(value, str) else ''


def _escape(value):
    return html.escape(_text(value), quote=True)


def _updated(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ''
    try:
        if not math.isfinite(value) or value <= 0:
            return ''
        stamp = datetime.datetime.fromtimestamp(value, datetime.timezone.utc)
        return stamp.strftime('%d.%m.%Y %H:%M UTC')
    except (ValueError, OverflowError, OSError):
        return ''


def _form(device_id, action, label, disabled, secondary=False):
    return (
        '<form class="i" method="post" action="/ios/location">'
        '<input type="hidden" name="device_id" value="%s">'
        '<input type="hidden" name="action" value="%s">'
        '<button type="submit"%s%s>%s</button></form>'
        % (_escape(device_id), _escape(action), ' class="g"' if secondary else '',
           ' disabled' if disabled else '', _escape(label)))


def render(snapshot):
    """Return a card from the public snapshot; rendering never schedules work."""
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    available = snapshot.get('available') is True
    busy = snapshot.get('busy') is True
    pairing = snapshot.get('pairing')
    pairing_active = isinstance(pairing, dict) and pairing.get('active') is True
    devices = snapshot.get('devices')
    devices = [item for item in devices if isinstance(item, dict)] if isinstance(devices, list) else []
    parts = [
        '<section class="c" aria-labelledby="ios-location-title">'
        '<h2 id="ios-location-title">Геолокация iPhone</h2>'
        '<p class="hint">Дополнительная настройка для сопряжённого iPhone. '
        'Для него нужен режим разработчика и первоначальное сопряжение с GeoBox.</p>'
    ]
    setup_message = _text(snapshot.get('setup_message'))
    if setup_message:
        parts.append('<p class="hint">%s</p>' % _escape(setup_message))
    if not available:
        parts.append('<p class="warn" role="status">Управление геолокацией пока недоступно.</p>')
    if busy:
        parts.append('<p class="hint" role="status">Команда выполняется. Дождись результата и обнови страницу.</p>')
    parts.append(_pairing(pairing, available, busy))

    if not devices:
        parts.append(
            '<p>Сопряжённых iPhone пока нет.</p>')
    else:
        parts.append(
            '<p class="hint">GeoBox автоматически определяет Wi-Fi устройство для каждого iPhone '
            'и использует назначенный ему прокси. Если отдельного назначения нет — общий прокси.</p>')
        for device in devices:
            device_id = _text(device.get('id'))
            name = _text(device.get('name')) or 'iPhone'
            auto = device.get('auto') is True
            label = STATUS_LABELS.get(_text(device.get('status')), 'Состояние не определено')
            disabled = not available or not device_id
            parts.append('<div style="margin-top:18px"><h3>%s</h3>' % _escape(name))
            parts.append('<p role="status">%s</p>' % _escape(label))
            city = _text(device.get('city'))
            if city:
                parts.append('<p class="hint">Город последней команды: %s</p>' % _escape(city))
            message = _text(device.get('message'))
            if message:
                parts.append('<p class="hint">%s</p>' % _escape(message))
            updated = _updated(device.get('updated_at'))
            if updated:
                parts.append('<p class="hint">Обновлено: %s</p>' % _escape(updated))
            parts.append('<div class="f">')
            parts.append(_form(device_id, 'sync', 'По текущему прокси', disabled or busy or pairing_active))
            parts.append(_form(device_id, 'clear', 'Вернуть реальную', disabled, True))
            parts.append('</div><p class="hint">Автообновление при смене прокси: %s.</p>'
                         % ('включено' if auto else 'выключено'))
            parts.append('<div class="f">%s</div></div>' % _form(
                device_id, 'auto_off' if auto else 'auto_on',
                'Выключить автообновление' if auto else 'Включить автообновление',
                disabled or ((busy or pairing_active) and not auto), True))
        parts.append(
            '<p class="hint">Автообновление включается только по твоему выбору. '
            'Подтверждение команды не проверяет фактическую геолокацию: после изменения '
            'открой Карты или проверку геолокации на iPhone.</p>')
    parts.append('</section>')
    return ''.join(parts)
