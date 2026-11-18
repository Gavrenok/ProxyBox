"""Bilingual setup wizard for an installed, authenticated panel."""
import html

import proxy_checks
import i18n


def language(value):
    return 'ru' if value == 'ru' else 'en'


def render(lang, step, wifi, current, item=None, flash=None, job=None, exit_ok=False):
    lang = language(lang)
    en = lang == 'en'
    def tr(ru, english):
        return english if en else ru
    def esc(value):
        return html.escape(str(value or ''), quote=True)
    def form(op, body, button):
        return ('<form class="setup" method="post" action="/setup"><input type="hidden" name="op" value="%s">'
                '<input type="hidden" name="lang" value="%s">%s<div class="f"><button>%s</button></div></form>'
                % (op, lang, body, button))
    def link(n, text):
        return '<a class="btn" href="/setup?lang=%s&amp;step=%d">%s</a>' % (lang, n, text)
    step = max(1, min(4, step))
    out = ['<h1>ProxyBox</h1><div class="f"><a href="/setup?lang=ru&amp;step=%d">Русский</a>'
           '<a href="/setup?lang=en&amp;step=%d">English</a></div>' % (step, step),
           '<p>%s</p>' % tr('Мастер настройки установленной панели. Пароль панели уже задан при установке.',
                             'Setup for an installed panel. Your panel password was created during installation.')]
    names = [tr('Wi-Fi', 'Wi-Fi'), tr('Прокси', 'Proxy'), tr('Проверка', 'Check'), tr('Готово', 'Finish')]
    out.append('<nav class="tabs" aria-label="Setup steps">' + ''.join(
        '<a class="%s" href="/setup?lang=%s&amp;step=%d">%d. %s</a>' %
        ('on' if n == step else '', lang, n, n, name) for n, name in enumerate(names, 1)) + '</nav>')
    if job and job.get('status') == 'running':
        out.append('<div class="c" id="panel-job" data-job="%s" data-lang="%s">'
                   '<b>%s</b><p id="panel-job-message">%s</p></div><script src="/panel.js" defer></script>' %
                   (esc(job['id']), lang, tr('Выполняется', 'Working'),
                    tr('Дождись завершения операции.', 'Wait for the operation to finish.')))
    if flash:
        level, message = flash
        message = i18n.text(message, lang)
        out.append('<div class="msg %s" role="status">%s</div>' %
                   ('ok' if level == 'ok' else 'warn', esc(message)))
    out.append('<div class="c"><h2>%d. %s</h2>' % (step, names[step-1]))
    if step == 1:
        out.append('<p>%s</p>' % tr('Роутер → Ethernet малины. Телефон → Wi-Fi малины. '
            'При смене Wi-Fi соединение прервётся: подключись к новой сети и вернись на 10.77.0.1/setup.',
            'Router → Pi Ethernet. Phone → Pi Wi-Fi. Changing Wi-Fi disconnects clients: '
            'join the new network and return to 10.77.0.1/setup.'))
        if wifi:
            fields = ('<label>%s<input type="text" name="ssid" required maxlength="32" value="%s"></label>'
                      '<label>%s<input type="password" name="pw" autocomplete="new-password" minlength="8" maxlength="63"></label>'
                      '<label>%s<input type="password" name="pw2" autocomplete="new-password" minlength="8" maxlength="63"></label>'
                      '<label>%s<select name="band"><option value="a"%s>5 GHz</option>'
                      '<option value="bg"%s>2.4 GHz</option></select></label>') % (
                tr('Имя сети', 'Network name'), esc(wifi.get('ssid')),
                tr('Новый пароль (пусто — оставить прежний)', 'New password (blank keeps existing)'),
                tr('Повтори пароль', 'Repeat password'), tr('Диапазон', 'Band'),
                ' selected' if wifi.get('band') == 'a' else '', ' selected' if wifi.get('band') == 'bg' else '')
            out.append(form('wifi', fields, tr('Сохранить и перезапустить Wi-Fi', 'Save and restart Wi-Fi')))
        else:
            out.append('<p>%s</p>' % tr('Настройки Wi-Fi пока недоступны. Проверь установку.',
                                       'Wi-Fi settings are unavailable. Check installation.'))
        out.append(link(2, tr('Оставить текущий Wi-Fi →', 'Keep current Wi-Fi →')))
    elif step == 2:
        out.append('<p>%s</p>' % tr('Вставь один прокси. Кнопка проверит его и применит как общий маршрут. '
            'Индивидуальные назначения устройств сохраняются.',
            'Paste one proxy. The button checks it and applies it as the default route. '
            'Individual device assignments remain in effect.'))
        out.append(form('proxy', '<label>%s<textarea name="proxy" required autocomplete="off" '
            'autocapitalize="off" spellcheck="false" placeholder="socks5://user:password@host:1080"></textarea></label>' %
            tr('Прокси или ссылка подключения', 'Proxy or connection URL'),
            tr('Проверить и применить', 'Check and apply')))
        if current:
            out.append(link(3, tr('Использовать текущий прокси →', 'Use current proxy →')))
    elif step == 3:
        out.append('<p>%s</p>' % tr('Проверка с малины отправляет запросы через текущий прокси к внешним '
            'IP/HTTPS-сервисам и Google STUN. Может занять около минуты. Она не меняет маршрутизацию.',
            'Checks from the Pi contact external IP/HTTPS services and Google STUN through the current proxy. '
            'Allow about a minute. Routing is not changed.'))
        if item:
            out.append(proxy_checks.render(item, lang, expanded=True))
            out.append(form('check', '', tr('Проверить возможности', 'Check capabilities')))
        else:
            out.append(link(2, tr('Сначала добавь прокси', 'Add a proxy first')))
        out.append(link(4, tr('Перейти к результату →', 'Continue to result →')))
    else:
        out.append('<p>%s</p>' % (tr('Выход через общий прокси недавно подтверждён.',
            'The default proxy exit was confirmed recently.') if exit_ok else
            tr('Выход пока не подтверждён. Проверь прокси перед использованием.',
               'The exit is not confirmed yet. Check the proxy before use.')))
        out.append('<p>%s</p>' % tr('На телефоне открой обычный сайт, затем Mimic в панели для проверок самого браузера. '
            'Геолокация iPhone настраивается отдельно: нужен режим разработчика и сопряжение.',
            'Open a website on your phone, then use Mimic in the panel to test the browser itself. '
            'iPhone location is optional and requires Developer Mode and pairing.'))
    out.append('</div><p><a href="/">%s</a></p>' % tr('Открыть основную панель', 'Open main panel'))
    return ''.join(out)
