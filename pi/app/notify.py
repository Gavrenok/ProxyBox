"""GeoBox DIY: уведомления в Telegram.

Токен бота и chat id задаются в панели (вкладка «Настройки») и лежат в /etc/geobox/settings.json.
В коде их нет - прошивку можно спокойно выкладывать и раздавать.
"""
import json
import re
import threading
import urllib.error
import urllib.request

API = 'https://api.telegram.org/bot%s/%s'
TOKEN_RE = re.compile(r'^\d{5,15}:[A-Za-z0-9_-]{30,60}$')
CHAT_RE = re.compile(r'^-?\d{1,20}$|^@[A-Za-z0-9_]{5,32}$')


def _mask(text, token):
    return str(text).replace(token, '***') if token else str(text)


def _call(token, method, payload, timeout=10):
    """Запрос к Telegram API. Возвращает (ответ, ошибка). Токен в ошибках не показываем."""
    req = urllib.request.Request(API % (token, method), data=json.dumps(payload).encode('utf-8'),
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode('utf-8'))
            return (d, None) if d.get('ok') else (None, d.get('description', 'ошибка Telegram'))
    except urllib.error.HTTPError as e:
        try:
            d = json.loads(e.read().decode('utf-8'))
            return None, _mask(d.get('description') or 'HTTP %d' % e.code, token)
        except Exception:
            return None, 'HTTP %d' % e.code
    except Exception as e:
        return None, _mask(e, token)


def send(token, chat_id, text, timeout=10):
    if not token or not chat_id:
        return False, 'не заданы токен или chat id'
    d, err = _call(token, 'sendMessage', {'chat_id': chat_id, 'text': text[:4000],
                                          'disable_web_page_preview': True}, timeout)
    return (d is not None), (err or '')


def send_async(token, chat_id, text):
    """Отправка в фоне: панель и слежение не ждут Telegram."""
    t = threading.Thread(target=send, args=(token, chat_id, text), daemon=True)
    t.start()
    return t


def find_chats(token):
    """Чаты, которые недавно писали боту: [(id, название)]. Нужно, чтобы не искать chat id вручную."""
    d, err = _call(token, 'getUpdates', {'limit': 50, 'timeout': 0})
    if err:
        return [], err
    seen = {}
    for u in d.get('result', []):
        msg = u.get('message') or u.get('channel_post') or u.get('my_chat_member') or {}
        chat = msg.get('chat') or {}
        if 'id' in chat:
            title = chat.get('title') or chat.get('username') or ' '.join(
                x for x in (chat.get('first_name'), chat.get('last_name')) if x) or str(chat['id'])
            seen[str(chat['id'])] = title
    return list(seen.items()), None
