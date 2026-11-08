"""Durable proxy switch transaction. Call with the app's apply_lock held.

The pending file contains credentials and is always written mode 0600.
No remote code, shell input, or notification is executed by this module.
"""
import base64
import json
import os
import time


def sync_parent(path):
    if hasattr(os, 'O_DIRECTORY'):
        fd = os.open(os.path.dirname(path) or '.', os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def private_write(path, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    tmp = path + '.switch-tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(tmp, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    # Persist rename on Linux; Windows is supported for isolated unit tests.
    sync_parent(path)


def snapshot(path):
    try:
        with open(path, 'rb') as f:
            return base64.b64encode(f.read()).decode('ascii')
    except FileNotFoundError:
        return None


def restore(path, value):
    if value is None:
        try:
            os.unlink(path)
            sync_parent(path)
        except FileNotFoundError:
            pass
    else:
        private_write(path, base64.b64decode(value, validate=True))


class Switcher:
    def __init__(self, config_path, proxy_path, journal_path, apply, verify, restart, stop,
                 extra_paths=(), refresh=None):
        self.config_path = config_path
        self.proxy_path = proxy_path
        self.journal_path = journal_path
        self.apply = apply
        self.verify = verify
        self.restart = restart
        self.stop = stop
        self.extra_paths = tuple(extra_paths)
        self.refresh = refresh

    def _clear(self):
        try:
            os.unlink(self.journal_path)
            sync_parent(self.journal_path)
        except FileNotFoundError:
            pass

    def _blocked(self, message):
        try:
            stopped = self.stop()
        except Exception:
            stopped = False
        return {'ok': False, 'status': 'blocked' if stopped else 'attention',
                'message': message + (' Туннель остановлен; прямой выход закрыт фаерволом.' if stopped
                                     else ' Не удалось подтвердить остановку туннеля; нужна проверка служб.'),
                'exit': None, 'time': time.time()}

    def _rollback(self, saved, reason):
        try:
            restore(self.config_path, saved['config'])
            restore(self.proxy_path, saved['proxy'])
            for path, value in saved.get('extra', {}).items():
                if path not in self.extra_paths:
                    raise ValueError('unexpected recovery path')
                restore(path, value)
            if saved.get('extra') and self.refresh and not self.refresh():
                return self._blocked(reason + ' Не удалось восстановить адреса устройств.')
            if saved['config'] is None or not self.restart():
                return self._blocked(reason + ' Старые настройки восстановлены, но служба не запустилась.')
            # If old proxy is unavailable, keep its configuration and say so.
            old_exit = self.verify() if saved['proxy'] is not None else None
            self._clear()
            return {'ok': False, 'status': 'rolled_back', 'exit': old_exit, 'time': time.time(),
                    'message': reason + (' Вернул прежний прокси; его выход проверен.' if old_exit else
                                        ' Вернул прежние настройки. Выход не подтверждён; прямой обход запрещён.')}
        except Exception:
            return self._blocked(reason + ' Восстановление настроек не завершено.')

    def recover(self):
        if not os.path.exists(self.journal_path):
            return None
        try:
            with open(self.journal_path, encoding='utf-8') as f:
                saved = json.load(f)
            if saved.get('version') != 1 or not all(k in saved for k in ('config', 'proxy')):
                raise ValueError('invalid journal')
            for key in ('config', 'proxy'):
                if saved[key] is not None:
                    base64.b64decode(saved[key], validate=True)
            if not isinstance(saved.get('extra', {}), dict):
                raise ValueError('invalid extra snapshots')
            for path, value in saved.get('extra', {}).items():
                if path not in self.extra_paths:
                    raise ValueError('unexpected recovery path')
                if value is not None:
                    base64.b64decode(value, validate=True)
        except Exception:
            return self._blocked('Не удалось прочитать журнал незавершённого переключения.')
        return self._rollback(saved, 'Восстановление после прерванного переключения.')

    def switch(self, proxy, prepare=None, verify=True):
        if os.path.exists(self.journal_path):
            recovered = self.recover()
            if recovered and recovered['status'] in ('blocked', 'attention'):
                return recovered
        try:
            saved = {'version': 1, 'config': snapshot(self.config_path), 'proxy': snapshot(self.proxy_path),
                     'extra': {path: snapshot(path) for path in self.extra_paths} if prepare else {}}
            private_write(self.journal_path, json.dumps(saved))
        except Exception:
            return {'ok': False, 'status': 'unchanged', 'message': 'Не удалось сохранить точку отката. Настройки не менял.',
                    'exit': None, 'time': time.time()}
        try:
            if prepare:
                prepare()
            ok, apply_mode = self.apply(proxy)
            if not ok:
                return self._rollback(saved, 'Новый прокси не удалось применить.')
            actual_exit = self.verify() if proxy is not None and verify else None
            if proxy is not None and verify and not actual_exit:
                return self._rollback(saved, 'После переключения новый выход не ответил.')
            if proxy is None:
                restore(self.proxy_path, None)
            else:
                private_write(self.proxy_path, json.dumps(proxy, ensure_ascii=False))
            self._clear()
            return {'ok': True, 'status': 'committed', 'exit': actual_exit, 'time': time.time(),
                    'mode': apply_mode if apply_mode in ('selector', 'restart') else None,
                    'message': ('Настройки устройства применены.' if not verify else
                                ('Новый выход подтверждён. Движок не перезапускался.' if apply_mode == 'selector'
                                 else 'Новый выход подтверждён.') if proxy else 'Общий прокси выключен.')}
        except Exception:
            return self._rollback(saved, 'Переключение прервано из-за ошибки.')
