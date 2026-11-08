"""Optional paired-iPhone location jobs. HTTP rendering never contacts a phone."""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

FILES = ('proxy.json', 'devices.json', 'library.json', 'ios-location.json')


def guards(etc, names=FILES):
    result = {}
    for name in names:
        try:
            result[name] = hashlib.sha256((Path(etc) / name).read_bytes()).hexdigest()
        except FileNotFoundError:
            result[name] = 'missing'
    return result


def routing_key(etc):
    """Ignore health checks/traffic/name edits; react to actual routing choices."""
    def load(name, default):
        try:
            return json.loads((Path(etc) / name).read_text())
        except (OSError, ValueError):
            return default
    proxy = load('proxy.json', {}) or {}
    devices = load('devices.json', {}) or {}
    library = load('library.json', {}) or {}
    intent = load('ios-location.json', {}) or {}
    value = {'proxy': proxy.get('outbound'), 'intent': intent,
             'devices': {key: {k: item.get(k) for k in ('ip', 'mode', 'item')}
                         for key, item in devices.items()},
             'library': {item.get('id'): item.get('outbound') for item in library.get('items', [])}}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def call_bridge(request):
    executable = os.environ.get('GEOBOX_IOS_PYTHON', '/opt/geobox-ios/venv/bin/python')
    helper = os.environ.get('GEOBOX_IOS_BRIDGE', '/opt/geobox/ios_device_bridge.py')
    env = dict(os.environ, GEOBOX_IOS_HOME='/var/lib/geobox/ios')
    process = subprocess.Popen([executable, helper], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, env=env, start_new_session=True)
    try:
        out, _ = process.communicate(json.dumps(request), timeout=180)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        return {'ok': False, 'status': 'unknown', 'outcome': 'unknown'}
    try:
        value = json.loads(out)
        return value if isinstance(value, dict) else {'ok': False, 'status': 'error'}
    except ValueError:
        return {'ok': False, 'status': 'unknown', 'outcome': 'unknown'}


class Controller:
    def __init__(self, etc, resolve_geo, *, bridge=call_bridge, available=None, pause_when=None):
        self.etc = Path(etc)
        self.path = self.etc / 'ios-location.json'
        self.resolve_geo = resolve_geo
        self.bridge = bridge
        self.available = available or (lambda: Path('/opt/geobox-ios/venv/bin/python').is_file()
                                      and Path('/opt/geobox/ios_device_bridge.py').is_file())
        self.pause_when = pause_when or (lambda: False)
        self.lock = threading.RLock()
        self.operation = threading.Lock()
        self.wake = threading.Event()
        self.stopped = threading.Event()
        self.devices = []
        self.results = {}
        self.attempts = {}
        self.next_try = {}
        self.thread = None

    def _config(self):
        try:
            value = json.loads(self.path.read_text())
            return value if isinstance(value, dict) and isinstance(value.get('devices'), dict) else {'devices': {}}
        except (OSError, ValueError):
            return {'devices': {}}

    def _save(self, config):
        self.etc.mkdir(parents=True, exist_ok=True)
        # Distinguish even two identical explicit clear/toggle requests.
        config['revision'] = time.time_ns()
        temp = self.path.with_suffix('.tmp')
        descriptor = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        os.chmod(temp, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(config, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, self.path)

    def refresh_devices(self):
        if not self.available():
            return
        response = self.bridge({'action': 'devices'})
        if isinstance(response.get('devices'), list):
            clean = []
            for item in response['devices']:
                if isinstance(item, dict) and isinstance(item.get('id'), str):
                    clean.append({'id': item['id'], 'name': str(item.get('name') or 'iPhone')[:100]})
            with self.lock:
                self.devices = clean

    def snapshot(self):
        with self.lock:
            config = self._config()['devices']
            devices = []
            for device in self.devices:
                item = dict(device, auto=config.get(device['id'], {}).get('auto') is True)
                item.update(copy.deepcopy(self.results.get(device['id'], {})))
                devices.append(item)
            return {'available': bool(self.available()), 'devices': devices,
                    'busy': self.operation.locked(),
                    'setup_message': 'При включённом автообновлении меняем координаты при смене профиля прокси. '
                                     'Точность зависит от базы геолокации IP; GPS-проверка выполняется на телефоне.'}

    def _result(self, device_id, status, message, city=''):
        with self.lock:
            self.results[device_id] = {'status': status, 'message': message,
                                       'city': city, 'updated_at': time.time()}

    def action(self, action, device_id):
        if action not in ('sync', 'clear', 'auto_on', 'auto_off'):
            return ('err', 'Неизвестная команда геолокации.')
        with self.lock:
            if device_id not in {d['id'] for d in self.devices}:
                return ('err', 'Сначала сопряги этот iPhone с GeoBox.')
            if not self.available():
                return ('err', 'Компонент управления iPhone не установлен.')
            config = self._config()
            entry = config['devices'].setdefault(device_id, {})
            if action in ('auto_on', 'auto_off', 'clear'):
                entry['auto'] = action == 'auto_on'
                if action == 'clear':
                    entry['pending_clear'] = True
                elif action == 'auto_on':
                    entry['pending_clear'] = False
                self._save(config)
            if action == 'sync' and entry.get('pending_clear'):
                return ('err', 'Сначала дождись возврата реальной геолокации.')
            self.attempts.pop(device_id, None)
            self.next_try.pop(device_id, None)
        self.wake.set()
        if action == 'auto_on':
            return ('ok', 'Автообновление включено. iPhone должен быть в Wi-Fi GeoBox.')
        if action == 'auto_off':
            return ('ok', 'Автообновление выключено. Последняя координата сохранится; для сброса нажми «Вернуть реальную».')
        if action == 'clear':
            self._result(device_id, 'pending_clear', 'Возврат поставлен в очередь; автообновление выключено.')
            return ('ok', 'Возврат реальной геолокации поставлен в очередь. Если iPhone недоступен, дождёмся подключения.')
        return self._perform(device_id, 'set')

    def _perform(self, device_id, action, expected_intent=None):
        if self.pause_when():
            return ('warn', 'Дождись завершения сопряжения iPhone.')
        if not self.operation.acquire(blocking=False):
            if action == 'clear':
                self._result(device_id, 'pending_clear', 'Возврат поставлен в очередь; автообновление выключено.')
                return ('warn', 'Возврат поставлен в очередь.')
            return ('warn', 'Уже выполняется команда iPhone. Повтори после её завершения.')
        mutation_attempted = False
        intent = None
        try:
            self._result(device_id, 'running', 'Подключаемся к сопряжённому iPhone…')
            # Capture the user's intent before potentially slow connection/image work.
            with self.lock:
                intent = expected_intent or guards(self.etc, ('ios-location.json',))
                if guards(self.etc, ('ios-location.json',)) != intent:
                    return ('warn', 'Команда отменена: настройки изменились.')
            identified = self.bridge({'action': 'identify', 'device_id': device_id})
            if not identified.get('ok'):
                return self._failed(device_id, action, identified, intent)
            address = identified.get('device_ipv4')
            try:
                in_wifi = ipaddress.ip_address(address) in ipaddress.ip_network('10.77.0.0/24')
            except (ValueError, TypeError):
                in_wifi = False
            if not in_wifi:
                self._result(device_id, 'offline', 'Подключи iPhone к Wi-Fi GeoBox.')
                return ('warn', 'Подключи iPhone к Wi-Fi GeoBox.')
            request = {'action': action, 'device_id': device_id,
                       'guard': dict(guards(self.etc), **intent), 'expected_ipv4': address}
            city = ''
            if action == 'set':
                geo = self.resolve_geo(address)
                if not geo or not geo.get('ok'):
                    message = (geo or {}).get('message', 'Не удалось определить геолокацию прокси.')
                    self._result(device_id, 'error', message)
                    return ('err', message)
                request.update(latitude=geo['latitude'], longitude=geo['longitude'])
                request['guard'] = dict(geo['guards'], **intent)
                city = geo.get('city', '')
            mutation_attempted = True
            result = self.bridge(request)
            if not result.get('ok'):
                return self._failed(device_id, action, result, intent)
            if action == 'clear':
                with self.lock:
                    if guards(self.etc, ('ios-location.json',)) == intent:
                        config = self._config()
                        entry = config['devices'].setdefault(device_id, {})
                        entry['pending_clear'] = False
                        self._save(config)
                message = 'iPhone принял команду возврата реальной геолокации. Проверь Карты.'
                with self.lock:
                    if not self._config()['devices'].get(device_id, {}).get('pending_clear'):
                        self._result(device_id, 'cleared', message)
            else:
                message = 'iPhone принял координаты прокси. Проверь Карты или BrowserLeaks.'
                with self.lock:
                    if guards(self.etc, ('ios-location.json',)) == intent:
                        self._result(device_id, 'accepted', message, city)
            return ('ok', message)
        except Exception:
            if mutation_attempted:
                return self._failed(device_id, action, {'outcome': 'unknown'}, intent)
            self._result(device_id, 'error', 'Не удалось выполнить команду. Настройки прокси не менялись.')
            return ('err', 'Не удалось выполнить команду iPhone.')
        finally:
            self.operation.release()

    def _failed(self, device_id, action, result, expected_intent):
        unknown = result.get('outcome') == 'unknown' or result.get('status') == 'unknown'
        stale = result.get('status') == 'stale_request' or result.get('error') == 'stale_request'
        if unknown:
            message = 'Ответ не получен: результат неизвестен. Проверь телефон; автоматический повтор остановлен.'
            # Persist uncertainty so a panel restart does not silently retry an action.
            with self.lock:
                if guards(self.etc, ('ios-location.json',)) == expected_intent:
                    config = self._config()
                    entry = config['devices'].setdefault(device_id, {})
                    entry.update(auto=False, pending_clear=False)
                    self._save(config)
                    self._result(device_id, 'timeout', message)
        elif stale:
            message = 'Настройки изменились во время подключения. Устаревшая команда отменена.'
            self._result(device_id, 'error', message)
        else:
            message = 'iPhone недоступен или не готов. Подключи его к Wi-Fi GeoBox и разблокируй.'
            self._result(device_id, 'pending_clear' if action == 'clear' else 'offline', message)
        return ('warn', message)

    def tick(self):
        if self.pause_when():
            return
        with self.lock:
            config = self._config()['devices']
            ids = [d['id'] for d in self.devices]
            intent = guards(self.etc, ('ios-location.json',))
        for device_id in ids:
            entry = config.get(device_id, {})
            if not entry.get('pending_clear') and entry.get('auto') is not True:
                continue
            fingerprint = routing_key(self.etc)
            if time.monotonic() < self.next_try.get(device_id, 0):
                continue
            if not entry.get('pending_clear') and self.attempts.get(device_id) == fingerprint:
                continue
            self.attempts[device_id] = fingerprint
            outcome = self._perform(device_id, 'clear' if entry.get('pending_clear') else 'set', intent)
            if outcome[0] != 'ok':
                # Reconnect retry only while user intent remains enabled; unknown disables it.
                self.attempts.pop(device_id, None)
                self.next_try[device_id] = time.monotonic() + 120

    def start(self):
        if self.thread is not None:
            return
        def work():
            refreshed = 0
            while not self.stopped.is_set():
                try:
                    if time.monotonic() - refreshed > 60:
                        self.refresh_devices()
                        refreshed = time.monotonic()
                    self.tick()
                except Exception:
                    pass
                self.wake.wait(10)
                self.wake.clear()
        self.thread = threading.Thread(target=work, daemon=True, name='iphone-location')
        self.thread.start()
