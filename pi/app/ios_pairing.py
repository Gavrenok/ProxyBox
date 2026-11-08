"""Bounded, session-owned pairing UI state. PINs only live in memory."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time

ACTIVE = {'starting', 'waiting', 'pin', 'stopping'}
MESSAGES = {
    'idle': 'Готово к подключению нового iPhone.',
    'starting': 'Запускаем сопряжение…',
    'waiting': 'На iPhone выбери GeoBox в разделе сопряжения режима разработчика.',
    'pin': 'Введи этот код в настройках iPhone.',
    'stopping': 'Закрываем окно сопряжения…',
    'paired': 'iPhone подключён. Теперь можно отправить координаты прокси.',
    'timeout': 'Время истекло. Можно начать подключение заново.',
    'cancelled': 'Подключение отменено.',
    'error': 'Не удалось завершить сопряжение. Можно повторить попытку.',
}


class PairingController:
    def __init__(self, *, on_paired=None, popen=subprocess.Popen,
                 available=None, clock=time.monotonic):
        self.on_paired = on_paired or (lambda: None)
        self.popen = popen
        self.clock = clock
        self.available = available or (lambda: Path('/opt/geobox/ios_pairing_worker.py').is_file()
                                      and Path('/opt/geobox-ios/venv/bin/python').is_file())
        self.lock = threading.RLock()
        self.owner = ''
        self.state = 'idle'
        self.pin = ''
        self.deadline = 0
        self.generation = 0
        self.process = None
        self.timer = None
        self.thread = None
        self.stop_reason = None

    @property
    def active(self):
        with self.lock:
            return self.state in ACTIVE

    def snapshot(self, owner=''):
        with self.lock:
            active = self.state in ACTIVE
            owned = bool(owner and owner == self.owner)
            return {'state': self.state, 'active': active,
                    'available': bool(self.available()), 'owned': owned,
                    'pin': self.pin if owned and self.state == 'pin' else '',
                    'seconds_left': max(0, int(self.deadline - self.clock())) if active else 0,
                    'message': ('Сопряжение запущено в другой сессии панели.'
                                if active and not owned else MESSAGES[self.state])}

    def start(self, owner):
        if not owner:
            return ('err', 'Для сопряжения войди в панель.')
        with self.lock:
            if self.state in ACTIVE:
                return ('warn', 'Сопряжение уже запущено.')
            if not self.available():
                return ('err', 'Компонент сопряжения не установлен.')
            self.owner, self.state, self.pin = owner, 'starting', ''
            self.stop_reason = None
            self.generation += 1
            generation = self.generation
            self.deadline = self.clock() + 300
            try:
                process = self.popen(['/opt/geobox-ios/venv/bin/python',
                                      '/opt/geobox/ios_pairing_worker.py', '--run'],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, bufsize=1,
                                     start_new_session=True,
                                     env=dict(os.environ, GEOBOX_IOS_HOME='/var/lib/geobox/ios',
                                              PYTHONNOUSERSITE='1'))
            except OSError:
                self.state = 'error'
                return ('err', MESSAGES['error'])
            self.process = process
            self.thread = threading.Thread(target=self._watch, args=(process, generation), daemon=True)
            self.thread.start()
            self.timer = threading.Timer(310, self._terminate, args=(generation, 'timeout'))
            self.timer.daemon = True
            self.timer.start()
        return ('ok', 'Окно сопряжения открывается на 5 минут. Подключи iPhone к Wi-Fi GeoBox.')

    def stop(self, owner):
        with self.lock:
            if self.state not in ACTIVE:
                return ('ok', 'Окно сопряжения уже закрыто.')
            if not owner or owner != self.owner:
                return ('err', 'Отмени подключение в той сессии панели, где оно было запущено.')
            generation = self.generation
            self.pin = ''
            self.state = 'stopping'
        threading.Thread(target=self._terminate, args=(generation, 'cancelled'), daemon=True).start()
        return ('ok', 'Сопряжение останавливается.')

    def _terminate(self, generation, reason):
        with self.lock:
            if generation != self.generation or self.state not in ACTIVE:
                return
            self.stop_reason = reason
            self.pin, self.state = '', 'stopping'
            process = self.process
        if process is None:
            return
        try:
            process.terminate()
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        except ProcessLookupError:
            pass

    def _event(self, event, generation):
        with self.lock:
            if generation != self.generation:
                return None
            kind = event.get('event')
            if kind in ('paired', 'timeout', 'cancelled', 'error'):
                self.pin = ''
                return kind
            if self.state == 'stopping':
                return None
            if kind == 'ready':
                self.state = 'waiting'
            elif kind == 'pin':
                pin = event.get('pin')
                if not isinstance(pin, str) or not re.fullmatch(r'[0-9]{6}', pin):
                    return 'error'
                self.pin, self.state = pin, 'pin'
            else:
                return 'error'
        return None

    def _watch(self, process, generation):
        terminal = None
        try:
            while True:
                line = process.stdout.readline(2049)
                if not line:
                    break
                if len(line) > 2048:
                    raise ValueError('invalid worker event')
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError('invalid worker event')
                result = self._event(event, generation)
                if result:
                    terminal = result
                    if result == 'error':
                        self._terminate(generation, 'error')
            returncode = process.wait(timeout=10)
        except Exception:
            terminal, returncode = 'error', -1
            self._terminate(generation, 'error')
        finally:
            if process.stdout:
                process.stdout.close()
        paired = terminal == 'paired' and returncode == 0
        with self.lock:
            if generation != self.generation:
                return
            if self.timer:
                self.timer.cancel()
            self.pin = ''
            self.process = None
            self.state = ('paired' if paired else self.stop_reason or
                          (terminal if terminal != 'paired' else 'error') or 'error')
        if paired:
            try:
                self.on_paired()
            except Exception:
                pass
