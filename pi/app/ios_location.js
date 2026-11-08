/* Authenticated pairing status only. No phone access or persistent PIN storage. */
(function () {
  'use strict';
  const card = document.getElementById('ios-pairing');
  if (!card || card.dataset.active !== '1') return;
  const node = id => document.getElementById('ios-pairing-' + id);
  const labels = {
    starting: 'Готовим сопряжение', waiting: 'Выбери GeoBox на iPhone',
    pin: 'Введи этот код на iPhone', paired: 'iPhone подключён',
    timeout: 'Время сопряжения истекло', cancelled: 'Сопряжение отменено',
    error: 'Не удалось завершить сопряжение', idle: 'Можно подключить iPhone',
    stopping: 'Закрываем окно сопряжения'
  };
  let stopped = false, reloaded = false, nextTimer = null, controller = null;
  const deadline = Date.now() + 300000;
  function stop() {
    stopped = true;
    clearTimeout(nextTimer);
    if (controller) controller.abort();
    node('pin').textContent = '';
  }
  function finishControls() {
    node('start-form').hidden = false;
    node('stop-form').hidden = true;
    node('stop').disabled = true;
    node('start').disabled = card.dataset.available !== '1' || card.dataset.busy === '1';
  }
  async function poll() {
    if (stopped) return;
    if (Date.now() >= deadline) {
      stop();
      node('status').textContent = 'Окно ожидания завершилось';
      node('message').textContent = 'Обнови страницу, чтобы узнать результат сопряжения.';
      node('time').textContent = '';
      return;
    }
    controller = new AbortController();
    const abortTimer = setTimeout(() => controller.abort(), 4000);
    try {
      const response = await fetch('/api/ios/pairing', {
        cache: 'no-store', credentials: 'same-origin', signal: controller.signal
      });
      if (stopped) return;
      if (response.status === 401) {
        stop();
        node('status').textContent = 'Сессия завершилась. Войди в панель заново.';
        node('message').textContent = '';
        node('time').textContent = '';
        node('start').disabled = true;
        node('stop').disabled = true;
        return;
      }
      if (!response.ok) throw new Error('unavailable');
      const value = await response.json();
      if (stopped) return;
      if (!value || !Object.prototype.hasOwnProperty.call(labels, value.state)) throw new Error('invalid state');
      const active = value.active === true && ['starting', 'waiting', 'pin', 'stopping'].includes(value.state);
      if (typeof value.owned === 'boolean') card.dataset.owned = value.owned ? '1' : '0';
      const owned = card.dataset.owned !== '0';
      node('stop').disabled = !active || !owned || value.state === 'stopping';
      node('status').textContent = labels[value.state];
      node('message').textContent = typeof value.message === 'string' ? value.message : '';
      node('pin').textContent = owned && active && value.state === 'pin' && typeof value.pin === 'string'
        && /^[0-9]{6}$/.test(value.pin) ? value.pin : '';
      const seconds = Number.isInteger(value.seconds_left) ? Math.max(0, Math.min(300, value.seconds_left)) : 0;
      node('time').textContent = active ? 'Осталось: ' + seconds + ' с' : '';
      if (!active) {
        stop();
        finishControls();
        if (value.state === 'paired' && !reloaded) {
          reloaded = true;
          window.location.reload();
        }
      }
    } catch (_) {
      if (!stopped) {
        node('pin').textContent = '';
        node('message').textContent = 'Ждём связь с панелью. Сопряжение может продолжаться на GeoBox.';
      }
    } finally {
      clearTimeout(abortTimer);
      controller = null;
      if (!stopped) nextTimer = setTimeout(poll, 1000);
    }
  }
  window.addEventListener('pagehide', stop);
  poll();
}());
