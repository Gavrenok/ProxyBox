/* Monitor only the authenticated session's operation; never send proxy secrets. */
(function () {
  'use strict';
  const card = document.getElementById('panel-job');
  if (!card) return;
  const message = document.getElementById('panel-job-message');
  const en = card.dataset.lang === 'en';
  let failures = 0;
  let stopped = false;
  async function poll() {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    try {
      const response = await fetch('/api/job?id=' + encodeURIComponent(card.dataset.job),
        {cache: 'no-store', credentials: 'same-origin', signal: controller.signal});
      if (response.status === 401) {
        message.textContent = en ? 'Session expired. Refresh and sign in again.' : 'Сессия завершилась. Обнови страницу и войди заново.';
        stopped = true; return;
      }
      if (response.status === 404) { window.location.reload(); return; }
      if (!response.ok) throw new Error('unavailable');
      const job = await response.json();
      if (job.status !== 'running') { stopped = true; window.location.reload(); return; }
      message.textContent = en ? 'Working for ' + job.seconds + ' s. You can use other tabs.' : 'Выполняется ' + job.seconds + ' с. Можно переходить между вкладками.';
      failures = 0;
    } catch (_) {
      failures += 1;
      message.textContent = en ? 'Waiting for the panel. The operation continues on the Pi.' : 'Ждём связь с панелью. Операция продолжает выполняться на малине.';
    } finally {
      clearTimeout(timer);
      if (!stopped) setTimeout(poll, failures ? 2500 : 600);
    }
  }
  window.addEventListener('pagehide', () => { stopped = true; });
  poll();
}());
