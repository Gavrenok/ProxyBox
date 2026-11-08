/* Client-only observations. Outside requests require an explicit button click. */
(function () {
  'use strict';
  function normalizeIP(value) {
    if (typeof value !== 'string' || value.length > 45 || value.trim() !== value) return null;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return value.split('.').every(x => /^(0|[1-9]\d{0,2})$/.test(x) && Number(x) <= 255) ? value : null;
    if (!/^[0-9a-fA-F:.]+$/.test(value) || !value.includes(':')) return null;
    try { return new URL('http://[' + value + ']/').hostname.slice(1, -1).toLowerCase(); } catch (_) { return null; }
  }
  function ipVersion(value) { const ip = normalizeIP(value); return ip ? (ip.includes(':') ? 6 : 4) : 0; }
  function addressKind(value) {
    if (typeof value === 'string' && /^[a-z0-9-]+\.local$/i.test(value)) return 'mdns';
    const ip = normalizeIP(value); if (!ip) return 'hidden';
    if (ip.includes(':')) {
      if (ip.startsWith('::ffff:')) {
        const words = ip.slice(7).split(':');
        if (words.length === 2) {
          const hi = parseInt(words[0], 16), lo = parseInt(words[1], 16);
          return addressKind([hi >> 8, hi & 255, lo >> 8, lo & 255].join('.'));
        }
      }
      if (ip === '::' || ip === '::1' || /^(fc|fd|fe[89ab])/.test(ip)) return 'private';
      if (/^ff|^2001:db8:|^100:/.test(ip)) return 'special';
      return 'public';
    }
    const a = ip.split('.').map(Number);
    if (a[0] === 0 || a[0] === 10 || a[0] === 127 || (a[0] === 169 && a[1] === 254) ||
        (a[0] === 172 && a[1] >= 16 && a[1] <= 31) || (a[0] === 192 && a[1] === 168) ||
        (a[0] === 100 && a[1] >= 64 && a[1] <= 127)) return 'private';
    if (a[0] >= 224 || (a[0] === 192 && a[1] === 0 && (a[2] === 0 || a[2] === 2)) ||
        (a[0] === 198 && (a[1] === 18 || a[1] === 19 || (a[1] === 51 && a[2] === 100))) ||
        (a[0] === 203 && a[1] === 0 && a[2] === 113)) return 'special';
    return 'public';
  }
  function isLocalAddress(value) { return ['mdns', 'private'].includes(addressKind(value)); }
  function candidateInfo(candidate) {
    const parts = String(candidate.candidate || '').trim().split(/\s+/), typeAt = parts.indexOf('typ'), tcpAt = parts.indexOf('tcptype');
    const rawType = candidate.type || (typeAt >= 0 ? parts[typeAt + 1] : '');
    const type = ['host', 'srflx', 'prflx', 'relay'].includes(rawType) ? rawType : 'unknown';
    const raw = candidate.address || parts[4] || '';
    const address = normalizeIP(raw) || (/^[a-z0-9-]+\.local$/i.test(raw) ? raw.toLowerCase() : 'адрес скрыт');
    const protocol = String(candidate.protocol || parts[2] || '').toLowerCase(), tcp = candidate.tcpType || (tcpAt >= 0 ? parts[tcpAt + 1] : '');
    return {address, type, protocol: ['udp', 'tcp'].includes(protocol) ? protocol : 'unknown',
      tcpType: ['active', 'passive', 'so'].includes(tcp) ? tcp : '', addressKind: addressKind(address), local: isLocalAddress(address)};
  }
  function comparison(context, address) {
    if (!normalizeIP(address)) return {kind: 'warn', text: 'Нет корректного IP для сравнения.'};
    if (context.policy === 'blocked') return {kind: 'warn', text: 'Внешний запрос прошёл, хотя правило GeoBox блокирует этот адрес. Проверь VPN, мобильную сеть и маршрут устройства.'};
    if (context.scope !== 'wifi') return {kind: 'warn', text: 'Это выход браузера. Панель открыта вне клиентской Wi-Fi-сети GeoBox; сравнение с её профилем неприменимо.'};
    const previous = context.reference && normalizeIP(context.reference.ip);
    if (!previous) return {kind: 'k', text: 'IP получен. У профиля нет сохранённого результата для сравнения.'};
    if (ipVersion(previous) !== ipVersion(address)) return {kind: 'warn', text: 'Версии IP различаются: прямое сравнение с прошлым результатом невозможно.'};
    if (previous === normalizeIP(address)) return {kind: 'ok', text: 'Совпадает с последним IP профиля. Это не полная проверка отсутствия утечек.'};
    return {kind: 'warn', text: 'Отличается от последнего IP профиля (' + previous + '). Возможны ротация прокси, другой маршрут, VPN или Private Relay; требуется проверка.'};
  }
  function rtcAssessment(result, observed, context) {
    const entries = result.candidates || [];
    // TURN relay is not the client's direct source address.
    const visible = entries.filter(x => x.addressKind === 'public' && x.type !== 'relay');
    const mismatch = visible.some(x => observed[ipVersion(x.address)] && normalizeIP(x.address) !== observed[ipVersion(x.address)]);
    let text, kind = 'hint';
    if (result.status === 'cancelled') text = 'Проверка отменена. Частичные адреса не дают полного результата.';
    else if (result.status === 'unsupported') text = 'WebRTC недоступен в этом браузере или контексте. Проверка не выполнена.';
    else if (result.status === 'error') text = 'Проверка не завершилась: ограничение браузера или ошибка WebRTC.';
    else if (result.status === 'timeout') text = 'Истекло время ожидания STUN. Результат частичный; это не подтверждение отсутствия утечек.';
    else if (!visible.length) text = 'Внешний адрес клиента не получен. Возможны блокировка UDP, ограничения браузера или недоступность STUN. Это не подтверждение отсутствия утечек.';
    else text = 'Получены адреса WebRTC. Это проверка одного STUN-сервера, а не всех приложений.';
    if (visible.length && context.policy === 'blocked') { kind = 'warn'; text += ' Видимый внешний адрес требует проверки: для устройства настроена блокировка.'; }
    if (visible.length && mismatch) { kind = 'warn'; text += ' Адрес отличается от HTTPS-проверки: возможны другой маршрут или ротация IP между тестами.'; }
    else if (visible.length && visible.every(x => observed[ipVersion(x.address)])) text += ' Сравнимые адреса совпали с HTTPS-проверкой; это не доказывает отсутствие других утечек.';
    else if (visible.length) text += ' Для части адресов нет HTTPS-результата той же версии; сравнение не выполнено.';
    if (context.scope !== 'wifi') text += ' Панель открыта вне Wi-Fi GeoBox — его настройки не подтверждают этот маршрут.';
    if (entries.some(x => x.type === 'relay')) text += ' Relay — адрес TURN-сервера; он не сравнивается как прямой адрес клиента.';
    if (result.status !== 'complete' || !visible.length) kind = 'warn';
    return {text, kind};
  }
  function makeReport(context, results, zone, language) {
    const audit = context.router_audit, udp = context.udp_probe_result;
    // Never serialize raw context, profile, GPS, audit details or SDP.
    return {version: 1, generated_at: new Date().toISOString(), scope: context.scope === 'wifi' ? 'wifi' : 'outside',
      policy: ['default', 'device', 'blocked', 'unknown'].includes(context.policy) ? context.policy : 'unknown',
      timezone: String(zone).slice(0, 80), language: String(language).slice(0, 40),
      tests: ['ip4', 'ip6', 'rtc'].map(id => {
        const r = results[id] || {status: 'not_run'}, test = {id, status: r.status, checked_at: r.checked_at || null};
        if (normalizeIP(r.address)) test.address = normalizeIP(r.address);
        if (r.candidates) test.candidates = r.candidates.map(c => ({address: c.address, type: c.type, protocol: c.protocol, tcpType: c.tcpType, addressKind: c.addressKind}));
        return test;
      }), dns: 'not_tested_from_client',
      router_audit: audit ? {checked_at: audit.checked_at, stale: audit.stale === true, status: audit.status,
        checks: (audit.checks || []).map(c => ({id: c.id, status: c.status}))} : null,
      udp_probe: udp ? {checked_at: udp.checked_at, stale: udp.stale === true, status: udp.status, scope: udp.scope,
        code: ['command_rejected', 'unsupported_proxy'].includes(udp.code) ? udp.code : ''} : null,
      limits: ['Single browser and STUN endpoint only; timeouts do not prove no leaks.',
        'Rotating proxy, VPN, mobile network and Private Relay may change the observed route.',
        'Router audit is a past snapshot, not a client DNS or GPS test.']};
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = {normalizeIP, ipVersion, addressKind, isLocalAddress, candidateInfo, comparison, rtcAssessment, makeReport};
  if (typeof document === 'undefined') return;
  const root = document.getElementById('mimic'); if (!root) return;
  let context; try { context = JSON.parse(root.dataset.context); } catch (_) { return; }
  const el = id => document.getElementById('mimic-' + id), isoNow = () => new Date().toISOString();
  const results = {ip4: {status: 'not_run'}, ip6: {status: 'not_run'}, rtc: {status: 'not_run'}}, observed = {4: null, 6: null};
  let active = null, geoGeneration = 0, pageHidden = false;
  const routerForms = root.querySelectorAll ? Array.from(root.querySelectorAll('form[action^="/diagnostics"]')) : [];
  const routerButtons = routerForms.map(form => form.querySelector('button[type="submit"]')).filter(Boolean);
  const jobRunning = !!document.getElementById('panel-job');
  function show(id, text, kind) { const node = el(id); if (node) { node.textContent = text; node.className = kind || ''; } }
  function timeLabel(ts) { const date = new Date(Number(ts) * 1000); return ts && Number.isFinite(date.getTime()) ? date.toLocaleString() : 'время не сохранено'; }
  function stamp(r) { return r.checked_at ? new Date(r.checked_at).toLocaleTimeString() : ''; }
  function buttons(busy) {
    ['run-button', 'ip-button', 'rtc-button'].forEach(id => { if (el(id)) el(id).disabled = busy || jobRunning; });
    if (el('cancel-button')) el('cancel-button').disabled = !busy;
    if (el('copy-button')) el('copy-button').disabled = busy;
    routerButtons.forEach(b => { b.disabled = busy || jobRunning; });
  }
  show('reference-time', 'Последняя проверка профиля: ' + timeLabel(context.reference && context.reference.time), 'hint');
  show('router-time', 'Последняя проверка малины: ' + timeLabel(context.router_exit && context.router_exit.time), 'hint');
  if (context.router_audit) show('audit-time', 'Проверка на малине: ' + timeLabel(context.router_audit.checked_at) + '. Это сохранённый результат.', 'hint');
  if (context.udp_probe_result) show('udp-time', 'Проверка UDP: ' + timeLabel(context.udp_probe_result.checked_at) + '. Это сохранённый результат.', 'hint');
  let zone = 'не определён'; try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone || zone; } catch (_) { /* unavailable */ }
  const language = navigator.language || 'не определён';
  show('browser', 'Часовой пояс: ' + zone + ' · язык браузера: ' + language + '. Эти данные прочитаны локально.', 'hint');
  buttons(false);
  if (jobRunning) show('summary', 'Дождись завершения операции на малине, затем запусти проверку устройства.', 'warn');
  function summary() {
    const labels = {not_run: 'не проверено', running: 'проверяется', observed: 'ответ получен', complete: 'сбор завершён', unavailable: 'ответ не получен', timeout: 'время истекло', error: 'ошибка', unsupported: 'недоступно', cancelled: 'отменено'};
    const text = [['ip4', 'IPv4'], ['ip6', 'IPv6'], ['rtc', 'WebRTC']].map(([id, label]) => label + ': ' + labels[results[id].status] + (stamp(results[id]) ? ' (' + stamp(results[id]) + ')' : '')).join(' · ');
    show('summary', text + '. DNS с устройства не проверен. Общей оценки «утечек нет» эта проверка не даёт.', 'hint');
  }
  function renderIPs() {
    [4, 6].forEach(family => {
      const r = results['ip' + family];
      if (r.status === 'observed') show('ip' + family, 'IPv' + family + ': ' + r.address + ' · ' + stamp(r), family === 6 ? 'warn' : '');
      else if (r.status === 'running') show('ip' + family, 'IPv' + family + ': проверяем…', 'k');
      else if (r.status !== 'not_run') show('ip' + family, 'IPv' + family + ': ' + (r.status === 'cancelled' ? 'отменено' : r.status === 'timeout' ? 'истекло время ожидания' : 'ответ не получен') + ' · ' + stamp(r) + '. Отсутствие ответа не доказывает блокировку или отсутствие утечки.', 'warn');
    });
    show('compare', '', 'hint');
    if (observed[4]) { const c = comparison(context, observed[4]); show('compare', c.text, c.kind); }
    if (observed[6]) {
      const n = document.createElement('div'); n.className = 'warn';
      n.textContent = context.scope === 'wifi' ? 'IPv6-запрос прошёл. Политика GeoBox блокирует IPv6 клиентов: проверь маршрут, VPN/Private Relay и другие интерфейсы.' : 'IPv6 доступен через текущий маршрут браузера вне Wi-Fi GeoBox; это не проверка его firewall.';
      el('compare').appendChild(n);
    }
  }
  function renderRTC() {
    const r = results.rtc; if (r.status === 'not_run') { show('rtc', 'Не проверено'); return; }
    if (r.status === 'running') { show('rtc', 'Собираем адреса WebRTC…', 'k'); return; }
    const n = el('rtc'); n.textContent = ''; n.className = '';
    const kinds = {mdns: 'mDNS: локальный адрес скрыт', private: 'локальный/частный адрес', public: 'публичный адрес', special: 'специальный диапазон', hidden: 'адрес не раскрыт'};
    const types = {host: 'host: интерфейс устройства', srflx: 'srflx: адрес, отражённый STUN', prflx: 'prflx: адрес, полученный от пира', relay: 'relay: TURN-сервер', unknown: 'тип неизвестен'};
    const list = document.createElement('ul');
    (r.candidates || []).forEach(item => { const li = document.createElement('li'); li.textContent = item.address + ' · ' + types[item.type] + ' · ' + item.protocol.toUpperCase() + (item.tcpType ? '/' + item.tcpType : '') + ' · ' + kinds[item.addressKind]; list.appendChild(li); });
    if ((r.candidates || []).length) n.appendChild(list);
    const a = rtcAssessment(r, observed, context), note = document.createElement('div'); note.className = a.kind; note.textContent = a.text + ' · ' + stamp(r); n.appendChild(note);
  }
  async function queryIP(run, url, family) {
    const controller = new AbortController(); run.controllers.add(controller); let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, 10000);
    try {
      const response = await fetch(url, {cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: controller.signal});
      if (!response.ok) throw new Error('service');
      const data = await response.json(), address = normalizeIP(data && data.ip);
      if (!address || ipVersion(address) !== family || addressKind(address) !== 'public') throw new Error('invalid');
      return {status: 'observed', address, checked_at: isoNow()};
    } catch (_) { return {status: run.cancelled ? 'cancelled' : timedOut ? 'timeout' : 'unavailable', checked_at: isoNow()}; }
    finally { clearTimeout(timer); run.controllers.delete(controller); }
  }
  async function runIPs(run) {
    observed[4] = null; observed[6] = null; results.ip4 = {status: 'running'}; results.ip6 = {status: 'running'}; renderIPs(); summary();
    await Promise.all([4, 6].map(async family => {
      const r = await queryIP(run, family === 4 ? 'https://api.ipify.org?format=json' : 'https://api6.ipify.org?format=json', family);
      if (active !== run || run.cancelled) return;
      results['ip' + family] = r; observed[family] = r.address || null; renderIPs(); summary();
    }));
  }
  function runRTC(run) {
    if (typeof RTCPeerConnection === 'undefined') { results.rtc = {status: 'unsupported', checked_at: isoNow(), candidates: []}; renderRTC(); return Promise.resolve(); }
    results.rtc = {status: 'running', candidates: []}; renderRTC(); summary();
    return new Promise(resolve => {
      let pc = null, timer = null, done = false; const entries = [];
      function finish(status) {
        if (done) return; done = true; clearTimeout(timer);
        if (pc) { pc.onicecandidate = null; try { pc.close(); } catch (_) { /* already closed */ } }
        run.finishRTC = null;
        if (active === run && !pageHidden) { results.rtc = {status, checked_at: isoNow(), candidates: entries}; renderRTC(); summary(); }
        resolve();
      }
      run.finishRTC = () => finish('cancelled');
      try {
        pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
        pc.onicecandidate = event => {
          if (done || run.cancelled) return;
          if (!event.candidate) { finish('complete'); return; }
          const item = candidateInfo(event.candidate);
          if (entries.length < 128 && !entries.some(x => x.address === item.address && x.type === item.type && x.protocol === item.protocol && x.tcpType === item.tcpType)) entries.push(item);
        };
        pc.createDataChannel('diagnostics'); timer = setTimeout(() => finish('timeout'), 8000);
        Promise.resolve(pc.createOffer()).then(offer => { if (!done && !run.cancelled) return pc.setLocalDescription(offer); }).catch(() => finish('error'));
      } catch (_) { finish('error'); }
    });
  }
  async function start(mode) {
    if (active || jobRunning || pageHidden) return;
    const run = {cancelled: false, controllers: new Set(), finishRTC: null}; active = run; buttons(true); show('copy-status', '', 'hint');
    if (el('report')) { el('report').hidden = true; el('report').value = ''; }
    if (mode !== 'rtc') { results.rtc = {status: 'not_run'}; renderRTC(); }
    try { if (mode !== 'rtc') await runIPs(run); if (mode !== 'ip' && active === run && !run.cancelled) await runRTC(run); }
    finally { if (active === run) { active = null; buttons(false); summary(); } }
  }
  function cancel() {
    const run = active; if (!run) return; run.cancelled = true; run.controllers.forEach(c => c.abort());
    if (run.finishRTC) run.finishRTC();
    ['ip4', 'ip6', 'rtc'].forEach(id => { if (results[id].status === 'running') results[id] = {status: 'cancelled', checked_at: isoNow()}; });
    active = null; buttons(false); renderIPs(); renderRTC(); summary();
  }
  el('ip-button').addEventListener('click', () => start('ip'));
  el('rtc-button').addEventListener('click', () => start('rtc'));
  if (el('run-button')) el('run-button').addEventListener('click', () => start('all'));
  if (el('cancel-button')) el('cancel-button').addEventListener('click', cancel);
  routerForms.forEach(form => form.addEventListener('submit', event => { if (active) { event.preventDefault(); show('copy-status', 'Сначала дождись завершения или отмени проверку устройства.', 'warn'); } }));
  if (el('copy-button')) el('copy-button').addEventListener('click', async () => {
    const text = JSON.stringify(makeReport(context, results, zone, language), null, 2);
    try { if (!navigator.clipboard || !window.isSecureContext) throw new Error('unavailable'); await navigator.clipboard.writeText(text); show('copy-status', 'Отчёт скопирован. Он содержит IP-адреса.', 'hint'); }
    catch (_) { const area = el('report'); area.value = text; area.hidden = false; if (area.focus) area.focus(); if (area.select) area.select(); show('copy-status', 'Браузер не разрешил копирование. Отчёт выделен ниже — скопируй его вручную.', 'hint'); }
  });
  const geoButton = el('geo-button');
  if (!window.isSecureContext || !navigator.geolocation) { geoButton.disabled = true; show('geo', !window.isSecureContext ? 'Недоступно по HTTP: браузеру нужен защищённый HTTPS-контекст. Геолокация не проверена.' : 'API геолокации недоступен. Проверка не выполнена.', 'warn'); }
  geoButton.addEventListener('click', function () {
    const generation = ++geoGeneration; this.disabled = true; show('geo', 'Ожидаем разрешения и координаты…', 'k');
    navigator.geolocation.getCurrentPosition(position => {
      if (pageHidden || generation !== geoGeneration) return;
      const c = position.coords; show('geo', 'Широта ' + c.latitude.toFixed(5) + ', долгота ' + c.longitude.toFixed(5) + ' · точность примерно ' + Math.round(c.accuracy) + ' м · ' + new Date(position.timestamp).toLocaleTimeString(), ''); geoButton.disabled = false;
    }, error => { if (pageHidden || generation !== geoGeneration) return;
      const reasons = {1: 'Доступ не разрешён.', 2: 'Источник местоположения недоступен.', 3: 'Истекло время ожидания.'}; show('geo', (reasons[error.code] || 'Не удалось получить координаты.') + ' Геолокация не проверена.', 'warn'); geoButton.disabled = false;
    }, {enableHighAccuracy: false, timeout: 12000, maximumAge: 0});
  });
  window.addEventListener('pagehide', () => { cancel(); pageHidden = true; geoGeneration++; });
  window.addEventListener('pageshow', () => { pageHidden = false; buttons(false); if (window.isSecureContext && navigator.geolocation) geoButton.disabled = false; });
}());
