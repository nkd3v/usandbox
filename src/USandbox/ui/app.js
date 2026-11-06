'use strict';

const host = window.chrome && window.chrome.webview;
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const state = {
  flows: new Map(),
  order: [],
  logs: [],
  session: null,
  rules: { rules: [] },
  rulesText: '',
  selected: null,
  detail: null,
  detailTab: 'req',
  outcome: '',
  query: '',
  endpointQuery: '',
  tab: 'traffic',
};

function send(message) {
  if (host) host.postMessage(message);
  else mock.handle(message);
}

// ---- formatting ------------------------------------------------------------

function bytes(n) {
  if (!n) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
function time(t) {
  const d = new Date(t);
  return d.toLocaleTimeString([], { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}
function splitUrl(f) {
  if (!f.url) return { path: f.kind === 'direct' || f.kind === 'listen' ? '' : '', origin: '' };
  try {
    const u = new URL(f.url.includes('://') ? f.url : `tcp://${f.url}`);
    return { path: u.pathname + u.search, origin: u.origin };
  } catch { return { path: f.url, origin: '' }; }
}
const kindLabel = { http: 'HTTP', https: 'HTTPS', tunnel: 'Tunnel', websocket: 'WebSocket', direct: 'Direct', listen: 'Listen' };
const outcomeLabel = { allowed: 'allowed', blocked: 'blocked', error: 'error', passthrough: 'not decrypted', pending: '…' };

// ---- messages from the host ----------------------------------------------------

function onMessage(msg) {
  switch (msg.type) {
    case 'init':
      fillLauncher(msg.defaults);
      setRules(msg.rules);
      $('rulesPath').textContent = msg.rulesPath ? `Saved to ${msg.rulesPath}` : '';
      break;
    case 'batch':
      for (const f of msg.flows) {
        if (!state.flows.has(f.id)) state.order.push(f.id);
        state.flows.set(f.id, f);
        if (state.selected === f.id && state.detail) state.detail.flow = f;
      }
      if (state.order.length > 20000) {
        for (const id of state.order.splice(0, state.order.length - 20000)) state.flows.delete(id);
      }
      for (const l of msg.logs) addLog(l);
      schedule();
      break;
    case 'session':
      state.session = msg.session;
      renderSession();
      break;
    case 'browsed':
      $('fProgram').value = msg.path;
      break;
    case 'detail':
      if (msg.flow.id === state.selected) { state.detail = msg; renderDetail(); }
      break;
    case 'rules':
      setRules(msg.rules);
      if (msg.saved) { ruleMsg('Saved. New connections use these rules.', 'ok'); }
      break;
    case 'rulesError':
      ruleMsg(msg.message, 'err');
      toast(msg.message, true);
      break;
    case 'error':
      toast(msg.message, true);
      addLog({ time: new Date().toISOString(), level: 'error', text: msg.message });
      break;
  }
}

// ---- session header & launcher --------------------------------------------------

function fillLauncher(d) {
  if (!d) return;
  $('fProgram').value = d.program || '';
  $('fArgs').value = d.arguments || '';
  $('fCwd').value = d.workingDirectory || '';
  $('fStage').value = d.stage || 'none';
  $('fNetwork').value = d.network || 'filter';
  $('fTls').checked = d.inspectTls !== false;
  $('fAuto').checked = d.autoPassthrough !== false;
  updateNetworkHelp();
}

const networkHelp = {
  filter: 'Programs that ignore the proxy settings cannot connect; their attempts are listed as blocked.',
  open: 'Programs that ignore the proxy settings can connect directly; their connections are listed, but rules cannot see inside them.',
  off: 'The same as running without usandbox\u2019s network features. Direct TCP connections are still listed.',
  none: 'Everything except loopback is blocked. Attempts are listed.',
};
function updateNetworkHelp() {
  const n = $('fNetwork').value;
  $('networkHelp').textContent = networkHelp[n];
  const proxied = n === 'filter' || n === 'open';
  $('fTls').disabled = $('fAuto').disabled = !proxied;
  $('tlsNote').hidden = !proxied || !$('fTls').checked;
}

function renderSession() {
  const s = state.session;
  const pill = $('state');
  const st = s ? s.state : 'idle';
  pill.textContent = st;
  pill.className = 'pill ' + st.split(' ')[0];
  const running = s && s.state !== 'finished';
  $('stopBtn').hidden = !running;
  $('newBtn').hidden = !s || running;
  $('launcher').hidden = !!s;
  $('tabs').hidden = !s;
  document.querySelector('main').hidden = !s;
  if (!s) { $('prog').textContent = 'No program running'; $('meta').textContent = ''; return; }
  const name = s.program.split('\\').pop();
  $('prog').textContent = name + (s.arguments ? ' ' + s.arguments : '');
  $('prog').title = s.program;
  const bits = [];
  if (s.user) bits.push(s.user);
  if (s.pid) bits.push(`PID ${s.pid}`);
  bits.push(`network: ${s.network}${(s.network === 'filter' || s.network === 'open') ? (s.inspectTls ? ', HTTPS decrypted' : ', HTTPS not decrypted') : ''}`);
  if (s.proxyPort) bits.push(`proxy 127.0.0.1:${s.proxyPort}`);
  if (s.exitCode !== null && s.exitCode !== undefined) bits.push(`exit code ${s.exitCode}`);
  $('meta').textContent = bits.join(' · ');
  $('cProcesses').textContent = s.processes.length;
  $('processes').tBodies[0].innerHTML = s.processes.map((p) =>
    `<tr><td class="n">${p.id}</td><td>${esc(p.name)}</td><td class="mono">${esc(p.path || '')}</td></tr>`).join('');
  $('processesEmpty').hidden = s.processes.length > 0;
}

// ---- traffic ------------------------------------------------------------------

let pending = false;
function schedule() {
  if (pending) return;
  pending = true;
  requestAnimationFrame(() => { pending = false; renderAll(); });
}
function renderAll() {
  renderCounts();
  if (state.tab === 'traffic') renderTraffic();
  if (state.tab === 'endpoints') renderEndpoints();
  if (state.detail) renderFacts();
}

function matches(f) {
  if (state.outcome === 'direct') { if (f.kind !== 'direct' && f.kind !== 'listen') return false; }
  else if (state.outcome && f.outcome !== state.outcome) return false;
  if (!state.query) return true;
  const hay = `${f.host}:${f.port} ${f.url || ''} ${f.process || ''} ${f.method || ''} ${f.status || ''} ${f.outcome} ${f.rule || ''} ${f.note || ''} ${f.kind}`.toLowerCase();
  return state.query.split(/\s+/).every((w) => hay.includes(w));
}

function renderCounts() {
  let blocked = 0, errors = 0;
  for (const f of state.flows.values()) {
    if (f.outcome === 'blocked') blocked++;
    else if (f.outcome === 'error') errors++;
  }
  $('cTraffic').textContent = state.flows.size;
  $('cBlocked').textContent = blocked;
  $('cErrors').textContent = errors;
  $('cEndpoints').textContent = endpoints().length;
}

function renderTraffic() {
  const wrap = $('trafficWrap');
  const atBottom = wrap.scrollTop + wrap.clientHeight >= wrap.scrollHeight - 30;
  const rows = [];
  for (let i = state.order.length - 1; i >= 0 && rows.length < 2000; i--) {
    const f = state.flows.get(state.order[i]);
    if (f && matches(f)) rows.push(f);
  }
  rows.reverse();
  const html = rows.map((f) => {
    const { path } = splitUrl(f);
    const st = f.status ? `<span class="st${String(f.status)[0]}">${f.status}</span>` : '';
    const where = f.kind === 'direct' || f.kind === 'listen' ? esc(f.note || '') : esc(path);
    return `<tr data-id="${f.id}" class="${f.outcome}${f.id === state.selected ? ' sel' : ''}">` +
      `<td class="t">${time(f.time)}</td><td>${esc(f.process || '')}</td><td>${kindLabel[f.kind] || esc(f.kind)}</td>` +
      `<td>${esc(f.method || '')}</td><td class="host" title="${esc(f.host)}:${f.port}">${esc(f.host)}${defaultPort(f) ? '' : `<span class="t">:${f.port}</span>`}</td>` +
      `<td class="path" title="${esc(f.url || f.note || '')}">${where}</td><td class="n">${st}</td>` +
      `<td class="n">${bytes(f.bytesSent)}</td><td class="n">${bytes(f.bytesReceived)}</td>` +
      `<td><span class="tag ${f.outcome}">${outcomeLabel[f.outcome] || esc(f.outcome)}</span>${f.count > 1 ? ` <span class="t">×${f.count}</span>` : ''}</td></tr>`;
  }).join('');
  $('traffic').tBodies[0].innerHTML = html;
  $('trafficEmpty').hidden = rows.length > 0;
  if ($('follow').checked && atBottom) wrap.scrollTop = wrap.scrollHeight;
}

function defaultPort(f) {
  return (f.port === 443 && (f.kind === 'https' || f.kind === 'tunnel' || f.kind === 'websocket')) || (f.port === 80 && f.kind === 'http');
}

$('traffic').addEventListener('click', (e) => {
  const tr = e.target.closest('tr[data-id]');
  if (!tr) return;
  select(Number(tr.dataset.id));
});

function select(id) {
  state.selected = id;
  state.detail = { flow: state.flows.get(id) };
  $('detail').hidden = false;
  $('detail').parentElement.classList.add('narrow');
  renderDetail();
  send({ type: 'detail', id });
  for (const tr of $('traffic').tBodies[0].rows) tr.classList.toggle('sel', Number(tr.dataset.id) === id);
}

$('dClose').onclick = () => {
  state.selected = null; state.detail = null;
  $('detail').hidden = true;
  $('detail').parentElement.classList.remove('narrow');
  schedule();
};
$('dTabs').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (!b) return;
  state.detailTab = b.dataset.d;
  for (const x of $('dTabs').children) x.classList.toggle('on', x === b);
  renderDetail();
});

function renderFacts() {
  const f = state.detail.flow;
  if (!f) return;
  $('dUrl').textContent = f.url || `${f.host}:${f.port}`;
  const facts = [
    ['Result', `<span class="tag ${f.outcome}">${outcomeLabel[f.outcome] || esc(f.outcome)}</span>${f.count > 1 ? ` ×${f.count}` : ''}`],
    f.rule && ['Rule', esc(f.rule)],
    f.note && ['Note', esc(f.note)],
    ['Type', kindLabel[f.kind] || esc(f.kind)],
    f.process && ['Process', `${esc(f.process)}${f.pid ? ` (PID ${f.pid})` : ''}`],
    ['Endpoint', `${esc(f.host)}:${f.port}`],
    f.status && ['Status', String(f.status)],
    f.contentType && ['Content type', esc(f.contentType)],
    (f.bytesSent || f.bytesReceived) && ['Bytes', `${bytes(f.bytesSent) || '0 B'} sent, ${bytes(f.bytesReceived) || '0 B'} received`],
    f.durationMs != null && ['Time', `${Math.round(f.durationMs)} ms`],
    ['Started', new Date(f.time).toLocaleString()],
  ].filter(Boolean);
  $('dFacts').innerHTML = facts.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('');
}

function renderDetail() {
  const d = state.detail;
  if (!d || !d.flow) return;
  const f = d.flow;
  renderFacts();

  const quick = [];
  const hostName = f.host;
  quick.push(`<button data-q="blockHost">Block ${esc(hostName)}</button>`);
  if (f.url && (f.kind === 'http' || f.kind === 'https')) quick.push('<button data-q="blockUrl">Block this URL</button>');
  if (f.kind === 'https' || f.kind === 'tunnel') quick.push(`<button data-q="passthrough">Don\u2019t decrypt ${esc(hostName)}</button>`);
  if (f.outcome === 'blocked' && f.kind !== 'direct') quick.push(`<button data-q="allowHost">Allow ${esc(hostName)}</button>`);
  $('dQuick').innerHTML = quick.join('');

  const req = d.requestHeaders !== undefined;
  const part = state.detailTab === 'req'
    ? { headers: d.requestHeaders, body: d.requestBody }
    : { headers: d.responseHeaders, body: d.responseBody };
  let html = '';
  if (!req) html = '<p class="muted">Loading…</p>';
  else if (!part.headers && !part.body) {
    html = `<p class="muted">${f.kind === 'tunnel' ? 'This connection was not decrypted, so only its host name is known.'
      : f.kind === 'direct' || f.kind === 'listen' ? 'This connection did not go through the proxy, so its contents are not visible.'
      : state.detailTab === 'res' ? 'No response.' : 'Nothing recorded.'}</p>`;
  } else {
    if (part.headers) html += `<h4>Headers</h4><pre>${esc(part.headers)}</pre>`;
    if (part.body) {
      html += `<h4>Body · ${bytes(part.body.size)}${part.body.kind === 'binary' ? ' · binary' : ''}${part.body.truncated ? ' · preview' : ''}</h4><pre>${esc(part.body.text)}</pre>`;
    } else if (part.headers) {
      html += '<h4>Body</h4><p class="muted">Empty.</p>';
    }
  }
  $('dBody').innerHTML = html;
}

function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

$('dQuick').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (!b || !state.detail) return;
  const f = state.detail.flow;
  let rule;
  switch (b.dataset.q) {
    case 'blockHost': rule = { name: `Block ${f.host}`, action: 'block', host: f.host }; break;
    case 'allowHost': rule = { name: `Allow ${f.host}`, action: 'allow', host: f.host }; break;
    case 'passthrough': rule = { name: `Don't decrypt ${f.host}`, action: 'passthrough', host: f.host }; break;
    case 'blockUrl': {
      const u = new URL(f.url);
      rule = { name: `Block ${u.host}${u.pathname}`, action: 'block', url: '^' + escapeRegex(u.origin + u.pathname) + '(\\?|$)' };
      break;
    }
  }
  if (rule) { send({ type: 'addRule', rule }); toast(`Added rule \u201c${rule.name}\u201d. It applies to new requests.`); }
});

// ---- endpoints ----------------------------------------------------------------

function endpoints() {
  const map = new Map();
  for (const id of state.order) {
    const f = state.flows.get(id);
    if (!f) continue;
    const key = `${f.host.toLowerCase()}:${f.port}`;
    let e = map.get(key);
    if (!e) { e = { key, host: f.host, port: f.port, kinds: new Set(), requests: 0, blocked: 0, sent: 0, received: 0, procs: new Set(), last: f.time }; map.set(key, e); }
    e.kinds.add(kindLabel[f.kind] || f.kind);
    e.requests += f.count || 1;
    if (f.outcome === 'blocked') e.blocked += f.count || 1;
    e.sent += f.bytesSent || 0;
    e.received += f.bytesReceived || 0;
    if (f.process) e.procs.add(f.process);
    if (f.time > e.last) e.last = f.time;
  }
  return [...map.values()];
}

function renderEndpoints() {
  const q = state.endpointQuery;
  const list = endpoints().filter((e) => !q || `${e.key} ${[...e.procs].join(' ')} ${[...e.kinds].join(' ')}`.toLowerCase().includes(q))
    .sort((a, b) => b.requests - a.requests);
  $('endpoints').tBodies[0].innerHTML = list.map((e) =>
    `<tr class="${e.blocked === e.requests ? 'blocked' : ''}"><td class="host">${esc(e.host)}<span class="t">:${e.port}</span></td>` +
    `<td>${[...e.kinds].join(', ')}</td><td class="n">${e.requests}</td><td class="n">${e.blocked ? `<span class="st4">${e.blocked}</span>` : ''}</td>` +
    `<td class="n">${bytes(e.sent)}</td><td class="n">${bytes(e.received)}</td><td>${esc([...e.procs].join(', '))}</td>` +
    `<td class="t">${time(e.last)}</td><td><button data-block="${esc(e.host)}" ${/^[\d.:a-f]+$/i.test(e.host) && e.kinds.has('Direct') ? 'disabled title="Direct connections are already blocked in filter mode"' : ''}>Block</button></td></tr>`).join('');
  $('endpointsEmpty').hidden = list.length > 0;
}

$('endpoints').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-block]');
  if (!b) return;
  send({ type: 'addRule', rule: { name: `Block ${b.dataset.block}`, action: 'block', host: b.dataset.block } });
  toast(`Added rule \u201cBlock ${b.dataset.block}\u201d.`);
});

// ---- rules --------------------------------------------------------------------

function setRules(json) {
  state.rulesText = json;
  try { state.rules = JSON.parse(json); } catch { state.rules = { rules: [] }; }
  if (!Array.isArray(state.rules.rules)) state.rules.rules = [];
  $('ruleText').value = json;
  renderRules();
}

function describeRule(r) {
  const parts = [];
  if (r.host) parts.push(`host ${r.host}`);
  if (r.method) parts.push(`method ${r.method}`);
  if (r.url) parts.push(`url ~ ${r.url}`);
  const where = r.target && r.target !== 'any' ? ` in ${r.target}` : '';
  const stage = r.stage && r.stage !== 'request' ? ` (${r.stage === 'both' ? 'sent or received' : 'received'})` : '';
  if (r.contains) parts.push(`contains \u201c${r.contains}\u201d${where}${stage}`);
  if (r.regex) parts.push(`regex /${r.regex}/${where}${stage}`);
  return parts.length ? parts.join(' and ') : 'everything';
}

function renderRules() {
  const rules = state.rules.rules;
  $('cRules').textContent = rules.length;
  $('ruleTable').tBodies[0].innerHTML = rules.map((r, i) =>
    `<tr class="${r.enabled === false ? 'off' : ''}"><td><input type="checkbox" data-toggle="${i}" ${r.enabled === false ? '' : 'checked'}></td>` +
    `<td>${esc(r.name || '')}</td><td><span class="tag ${r.action === 'block' ? 'blocked' : r.action === 'allow' ? 'allowed' : 'passthrough'}">${esc(r.action || 'block')}</span></td>` +
    `<td>${esc(describeRule(r))}</td>` +
    `<td><button data-up="${i}" ${i === 0 ? 'disabled' : ''} title="Move up">↑</button><button data-down="${i}" ${i === rules.length - 1 ? 'disabled' : ''} title="Move down">↓</button><button data-del="${i}" title="Delete">Delete</button></td></tr>`).join('');
  $('rulesEmpty').hidden = rules.length > 0;
}

function saveRules(obj) {
  send({ type: 'saveRules', json: JSON.stringify(obj, null, 2) });
}

$('ruleTable').addEventListener('click', (e) => {
  const t = e.target;
  const rules = state.rules.rules.slice();
  const obj = { ...state.rules, rules };
  if (t.dataset.toggle !== undefined) { const i = +t.dataset.toggle; rules[i] = { ...rules[i], enabled: t.checked }; saveRules(obj); }
  else if (t.dataset.up !== undefined) { const i = +t.dataset.up; [rules[i - 1], rules[i]] = [rules[i], rules[i - 1]]; saveRules(obj); }
  else if (t.dataset.down !== undefined) { const i = +t.dataset.down; [rules[i + 1], rules[i]] = [rules[i], rules[i + 1]]; saveRules(obj); }
  else if (t.dataset.del !== undefined) { rules.splice(+t.dataset.del, 1); saveRules(obj); }
});

$('ruleForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const v = (id) => $(id).value.trim();
  const rule = { action: v('rAction') };
  if (v('rName')) rule.name = v('rName');
  if (v('rHost')) rule.host = v('rHost');
  if (v('rUrl')) rule.url = v('rUrl');
  if (v('rMethod')) rule.method = v('rMethod').toUpperCase();
  if (v('rContains')) rule.contains = $('rContains').value;
  if (v('rRegex')) rule.regex = $('rRegex').value;
  if (rule.contains || rule.regex) { rule.target = v('rTarget'); rule.stage = v('rStage'); }
  if (!rule.host && !rule.url && !rule.method && !rule.contains && !rule.regex &&
      !confirm('This rule has no conditions, so it matches every request. Add it anyway?')) return;
  saveRules({ ...state.rules, rules: [...state.rules.rules, rule] });
  for (const id of ['rName', 'rHost', 'rUrl', 'rMethod', 'rContains', 'rRegex']) $(id).value = '';
});

$('ruleSave').onclick = () => send({ type: 'saveRules', json: $('ruleText').value });
$('ruleReload').onclick = () => { $('ruleText').value = state.rulesText; ruleMsg('', ''); };
function ruleMsg(text, kind) { const m = $('ruleMsg'); m.textContent = text; m.className = 'msg ' + kind; }

// ---- log ----------------------------------------------------------------------

function addLog(l) {
  state.logs.push(l);
  const div = document.createElement('div');
  div.className = l.level;
  div.innerHTML = `<span class="time">${time(l.time)}</span>${esc(l.text)}`;
  const log = $('log');
  const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
  log.appendChild(div);
  if (atBottom) log.scrollTop = log.scrollHeight;
  $('cLog').textContent = state.logs.length;
  if (l.level === 'error') toast(l.text, true);
}

// ---- misc UI wiring -------------------------------------------------------------

let toastTimer;
function toast(text, err) {
  const t = $('toast');
  t.textContent = text;
  t.className = 'toast' + (err ? ' err' : '');
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), err ? 7000 : 3500);
}

$('tabs').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-tab]');
  if (!b) return;
  state.tab = b.dataset.tab;
  for (const x of $('tabs').children) x.classList.toggle('on', x === b);
  for (const p of document.querySelectorAll('.pane')) p.classList.toggle('on', p.id === `tab-${state.tab}`);
  renderAll();
});

$('chips').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (!b) return;
  state.outcome = b.dataset.o;
  for (const x of $('chips').children) x.classList.toggle('on', x === b);
  renderTraffic();
});

$('q').addEventListener('input', () => { state.query = $('q').value.trim().toLowerCase(); renderTraffic(); });
$('eq').addEventListener('input', () => { state.endpointQuery = $('eq').value.trim().toLowerCase(); renderEndpoints(); });
$('clearBtn').onclick = () => { state.flows.clear(); state.order = []; $('dClose').onclick(); schedule(); };
$('browseBtn').onclick = () => send({ type: 'browse' });
$('fNetwork').onchange = updateNetworkHelp;
$('fTls').onchange = updateNetworkHelp;
$('stopBtn').onclick = () => send({ type: 'stop' });
$('newBtn').onclick = () => {
  state.session = null;
  renderSession();
};

$('launchForm').addEventListener('submit', (e) => {
  e.preventDefault();
  state.flows.clear(); state.order = []; state.selected = null; state.detail = null; $('detail').hidden = true;
  send({
    type: 'start',
    program: $('fProgram').value,
    arguments: $('fArgs').value,
    workingDirectory: $('fCwd').value,
    stage: $('fStage').value,
    network: $('fNetwork').value,
    inspectTls: $('fTls').checked,
    autoPassthrough: $('fAuto').checked,
  });
});

// ---- preview outside WebView2 (opening index.html in a browser shows sample data) ---------

const mock = {
  handle(m) {
    if (m.type === 'start') { mock.run(m); }
    if (m.type === 'detail') {
      const f = state.flows.get(m.id);
      setTimeout(() => onMessage({ type: 'detail', flow: f,
        requestHeaders: f.kind === 'https' || f.kind === 'http' ? `${f.method} ${splitUrl(f).path} HTTP/1.1\r\nHost: ${f.host}\r\nUser-Agent: sample/1.0\r\nAccept: */*\r\n` : null,
        requestBody: f.method === 'POST' ? { kind: 'text', size: 42, text: '{"user":"me","password":"hunter2"}' } : null,
        responseHeaders: f.status ? `HTTP/1.1 ${f.status} OK\r\nContent-Type: application/json\r\n` : null,
        responseBody: f.status === 200 ? { kind: 'text', size: 17, text: '{"ok":true}' } : null }), 50);
    }
    if (m.type === 'saveRules' || m.type === 'addRule') {
      const obj = m.type === 'addRule' ? { ...state.rules, rules: [m.rule, ...state.rules.rules] } : JSON.parse(m.json);
      setTimeout(() => onMessage({ type: 'rules', rules: JSON.stringify(obj, null, 2), saved: true }), 50);
    }
    if (m.type === 'stop') mock.finish();
  },
  init() {
    onMessage({ type: 'init', defaults: { program: 'C:\\Tools\\example\\example.exe', stage: 'folder', network: 'filter', inspectTls: true, autoPassthrough: true },
      rules: JSON.stringify({ rules: [{ name: 'No passwords out', action: 'block', contains: 'password', stage: 'request' }, { action: 'block', host: '*.telemetry.example.com' }], maxInspectBytes: 8388608 }, null, 2),
      rulesPath: 'C:\\Users\\you\\AppData\\Roaming\\usandbox\\rules.json' });
    onMessage({ type: 'session', session: null });
  },
  run(m) {
    const s = { state: 'running', user: 'PC\\usbx-3fa9c021', program: m.program, arguments: m.arguments, network: m.network, inspectTls: m.inspectTls, pid: 4242, proxyPort: 51873, processes: [{ id: 4242, name: 'example', path: m.program }, { id: 4310, name: 'example-helper', path: 'C:\\ProgramData\\usandbox\\usbx-3fa9c021\\program\\helper.exe' }] };
    onMessage({ type: 'session', session: s });
    let id = 1;
    const now = Date.now();
    const sample = [
      ['https', 'GET', 'api.example.com', 443, '/v1/config?build=1931', 200, 'allowed', 812, 5120],
      ['https', 'POST', 'api.example.com', 443, '/v1/login', 403, 'blocked', 0, 0, 'No passwords out'],
      ['https', 'GET', 'cdn.example.net', 443, '/assets/app.js', 200, 'allowed', 640, 381220],
      ['tunnel', 'CONNECT', 'pinned.example.org', 443, '', null, 'passthrough', 5212, 18833],
      ['https', 'POST', 'events.telemetry.example.com', 443, '/collect', 403, 'blocked', 0, 0, 'block host=*.telemetry.example.com'],
      ['http', 'GET', 'update.example.com', 80, '/latest.json', 304, 'allowed', 420, 0],
      ['direct', null, '142.250.74.110', 443, '', null, 'blocked', 0, 0, 'network lock (did not use the proxy)'],
      ['websocket', 'GET', 'live.example.com', 443, '/socket', 101, 'allowed', 1820, 90210],
      ['https', 'GET', 'api.example.com', 443, '/v1/items?page=2', 200, 'allowed', 790, 22410],
    ];
    const flows = sample.map(([kind, method, host, port, path, status, outcome, sent, recv, rule], i) => ({
      id: id++, time: new Date(now - (sample.length - i) * 1300).toISOString(), kind, method, host, port,
      url: kind === 'direct' ? null : kind === 'tunnel' ? `${host}:${port}` : `${kind === 'http' ? 'http' : 'https'}://${host}${path}`,
      status, outcome, rule, process: i === 6 ? 'example-helper' : 'example', pid: i === 6 ? 4310 : 4242, bytesSent: sent, bytesReceived: recv, durationMs: 40 + i * 13,
      count: i === 6 ? 4 : 1, note: kind === 'direct' ? 'Blocked direct TCP connection by C:\\ProgramData\\usandbox\\usbx-3fa9c021\\program\\helper.exe.' : kind === 'tunnel' ? 'TLS, server name pinned.example.org; not decrypted: rule: Pinned app' : null,
    }));
    onMessage({ type: 'batch', flows, logs: [
      { time: new Date(now - 15000).toISOString(), level: 'info', text: 'Created throwaway user PC\\usbx-3fa9c021 (S-1-5-21-…-1042).' },
      { time: new Date(now - 14000).toISOString(), level: 'info', text: 'Proxy listening on 127.0.0.1:51873.' },
      { time: new Date(now - 13000).toISOString(), level: 'warn', text: 'Sample data: open usandbox.exe to see real traffic.' },
    ] });
  },
  finish() {
    onMessage({ type: 'session', session: { ...state.session, state: 'finished', exitCode: 0, processes: [] } });
  },
};

if (host) {
  host.addEventListener('message', (e) => onMessage(e.data));
  send({ type: 'ready' });
} else {
  mock.init();
}
updateNetworkHelp();
