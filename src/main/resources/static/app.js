// Presentation only. Every verdict, match offset, Bloom bit and traffic total comes from the Java backend.
const $ = id => document.getElementById(id);
const fmt = n => Number(n).toLocaleString();
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const LABEL = {
  SQLI: 'SQL injection', XSS: 'Cross-site scripting', TRAVERSAL: 'Path traversal', CMDI: 'Command injection',
  LOG4SHELL: 'Log4Shell', SSRF: 'Server-side request forgery', SCANNER: 'Scanner probe',
};
const VERDICT = { BLOCK: 'Stopped', FLAG: 'Flagged for review', ALLOW: 'Passed' };
const who = ip => ['127.0.0.1', '0:0:0:0:0:0:0:1', '::1'].includes(ip) ? 'this laptop' : ip ?? 'unknown';

async function api(path, body) {
  const res = await fetch('/api/' + path, body === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || data.detail || res.statusText);
  return data;
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === 'class' ? e.className = v : e.setAttribute(k, v);
  for (const k of kids) e.append(k); // strings become text nodes: attacker text is never parsed as HTML
  return e;
}

// Canvas can't read CSS variables, so pull the theme's tokens when painting.
const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const rgb = hex => [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16));

let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.hidden = true, 4500);
}

// ---------- header: shop address + scan-to-attack QR ----------
(async () => {
  let url = location.origin + '/shop/index.html';
  try {
    const { shopUrls } = await api('info');
    if (shopUrls.length && ['localhost', '127.0.0.1'].includes(location.hostname)) url = shopUrls[0];
  } catch { /* keep the same-origin URL */ }
  $('shopUrl').href = url;
  $('shopUrl').textContent = url.replace(/^https?:\/\//, '').replace(/\/index\.html$/, '');

  const q = qrcode(0, 'M');
  q.addData(url);
  q.make();
  const n = q.getModuleCount(), quiet = 2, c = $('qr');
  c.width = c.height = n + quiet * 2;
  const g = c.getContext('2d');
  g.fillStyle = '#fff'; g.fillRect(0, 0, c.width, c.height);
  g.fillStyle = '#061426'; // always dark-on-white: phone cameras read that best
  for (let r = 0; r < n; r++) for (let col = 0; col < n; col++) if (q.isDark(r, col)) g.fillRect(col + quiet, r + quiet, 1, 1);
})();

// ---------- live stream ----------
const events = new EventSource('/api/events');
events.onopen = () => { $('live').classList.add('on'); $('live').textContent = 'Live'; };
events.onerror = () => { $('live').classList.remove('on'); $('live').textContent = 'Reconnecting'; };
events.addEventListener('inspection', e => arrive(JSON.parse(e.data)));
events.addEventListener('simulation', e => showSim(JSON.parse(e.data)));

function arrive(i) {
  queue.push(i);
  if (queue.length > 400) queue.splice(0, queue.length - 400); // a flood can outrun the belt; keep the newest
  probe(i);
  if (i.verdict !== 'ALLOW') autopsy(i);
}

// ---------- the belt ----------
const queue = [];
const gates = [...document.querySelectorAll('.gate')];
const GATE_X = [0.22, 0.44, 0.66, 0.86];
let inFlight = 0;

setInterval(() => {
  while (queue.length && inFlight < (reduced ? 6 : 24)) {
    launch(queue.shift());
    if (!reduced) break; // one new tag per tick reads as a stream, not a pile
  }
}, 75);

function launch(i) {
  $('beltEmpty').hidden = true;
  const tag = el('div', { class: 'tag ' + i.verdict }, el('i', {}, who(i.ip)), el('b', {}, i.request));
  $('lane').append(tag);
  inFlight++;

  const W = $('lane').clientWidth, tw = tag.offsetWidth;
  const center = f => f * W - tw / 2;
  const stopX = center(GATE_X[3]);
  const D = reduced ? 1 : 3400;
  const results = [
    i.bloomHit ? 'hit' : 'clear',
    i.confirmedBadIp ? 'hit' : i.bloomHit ? 'clear' : null,
    i.matches.length ? 'hit' : 'clear',
    i.verdict === 'ALLOW' ? 'clear' : 'hit',
  ];

  let frames, crossAt;
  if (i.verdict === 'BLOCK') {
    frames = [
      { transform: `translateX(${-tw}px)` },
      { transform: `translateX(${stopX}px)`, offset: 0.8 },
      { transform: `translate(${stopX}px, 74px) rotate(5deg)`, opacity: 0 },
    ];
    crossAt = f => 0.8 * (center(f) + tw) / (stopX + tw);
  } else {
    const end = W + 12;
    frames = [{ transform: `translateX(${-tw}px)` }, { transform: `translateX(${end}px)` }];
    crossAt = f => (center(f) + tw) / (end + tw);
  }
  GATE_X.forEach((f, g) => results[g] && setTimeout(() => flash(gates[g], results[g]), D * crossAt(f)));

  const anim = tag.animate(frames, { duration: D, easing: 'linear', fill: 'forwards' });
  anim.onfinish = () => {
    tag.remove();
    inFlight--;
    if (i.verdict === 'BLOCK') bump();
  };
}

function flash(gate, cls) {
  gate.classList.remove('hit', 'clear');
  void gate.offsetWidth;
  gate.classList.add(cls);
  setTimeout(() => gate.classList.remove(cls), 180);
}

function bump() {
  const b = $('bin');
  b.classList.remove('bump'); void b.offsetWidth; b.classList.add('bump');
}

// ---------- autopsy: the stopped request, taken apart ----------
let lastAutopsy = 0, pendingAutopsy = null, autopsyTimer = null;

function autopsy(i) {
  const wait = 2200 - (performance.now() - lastAutopsy); // hold each specimen long enough to read
  if (wait > 0) {
    pendingAutopsy = i;
    autopsyTimer ??= setTimeout(() => { autopsyTimer = null; autopsy(pendingAutopsy); }, wait);
    return;
  }
  lastAutopsy = performance.now();
  renderAutopsy(i);
}

function renderAutopsy(i, heading = 'Latest stopped request') {
  $('autopsyTitle').firstChild.nodeValue = heading + ' ';
  const text = i.normalized;
  const ranges = i.matches
    .map(m => ({ from: m.position, to: m.position + m.signature.length, label: LABEL[m.category] ?? m.category }))
    .sort((a, b) => a.from - b.from || b.to - a.to);
  const merged = [];
  for (const r of ranges) {
    const last = merged.at(-1);
    if (last && r.from <= last.to) last.to = Math.max(last.to, r.to);
    else merged.push({ ...r });
  }

  // Long requests: show a window around the first match.
  const MAX = 64;
  let from = 0, to = text.length;
  if (text.length > MAX) {
    from = Math.max(0, (merged[0]?.from ?? 0) - 16);
    to = Math.min(text.length, from + MAX);
  }
  const read = $('read');
  read.replaceChildren();
  if (from > 0) read.append('…');
  let at = from;
  for (const r of merged) {
    if (r.to <= from || r.from >= to) continue;
    const a = Math.max(r.from, from), b = Math.min(r.to, to);
    if (a > at) read.append(text.slice(at, a));
    read.append(el('mark', { 'data-label': r.label }, text.slice(a, b)));
    at = b;
  }
  if (at < to) read.append(text.slice(at, to));
  if (to < text.length) read.append('…');
  const shown = to - from;
  read.style.setProperty('--read-size', shown <= 26 ? '58px' : shown <= 42 ? '46px' : '34px');

  $('sent').textContent = i.request.length > 150 ? i.request.slice(0, 150) + '…' : i.request;

  const exact = !i.bloomHit ? 'skipped' : i.confirmedBadIp ? 'IP is on the blocklist' : 'false alarm, cleared';
  const pats = i.matches.length;
  $('trace').replaceChildren(
    el('li', { class: i.bloomHit ? 'hot' : '' }, el('b', {}, 'Bloom filter'), el('span', {}, i.bloomHit ? 'possibly listed' : 'not listed')),
    el('li', { class: i.confirmedBadIp ? 'hot' : '' }, el('b', {}, 'Exact check'), el('span', {}, exact)),
    el('li', { class: pats ? 'hot' : '' }, el('b', {}, 'Trie'), el('span', {}, pats ? `${pats} pattern${pats > 1 ? 's' : ''} found` : 'no patterns')),
    el('li', { class: 'final ' + i.verdict }, VERDICT[i.verdict]),
    el('li', { class: 'meta' }, el('span', {}, `from ${who(i.ip)} in ${(i.nanos / 1000).toFixed(1)} µs`)),
  );

  const s = $('specimen');
  if (!reduced) { s.classList.remove('swap'); void s.offsetWidth; s.classList.add('swap'); }
}

// ---------- Bloom field: the filter's real memory, one pixel per bit ----------
let bitBytes = null, bitCount = 0, side = 0, k = 7, fieldImg = null;
const markers = [];
const field = $('bits');

async function loadBits() {
  const stats = await api('stats');
  const buf = await (await fetch('/api/bloom/bits')).arrayBuffer();
  bitBytes = new Uint8Array(buf);
  bitCount = stats.bloomBits;
  k = stats.bloomHashes;
  side = Math.ceil(Math.sqrt(bitCount));
  field.width = field.height = side;
  await paintBits();

  const kb = Math.round(bitCount / 8 / 1024);
  $('fieldNote').replaceChildren(
    `${fmt(bitCount)} bits, ${kb} KB, holding ${fmt(stats.blocklistSize)} blocked IPs. Each lookup checks ${k} bits. `,
    el('em', { class: 'z' }, 'Blue'), ' marks an empty bit: one is proof the IP is not listed. ',
    el('em', { class: 'o' }, 'Orange'), ` marks a set bit: only all ${k} set means “possibly listed”.`,
  );
}
const isSet = i => (bitBytes[i >> 3] >> (i & 7)) & 1;

async function paintBits() {
  if (!bitBytes) return;
  const on = rgb(css('--bit-on')), off = rgb(css('--bit-off'));
  const img = new ImageData(side, side);
  for (let i = 0; i < bitCount; i++) {
    const c = isSet(i) ? on : off, o = i * 4;
    img.data[o] = c[0]; img.data[o + 1] = c[1]; img.data[o + 2] = c[2]; img.data[o + 3] = 255;
  }
  fieldImg = await createImageBitmap(img);
  drawField();
}

function probe(i) {
  if (!bitBytes || !i.bloomProbes) return;
  const t = performance.now();
  for (const p of i.bloomProbes) markers.push({ x: p % side, y: Math.floor(p / side), set: isSet(p), t });
  if (markers.length > 280) markers.splice(0, markers.length - 280);
  if (markers.length === i.bloomProbes.length) requestAnimationFrame(drawField);
}

function drawField() {
  if (!fieldImg) return;
  const g = field.getContext('2d');
  g.imageSmoothingEnabled = false;
  g.drawImage(fieldImg, 0, 0);
  const now = performance.now(), life = reduced ? 2500 : 1600, stop = css('--stop'), pass = css('--pass');
  while (markers.length && now - markers[0].t > life) markers.shift();
  for (const m of markers) {
    const age = (now - m.t) / life;
    const r = reduced ? 22 : 14 + age * 34;
    g.globalAlpha = 1 - age;
    g.strokeStyle = g.fillStyle = m.set ? stop : pass;
    g.lineWidth = 7;
    g.beginPath(); g.arc(m.x, m.y, r, 0, Math.PI * 2); g.stroke();
    g.fillRect(m.x - 6, m.y - 6, 12, 12);
  }
  g.globalAlpha = 1;
  if (markers.length) requestAnimationFrame(drawField);
}
loadBits().catch(() => $('fieldNote').textContent = 'Could not load the filter. Is the server running?');

// ---------- numbers, gates, traffic pulse (polled every second) ----------
async function refresh() {
  try {
    const [s, t60, t10] = await Promise.all([api('stats'), api('traffic?seconds=60'), api('traffic?seconds=10')]);
    $('nTotal').textContent = fmt(s.total);
    $('nBlocked').textContent = fmt(s.blocked);
    $('nFlagged').textContent = fmt(s.flagged);
    $('nFp').textContent = fmt(s.bloomFalsePositives);
    $('nMicros').textContent = s.avgInspectMicros.toFixed(1);
    $('gBloom').textContent = `${fmt(s.bloomHits)} possibly listed`;
    $('gExact').textContent = `${fmt(s.bloomFalsePositives)} false alarms cleared`;
    $('gTrie').textContent = `${fmt(s.signatureHits)} matched`;
    $('gVerdict').textContent = `${fmt(s.blocked)} stopped`;
    $('binCount').textContent = fmt(s.blocked);
    drawPulse(t60);

    const before = (t60.total - t10.total) / 5; // average per 10 s over the 50 s before
    const flood = t10.total > 200 && t10.total > 3 * Math.max(before, 1);
    $('flood').hidden = !flood;
    if (flood) $('flood').textContent = `Flood detected: ${fmt(t10.total)} requests in the last 10 s, peak ${fmt(t60.peakCount)} per second.`;
  } catch { /* server restarting: next tick retries */ }
}

function drawPulse(t) {
  const c = $('chart'), dpr = devicePixelRatio || 1;
  c.width = c.clientWidth * dpr;
  c.height = c.clientHeight * dpr;
  const g = c.getContext('2d'), w = c.width, h = c.height, n = t.all.length;
  const top = 22 * dpr, max = Math.max(1, ...t.all), bw = w / n, scale = (h - top) / max;
  const [rail, pass, stop, muted, text] = ['--rail', '--pass', '--stop', '--muted', '--text'].map(css);
  g.clearRect(0, 0, w, h);
  g.fillStyle = rail;
  g.fillRect(0, h - dpr, w, dpr);
  t.all.forEach((v, i) => {
    const b = t.blocked[i];
    g.fillStyle = pass;
    g.fillRect(i * bw + dpr, h - (v - b) * scale, bw - 2 * dpr, (v - b) * scale);
    g.fillStyle = stop;
    g.fillRect(i * bw + dpr, h - v * scale, bw - 2 * dpr, b * scale);
  });
  g.font = `600 ${12 * dpr}px Archivo, sans-serif`;
  g.fillStyle = muted;
  g.fillText(`${fmt(max)} per second`, 0, 13 * dpr);
  if (t.peakCount > 0) {
    const x = (n - 1 - t.peakSecondsAgo) * bw + bw / 2;
    const label = `peak ${fmt(t.peakCount)}`;
    g.fillStyle = text;
    g.textAlign = x > w - 80 * dpr ? 'right' : 'center';
    g.fillText(label, Math.min(Math.max(x, 40 * dpr), w), 13 * dpr);
    g.textAlign = 'left';
  }
}
setInterval(refresh, 1000);
refresh();

// ---------- flood ----------
$('simRatio').oninput = () => $('simRatioOut').textContent = $('simRatio').value + ' %';
$('openFlood').onclick = () => $('floodDlg').showModal();
$('simGo').onclick = async () => {
  const btn = $('simGo');
  btn.disabled = true;
  btn.textContent = 'Flooding…';
  try {
    showSim(await api('simulate', { requests: +$('simN').value, attackRatio: $('simRatio').value / 100 }));
  } catch (e) {
    $('simResult').replaceChildren(el('dt', {}, 'Error'), el('dd', {}, e.message));
  } finally {
    btn.disabled = false;
    btn.textContent = 'Launch flood';
  }
};

function showSim(r) {
  const pct = x => (x * 100).toFixed(2) + ' %';
  const rows = [
    ['Caught', pct(r.detectionRate), true], ['False alarms', pct(r.falseAlarmRate), true],
    ['Requests', `${fmt(r.requests)} (${fmt(r.attacks)} attacks)`], ['Throughput', `${fmt(r.requestsPerSecond)} per second`],
    ['Bloom false alarms', `${fmt(r.bloomFalsePositives)}, all cleared by the exact check`], ['Time', `${fmt(r.elapsedMillis)} ms`],
  ];
  $('simResult').replaceChildren(...rows.flatMap(([k, v, big]) => [el('dt', {}, k), el('dd', { class: big ? 'big' : '' }, v)]),
    el('dt', {}, 'Note'), el('dd', { class: 'note' }, 'These attacks are built from the shield’s own signature list, so a catch rate near 100 % is expected. Real-traffic results belong in the report.'));
}

// ---------- inspect any text (the examiner's own input) ----------
function openInspect() {
  $('inspMsg').textContent = '';
  $('inspectDlg').showModal();
  $('inspText').focus();
}
$('openInspect').onclick = openInspect;
$('inspGo').onclick = async () => {
  const btn = $('inspGo');
  btn.disabled = true;
  try {
    const i = await api('inspect', { text: $('inspText').value, ip: $('inspIp').value });
    $('inspectDlg').close();
    lastAutopsy = performance.now() + 6000; // hold the answer on screen ~8 s before live traffic replaces it
    renderAutopsy(i, 'Your text, inspected');
    toast(`${VERDICT[i.verdict]}. ${i.reasons.length ? i.reasons.join('; ') : 'No attack pattern; IP not listed'}.`);
  } catch (e) {
    $('inspMsg').textContent = 'Could not inspect: ' + e.message;
  } finally {
    btn.disabled = false;
  }
};

// ---------- block my IP ----------
async function blockMe() {
  try {
    const r = await api('blocklist', {});
    toast(r.added ? `${r.ip} is now blocked. Its next shop request stops at the Bloom filter.` : `${r.ip} was already blocked.`);
    loadBits();
  } catch (e) { toast('Could not block: ' + e.message); }
}
$('blockMe').onclick = blockMe;

// ---------- network bottleneck (Edmonds–Karp on the server) ----------
const defaultNet = {
  nodes: ['internet', 'cdn', 'firewall', 'balancer', 'app-1', 'app-2', 'cache', 'database'],
  links: [
    { from: 'internet', to: 'cdn', capacity: 20000 }, { from: 'cdn', to: 'firewall', capacity: 12000 },
    { from: 'firewall', to: 'balancer', capacity: 9000 }, { from: 'balancer', to: 'app-1', capacity: 4000 },
    { from: 'balancer', to: 'app-2', capacity: 4000 }, { from: 'app-1', to: 'cache', capacity: 3000 },
    { from: 'app-2', to: 'cache', capacity: 3000 }, { from: 'app-1', to: 'database', capacity: 1200 },
    { from: 'app-2', to: 'database', capacity: 1200 }, { from: 'cache', to: 'database', capacity: 2500 },
  ],
  source: 'internet', sink: 'database',
};
$('netJson').value = JSON.stringify(defaultNet, null, 2);
$('openNet').onclick = () => { $('netDlg').showModal(); solveNet(); };
$('netGo').onclick = solveNet;

async function solveNet() {
  let net;
  try { net = JSON.parse($('netJson').value); } catch { $('netMsg').textContent = 'That JSON does not parse. Check for a missing comma or quote.'; return; }
  try {
    const r = await api('bottleneck', net);
    drawNet(net, r);
    const cut = r.minCut.map(l => `${l.from} → ${l.to} (${fmt(l.capacity)})`).join(', ');
    $('netMsg').replaceChildren('Most this network can carry: ', el('b', {}, `${fmt(r.maxFlow)} requests per second`), '. ',
      r.minCut.length ? `Bottleneck: ${cut}.` : 'Source and sink are not connected.');
  } catch (e) { $('netMsg').textContent = 'Could not solve: ' + e.message; }
}

function drawNet(net, r) {
  // Columns by hop distance from the source. Layout only; the flow is computed in Java.
  const depth = { [net.source]: 0 }, q = [net.source];
  while (q.length) {
    const u = q.shift();
    for (const l of net.links) if (l.from === u && !(l.to in depth)) { depth[l.to] = depth[u] + 1; q.push(l.to); }
  }
  const maxD = Math.max(0, ...Object.values(depth));
  for (const n of net.nodes) if (!(n in depth)) depth[n] = maxD + 1;
  const cols = {};
  for (const n of net.nodes) (cols[depth[n]] ??= []).push(n);
  const ncol = Object.keys(cols).length, pos = {};
  for (const [d, ns] of Object.entries(cols))
    ns.forEach((n, i) => pos[n] = { x: 60 + d * (680 / Math.max(1, ncol - 1)), y: 300 * (i + 1) / (ns.length + 1) });

  const NS = 'http://www.w3.org/2000/svg', svg = $('net');
  const add = (tag, attrs, text) => {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    if (text !== undefined) e.textContent = text;
    svg.append(e);
  };
  svg.replaceChildren();
  const cut = new Set(r.minCut.map(l => l.from + '\n' + l.to));
  const drawn = net.links.filter(l => pos[l.from] && pos[l.to]);
  // Order matters: links, then nodes on top, then capacity labels on top of everything.
  for (const l of drawn) {
    const a = pos[l.from], b = pos[l.to];
    add('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: cut.has(l.from + '\n' + l.to) ? 'cut' : '' });
  }
  const side = new Set(r.sourceSide);
  for (const n of net.nodes) {
    const w = Math.max(56, n.length * 7.5 + 16);
    add('rect', { x: pos[n].x - w / 2, y: pos[n].y - 13, width: w, height: 26, rx: 2, class: side.has(n) ? 'src' : '' });
    add('text', { x: pos[n].x, y: pos[n].y + 4, 'text-anchor': 'middle', class: side.has(n) ? 'src' : '' }, n);
  }
  for (const l of drawn) {
    const a = pos[l.from], b = pos[l.to];
    add('text', { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 + 4, 'text-anchor': 'middle',
      class: 'cap' + (cut.has(l.from + '\n' + l.to) ? ' cut' : '') }, fmt(l.capacity));
  }
}

// ---------- presenter keys ----------
addEventListener('keydown', e => {
  if (e.ctrlKey || e.metaKey || e.altKey || document.querySelector('dialog[open]')) return;
  if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;
  const key = e.key.toLowerCase();
  if (key === 'i') { e.preventDefault(); openInspect(); }
  if (key === 'f') { e.preventDefault(); $('floodDlg').showModal(); }
  if (key === 'n') { e.preventDefault(); $('netDlg').showModal(); solveNet(); }
  if (key === 'b') { e.preventDefault(); blockMe(); }
  if (key === 'd') { e.preventDefault(); toggleTheme(); }
});

// ---------- daylight mode for bright rooms ----------
function toggleTheme() {
  const light = document.documentElement.dataset.theme !== 'light';
  if (light) document.documentElement.dataset.theme = 'light'; else delete document.documentElement.dataset.theme;
  try { localStorage.setItem('theme', light ? 'light' : 'dark'); } catch { /* private window: just don't remember */ }
  syncThemeButton();
  paintBits();
  refresh();
}
const syncThemeButton = () => $('theme').setAttribute('aria-pressed', document.documentElement.dataset.theme === 'light');
$('theme').onclick = toggleTheme;
syncThemeButton();

// ---------- boot sequence: once per browser tab, real numbers from the engine ----------
(async () => {
  try { if (reduced || sessionStorage.getItem('booted')) return; sessionStorage.setItem('booted', '1'); } catch { return; }
  const boot = $('boot'), log = $('bootLog');
  let s;
  try { s = await api('stats'); } catch { return; } // server down: skip straight to the dashboard
  boot.hidden = false;
  let skip = false;
  const end = () => { skip = true; boot.classList.add('done'); setTimeout(() => boot.hidden = true, 400); };
  addEventListener('keydown', end, { once: true });
  boot.onclick = end;
  const lines = [
    `attack-shield: live request inspection`,
    `loading blocklist ............ ${fmt(s.blocklistSize)} IPs`,
    `sizing Bloom filter .......... m = ${fmt(s.bloomBits)} bits, k = ${s.bloomHashes}`,
    `  expected false-alarm rate    ${(s.bloomExpectedFpr * 100).toFixed(2)} %`,
    `compiling signature trie ..... ${s.signatures} patterns`,
    `traffic segment tree ......... 600 one-second buckets`,
    `opening live event stream .... ok`,
    `armed.`,
  ];
  for (const line of lines) {
    if (skip) return;
    const row = el('span', {}, '');
    log.append(row, '\n');
    for (let c = 1; c <= line.length && !skip; c += 2) { row.textContent = line.slice(0, c); await new Promise(r => setTimeout(r, 9)); }
    row.textContent = line;
    if (line.endsWith('ok') || line === 'armed.') row.className = 'ok';
    await new Promise(r => setTimeout(r, 120));
  }
  setTimeout(end, 600);
})();
