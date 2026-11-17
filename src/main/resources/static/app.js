// Presentation only: every algorithm runs in the Java backend; this file draws what the API returns.
const $ = id => document.getElementById(id);
const fmt = n => Number(n).toLocaleString();

async function api(path, body) {
  const res = await fetch('/api/' + path, body === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || data.detail || res.statusText);
  return data;
}

// ---- header ---------------------------------------------------------------
const shopUrl = location.origin + '/shop/index.html';
$('shopLink').textContent = shopUrl;
$('shopLink').href = shopUrl;
if (['localhost', '127.0.0.1'].includes(location.hostname))
  $('shopLink').insertAdjacentText('afterend', ' (other devices: replace localhost with this PC\'s Wi-Fi IP)');

// ---- live feed over Server-Sent Events -------------------------------------
const events = new EventSource('/api/events');
events.onopen = () => $('live').classList.add('on');
events.onerror = () => $('live').classList.remove('on');
events.addEventListener('inspection', e => addRow(JSON.parse(e.data)));
events.addEventListener('simulation', e => showSim(JSON.parse(e.data)));

function addRow(i) {
  const tr = document.createElement('tr');
  tr.className = i.verdict + ' new';
  const cells = [new Date(i.timeMillis).toLocaleTimeString(), i.verdict, i.ip, i.request,
    i.reasons.join(' · ') || 'clean', (i.nanos / 1000).toFixed(1)];
  for (const c of cells) {
    const td = document.createElement('td');
    td.textContent = c;           // never innerHTML: these strings are attacker-controlled
    td.title = c;
    tr.appendChild(td);
  }
  const feed = $('feed');
  feed.prepend(tr);
  while (feed.rows.length > 60) feed.deleteRow(-1);
  if (i.verdict === 'BLOCK') flash($('sBlocked').parentElement);
}

function flash(el) { el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash'); }

// ---- stats + traffic chart (polled every second) ---------------------------
async function refresh() {
  try {
    const [s, t] = await Promise.all([api('stats'), api('traffic?seconds=60')]);
    $('sTotal').textContent = fmt(s.total);
    $('sBlocked').textContent = fmt(s.blocked);
    $('sFlagged').textContent = fmt(s.flagged);
    $('sFp').textContent = fmt(s.bloomFalsePositives);
    $('sList').textContent = fmt(s.blocklistSize);
    $('sMicros').textContent = s.avgInspectMicros.toFixed(1);
    $('peak').textContent = t.peakCount > 0
      ? `· ${fmt(t.total)} req, ${fmt(t.totalBlocked)} blocked · peak ${fmt(t.peakCount)} req/s ${t.peakSecondsAgo}s ago` : '';
    drawChart(t);
  } catch { /* server restarting; the next tick retries */ }
}

function drawChart(t) {
  const c = $('chart'), dpr = devicePixelRatio || 1;
  c.width = c.clientWidth * dpr; c.height = 180 * dpr;
  const g = c.getContext('2d'), w = c.width, h = c.height, n = t.all.length;
  const max = Math.max(1, ...t.all), bw = w / n;
  g.clearRect(0, 0, w, h);
  const css = getComputedStyle(document.documentElement);
  t.all.forEach((v, i) => {
    const ha = v / max * (h - 16 * dpr), hb = t.blocked[i] / max * (h - 16 * dpr);
    g.fillStyle = css.getPropertyValue('--accent'); g.fillRect(i * bw + 1, h - ha, bw - 2, ha);
    g.fillStyle = css.getPropertyValue('--bad'); g.fillRect(i * bw + 1, h - hb, bw - 2, hb);
  });
  g.fillStyle = css.getPropertyValue('--muted');
  g.font = `${11 * dpr}px monospace`;
  g.fillText(`max ${fmt(max)}/s`, 4 * dpr, 12 * dpr);
}

setInterval(refresh, 1000);
refresh();

// ---- flood simulator --------------------------------------------------------
$('simRatio').oninput = () => $('simRatioOut').textContent = $('simRatio').value + '%';
$('simGo').onclick = async () => {
  const btn = $('simGo');
  btn.disabled = true; btn.textContent = 'Flooding…';
  try {
    showSim(await api('simulate', { requests: +$('simN').value, attackRatio: $('simRatio').value / 100 }));
  } catch (e) {
    $('simResult').innerHTML = '';
    $('simResult').append(Object.assign(document.createElement('dd'), { textContent: 'Error: ' + e.message }));
  } finally {
    btn.disabled = false; btn.textContent = 'Launch';
  }
};

function showSim(r) {
  const rows = [
    ['requests', fmt(r.requests)], ['attacks / benign', `${fmt(r.attacks)} / ${fmt(r.benign)}`],
    ['detection rate', (r.detectionRate * 100).toFixed(2) + '%'],
    ['false alarms', (r.falseAlarmRate * 100).toFixed(2) + '%'],
    ['Bloom FPs caught', fmt(r.bloomFalsePositives)],
    ['throughput', fmt(r.requestsPerSecond) + ' req/s'], ['time', fmt(r.elapsedMillis) + ' ms'],
  ];
  const dl = $('simResult');
  dl.innerHTML = '';
  for (const [k, v] of rows) {
    dl.append(Object.assign(document.createElement('dt'), { textContent: k }));
    dl.append(Object.assign(document.createElement('dd'), { textContent: v }));
  }
}

$('blockMe').onclick = async () => {
  try {
    const r = await api('blocklist', {});
    $('blockMsg').textContent = r.added ? `${r.ip} is now blocked. Reload the shop to see it.` : `${r.ip} was already blocked.`;
  } catch (e) { $('blockMsg').textContent = 'Error: ' + e.message; }
};

// ---- network bottleneck (min-cut computed by Java Edmonds–Karp) -----------
const defaultNet = {
  nodes: ['internet', 'cdn', 'waf', 'lb', 'app-1', 'app-2', 'cache', 'db'],
  links: [
    { from: 'internet', to: 'cdn', capacity: 20000 }, { from: 'cdn', to: 'waf', capacity: 12000 },
    { from: 'waf', to: 'lb', capacity: 9000 }, { from: 'lb', to: 'app-1', capacity: 4000 },
    { from: 'lb', to: 'app-2', capacity: 4000 }, { from: 'app-1', to: 'cache', capacity: 3000 },
    { from: 'app-2', to: 'cache', capacity: 3000 }, { from: 'app-1', to: 'db', capacity: 1200 },
    { from: 'app-2', to: 'db', capacity: 1200 }, { from: 'cache', to: 'db', capacity: 2500 },
  ],
  source: 'internet', sink: 'db',
};
$('netJson').value = JSON.stringify(defaultNet, null, 2);

$('netGo').onclick = async () => {
  let net;
  try { net = JSON.parse($('netJson').value); } catch { $('netMsg').textContent = 'That JSON does not parse.'; return; }
  try {
    const r = await api('bottleneck', net);
    drawNet(net, r);
    $('netMsg').textContent = `Max throughput ${fmt(r.maxFlow)} req/s. Bottleneck: ` +
      (r.minCut.map(l => `${l.from}→${l.to} (${fmt(l.capacity)})`).join(', ') || 'source and sink are disconnected');
  } catch (e) { $('netMsg').textContent = 'Error: ' + e.message; }
};

function drawNet(net, r) {
  // Lay nodes out in columns by hop distance from the source (layout only).
  const depth = { [net.source]: 0 }, q = [net.source];
  while (q.length) {
    const u = q.shift();
    for (const l of net.links) if (l.from === u && !(l.to in depth)) { depth[l.to] = depth[u] + 1; q.push(l.to); }
  }
  const maxD = Math.max(0, ...Object.values(depth));
  net.nodes.forEach(n => { if (!(n in depth)) depth[n] = maxD + 1; });
  const cols = {};
  net.nodes.forEach(n => (cols[depth[n]] ??= []).push(n));
  const ncol = Object.keys(cols).length, pos = {};
  for (const [d, ns] of Object.entries(cols))
    ns.forEach((n, i) => pos[n] = { x: 30 + d * (340 / Math.max(1, ncol - 1)), y: 220 * (i + 1) / (ns.length + 1) });

  const cut = new Set(r.minCut.map(l => l.from + '\u0000' + l.to));
  const svg = $('net'), NS = 'http://www.w3.org/2000/svg';
  svg.innerHTML = '';
  const el = (tag, attrs, text) => {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    if (text !== undefined) e.textContent = text;
    svg.append(e);
  };
  for (const l of net.links) {
    const a = pos[l.from], b = pos[l.to];
    if (!a || !b) continue;
    el('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: cut.has(l.from + '\u0000' + l.to) ? 'cut' : '' });
    el('text', { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - 3, 'text-anchor': 'middle' }, fmt(l.capacity));
  }
  const side = new Set(r.sourceSide);
  for (const n of net.nodes) {
    el('circle', { cx: pos[n].x, cy: pos[n].y, r: 9, class: side.has(n) ? 'src' : '' });
    el('text', { x: pos[n].x, y: pos[n].y + 20, 'text-anchor': 'middle' }, n);
  }
}
$('netGo').click();
