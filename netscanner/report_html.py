"""Self-contained, tabbed HTML report (no external assets, works offline).

Scan data is embedded as JSON and rendered client-side. Everything that came
off the network (banners, headers, hostnames, CVE text) is untrusted:

* the JSON is written with <, > and & escaped so it cannot close the <script>
* the page script HTML-escapes every value before inserting it into the DOM
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape

from . import __version__
from .risks import SEVERITIES
from .scanner import HostResult

CSS = """
:root{--bg:#f4f5f7;--surface:#fff;--sunken:#f8f9fb;--text:#171b24;--muted:#5b6475;--line:#e2e5ea;--accent:#3b5bdb;
--CRITICAL:#c92a2a;--HIGH:#e8590c;--MEDIUM:#f08c00;--LOW:#1c7ed6;--INFO:#868e96;--ok:#2b8a3e;--on-sev:#fff;--on-MEDIUM:#2b1d00}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--surface:#161a22;--sunken:#11151c;--text:#e6e9ef;--muted:#99a2b3;
--line:#262c37;--accent:#7b93ff;--CRITICAL:#ff6b6b;--HIGH:#ff922b;--MEDIUM:#fcc419;--LOW:#4dabf7;--INFO:#adb5bd;
--ok:#51cf66;--on-sev:#111;--on-MEDIUM:#111}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
button,input,select{font:inherit;color:inherit}
.wrap{max-width:1200px;margin:0 auto;padding:0 16px}
header.top{position:sticky;top:0;z-index:5;background:var(--surface);border-bottom:1px solid var(--line)}
header.top .wrap{padding-top:14px}
h1{font-size:18px;margin:0}.meta{color:var(--muted);font-size:13px;margin-top:2px;overflow-wrap:anywhere}
code,.mono{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:12.5px}
[role=tablist]{display:flex;gap:4px;margin-top:10px;overflow-x:auto;scrollbar-width:none}
[role=tab]{background:none;border:0;border-bottom:2px solid transparent;padding:9px 12px;cursor:pointer;
color:var(--muted);font-weight:600;white-space:nowrap;display:flex;gap:6px;align-items:center}
[role=tab]:hover{color:var(--text)}
[role=tab][aria-selected=true]{color:var(--accent);border-bottom-color:var(--accent)}
[role=tab]:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.count{background:var(--sunken);border:1px solid var(--line);border-radius:999px;padding:0 7px;font-size:12px;color:var(--muted)}
main.wrap{padding-top:20px;padding-bottom:48px}
h2{font-size:15px;margin:0 0 10px}
.grid{display:grid;gap:14px}
.kpis{grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}
.two{grid-template-columns:minmax(0,3fr) minmax(0,2fr);align-items:start}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;min-width:0}
.kpi .n{font-size:28px;font-weight:700;line-height:1.1}.kpi .l{color:var(--muted);font-size:13px}
.kpi.alert .n{color:var(--CRITICAL)}
.bar{display:flex;height:12px;border-radius:6px;overflow:hidden;background:var(--sunken);margin:4px 0 10px}
.bar span{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:6px}
.chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:var(--surface);
border-radius:999px;padding:3px 10px;cursor:pointer;font-size:13px}
.chip[aria-pressed=false]{opacity:.45}
.dot{width:9px;height:9px;border-radius:50%;background:var(--c);flex:none}
.pill{display:inline-block;min-width:72px;text-align:center;padding:1px 6px;border-radius:5px;font-size:11px;
font-weight:700;letter-spacing:.03em;background:var(--c);color:var(--on-sev)}
.s-CRITICAL{--c:var(--CRITICAL)}.s-HIGH{--c:var(--HIGH)}.s-MEDIUM{--c:var(--MEDIUM)}.s-LOW{--c:var(--LOW)}.s-INFO{--c:var(--INFO)}
.pill.s-MEDIUM{color:var(--on-MEDIUM)}
.rows{display:flex;flex-direction:column}
.row{display:grid;grid-template-columns:84px minmax(0,1fr) auto;gap:10px;align-items:center;padding:9px 4px;
border-bottom:1px solid var(--line);cursor:pointer;background:none;border-left:0;border-right:0;border-top:0;text-align:left;width:100%}
.row:last-child{border-bottom:0}.row:hover{background:var(--sunken)}
.row .where{color:var(--muted);font-size:12.5px;white-space:nowrap}
.row .t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
details.f{border-bottom:1px solid var(--line)}details.f:last-child{border-bottom:0}
details.f summary{list-style:none;display:grid;grid-template-columns:84px minmax(0,1fr) auto 14px;gap:10px;
align-items:center;padding:9px 4px;cursor:pointer}
details.f summary::-webkit-details-marker{display:none}
details.f summary:hover{background:var(--sunken)}
details.f summary::after{content:"\\25B8";color:var(--muted);transition:transform .15s}
details.f[open] summary::after{transform:rotate(90deg)}
details.f summary .t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500}
details.f summary .where{color:var(--muted);font-size:12.5px;white-space:nowrap}
.fbody{padding:2px 4px 12px 98px;color:var(--muted);overflow-wrap:anywhere}
.fbody .rec{color:var(--text);margin-top:6px}.fbody .rec b{color:var(--ok)}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.toolbar input[type=search],.toolbar select{padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--surface)}
.toolbar input[type=search]{flex:1;min-width:200px}
.toggle{display:inline-flex;gap:6px;align-items:center;cursor:pointer;font-size:13px}
.pager{display:flex;gap:10px;align-items:center;justify-content:flex-end;margin-top:12px;color:var(--muted);font-size:13px}
.pager button,.btn{border:1px solid var(--line);background:var(--surface);border-radius:8px;padding:5px 12px;cursor:pointer}
.pager button:disabled{opacity:.4;cursor:default}
.btn.primary{border-color:var(--accent);color:var(--accent);font-weight:600}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}
tbody tr.click{cursor:pointer}tbody tr.click:hover{background:var(--sunken)}
.scroll{overflow-x:auto}
.clamp{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;color:var(--muted)}
tr.open .clamp{-webkit-line-clamp:unset}
.nowrap{white-space:nowrap}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.kev{color:var(--CRITICAL);font-weight:700;white-space:nowrap}
.hostlayout{display:grid;grid-template-columns:270px minmax(0,1fr);gap:14px;align-items:start}
.hostlist{padding:6px;position:sticky;top:120px;max-height:calc(100vh - 140px);overflow:auto}
.hostbtn{display:flex;width:100%;gap:8px;align-items:center;padding:8px 10px;border:0;background:none;border-radius:8px;cursor:pointer;text-align:left}
.hostbtn:hover{background:var(--sunken)}
.hostbtn[aria-current=true]{background:var(--sunken);box-shadow:inset 3px 0 0 var(--accent)}
.hostbtn .name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hostbtn .sub{color:var(--muted);font-size:12px}
.hosthead{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:baseline;justify-content:space-between;margin-bottom:12px}
.hosthead h2{font-size:17px;margin:0}
.mini{display:flex;gap:4px;flex-wrap:wrap}
.mini span{font-size:11px;font-weight:700;border-radius:4px;padding:0 6px;background:var(--c);color:var(--on-sev)}
.mini span.s-MEDIUM{color:var(--on-MEDIUM)}
.section-title{display:flex;justify-content:space-between;align-items:center;margin:18px 0 6px}
.section-title h3{font-size:13px;margin:0;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.empty{color:var(--muted);padding:24px;text-align:center}
.changes{grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.changes ul{list-style:none;margin:0;padding:0}.changes li{padding:6px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
.changes li:last-child{border-bottom:0}
.plus{color:var(--HIGH)}.minus{color:var(--ok)}
.hint{color:var(--muted);font-size:13px}
footer{color:var(--muted);font-size:12.5px;margin-top:28px}
@media (max-width:820px){.two,.hostlayout{grid-template-columns:1fr}.hostlist{position:static;max-height:240px}
.fbody{padding-left:4px}details.f summary,.row{grid-template-columns:76px minmax(0,1fr) 14px}
details.f summary .where,.row .where{display:none}}
"""

JS = r"""
const D = JSON.parse(document.getElementById('scan-data').textContent);
const SEV = D.severities;
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pill = s => `<span class="pill s-${s}">${s}</span>`;
const hostName = h => h.address + (h.hostname ? ` (${h.hostname})` : '');
const pct = v => v == null ? '–' : (v * 100).toFixed(1) + '%';
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const worst = h => SEV.find(s => h.counts[s]) || null;
const mini = counts => `<span class="mini">${SEV.filter(s => counts[s]).map(s => `<span class="s-${s}" title="${s}">${counts[s]}</span>`).join('')}</span>`;

const FINDINGS = D.hosts.flatMap((h, i) => h.findings.map(f => ({...f, host: i})))
  .sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.host - b.host || (a.port || 0) - (b.port || 0));
const label = h => h.hostname || h.address;
const where = f => `${esc(label(D.hosts[f.host]))}${f.port ? ':' + f.port : ''}`;

function findingRow(f, showHost = true) {
  return `<details class="f"><summary>${pill(f.severity)}<span class="t">${esc(f.title)}</span>` +
    `<span class="where mono">${showHost ? where(f) : (f.port ? f.port + '/tcp' : 'host')}</span></summary>` +
    `<div class="fbody">${esc(f.detail)}<div class="rec"><b>Fix:</b> ${esc(f.recommendation)}</div></div></details>`;
}

function pager(el, total, page, size, go) {
  if (total <= size) { el.innerHTML = total ? plural(total, 'item') : ''; return; }
  const pages = Math.ceil(total / size);
  el.innerHTML = `<span>${page * size + 1}–${Math.min(total, (page + 1) * size)} of ${total}</span>` +
    `<button data-p="${page - 1}" ${page ? '' : 'disabled'}>‹ Prev</button>` +
    `<button data-p="${page + 1}" ${page < pages - 1 ? '' : 'disabled'}>Next ›</button>`;
  el.querySelectorAll('button').forEach(b => b.onclick = () => go(+b.dataset.p));
}

function hostOptions(sel) {
  sel.innerHTML = '<option value="">All hosts</option>' +
    D.hosts.map((h, i) => `<option value="${i}">${esc(hostName(h))}</option>`).join('');
}

/* ---------------- tabs ---------------- */
const tabs = [...document.querySelectorAll('[role=tab]')];
function show(name) {
  if (!tabs.some(t => t.dataset.tab === name)) name = 'overview';
  tabs.forEach(t => { const on = t.dataset.tab === name; t.setAttribute('aria-selected', on); t.tabIndex = on ? 0 : -1; });
  document.querySelectorAll('[role=tabpanel]').forEach(p => p.hidden = p.id !== 'tab-' + name);
  if (location.hash.slice(1) !== name) history.replaceState(null, '', '#' + name);
  window.scrollTo({top: 0});
}
tabs.forEach((t, i) => {
  t.onclick = () => show(t.dataset.tab);
  t.onkeydown = e => {
    const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (d) { const n = tabs[(i + d + tabs.length) % tabs.length]; n.focus(); show(n.dataset.tab); }
  };
});
window.addEventListener('hashchange', () => show(location.hash.slice(1)));

/* ---------------- overview ---------------- */
function renderOverview() {
  const total = FINDINGS.length || 1;
  const counts = Object.fromEntries(SEV.map(s => [s, FINDINGS.filter(f => f.severity === s).length]));
  const exploited = new Set(D.cves.filter(c => c.kev).map(c => c.id)).size;
  const openPorts = D.hosts.reduce((n, h) => n + h.ports.length, 0);
  $('#kpis').innerHTML = [
    [D.hosts.length, `hosts up of ${D.meta.scanned} scanned`],
    [openPorts, 'open ports'],
    [FINDINGS.length, 'findings'],
    D.meta.cve ? [exploited, 'actively exploited CVEs', exploited > 0] : ['–', 'CVE lookup off (run with --cve)'],
  ].map(([n, l, alert]) => `<div class="panel kpi${alert ? ' alert' : ''}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');

  $('#sevbar').innerHTML = SEV.filter(s => counts[s]).map(s =>
    `<span class="s-${s}" style="width:${counts[s] * 100 / total}%;background:var(--c)" title="${counts[s]} ${s}"></span>`).join('');
  $('#legend').innerHTML = SEV.map(s =>
    `<button class="chip s-${s}" data-sev="${s}"><span class="dot"></span>${s.toLowerCase()} <b>${counts[s]}</b></button>`).join('');
  $('#legend').querySelectorAll('button').forEach(b => b.onclick = () => { F.sevs = new Set([b.dataset.sev]); F.page = 0; renderFindings(); show('findings'); });

  const top = FINDINGS.slice(0, 6);
  $('#fixfirst').innerHTML = top.length ? top.map(f =>
    `<button class="row" data-host="${f.host}">${pill(f.severity)}<span class="t">${esc(f.title)}</span><span class="where mono">${where(f)}</span></button>`).join('')
    : '<div class="empty">No findings. Nice.</div>';
  $('#fixfirst').querySelectorAll('[data-host]').forEach(b => b.onclick = () => openHost(+b.dataset.host));
  $('#fixmore').hidden = FINDINGS.length <= top.length;
  $('#fixmore').textContent = `View all ${FINDINGS.length} findings →`;
  $('#fixmore').onclick = () => show('findings');

  const ranked = D.hosts.map((h, i) => ({h, i})).sort((a, b) =>
    SEV.indexOf(worst(a.h) ?? 'Z') - SEV.indexOf(worst(b.h) ?? 'Z') || b.h.findings.length - a.h.findings.length);
  $('#hostsum').innerHTML = ranked.length ? `<table><thead><tr><th>Host</th><th class="num">Ports</th><th>Findings</th></tr></thead><tbody>` +
    ranked.slice(0, 8).map(({h, i}) => `<tr class="click" data-host="${i}"><td class="mono">${esc(hostName(h))}</td>` +
      `<td class="num">${h.ports.length}</td><td>${mini(h.counts) || '<span class="hint">none</span>'}</td></tr>`).join('') +
    `</tbody></table>` + (ranked.length > 8 ? `<p class="hint">+ ${ranked.length - 8} more in the Hosts tab</p>` : '')
    : '<div class="empty">No hosts responded.</div>';
  $('#hostsum').querySelectorAll('[data-host]').forEach(r => r.onclick = () => openHost(+r.dataset.host));

  if (D.changes) {
    const c = D.changes, n = changeCount(c);
    $('#changesum').innerHTML = `<h2>Changes since baseline</h2><p class="hint">Compared with scan from ${esc(c.baseline_generated || 'unknown date')}</p>` +
      `<p>${n ? `<b>${plural(n, 'change')}</b>: ${c.opened_ports.length} opened, ${c.closed_ports.length} closed ports; ` +
      `${c.new_findings.length} new, ${c.resolved_findings.length} resolved findings.` : 'No changes.'}</p>` +
      (n ? '<button class="btn primary" id="gochanges">See changes →</button>' : '');
    const b = $('#gochanges'); if (b) b.onclick = () => show('changes');
  }
}

/* ---------------- findings ---------------- */
const F = {sevs: new Set(SEV), q: '', host: '', page: 0, size: 20};
function renderFindings() {
  $('#fsev').innerHTML = SEV.map(s => `<button class="chip s-${s}" aria-pressed="${F.sevs.has(s)}" data-sev="${s}"><span class="dot"></span>${s.toLowerCase()} ${FINDINGS.filter(f => f.severity === s).length}</button>`).join('');
  $('#fsev').querySelectorAll('button').forEach(b => b.onclick = () => {
    const s = b.dataset.sev;
    if (F.sevs.size === SEV.length) F.sevs = new Set([s]); else F.sevs.has(s) ? F.sevs.delete(s) : F.sevs.add(s);
    if (!F.sevs.size) F.sevs = new Set(SEV);
    F.page = 0; renderFindings();
  });
  const q = F.q.toLowerCase();
  const list = FINDINGS.filter(f => F.sevs.has(f.severity) && (F.host === '' || f.host === +F.host) &&
    (!q || `${f.title} ${f.detail} ${where(f)} ${D.hosts[f.host].hostname}`.toLowerCase().includes(q)));
  const page = list.slice(F.page * F.size, (F.page + 1) * F.size);
  $('#flist').innerHTML = page.length ? page.map(f => findingRow(f)).join('') : '<div class="empty">No findings match these filters.</div>';
  pager($('#fpager'), list.length, F.page, F.size, p => { F.page = p; renderFindings(); window.scrollTo({top: 0}); });
}
$('#fq').oninput = e => { F.q = e.target.value; F.page = 0; renderFindings(); };
hostOptions($('#fhost'));
$('#fhost').onchange = e => { F.host = e.target.value; F.page = 0; renderFindings(); };

/* ---------------- hosts ---------------- */
let current = 0;
function openHost(i) { current = i; renderHosts(); show('hosts'); }
function renderHosts() {
  const q = ($('#hq')?.value || '').toLowerCase();
  $('#hlist').innerHTML = D.hosts.map((h, i) => ({h, i})).filter(({h}) => !q || hostName(h).toLowerCase().includes(q))
    .map(({h, i}) => { const w = worst(h);
      return `<button class="hostbtn ${w ? 's-' + w : ''}" data-host="${i}" aria-current="${i === current}">` +
        `<span class="dot" style="${w ? '' : 'background:var(--line)'}"></span><span class="name"><span class="mono">${esc(h.address)}</span>` +
        `${h.hostname ? `<br><span class="sub">${esc(h.hostname)}</span>` : ''}</span><span class="sub">${plural(h.ports.length, 'port')}</span></button>`; }).join('')
    || '<div class="empty">No hosts</div>';
  $('#hlist').querySelectorAll('[data-host]').forEach(b => b.onclick = () => { current = +b.dataset.host; renderHosts(); });

  const h = D.hosts[current];
  if (!h) { $('#hdetail').innerHTML = '<div class="empty">No hosts responded.</div>'; return; }
  const cveCount = D.cves.filter(c => c.host === current).length;
  $('#hdetail').innerHTML =
    `<div class="hosthead"><h2 class="mono">${esc(hostName(h))}</h2>${mini(h.counts)}</div>` +
    `<div class="section-title"><h3>Open ports</h3></div>` +
    (h.ports.length ? `<div class="scroll"><table><thead><tr><th>Port</th><th>Service</th><th>Version / banner</th><th>TLS</th><th class="num">CVEs</th></tr></thead><tbody>` +
      h.ports.map(p => `<tr><td class="mono">${p.port}/tcp</td><td>${esc(p.service)}</td><td class="mono">${esc(p.version)}</td>` +
        `<td>${esc(p.tls)}</td><td class="num">${p.cves ? p.cves + (p.kev ? ` <span class="kev">(${p.kev} KEV)</span>` : '') : ''}</td></tr>`).join('') +
      `</tbody></table></div>` : '<div class="empty">No open ports found.</div>') +
    `<div class="section-title"><h3>Findings (${h.findings.length})</h3>` +
    (cveCount ? `<button class="btn" id="hcves">View ${plural(cveCount, 'CVE')} →</button>` : '') + `</div>` +
    (h.findings.length ? `<div>${h.findings.map(f => findingRow({...f, host: current}, false)).join('')}</div>` : '<div class="empty">No findings for this host.</div>');
  const b = $('#hcves'); if (b) b.onclick = () => { V.host = String(current); $('#vhost').value = V.host; V.page = 0; renderVulns(); show('vulns'); };
}
$('#hq').oninput = renderHosts;

/* ---------------- vulnerabilities ---------------- */
const V = {kev: false, q: '', host: '', page: 0, size: 25};
function renderVulns() {
  if (!D.meta.cve) { $('#vbody').innerHTML = '<div class="empty">CVE lookup was not enabled for this scan.<br>Re-run with <code>--cve</code> to see known vulnerabilities, ranked by CISA KEV and EPSS.</div>'; return; }
  const q = V.q.toLowerCase();
  const list = D.cves.filter(c => (!V.kev || c.kev) && (V.host === '' || c.host === +V.host) &&
    (!q || `${c.id} ${c.product} ${c.summary} ${hostName(D.hosts[c.host])}`.toLowerCase().includes(q)));
  const page = list.slice(V.page * V.size, (V.page + 1) * V.size);
  $('#vtable').innerHTML = page.length ? `<table><thead><tr><th>CVE</th><th>Affects</th><th class="num">CVSS</th><th class="num">EPSS</th><th>KEV</th><th>Summary</th></tr></thead><tbody>` +
    page.map(c => `<tr class="click"><td class="mono nowrap"><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}" target="_blank" rel="noopener">${esc(c.id)}</a></td>` +
      `<td><span class="mono nowrap">${esc(label(D.hosts[c.host]))}:${c.port}</span><br><span class="hint">${esc(c.product)}</span></td>` +
      `<td class="num">${c.cvss ?? '–'}</td><td class="num">${pct(c.epss)}</td>` +
      `<td>${c.kev ? `<span class="kev">Exploited${c.ransomware ? ' · ransomware' : ''}</span>` : ''}</td>` +
      `<td><div class="clamp">${esc(c.summary)}</div></td></tr>`).join('') + `</tbody></table>`
    : '<div class="empty">No CVEs match these filters.</div>';
  $('#vtable').querySelectorAll('tr.click').forEach(r => r.onclick = e => { if (e.target.tagName !== 'A') r.classList.toggle('open'); });
  pager($('#vpager'), list.length, V.page, V.size, p => { V.page = p; renderVulns(); window.scrollTo({top: 0}); });
}
$('#vkev').onchange = e => { V.kev = e.target.checked; V.page = 0; renderVulns(); };
$('#vq').oninput = e => { V.q = e.target.value; V.page = 0; renderVulns(); };
hostOptions($('#vhost'));
$('#vhost').onchange = e => { V.host = e.target.value; V.page = 0; renderVulns(); };

/* ---------------- changes ---------------- */
function changeCount(c) {
  return ['new_hosts', 'missing_hosts', 'opened_ports', 'closed_ports', 'new_findings', 'resolved_findings'].reduce((n, k) => n + c[k].length, 0);
}
function renderChanges() {
  const c = D.changes; if (!c) return;
  const loc = x => `<span class="mono">${esc(x.address)}${x.port ? ':' + x.port : ''}</span>`;
  const box = (title, items, cls) => `<div class="panel"><h2>${title} <span class="count">${items.length}</span></h2>` +
    (items.length ? `<ul>${items.map(i => `<li class="${cls}">${i}</li>`).join('')}</ul>` : '<p class="hint">None</p>') + `</div>`;
  $('#cbody').innerHTML = `<p class="hint">Compared with scan from ${esc(c.baseline_generated || 'unknown date')}. Use the same targets and ports for both scans.</p>` +
    `<div class="grid changes">` +
    box('New findings', c.new_findings.map(x => `${pill(x.severity)} ${esc(x.title)}<br>${loc(x)}`), '') +
    box('Newly opened ports', c.opened_ports.map(x => `${loc(x)} ${esc(x.service)}`), 'plus') +
    box('Resolved findings', c.resolved_findings.map(x => `${pill(x.severity)} ${esc(x.title)}<br>${loc(x)}`), '') +
    box('Closed ports', c.closed_ports.map(x => `${loc(x)} ${esc(x.service)}`), 'minus') +
    box('New hosts', c.new_hosts.map(h => `<span class="mono">${esc(h)}</span>`), 'plus') +
    box('Hosts gone', c.missing_hosts.map(h => `<span class="mono">${esc(h)}</span>`), 'minus') + `</div>`;
}

renderOverview(); renderFindings(); renderHosts(); renderVulns(); renderChanges();
show(location.hash.slice(1));
"""


def _data(hosts: list[HostResult], changes: dict | None) -> dict:
    up = [h for h in hosts if h.up]
    hosts_data, cves = [], []
    for i, h in enumerate(up):
        ports = []
        for p in sorted(h.ports, key=lambda p: p.port):
            software = f"{p.product} {p.version}".strip()
            ports.append({"port": p.port, "service": p.service, "version": software or p.banner,
                          "tls": (p.tls or {}).get("protocol", ""), "cves": len(p.cves),
                          "kev": sum(1 for c in p.cves if c.get("kev"))})
            cves += [{"id": c["id"], "host": i, "port": p.port, "product": software,
                      "cvss": c.get("cvss"), "epss": c.get("epss"), "kev": bool(c.get("kev")),
                      "ransomware": bool(c.get("ransomware")), "summary": c.get("summary", "")}
                     for c in p.cves]
        hosts_data.append({
            "address": h.target.address, "hostname": h.target.hostname, "ports": ports,
            "counts": {s: sum(f.severity == s for f in h.findings) for s in SEVERITIES},
            "findings": [{"severity": f.severity, "port": f.port, "title": f.title,
                          "detail": f.detail, "recommendation": f.recommendation} for f in h.findings],
        })
    cves.sort(key=lambda c: (c["kev"], c["epss"] or 0, c["cvss"] or 0), reverse=True)
    return {
        "severities": SEVERITIES,
        "meta": {"scanned": len(hosts), "cve": any(p.cpes for h in up for p in h.ports)},
        "hosts": hosts_data, "cves": cves, "changes": changes,
    }


def _script_safe_json(data: dict) -> str:
    """JSON that can't terminate the surrounding <script> element."""
    return (json.dumps(data, separators=(",", ":"))
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def _esc(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def render(hosts: list[HostResult], meta: dict, changes: dict | None = None) -> str:
    data = _data(hosts, changes)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    findings = sum(len(h["findings"]) for h in data["hosts"])
    tab = lambda key, label, count=None: (
        f'<button role="tab" id="t-{key}" data-tab="{key}" aria-controls="tab-{key}" aria-selected="false">'
        f'{label}{f" <span class=count>{count}</span>" if count is not None else ""}</button>')
    tabs = (tab("overview", "Overview") + tab("findings", "Findings", findings)
            + tab("hosts", "Hosts", len(data["hosts"])) + tab("vulns", "Vulnerabilities", len(data["cves"]))
            + (tab("changes", "Changes", sum(len(v) for k, v in changes.items() if isinstance(v, list)))
               if changes is not None else ""))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Scan Report</title><style>{CSS}</style></head>
<body>
<header class="top"><div class="wrap">
<h1>Network Scan Report</h1>
<div class="meta">Targets <code>{_esc(meta.get("targets"))}</code> &middot; ports <code>{_esc(meta.get("ports"))}</code>
&middot; {generated} &middot; {_esc(meta.get("elapsed_seconds"))}s &middot; netscanner {__version__}</div>
<nav role="tablist" aria-label="Report sections">{tabs}</nav>
</div></header>
<main class="wrap">

<section role="tabpanel" id="tab-overview" aria-labelledby="t-overview">
  <div class="grid kpis" id="kpis"></div>
  <div class="panel" style="margin-top:14px"><h2>Findings by severity</h2><div class="bar" id="sevbar"></div><div class="legend" id="legend"></div></div>
  <div class="grid two" style="margin-top:14px">
    <div class="panel"><h2>Fix these first</h2><div class="rows" id="fixfirst"></div>
      <div style="margin-top:10px"><button class="btn primary" id="fixmore"></button></div></div>
    <div class="grid">
      <div class="panel"><h2>Hosts by risk</h2><div class="scroll" id="hostsum"></div></div>
      {'<div class="panel" id="changesum"></div>' if changes is not None else ''}
    </div>
  </div>
</section>

<section role="tabpanel" id="tab-findings" aria-labelledby="t-findings" hidden>
  <div class="panel">
    <div class="toolbar"><div class="legend" id="fsev"></div></div>
    <div class="toolbar"><select id="fhost" aria-label="Host"></select>
      <input id="fq" type="search" placeholder="Search findings, hosts, ports..." aria-label="Search findings"></div>
    <div id="flist"></div><div class="pager" id="fpager"></div>
  </div>
</section>

<section role="tabpanel" id="tab-hosts" aria-labelledby="t-hosts" hidden>
  <div class="hostlayout">
    <div class="panel hostlist"><input id="hq" type="search" placeholder="Filter hosts..." aria-label="Filter hosts"
      style="width:100%;padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--surface);margin-bottom:6px">
      <div id="hlist"></div></div>
    <div class="panel" id="hdetail"></div>
  </div>
</section>

<section role="tabpanel" id="tab-vulns" aria-labelledby="t-vulns" hidden>
  <div class="panel" id="vbody">
    <div class="toolbar"><label class="toggle"><input type="checkbox" id="vkev"> Actively exploited only (CISA KEV)</label>
      <select id="vhost" aria-label="Host"></select>
      <input id="vq" type="search" placeholder="Search CVE id, product, description..." aria-label="Search CVEs"></div>
    <p class="hint" style="margin-top:0">Sorted by priority: exploited in the wild first, then EPSS (chance of exploitation in 30 days), then CVSS. Click a row to expand.</p>
    <div class="scroll" id="vtable"></div><div class="pager" id="vpager"></div>
  </div>
</section>

<section role="tabpanel" id="tab-changes" aria-labelledby="t-changes" hidden><div id="cbody"></div></section>

<footer>Findings are heuristics based on exposure and version strings &mdash; verify before acting.
Only scan systems you are authorized to test.</footer>
</main>
<script type="application/json" id="scan-data">{_script_safe_json(data)}</script>
<script>{JS}</script>
</body></html>
"""
