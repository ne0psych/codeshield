/* CodeShield Professional Scanner - app.js */
(function() {
'use strict';

// ─── State ───
let currentPage = 'dashboard';
let scanHistory = [];
let activeScanId = null;
let allFindings = [];
let currentFindings = [];
let activeFilter = { tab: 'all', sev: '', owasp: '', search: '' };
let elapsedTimer = null;

// ─── DOM helpers ───
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
const hide = el => el?.classList.add('hidden');
const show = el => el?.classList.remove('hidden');
const esc = s => { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; };

// ─── Navigation ───
function navigateTo(page) {
    currentPage = page;
    $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.page === page));
    $$('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page));
    if (page === 'dashboard') loadDashboard();
    else if (page === 'results' && activeScanId) loadResults(activeScanId);
    else if (page === 'reports') loadReportsPage();
    else if (page === 'sync') loadSyncStatus();
    else if (page === 'settings') loadSettings();
}

$$('.nav-item').forEach(btn => btn.addEventListener('click', () => navigateTo(btn.dataset.page)));

// ─── Theme ───
$('#theme-toggle').addEventListener('click', () => {
    const html = document.documentElement;
    const next = html.dataset.theme === 'dark' ? 'light' : 'dark';
    html.dataset.theme = next;
    localStorage.setItem('cs-theme', next);
});
if (localStorage.getItem('cs-theme') === 'light') document.documentElement.dataset.theme = 'light';

// ─── Dashboard ───
async function loadDashboard() {
    try {
        const resp = await fetch('/api/scans');
        if (!resp.ok) return;
        const data = await resp.json();
        scanHistory = Array.isArray(data) ? data : (data.scans || []);
        if (scanHistory.length > 0 && !activeScanId) activeScanId = scanHistory[0].scan_id;
    } catch(e) { scanHistory = []; }

    let totalFindings = 0, crit = 0, high = 0, med = 0, low = 0;
    scanHistory.forEach(s => {
        totalFindings += s.total_findings || 0;
        crit += s.critical_count || 0;
        high += s.high_count || 0;
        med += s.medium_count || 0;
        low += s.low_count || 0;
    });
    $('#stat-scans').textContent = scanHistory.length;
    $('#stat-findings').textContent = totalFindings;
    $('#stat-critical').textContent = crit;
    $('#stat-high').textContent = high;
    $('#stat-medium').textContent = med;
    $('#stat-low').textContent = low;

    drawSeverityPie(crit, high, med, low);

    // Recent scans table
    const body = $('#recent-scans-body');
    body.innerHTML = '';
    scanHistory.slice(0, 10).forEach(s => {
        const tr = document.createElement('tr');
        const statusCls = (s.critical_count||0) > 0 ? 'status-fail' : 'status-ok';
        const statusTxt = (s.critical_count||0) > 0 ? 'At Risk' : 'Secure';
        tr.innerHTML = `<td>${esc(s.filename)}</td><td>${formatDate(s.started_at)}</td>
            <td>${s.total_findings||0}</td><td>${s.critical_count||0}</td><td>${s.high_count||0}</td>
            <td><span class="${statusCls}">${statusTxt}</span></td>
            <td><button class="btn btn-sm" onclick="viewScan('${s.scan_id}')">View</button></td>`;
        body.appendChild(tr);
    });

    loadOWASPGrid();
}

function drawSeverityPie(c, h, m, l) {
    const canvas = $('#sev-pie');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const total = c + h + m + l || 1;
    const data = [
        { val: c, color: '#ef4444', label: 'Critical' },
        { val: h, color: '#f97316', label: 'High' },
        { val: m, color: '#eab308', label: 'Medium' },
        { val: l, color: '#3b82f6', label: 'Low' },
    ];
    const W = canvas.width, H = canvas.height;
    const cx = W/2, cy = H/2, R = Math.min(W,H)/2 - 30;
    ctx.clearRect(0, 0, W, H);
    let angle = -Math.PI/2;
    data.forEach(d => {
        const slice = (d.val / total) * Math.PI * 2;
        if (d.val > 0) {
            ctx.beginPath();
            ctx.moveTo(cx, cy);
            ctx.arc(cx, cy, R, angle, angle + slice);
            ctx.closePath();
            ctx.fillStyle = d.color;
            ctx.fill();
            // Label
            const mid = angle + slice/2;
            const lx = cx + (R * 0.65) * Math.cos(mid);
            const ly = cy + (R * 0.65) * Math.sin(mid);
            if (slice > 0.3) {
                ctx.fillStyle = '#fff';
                ctx.font = 'bold 12px Inter';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(d.val, lx, ly);
            }
        }
        angle += slice;
    });
    // Legend
    let ly = H - 18;
    ctx.font = '11px Inter';
    ctx.textBaseline = 'middle';
    let lx = 10;
    data.forEach(d => {
        ctx.fillStyle = d.color;
        ctx.fillRect(lx, ly - 5, 10, 10);
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-2').trim() || '#888';
        ctx.textAlign = 'left';
        ctx.fillText(`${d.label}: ${d.val}`, lx + 14, ly);
        lx += 85;
    });
}

async function loadOWASPGrid() {
    const grid = $('#owasp-grid');
    if (!grid) return;
    const labels = {
        'A01:2021': 'Broken Access Control', 'A02:2021': 'Cryptographic Failures',
        'A03:2021': 'Injection', 'A04:2021': 'Insecure Design',
        'A05:2021': 'Security Misconfiguration', 'A06:2021': 'Vulnerable Components',
        'A07:2021': 'Auth Failures', 'A08:2021': 'Integrity Failures',
        'A09:2021': 'Logging Failures', 'A10:2021': 'SSRF'
    };
    // Count from last scan
    const counts = {};
    Object.keys(labels).forEach(k => counts[k] = 0);
    if (scanHistory.length > 0 && activeScanId) {
        try {
            const r = await fetch(`/api/scan/${activeScanId}/results`);
            if (r.ok) {
                const d = await r.json();
                (d.findings || []).forEach(f => {
                    const o = f.owasp_category;
                    if (o && counts[o] !== undefined) counts[o]++;
                });
            }
        } catch(e) {}
    }
    grid.innerHTML = '';
    Object.entries(labels).forEach(([k, v]) => {
        const n = counts[k] || 0;
        const bgC = n === 0 ? 'var(--bg-2)' : n < 3 ? 'var(--med-bg)' : 'var(--crit-bg)';
        const c = n === 0 ? 'var(--text-3)' : n < 3 ? 'var(--med)' : 'var(--crit)';
        grid.innerHTML += `<div class="owasp-cell" style="background:${bgC};color:${c}" title="${k}: ${v}"><span class="oc-n">${n}</span><span class="oc-l">${k.split(':')[0]}</span></div>`;
    });
}

// ─── Upload / Scan ───
const uploadZone = $('#upload-zone');
const fileInput = $('#file-input');

uploadZone?.addEventListener('click', () => fileInput.click());
$('#browse-btn')?.addEventListener('click', e => { e.stopPropagation(); fileInput.click(); });
fileInput?.addEventListener('change', e => { if (e.target.files[0]) startUpload(e.target.files[0]); });

['dragover','dragenter'].forEach(ev => uploadZone?.addEventListener(ev, e => { e.preventDefault(); uploadZone.classList.add('drag-over'); }));
['dragleave','drop'].forEach(ev => uploadZone?.addEventListener(ev, e => { e.preventDefault(); uploadZone.classList.remove('drag-over'); }));
uploadZone?.addEventListener('drop', e => { if (e.dataTransfer.files[0]) startUpload(e.dataTransfer.files[0]); });

async function startUpload(file) {
    if (!file.name.endsWith('.zip')) return alert('Please upload a .zip file');
    const formData = new FormData();
    formData.append('file', file);

    hide(uploadZone);
    show($('#progress-section'));
    $('#scan-filename').textContent = file.name;
    $('#plugin-progress').innerHTML = '<div class="plug-item"><div class="spinner"></div><span class="plug-name">Uploading...</span></div>';

    let startTime = Date.now();
    elapsedTimer = setInterval(() => {
        const secs = Math.floor((Date.now() - startTime) / 1000);
        $('#elapsed-time').textContent = `${String(Math.floor(secs/60)).padStart(2,'0')}:${String(secs%60).padStart(2,'0')}`;
    }, 1000);

    try {
        const resp = await fetch('/api/upload', { method: 'POST', body: formData });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Upload failed');
        activeScanId = data.scan_id;
        listenSSE(data.scan_id);
    } catch(e) {
        clearInterval(elapsedTimer);
        $('#plugin-progress').innerHTML = `<div class="plug-item failed"><div class="plug-icon failed">X</div><span class="plug-name">${esc(e.message)}</span></div>`;
    }
}

function listenSSE(scanId) {
    const es = new EventSource(`/api/scan/${scanId}/events`);
    const plugStates = {};
    const container = $('#plugin-progress');

    es.addEventListener('plugin_start', e => {
        const d = JSON.parse(e.data);
        plugStates[d.plugin] = { status: 'running', findings: 0 };
        renderPluginProgress(container, plugStates);
    });
    es.addEventListener('plugin_complete', e => {
        const d = JSON.parse(e.data);
        plugStates[d.plugin] = { status: 'complete', findings: d.findings_count || 0 };
        renderPluginProgress(container, plugStates);
    });
    es.addEventListener('plugin_error', e => {
        const d = JSON.parse(e.data);
        plugStates[d.plugin] = { status: 'failed', error: d.error || '' };
        renderPluginProgress(container, plugStates);
    });
    es.addEventListener('scan_complete', e => {
        es.close();
        clearInterval(elapsedTimer);
        const d = JSON.parse(e.data);
        container.innerHTML += `<div class="plug-item complete"><div class="plug-icon complete">&#10003;</div><span class="plug-name">Scan complete - ${d.total_findings || 0} findings</span></div>`;
        activeScanId = scanId;
        setTimeout(() => navigateTo('results'), 800);
    });
    es.addEventListener('scan_error', e => {
        es.close();
        clearInterval(elapsedTimer);
        const d = JSON.parse(e.data);
        container.innerHTML += `<div class="plug-item failed"><div class="plug-icon failed">X</div><span class="plug-name">Scan failed: ${esc(d.error)}</span></div>`;
    });
    es.onerror = () => { es.close(); };
}

function renderPluginProgress(container, states) {
    container.innerHTML = '';
    Object.entries(states).forEach(([name, s]) => {
        let icon = '<div class="spinner"></div>';
        let cls = '';
        if (s.status === 'complete') { icon = '<div class="plug-icon complete">&#10003;</div>'; cls = 'complete'; }
        else if (s.status === 'failed') { icon = '<div class="plug-icon failed">&#10007;</div>'; cls = 'failed'; }
        const detail = s.status === 'complete' ? `${s.findings} findings` : s.error || '';
        container.innerHTML += `<div class="plug-item ${cls}">${icon}<span class="plug-name">${esc(name)}</span><span class="plug-detail">${esc(detail)}</span></div>`;
    });
}

// ─── Results ───
async function loadResults(scanId) {
    if (!scanId) return;
    activeScanId = scanId;
    try {
        const resp = await fetch(`/api/scan/${scanId}/results`);
        if (!resp.ok) return;
        const data = await resp.json();
        allFindings = data.findings || [];
        currentFindings = [...allFindings];
        renderSeverityCounts(data.scan);
        applyFilters();
        loadSBOM(data);
    } catch(e) { console.error('Load results error:', e); }

    // Risk score
    try {
        const r2 = await fetch(`/api/scan/${scanId}/risk-score`);
        if (r2.ok) {
            const rd = await r2.json();
            const badge = $('#risk-badge');
            badge.textContent = rd.risk_score ?? '--';
            badge.className = 'risk-badge ' + (rd.risk_score >= 75 ? 'risk-crit' : rd.risk_score >= 50 ? 'risk-high' : rd.risk_score >= 25 ? 'risk-med' : 'risk-low');
        }
    } catch(e) {}

    // Trends
    try {
        const r3 = await fetch(`/api/scan/${scanId}/trends`);
        if (r3.ok) {
            const td = await r3.json();
            $('#trend-new').textContent = `${td.new_count ?? 0} New`;
            $('#trend-rec').textContent = `${td.recurring_count ?? 0} Recurring`;
        }
    } catch(e) {}

    // Download buttons
    $('#btn-xlsx').onclick = () => window.open(`/api/scan/${scanId}/report/excel`);
    $('#btn-pdf').onclick = () => window.open(`/api/scan/${scanId}/report/pdf`);
}

function renderSeverityCounts(scan) {
    if (!scan) return;
    $('#rc-critical').textContent = scan.critical_count || 0;
    $('#rc-high').textContent = scan.high_count || 0;
    $('#rc-medium').textContent = scan.medium_count || 0;
    $('#rc-low').textContent = scan.low_count || 0;
    $('#rc-info').textContent = scan.info_count || 0;
}

// Filter tabs
$$('.ftab').forEach(tab => tab.addEventListener('click', () => {
    $$('.ftab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    activeFilter.tab = tab.dataset.tab;
    applyFilters();
}));
$('#f-sev')?.addEventListener('change', e => { activeFilter.sev = e.target.value; applyFilters(); });
$('#f-owasp')?.addEventListener('change', e => { activeFilter.owasp = e.target.value; applyFilters(); });
$('#f-search')?.addEventListener('input', e => { activeFilter.search = e.target.value.toLowerCase(); applyFilters(); });

function applyFilters() {
    currentFindings = allFindings.filter(f => {
        if (activeFilter.tab !== 'all' && f.plugin_name !== activeFilter.tab) return false;
        if (activeFilter.sev && f.severity !== activeFilter.sev) return false;
        if (activeFilter.owasp && f.owasp_category !== activeFilter.owasp) return false;
        if (activeFilter.search) {
            const haystack = [f.title, f.file_path, f.cwe_id, f.cve_id, f.rule_id, f.description].join(' ').toLowerCase();
            if (!haystack.includes(activeFilter.search)) return false;
        }
        return true;
    });
    renderFindings();
}

function renderFindings() {
    const body = $('#findings-body');
    body.innerHTML = '';
    if (currentFindings.length === 0) { show($('#no-findings')); return; }
    hide($('#no-findings'));

    currentFindings.forEach((f, i) => {
        const tr = document.createElement('tr');
        tr.addEventListener('click', () => openFindingModal(f));
        const trendCls = f.trend_status === 'recurring' ? 'recurring' : '';
        tr.innerHTML = `<td>${i+1}</td>
            <td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td>
            <td>${esc(f.plugin_name)}</td>
            <td>${esc(f.title)}</td>
            <td title="${esc(f.file_path)}">${esc(shortPath(f.file_path))}:${f.line_number||''}</td>
            <td>${f.cwe_id ? `<span class="tag tag-cwe">${f.cwe_id}</span>` : ''}</td>
            <td>${f.owasp_category ? `<span class="tag tag-owasp">${f.owasp_category.split(':')[0]}</span>` : ''}</td>
            <td>${f.cve_id ? `<span class="tag tag-cve">${f.cve_id}</span>` : ''}</td>
            <td><span class="tag tag-trend ${trendCls}">${f.trend_status || 'new'}</span></td>`;
        body.appendChild(tr);
    });
}

function shortPath(p) {
    if (!p) return '';
    const parts = p.split(/[\/\\]/);
    return parts.length > 2 ? '.../' + parts.slice(-2).join('/') : p;
}

// ─── Finding Modal ───
function openFindingModal(f) {
    const m = $('#modal-body');
    m.innerHTML = `
        <div class="modal-title"><span class="sev-badge sev-${f.severity}">${f.severity}</span> ${esc(f.title)}</div>
        <div class="mf-grid">
            <div class="mf"><div class="mf-label">Scanner</div><div class="mf-val">${esc(f.plugin_name)}</div></div>
            <div class="mf"><div class="mf-label">Rule ID</div><div class="mf-val">${esc(f.rule_id||'')}</div></div>
            <div class="mf"><div class="mf-label">File</div><div class="mf-val">${esc(f.file_path||'')}:${f.line_number||''}</div></div>
            <div class="mf"><div class="mf-label">CWE</div><div class="mf-val">${f.cwe_id ? `<span class="tag tag-cwe">${f.cwe_id}</span> ${esc(f.cwe_label||'')}` : '-'}</div></div>
            <div class="mf"><div class="mf-label">OWASP</div><div class="mf-val">${f.owasp_category ? `<span class="tag tag-owasp">${f.owasp_category}</span> ${esc(f.owasp_label||'')}` : '-'}</div></div>
            <div class="mf"><div class="mf-label">MITRE ATT&CK</div><div class="mf-val">${f.mitre_id || '-'} ${esc(f.mitre_label||'')}</div></div>
            <div class="mf"><div class="mf-label">CVE</div><div class="mf-val">${f.cve_id ? `<span class="tag tag-cve">${f.cve_id}</span>` : '-'}</div></div>
            <div class="mf"><div class="mf-label">CVSS Score</div><div class="mf-val">${f.cvss_score || '-'}</div></div>
            <div class="mf"><div class="mf-label">Exploit</div><div class="mf-val">${esc(f.exploit_available||'unknown')}</div></div>
            <div class="mf"><div class="mf-label">Fix Effort</div><div class="mf-val">${f.fix_effort_hours||'?'} hours</div></div>
            <div class="mf"><div class="mf-label">PCI-DSS</div><div class="mf-val">${esc(f.pci_dss||'-')}</div></div>
            <div class="mf"><div class="mf-label">HIPAA</div><div class="mf-val">${esc(f.hipaa||'-')}</div></div>
        </div>
        ${f.description ? `<div class="mf"><div class="mf-label">Description</div><div class="mf-val">${esc(f.description)}</div></div>` : ''}
        ${f.code_snippet ? `<div class="mf"><div class="mf-label">Code Snippet</div><div class="mf-code">${esc(f.code_snippet)}</div></div>` : ''}
        ${f.remediation ? `<div class="mf"><div class="mf-label">Remediation</div><div class="mf-fix">${esc(f.remediation)}</div></div>` : ''}
        <div style="margin-top:.8rem;display:flex;gap:.5rem;align-items:center">
            <label style="font-size:.78rem;font-weight:500">False Positive:</label>
            <button class="btn btn-sm" id="fp-toggle">${f.false_positive ? 'Yes - Click to reset' : 'No - Mark as FP'}</button>
        </div>
    `;
    show($('#modal'));
    $('#fp-toggle').addEventListener('click', async () => {
        if (!activeScanId || !f.id) return;
        try {
            const r = await fetch(`/api/finding/${f.id}/false-positive`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ false_positive: !f.false_positive }) });
            if (r.ok) { f.false_positive = !f.false_positive; openFindingModal(f); }
        } catch(e) {}
    });
}

$('#modal-close')?.addEventListener('click', () => hide($('#modal')));
$('#modal')?.addEventListener('click', e => { if (e.target === $('#modal')) hide($('#modal')); });

// ─── SBOM ───
function loadSBOM(data) {
    const body = $('#sbom-body');
    const sbom = data.sbom || {};
    const comps = sbom.components || [];
    body.innerHTML = '';
    if (comps.length === 0) { show($('#no-sbom')); return; }
    hide($('#no-sbom'));
    comps.forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${esc(c.name)}</td><td>${esc(c.version)}</td><td>${esc(c.ecosystem)}</td><td>${esc(c.license)}</td><td title="${esc(c.purl)}">${esc(shortPurl(c.purl))}</td>`;
        body.appendChild(tr);
    });
}
function shortPurl(p) { return p && p.length > 50 ? p.slice(0, 48) + '...' : (p || ''); }

// ─── Reports page ───
async function loadReportsPage() {
    const body = $('#reports-body');
    body.innerHTML = '';
    scanHistory.forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${esc(s.filename)}</td><td>${formatDate(s.started_at)}</td><td>${s.total_findings||0}</td>
            <td><button class="btn btn-sm btn-primary" onclick="window.open('/api/scan/${s.scan_id}/report/pdf')">PDF</button></td>
            <td><button class="btn btn-sm" onclick="window.open('/api/scan/${s.scan_id}/report/excel')">Excel</button></td>`;
        body.appendChild(tr);
    });
}

// ─── Sync Status ───
async function loadSyncStatus() {
    const grid = $('#sync-grid');
    grid.innerHTML = '<p style="color:var(--text-3)">Loading sync status...</p>';
    try {
        const r = await fetch('/api/health');
        if (!r.ok) return;
        const d = await r.json();
        grid.innerHTML = '';

        // Plugins card
        grid.innerHTML += `<div class="sync-card"><h4>Scanner Plugins</h4>
            ${(d.plugins || []).map(p => `<div class="sync-row"><span>${esc(p)}</span><span class="sync-ok">Active</span></div>`).join('')}
        </div>`;

        // Sync sources
        const sources = ['osv_vulnerabilities', 'spdx_licenses', 'nvd_vulnerabilities', 'github_advisories', 'ossindex'];
        const labels = { osv_vulnerabilities: 'OSV.dev', spdx_licenses: 'SPDX Licenses', nvd_vulnerabilities: 'NVD (NIST)', github_advisories: 'GitHub Advisory', ossindex: 'OSS Index' };

        let syncHtml = '<div class="sync-card"><h4>Data Sources</h4>';
        for (const src of sources) {
            try {
                const sr = await fetch(`/api/sync/${src}`);
                if (sr.ok) {
                    const sd = await sr.json();
                    const statusOk = ['ok','updated','unchanged'].includes(sd.status);
                    const statusCls = statusOk ? 'sync-ok' : sd.status === 'degraded' ? 'sync-fail' : 'sync-skip';
                    const statusText = statusOk ? 'Synced' : sd.status === 'degraded' ? 'Degraded' : sd.status === 'not_synced' ? 'Not synced' : 'Pending';
                    syncHtml += `<div class="sync-row"><span>${labels[src]||src}</span><span class="${statusCls}">${statusText}</span></div>`;
                    if (sd.last_sync_at) syncHtml += `<div class="sync-row" style="padding-left:1rem"><span style="color:var(--text-3);font-size:.72rem">Last: ${formatDate(sd.last_sync_at)}</span><span style="font-size:.72rem;color:var(--text-3)">${sd.records_count||0} records</span></div>`;
                } else {
                    syncHtml += `<div class="sync-row"><span>${labels[src]||src}</span><span class="sync-skip">Not synced</span></div>`;
                }
            } catch(e) {
                syncHtml += `<div class="sync-row"><span>${labels[src]||src}</span><span class="sync-skip">Not available</span></div>`;
            }
        }
        syncHtml += '</div>';
        grid.innerHTML += syncHtml;
    } catch(e) {
        grid.innerHTML = '<p class="empty-state">Could not load sync status</p>';
    }
}

// ─── Settings ───
async function loadSettings() {
    try {
        const r = await fetch('/api/health');
        if (r.ok) {
            const d = await r.json();
            $('#settings-plugins').textContent = (d.plugins || []).join(', ');
        }
    } catch(e) {}
}

// ─── Global Search ───
$('#global-search')?.addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    if (q.length < 2) return;
    // If on results page, filter inline
    if (currentPage === 'results') {
        activeFilter.search = q;
        applyFilters();
    }
});

// ─── Utility ───
function formatDate(d) {
    if (!d) return '-';
    try { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); } catch(e) { return d; }
}

// Global helpers for inline onclick
window.viewScan = function(id) { activeScanId = id; navigateTo('results'); };

// ─── Init ───
loadDashboard();
fetch('/api/health').then(r => r.json()).then(d => {
    $('#plugin-count-badge').textContent = `${d.plugin_count || 0} Plugins`;
}).catch(() => {});

})();
