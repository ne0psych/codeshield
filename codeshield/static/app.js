/**
 * CodeShield Enterprise Dashboard — JavaScript
 * Handles upload, SSE, results with full enrichment, OWASP heatmap,
 * trend analysis, report downloads, theme toggle.
 */
(function () {
    'use strict';

    function esc(s) {
        if (s == null) return '';
        const d = document.createElement('div');
        d.textContent = String(s);
        return d.innerHTML;
    }

    let currentScanId = null, currentResults = null, currentTab = 'all';
    let scanStartTime = null, timerInterval = null;

    const $ = (s) => document.querySelector(s);
    const $$ = (s) => document.querySelectorAll(s);

    // DOM refs
    const uploadSection = $('#upload-section'), progressSection = $('#progress-section'), resultsSection = $('#results-section');
    const uploadZone = $('#upload-zone'), fileInput = $('#file-input'), browseBtn = $('#browse-btn');
    const scanFilename = $('#scan-filename'), elapsedTime = $('#elapsed-time'), pluginProgress = $('#plugin-progress');
    const findingsList = $('#findings-list'), sbomContainer = $('#sbom-container'), sbomList = $('#sbom-list');
    const findingsContainer = $('#findings-container'), emptyState = $('#empty-state');
    const historyList = $('#history-list'), findingModal = $('#finding-modal');
    const modalBody = $('#modal-body'), modalClose = $('#modal-close'), newScanBtn = $('#new-scan-btn');
    const filterSeverity = $('#filter-severity'), filterSearch = $('#filter-search');
    const filterOwasp = $('#filter-owasp'), filterTrend = $('#filter-trend');
    const filtersBar = $('#filters-bar'), owaspGrid = $('#owasp-grid');
    const riskBadge = $('#risk-score-badge');

    // Theme toggle
    const themeToggle = $('#theme-toggle');
    const savedTheme = localStorage.getItem('cs-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    themeToggle.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('cs-theme', next);
    });

    // Navigation
    $$('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            $$('.nav-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            $$('.view').forEach(v => v.classList.remove('active'));
            $(`#view-${btn.dataset.view}`).classList.add('active');
            if (btn.dataset.view === 'history') loadHistory();
        });
    });

    // Upload
    browseBtn.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
    uploadZone.addEventListener('click', () => fileInput.click());
    uploadZone.addEventListener('dragover', (e) => { e.preventDefault(); uploadZone.classList.add('drag-over'); });
    uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
    uploadZone.addEventListener('drop', (e) => { e.preventDefault(); uploadZone.classList.remove('drag-over'); if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]); });
    fileInput.addEventListener('change', () => { if (fileInput.files.length) handleFile(fileInput.files[0]); });

    function handleFile(file) {
        if (!file.name.toLowerCase().endsWith('.zip')) { showError('Please select a ZIP file.'); return; }
        if (file.size > 524288000) { showError('File exceeds 500MB limit.'); return; }
        uploadFile(file);
    }

    async function uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        scanFilename.textContent = esc(file.name);
        showSection('progress');
        startTimer();
        initPluginProgress();
        try {
            const resp = await fetch('/api/upload', { method: 'POST', body: formData });
            const data = await resp.json();
            if (!resp.ok) { showError(data.error || 'Upload failed.'); showSection('upload'); stopTimer(); return; }
            currentScanId = data.scan_id;
            connectSSE(data.scan_id);
        } catch (err) { showError('Upload failed.'); showSection('upload'); stopTimer(); }
    }

    // SSE
    function connectSSE(scanId) {
        const source = new EventSource(`/api/scan/${scanId}/events`);
        source.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                updatePluginProgress(data);
                if (data.plugin_name === 'engine' && data.status === 'complete') { source.close(); stopTimer(); loadResults(scanId); }
                else if (data.plugin_name === 'engine' && data.status === 'failed') { source.close(); stopTimer(); showError('Scan failed.'); showSection('upload'); }
            } catch (e) {}
        };
        source.onerror = () => {
            setTimeout(() => {
                fetch(`/api/scan/${scanId}/results`).then(r => r.json()).then(data => {
                    if (data.scan && data.scan.status === 'complete') { source.close(); stopTimer(); loadResults(scanId); }
                }).catch(() => {});
            }, 2000);
        };
    }

    function initPluginProgress() {
        const plugins = [
            { name: 'engine', label: 'Engine' }, { name: 'sast', label: 'SAST' },
            { name: 'sca', label: 'SCA' }, { name: 'secrets', label: 'Secrets' },
            { name: 'license', label: 'License' }, { name: 'supplychain', label: 'Supply Chain' },
            { name: 'apisecurity', label: 'API Security' }, { name: 'codequality', label: 'Code Quality' },
        ];
        pluginProgress.innerHTML = plugins.map(p => `
            <div class="plugin-item" id="plugin-${esc(p.name)}" data-status="queued">
                <div class="plugin-status-icon queued" id="icon-${esc(p.name)}">&#x23F3;</div>
                <div class="plugin-name">${esc(p.label)}</div>
                <div class="plugin-detail" id="detail-${esc(p.name)}">Queued</div>
            </div>`).join('');
    }

    function updatePluginProgress(data) {
        const item = $(`#plugin-${data.plugin_name}`);
        if (!item) return;
        const icon = $(`#icon-${data.plugin_name}`), detail = $(`#detail-${data.plugin_name}`);
        item.className = `plugin-item ${data.status}`;
        if (icon) {
            icon.className = `plugin-status-icon ${data.status}`;
            if (data.status === 'complete') icon.innerHTML = '&#x2713;';
            else if (data.status === 'failed') icon.innerHTML = '&#x2717;';
            else if (['running','extracting','analyzing'].includes(data.status)) icon.innerHTML = '<div class="spinner-small"></div>';
        }
        if (detail) {
            const labels = { queued:'Queued', running:'Running...', extracting:'Extracting...', analyzing:'Analyzing...', complete:data.detail||'Complete', failed:data.detail||'Failed' };
            detail.textContent = labels[data.status] || data.detail || data.status;
        }
    }

    function startTimer() { scanStartTime = Date.now(); timerInterval = setInterval(() => { const e = Math.floor((Date.now()-scanStartTime)/1000); elapsedTime.textContent = `${String(Math.floor(e/60)).padStart(2,'0')}:${String(e%60).padStart(2,'0')}`; }, 1000); }
    function stopTimer() { if (timerInterval) { clearInterval(timerInterval); timerInterval = null; } }

    // Results
    async function loadResults(scanId) {
        try {
            const resp = await fetch(`/api/scan/${scanId}/results`);
            const data = await resp.json();
            currentResults = data;
            renderResults(data);
            showSection('results');
            loadRiskScore(scanId);
            loadTrends(scanId);
        } catch (err) { showError('Failed to load results.'); }
    }

    async function loadRiskScore(scanId) {
        try {
            const r = await fetch(`/api/scan/${scanId}/risk-score`);
            const d = await r.json();
            const score = d.risk_score || 0;
            riskBadge.textContent = score;
            riskBadge.className = 'risk-score-badge ' + (score >= 75 ? 'risk-critical' : score >= 50 ? 'risk-high' : score >= 25 ? 'risk-medium' : 'risk-low');
        } catch (e) {}
    }

    async function loadTrends(scanId) {
        try {
            const r = await fetch(`/api/scan/${scanId}/trends`);
            const d = await r.json();
            $('#trend-new').textContent = `${d.trends.new || 0} New`;
            $('#trend-recurring').textContent = `${d.trends.recurring || 0} Recurring`;
        } catch (e) {}
    }

    function renderResults(data) {
        const scan = data.scan;
        $('#card-critical .card-count').textContent = scan.critical_count || 0;
        $('#card-high .card-count').textContent = scan.high_count || 0;
        $('#card-medium .card-count').textContent = scan.medium_count || 0;
        $('#card-low .card-count').textContent = scan.low_count || 0;
        $('#card-info .card-count').textContent = scan.info_count || 0;

        // OWASP Heatmap
        renderOwaspHeatmap(data.findings);

        // Tab handlers
        $$('.tab-btn').forEach(btn => {
            btn.onclick = () => {
                $$('.tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentTab = btn.dataset.tab;
                if (currentTab === 'sbom') { renderSBOM(data.sbom); findingsContainer.classList.add('hidden'); sbomContainer.classList.remove('hidden'); filtersBar.classList.add('hidden'); $('#owasp-panel').classList.add('hidden'); }
                else { sbomContainer.classList.add('hidden'); findingsContainer.classList.remove('hidden'); filtersBar.classList.remove('hidden'); $('#owasp-panel').classList.remove('hidden'); filterFindings(); }
            };
        });

        // Report downloads
        $('#btn-download-xlsx').onclick = () => window.open(`/api/scan/${currentScanId}/report/excel`);
        $('#btn-download-pdf').onclick = () => window.open(`/api/scan/${currentScanId}/report/pdf`);

        filterFindings();
    }

    const OWASP_LABELS = {
        'A01:2021': 'Access Ctrl', 'A02:2021': 'Crypto', 'A03:2021': 'Injection',
        'A04:2021': 'Design', 'A05:2021': 'Misconfig', 'A06:2021': 'Components',
        'A07:2021': 'Auth', 'A08:2021': 'Integrity', 'A09:2021': 'Logging', 'A10:2021': 'SSRF',
    };

    function renderOwaspHeatmap(findings) {
        const counts = {};
        Object.keys(OWASP_LABELS).forEach(k => counts[k] = 0);
        findings.forEach(f => { const o = f.owasp_category; if (o && counts[o] !== undefined) counts[o]++; });
        owaspGrid.innerHTML = Object.entries(OWASP_LABELS).map(([code, label]) => {
            const c = counts[code] || 0;
            const intensity = c === 0 ? 'var(--bg-input)' : c < 3 ? 'var(--low-bg)' : c < 6 ? 'var(--medium-bg)' : c < 10 ? 'var(--high-bg)' : 'var(--critical-bg)';
            const textColor = c === 0 ? 'var(--text-muted)' : c < 3 ? 'var(--low)' : c < 6 ? '#b8860b' : c < 10 ? 'var(--high)' : 'var(--critical)';
            return `<div class="owasp-cell" style="background:${intensity};color:${textColor}"><span class="owasp-count">${c}</span><span class="owasp-label">${code.split(':')[0]}<br>${esc(label)}</span></div>`;
        }).join('');
    }

    function filterFindings() {
        if (!currentResults) return;
        let findings = currentResults.findings;
        if (currentTab !== 'all') findings = findings.filter(f => f.plugin_name === currentTab);
        const sevF = filterSeverity.value;
        if (sevF) findings = findings.filter(f => f.severity === sevF);
        const owaspF = filterOwasp.value;
        if (owaspF) findings = findings.filter(f => f.owasp_category === owaspF);
        const trendF = filterTrend.value;
        if (trendF) findings = findings.filter(f => (f.trend_status || 'new') === trendF);
        const search = filterSearch.value.toLowerCase().trim();
        if (search) findings = findings.filter(f =>
            (f.title||'').toLowerCase().includes(search) || (f.file_path||'').toLowerCase().includes(search) ||
            (f.cve_id||'').toLowerCase().includes(search) || (f.cwe_id||'').toLowerCase().includes(search) ||
            (f.rule_id||'').toLowerCase().includes(search) || (f.mitre_id||'').toLowerCase().includes(search)
        );
        renderFindings(findings);
    }

    filterSeverity.addEventListener('change', filterFindings);
    filterOwasp.addEventListener('change', filterFindings);
    filterTrend.addEventListener('change', filterFindings);
    let searchTimeout;
    filterSearch.addEventListener('input', () => { clearTimeout(searchTimeout); searchTimeout = setTimeout(filterFindings, 250); });

    function renderFindings(findings) {
        if (!findings.length) { findingsList.innerHTML = ''; emptyState.classList.remove('hidden'); return; }
        emptyState.classList.add('hidden');
        const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        findings.sort((a, b) => (sevOrder[a.severity] || 5) - (sevOrder[b.severity] || 5));
        findingsList.innerHTML = findings.map((f, i) => {
            const tags = [];
            if (f.cwe_id) tags.push(`<span class="tag tag-cwe">${esc(f.cwe_id)}</span>`);
            if (f.owasp_category) tags.push(`<span class="tag tag-owasp">${esc(f.owasp_category)}</span>`);
            if (f.mitre_id) tags.push(`<span class="tag tag-mitre">${esc(f.mitre_id)}</span>`);
            if (f.trend_status) tags.push(`<span class="tag tag-trend ${f.trend_status === 'recurring' ? 'recurring' : ''}">${esc(f.trend_status)}</span>`);
            if (f.exploit_available === 'high') tags.push(`<span class="tag tag-exploit">Exploit likely</span>`);
            return `<div class="finding-item" onclick="window.showFinding(${i})">
                <span class="finding-severity sev-${esc(f.severity).toLowerCase()}">${esc(f.severity)}</span>
                <div class="finding-content">
                    <div class="finding-title">${esc(f.title)}</div>
                    <div class="finding-meta">
                        ${f.plugin_name ? `<span>${esc(f.plugin_name.toUpperCase())}</span>` : ''}
                        ${f.file_path ? `<span>${esc(f.file_path)}</span>` : ''}
                        ${f.line_number ? `<span>L${f.line_number}</span>` : ''}
                        ${f.fix_effort_hours ? `<span>${f.fix_effort_hours}h</span>` : ''}
                    </div>
                    ${tags.length ? `<div class="finding-tags">${tags.join('')}</div>` : ''}
                </div>
            </div>`;
        }).join('');
        window._filteredFindings = findings;
    }

    // Modal
    window.showFinding = function (idx) {
        const f = window._filteredFindings?.[idx];
        if (!f) return;
        modalBody.innerHTML = `
            <div class="modal-title"><span class="finding-severity sev-${esc(f.severity).toLowerCase()}">${esc(f.severity)}</span> ${esc(f.title)}</div>
            ${f.description ? `<div class="modal-field"><div class="modal-label">Description</div><div class="modal-value">${esc(f.description)}</div></div>` : ''}
            <div class="modal-field modal-compliance">
                ${f.plugin_name ? `<div><div class="modal-label">Scanner</div><div class="modal-value">${esc(f.plugin_name.toUpperCase())}</div></div>` : ''}
                ${f.rule_id ? `<div><div class="modal-label">Rule ID</div><div class="modal-value">${esc(f.rule_id)}</div></div>` : ''}
                ${f.cwe_id ? `<div><div class="modal-label">CWE</div><div class="modal-value">${esc(f.cwe_id)} ${esc(f.cwe_label||'')}</div></div>` : ''}
                ${f.owasp_category ? `<div><div class="modal-label">OWASP</div><div class="modal-value">${esc(f.owasp_category)} ${esc(f.owasp_label||'')}</div></div>` : ''}
                ${f.mitre_id ? `<div><div class="modal-label">MITRE ATT&CK</div><div class="modal-value">${esc(f.mitre_id)} ${esc(f.mitre_label||'')}</div></div>` : ''}
                ${f.cve_id ? `<div><div class="modal-label">CVE</div><div class="modal-value">${esc(f.cve_id)}</div></div>` : ''}
                ${f.cvss_score ? `<div><div class="modal-label">CVSS</div><div class="modal-value">${f.cvss_score}</div></div>` : ''}
                ${f.pci_dss ? `<div><div class="modal-label">PCI-DSS</div><div class="modal-value">${esc(f.pci_dss)}</div></div>` : ''}
                ${f.hipaa ? `<div><div class="modal-label">HIPAA</div><div class="modal-value">${esc(f.hipaa)}</div></div>` : ''}
                ${f.exploit_available ? `<div><div class="modal-label">Exploit Available</div><div class="modal-value">${esc(f.exploit_available)}</div></div>` : ''}
                <div><div class="modal-label">Fix Effort</div><div class="modal-value">${f.fix_effort_hours || 2}h</div></div>
                <div><div class="modal-label">Trend</div><div class="modal-value">${esc(f.trend_status || 'new')}</div></div>
                <div><div class="modal-label">False Positive</div><div class="modal-value">${f.false_positive ? 'Yes' : 'No'} ${f.id ? `<button class="btn btn-sm btn-outline" onclick="window.toggleFP(${f.id})">Toggle</button>` : ''}</div></div>
            </div>
            ${f.file_path ? `<div class="modal-field"><div class="modal-label">Location</div><div class="modal-value">${esc(f.file_path)}${f.line_number ? ` : L${f.line_number}` : ''}</div></div>` : ''}
            ${f.package_name ? `<div class="modal-field"><div class="modal-label">Package</div><div class="modal-value">${esc(f.package_name)}${f.package_version ? '==' + esc(f.package_version) : ''}${f.fixed_version ? ' -> ' + esc(f.fixed_version) : ''}</div></div>` : ''}
            ${f.code_snippet ? `<div class="modal-field"><div class="modal-label">Code Snippet</div><pre class="modal-code">${esc(f.code_snippet)}</pre></div>` : ''}
            ${f.remediation ? `<div class="modal-field"><div class="modal-label">Remediation</div><div class="modal-remediation">${esc(f.remediation)}</div></div>` : ''}
        `;
        findingModal.classList.remove('hidden');
    };

    window.toggleFP = async function (id) {
        try {
            await fetch(`/api/finding/${id}/false-positive`, { method: 'POST' });
            if (currentScanId) loadResults(currentScanId);
        } catch (e) {}
        findingModal.classList.add('hidden');
    };

    modalClose.addEventListener('click', () => findingModal.classList.add('hidden'));
    findingModal.addEventListener('click', (e) => { if (e.target === findingModal) findingModal.classList.add('hidden'); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') findingModal.classList.add('hidden'); });

    // SBOM
    function renderSBOM(sbom) {
        if (!sbom?.components?.length) { sbomList.innerHTML = '<div class="empty-state"><p>No SBOM components found</p></div>'; return; }
        sbomList.innerHTML = sbom.components.map(c => `<div class="sbom-item"><div class="sbom-name">${esc(c.name)}</div><div class="sbom-version">${esc(c.version)}</div><div class="sbom-purl">${esc(c.purl)}</div></div>`).join('');
    }

    // History
    async function loadHistory() {
        try { const r = await fetch('/api/scans'); const d = await r.json(); renderHistory(d.scans); }
        catch (e) { historyList.innerHTML = '<div class="empty-state"><p>Failed to load history</p></div>'; }
    }

    function renderHistory(scans) {
        if (!scans?.length) { historyList.innerHTML = '<div class="empty-state"><p>No scans yet.</p></div>'; return; }
        historyList.innerHTML = scans.map(s => {
            const date = s.started_at ? new Date(s.started_at).toLocaleString() : 'Unknown';
            const cls = s.status === 'complete' ? 'complete' : s.status === 'running' ? 'running' : 'failed';
            const icon = s.status === 'complete' ? '&#x2713;' : s.status === 'running' ? '&#x21BB;' : '&#x2717;';
            return `<div class="history-item" onclick="window.loadHistoryScan('${esc(s.scan_id)}')">
                <div class="history-icon ${cls}">${icon}</div>
                <div class="history-info"><div class="history-filename">${esc(s.filename)}</div><div class="history-date">${esc(date)} - ${s.total_findings||0} findings</div></div>
                <div class="history-badges">
                    ${s.critical_count?`<span class="history-badge badge-c">${s.critical_count}C</span>`:''}
                    ${s.high_count?`<span class="history-badge badge-h">${s.high_count}H</span>`:''}
                    ${s.medium_count?`<span class="history-badge badge-m">${s.medium_count}M</span>`:''}
                </div></div>`;
        }).join('');
    }

    window.loadHistoryScan = async function (scanId) {
        $$('.nav-btn').forEach(b => b.classList.remove('active'));
        $('#nav-scanner').classList.add('active');
        $$('.view').forEach(v => v.classList.remove('active'));
        $('#view-scanner').classList.add('active');
        currentScanId = scanId;
        await loadResults(scanId);
    };

    // Section management
    function showSection(s) {
        uploadSection.classList.add('hidden'); progressSection.classList.add('hidden'); resultsSection.classList.add('hidden');
        if (s === 'upload') uploadSection.classList.remove('hidden');
        else if (s === 'progress') progressSection.classList.remove('hidden');
        else if (s === 'results') resultsSection.classList.remove('hidden');
    }
    newScanBtn.addEventListener('click', () => { currentScanId = null; currentResults = null; fileInput.value = ''; showSection('upload'); });

    function showError(msg) {
        const t = document.createElement('div');
        t.style.cssText = 'position:fixed;bottom:2rem;right:2rem;z-index:300;padding:0.8rem 1.2rem;background:var(--critical-bg);border:1px solid var(--critical-border);border-radius:8px;color:var(--critical);font-size:0.85rem;font-weight:500;box-shadow:var(--shadow-lg);max-width:400px;animation:fadeIn 0.3s ease';
        t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity 0.3s'; setTimeout(() => t.remove(), 300); }, 4000);
    }
})();
