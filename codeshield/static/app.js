/* CodeShield v3.0 — Project-Centric Scanner UI */
(function(){'use strict';

/* ── State ── */
let projects=[],activeProjectId=null,activeScanId=null,scanFindings=[],filteredFindings=[],scanSbom={},filter={tab:'all',sev:'',owasp:'',q:''};
const $=s=>document.querySelector(s),$$=s=>document.querySelectorAll(s);
const hide=el=>{if(el)el.classList.add('hidden')};
const show=el=>{if(el)el.classList.remove('hidden')};
const esc=s=>{const d=document.createElement('div');d.textContent=s||'';return d.innerHTML};
const fmtD=d=>{if(!d)return'-';try{return new Date(d).toLocaleDateString('en-US',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});}catch(e){return d;}};
const shortP=p=>{if(!p)return'';const s=p.split(/[\/\\]/);return s.length>2?'…/'+s.slice(-2).join('/'):p;};

/* ── Navigation ── */
function nav(page){
  $$('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===page));
  $$('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+page));
  if(page==='dashboard')renderDashboard();
  else if(page==='projects')renderProjects();
  else if(page==='scan')renderScanPage();
  else if(page==='results')renderResults();
  else if(page==='sbom')renderSbom();
  else if(page==='reports')renderReports();
  else if(page==='sync')renderSync();
  else if(page==='settings')renderSettings();
}
$$('.nav-item').forEach(b=>b.addEventListener('click',()=>nav(b.dataset.page)));

/* ── Theme ── */
if(localStorage.getItem('cs-theme')==='light')document.documentElement.dataset.theme='light';
$('#theme-toggle').addEventListener('click',()=>{const t=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=t;localStorage.setItem('cs-theme',t);});

/* ── API helpers ── */
async function api(url){const r=await fetch(url);if(!r.ok)throw new Error(r.statusText);return r.json();}
async function loadProjects(){try{const d=await api('/api/projects');projects=d.projects||[];}catch(e){projects=[];}}

/* ═══════════ DASHBOARD ═══════════ */
async function renderDashboard(){
  await loadProjects();
  let tot=0,c=0,h=0,m=0,l=0;
  projects.forEach(p=>{tot+=(p.total_findings||0);c+=(p.critical_count||0);h+=(p.high_count||0);m+=(p.medium_count||0);l+=(p.low_count||0);});
  $('#stat-projects').textContent=projects.length;
  $('#stat-findings').textContent=tot;
  $('#stat-critical').textContent=c;
  $('#stat-high').textContent=h;
  $('#stat-medium').textContent=m;
  $('#stat-low').textContent=l;
  drawPie(c,h,m,l);

  // Project summary table
  const tb=$('#recent-scans-body');tb.innerHTML='';
  projects.forEach(p=>{
    const risk=(p.critical_count||0)>0?'At Risk':'Secure';
    const cls=(p.critical_count||0)>0?'status-fail':'status-ok';
    const tr=document.createElement('tr');
    tr.innerHTML=`<td><strong>${esc(p.name)}</strong></td><td>${p.total_scans||0} scans</td><td>${fmtD(p.last_scan_at)}</td><td>${p.total_findings||0}</td><td>${p.critical_count||0}</td><td><span class="${cls}">${risk}</span></td><td><button class="btn btn-sm" data-pid="${p.project_id}">Open</button></td>`;
    tr.querySelector('button').addEventListener('click',()=>{activeProjectId=p.project_id;nav('results');});
    tb.appendChild(tr);
  });

  // OWASP grid placeholder
  const g=$('#owasp-grid');if(g){g.innerHTML='';
    const cats=['A01','A02','A03','A04','A05','A06','A07','A08','A09','A10'];
    cats.forEach(c=>{g.innerHTML+=`<div class="owasp-cell" style="background:var(--bg-2);color:var(--text-3)"><span class="oc-n">-</span><span class="oc-l">${c}</span></div>`;});
  }
}

function drawPie(c,h,m,l){
  const cv=$('#sev-pie');if(!cv)return;const ctx=cv.getContext('2d');
  const t=c+h+m+l||1;
  const data=[{v:c,co:'#ef4444',la:'Critical'},{v:h,co:'#f97316',la:'High'},{v:m,co:'#f59e0b',la:'Medium'},{v:l,co:'#3b82f6',la:'Low'}];
  const W=cv.width,H=cv.height,cx=W/2,cy=H/2-10,R=Math.min(W,H)/2-35;
  ctx.clearRect(0,0,W,H);
  let a=-Math.PI/2;
  data.forEach(d=>{const sl=(d.v/t)*Math.PI*2;if(d.v>0){ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,R,a,a+sl);ctx.closePath();ctx.fillStyle=d.co;ctx.fill();if(sl>0.3){const mi=a+sl/2;ctx.fillStyle='#fff';ctx.font='bold 13px sans-serif';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(d.v,cx+R*0.6*Math.cos(mi),cy+R*0.6*Math.sin(mi));}}a+=sl;});
  let lx=10,ly=H-15;ctx.font='11px sans-serif';
  data.forEach(d=>{ctx.fillStyle=d.co;ctx.fillRect(lx,ly-5,10,10);ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--text-2').trim()||'#888';ctx.textAlign='left';ctx.fillText(`${d.la}: ${d.v}`,lx+14,ly);lx+=80;});
}

/* ═══════════ PROJECTS ═══════════ */
async function renderProjects(){
  await loadProjects();
  const tb=$('#projects-body');tb.innerHTML='';
  if(!projects.length){show($('#no-projects'));return;}
  hide($('#no-projects'));
  projects.forEach(p=>{
    const cls=(p.critical_count||0)>0?'status-fail':'status-ok';
    const st=(p.critical_count||0)>0?'At Risk':'Secure';
    const tr=document.createElement('tr');
    tr.innerHTML=`<td><strong>${esc(p.name)}</strong></td><td>${p.total_scans||0}</td><td>${p.total_findings||0}</td><td>${p.critical_count||0}</td><td>${p.high_count||0}</td><td>${fmtD(p.last_scan_at)}</td><td><span class="${cls}">${st}</span></td><td><button class="btn btn-sm view-btn">View</button> <button class="btn btn-sm del-btn">Del</button></td>`;
    tr.querySelector('.view-btn').addEventListener('click',()=>{activeProjectId=p.project_id;nav('results');});
    tr.querySelector('.del-btn').addEventListener('click',async()=>{if(!confirm('Delete project "'+p.name+'" and all its scans?'))return;await fetch('/api/projects/'+p.project_id,{method:'DELETE'});renderProjects();});
    tb.appendChild(tr);
  });
}

// New project modal
$('#btn-new-project')?.addEventListener('click',()=>show($('#project-modal')));
$('#project-modal-close')?.addEventListener('click',()=>hide($('#project-modal')));
$('#project-modal')?.addEventListener('click',e=>{if(e.target.id==='project-modal')hide($('#project-modal'));});
$('#create-proj-btn')?.addEventListener('click',async()=>{
  const name=$('#new-proj-name').value.trim();if(!name)return alert('Enter a project name');
  const r=await fetch('/api/projects',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,description:$('#new-proj-desc').value.trim()})});
  if(r.ok){hide($('#project-modal'));$('#new-proj-name').value='';$('#new-proj-desc').value='';renderProjects();}
});

/* ═══════════ NEW SCAN ═══════════ */
async function renderScanPage(){
  await loadProjects();
  const sel=$('#scan-project-select');sel.innerHTML='<option value="">-- Select a project --</option>';
  projects.forEach(p=>{const o=document.createElement('option');o.value=p.project_id;o.textContent=p.name;if(p.project_id===activeProjectId)o.selected=true;sel.appendChild(o);});
  show($('#upload-zone'));hide($('#progress-section'));
}

const uz=$('#upload-zone'),fi=$('#file-input');
uz?.addEventListener('click',()=>fi?.click());
$('#browse-btn')?.addEventListener('click',e=>{e.stopPropagation();fi?.click();});
fi?.addEventListener('change',e=>{if(e.target.files[0])startUpload(e.target.files[0]);});
['dragover','dragenter'].forEach(ev=>uz?.addEventListener(ev,e=>{e.preventDefault();uz.classList.add('drag-over');}));
['dragleave','drop'].forEach(ev=>uz?.addEventListener(ev,e=>{e.preventDefault();uz.classList.remove('drag-over');}));
uz?.addEventListener('drop',e=>{if(e.dataTransfer.files[0])startUpload(e.dataTransfer.files[0]);});

async function startUpload(file){
  if(!file.name.endsWith('.zip'))return alert('Only .zip files accepted');
  const projSel=$('#scan-project-select')?.value||'';
  const projName=$('#scan-project-name')?.value?.trim()||'';
  if(!projSel&&!projName)return alert('Please select an existing project or enter a new project name.');
  const fd=new FormData();fd.append('file',file);
  if(projSel)fd.append('project_id',projSel);else fd.append('project_name',projName);
  hide(uz);show($('#progress-section'));$('#scan-filename').textContent=file.name;
  $('#plugin-progress').innerHTML='<div class="plug-item"><div class="spinner"></div><span class="plug-name">Uploading…</span></div>';
  let t0=Date.now(),timer=setInterval(()=>{const s=Math.floor((Date.now()-t0)/1000);$('#elapsed-time').textContent=`${String(s/60|0).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`;},1000);
  try{
    const r=await fetch('/api/upload',{method:'POST',body:fd});const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Upload failed');
    activeScanId=d.scan_id;activeProjectId=d.project_id;
    listenSSE(d.scan_id,timer);
  }catch(e){clearInterval(timer);$('#plugin-progress').innerHTML=`<div class="plug-item failed"><div class="plug-icon failed">✗</div><span class="plug-name">${esc(e.message)}</span></div>`;}
}

function listenSSE(sid,timer){
  const es=new EventSource(`/api/scan/${sid}/events`);const ps={};const c=$('#plugin-progress');
  es.addEventListener('plugin_start',e=>{const d=JSON.parse(e.data);ps[d.plugin]={s:'run'};rPP(c,ps);});
  es.addEventListener('plugin_complete',e=>{const d=JSON.parse(e.data);ps[d.plugin]={s:'ok',n:d.findings_count||0};rPP(c,ps);});
  es.addEventListener('plugin_error',e=>{const d=JSON.parse(e.data);ps[d.plugin]={s:'err',e:d.error};rPP(c,ps);});
  es.addEventListener('scan_complete',e=>{es.close();clearInterval(timer);const d=JSON.parse(e.data);c.innerHTML+=`<div class="plug-item complete"><div class="plug-icon complete">✓</div><span class="plug-name">Complete — ${d.total_findings||0} findings</span></div>`;setTimeout(()=>nav('results'),800);});
  es.addEventListener('scan_error',e=>{es.close();clearInterval(timer);const d=JSON.parse(e.data);c.innerHTML+=`<div class="plug-item failed"><div class="plug-icon failed">✗</div><span class="plug-name">${esc(d.error)}</span></div>`;});
  es.onerror=()=>es.close();
}
function rPP(c,st){c.innerHTML='';Object.entries(st).forEach(([n,s])=>{let ic='<div class="spinner"></div>',cl='';if(s.s==='ok'){ic='<div class="plug-icon complete">✓</div>';cl='complete';}else if(s.s==='err'){ic='<div class="plug-icon failed">✗</div>';cl='failed';}c.innerHTML+=`<div class="plug-item ${cl}">${ic}<span class="plug-name">${esc(n)}</span><span class="plug-detail">${s.s==='ok'?s.n+' findings':esc(s.e||'')}</span></div>`;});}

/* ═══════════ RESULTS (project-scoped) ═══════════ */
async function renderResults(){
  if(!activeProjectId){$('#results-project-name').textContent='No project selected';$('#findings-body').innerHTML='';return;}
  try{
    const pd=await api('/api/projects/'+activeProjectId);
    const proj=pd.project||{};const scans=pd.scans||[];
    $('#results-project-name').textContent=proj.name||'Unknown';

    // Populate scan selector
    const sel=$('#results-scan-select');if(sel){sel.innerHTML='';
      scans.forEach((s,i)=>{const o=document.createElement('option');o.value=s.scan_id;o.textContent=`${fmtD(s.started_at)} — ${s.total_findings||0} findings`;if(i===0||s.scan_id===activeScanId)o.selected=true;sel.appendChild(o);});
      if(scans.length>0&&!activeScanId)activeScanId=scans[0].scan_id;
      sel.onchange=()=>{activeScanId=sel.value;loadScanFindings(activeScanId);};
    }
    if(activeScanId)loadScanFindings(activeScanId);
    else{$('#findings-body').innerHTML='';show($('#no-findings'));}
  }catch(e){console.error(e);}
}

async function loadScanFindings(sid){
  try{
    const d=await api(`/api/scan/${sid}/results`);
    scanFindings=d.findings||[];filteredFindings=[...scanFindings];scanSbom=d.sbom||{};
    const s=d.scan||{};
    $('#rc-critical').textContent=s.critical_count||0;$('#rc-high').textContent=s.high_count||0;
    $('#rc-medium').textContent=s.medium_count||0;$('#rc-low').textContent=s.low_count||0;$('#rc-info').textContent=s.info_count||0;
    applyFilter();
  }catch(e){console.error(e);}
  try{const d=await api(`/api/scan/${sid}/risk-score`);const b=$('#risk-badge');b.textContent=d.risk_score??'--';b.className='risk-badge '+(d.risk_score>=75?'risk-crit':d.risk_score>=50?'risk-high':d.risk_score>=25?'risk-med':'risk-low');}catch(e){}
  try{const d=await api(`/api/scan/${sid}/trends`);$('#trend-new').textContent=`${d.new_count||0} New`;$('#trend-rec').textContent=`${d.recurring_count||0} Recurring`;}catch(e){}
  $('#btn-xlsx').onclick=()=>window.open(`/api/scan/${sid}/report/excel`);
  $('#btn-pdf').onclick=()=>window.open(`/api/scan/${sid}/report/pdf`);
}

// Filters
$$('.ftab').forEach(t=>t.addEventListener('click',()=>{$$('.ftab').forEach(x=>x.classList.remove('active'));t.classList.add('active');filter.tab=t.dataset.tab;applyFilter();}));
$('#f-sev')?.addEventListener('change',e=>{filter.sev=e.target.value;applyFilter();});
$('#f-owasp')?.addEventListener('change',e=>{filter.owasp=e.target.value;applyFilter();});
$('#f-search')?.addEventListener('input',e=>{filter.q=e.target.value.toLowerCase();applyFilter();});

function applyFilter(){
  filteredFindings=scanFindings.filter(f=>{
    if(filter.tab!=='all'&&f.plugin_name!==filter.tab)return false;
    if(filter.sev&&f.severity!==filter.sev)return false;
    if(filter.owasp&&f.owasp_category!==filter.owasp)return false;
    if(filter.q){const h=[f.title,f.file_path,f.cwe_id,f.cve_id,f.description].join(' ').toLowerCase();if(!h.includes(filter.q))return false;}
    return true;
  });
  const tb=$('#findings-body');tb.innerHTML='';
  if(!filteredFindings.length){show($('#no-findings'));return;}hide($('#no-findings'));
  filteredFindings.forEach((f,i)=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${i+1}</td><td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td><td>${esc(f.plugin_name)}</td><td>${esc(f.title)}</td><td title="${esc(f.file_path)}">${esc(shortP(f.file_path))}:${f.line_number||''}</td><td>${f.cwe_id?`<span class="tag tag-cwe">${f.cwe_id}</span>`:''}</td><td>${f.owasp_category?`<span class="tag tag-owasp">${f.owasp_category.split(':')[0]}</span>`:''}</td><td>${f.cve_id?`<span class="tag tag-cve">${f.cve_id}</span>`:''}</td><td><span class="tag tag-trend ${f.trend_status==='recurring'?'recurring':''}">${f.trend_status||'new'}</span></td>`;
    tr.addEventListener('click',()=>openModal(f));
    tb.appendChild(tr);
  });
}

function openModal(f){
  $('#modal-body').innerHTML=`<div class="modal-title"><span class="sev-badge sev-${f.severity}">${f.severity}</span> ${esc(f.title)}</div><div class="mf-grid"><div class="mf"><div class="mf-label">Scanner</div><div class="mf-val">${esc(f.plugin_name)}</div></div><div class="mf"><div class="mf-label">Rule ID</div><div class="mf-val">${esc(f.rule_id||'-')}</div></div><div class="mf"><div class="mf-label">File</div><div class="mf-val">${esc(f.file_path||'')}:${f.line_number||''}</div></div><div class="mf"><div class="mf-label">CWE</div><div class="mf-val">${f.cwe_id?`<span class="tag tag-cwe">${f.cwe_id}</span> ${esc(f.cwe_label||'')}`:'-'}</div></div><div class="mf"><div class="mf-label">OWASP</div><div class="mf-val">${f.owasp_category?`<span class="tag tag-owasp">${f.owasp_category}</span> ${esc(f.owasp_label||'')}`:'-'}</div></div><div class="mf"><div class="mf-label">MITRE ATT&amp;CK</div><div class="mf-val">${esc(f.mitre_id||'-')}</div></div><div class="mf"><div class="mf-label">CVE</div><div class="mf-val">${f.cve_id||'-'}</div></div><div class="mf"><div class="mf-label">CVSS</div><div class="mf-val">${f.cvss_score||'-'}</div></div><div class="mf"><div class="mf-label">Exploit</div><div class="mf-val">${esc(f.exploit_available||'unknown')}</div></div><div class="mf"><div class="mf-label">Fix Effort</div><div class="mf-val">${f.fix_effort_hours||'?'}h</div></div><div class="mf"><div class="mf-label">PCI-DSS</div><div class="mf-val">${esc(f.pci_dss||'-')}</div></div><div class="mf"><div class="mf-label">HIPAA</div><div class="mf-val">${esc(f.hipaa||'-')}</div></div></div>${f.description?`<div class="mf"><div class="mf-label">Description</div><div class="mf-val">${esc(f.description)}</div></div>`:''}${f.code_snippet?`<div class="mf"><div class="mf-label">Code</div><div class="mf-code">${esc(f.code_snippet)}</div></div>`:''}${f.remediation?`<div class="mf"><div class="mf-label">Remediation</div><div class="mf-fix">${esc(f.remediation)}</div></div>`:''}`;
  show($('#modal'));
}
$('#modal-close')?.addEventListener('click',()=>hide($('#modal')));
$('#modal')?.addEventListener('click',e=>{if(e.target.id==='modal')hide($('#modal'));});

/* ═══════════ SBOM (project-scoped) ═══════════ */
async function renderSbom(){
  const tb=$('#sbom-body');tb.innerHTML='';
  if(!activeProjectId||!activeScanId){$('#no-sbom').querySelector('p').textContent='Select a project first, then view SBOM.';show($('#no-sbom'));return;}
  try{
    const d=await api(`/api/scan/${activeScanId}/results`);
    const comps=(d.sbom&&d.sbom.components)||[];
    if(!comps.length){show($('#no-sbom'));return;}hide($('#no-sbom'));
    comps.forEach(c=>{const tr=document.createElement('tr');tr.innerHTML=`<td>${esc(c.name)}</td><td>${esc(c.version)}</td><td>${esc(c.ecosystem)}</td><td>${esc(c.license)}</td><td title="${esc(c.purl)}">${esc((c.purl||'').slice(0,50))}</td>`;tb.appendChild(tr);});
  }catch(e){show($('#no-sbom'));}
}

/* ═══════════ REPORTS (project-scoped) ═══════════ */
async function renderReports(){
  await loadProjects();
  const tb=$('#reports-body');tb.innerHTML='';
  for(const p of projects){
    try{
      const pd=await api('/api/projects/'+p.project_id);
      (pd.scans||[]).forEach(s=>{
        if(s.status!=='complete')return;
        const tr=document.createElement('tr');
        tr.innerHTML=`<td><strong>${esc(p.name)}</strong></td><td>${esc(s.filename)}</td><td>${fmtD(s.started_at)}</td><td>${s.total_findings||0}</td><td><button class="btn btn-sm btn-primary" onclick="window.open('/api/scan/${s.scan_id}/report/pdf')">PDF</button></td><td><button class="btn btn-sm" onclick="window.open('/api/scan/${s.scan_id}/report/excel')">Excel</button></td>`;
        tb.appendChild(tr);
      });
    }catch(e){}
  }
}

/* ═══════════ SYNC ═══════════ */
async function renderSync(){
  const g=$('#sync-grid');g.innerHTML='<p style="color:var(--text-3)">Loading…</p>';
  try{
    const h=await api('/api/health');g.innerHTML='';
    g.innerHTML+=`<div class="sync-card"><h4>Scanner Plugins</h4>${(h.plugins||[]).map(p=>`<div class="sync-row"><span>${esc(p)}</span><span class="sync-ok">Active</span></div>`).join('')}</div>`;
    const srcs=['osv_vulnerabilities','spdx_licenses','nvd_vulnerabilities','github_advisories','ossindex'];
    const labels={osv_vulnerabilities:'OSV.dev',spdx_licenses:'SPDX Licenses',nvd_vulnerabilities:'NVD (NIST)',github_advisories:'GitHub Advisory',ossindex:'OSS Index'};
    let sh='<div class="sync-card"><h4>Data Sources</h4>';
    for(const src of srcs){try{const r=await api('/api/sync/'+src);const ok=['ok','updated','unchanged'].includes(r.status);sh+=`<div class="sync-row"><span>${labels[src]}</span><span class="${ok?'sync-ok':r.status==='not_synced'?'sync-skip':'sync-fail'}">${ok?'Synced':r.status==='not_synced'?'Not synced':'Pending'}</span></div>`;if(r.last_sync_at)sh+=`<div class="sync-row" style="padding-left:1rem"><span style="color:var(--text-3);font-size:.72rem">Last: ${fmtD(r.last_sync_at)}</span><span style="font-size:.72rem;color:var(--text-3)">${r.records_count||0} records</span></div>`;}catch(e){sh+=`<div class="sync-row"><span>${labels[src]}</span><span class="sync-skip">N/A</span></div>`;}}
    sh+='</div>';g.innerHTML+=sh;
  }catch(e){g.innerHTML='<p class="empty-state">Could not load</p>';}
}

/* ═══════════ SETTINGS ═══════════ */
async function renderSettings(){try{const d=await api('/api/health');$('#settings-plugins').textContent=(d.plugins||[]).join(', ');}catch(e){}}

/* ── Init ── */
renderDashboard();
api('/api/health').then(d=>{$('#plugin-count-badge').textContent=`${d.plugin_count||0} Plugins`;}).catch(()=>{});

})();
