import { scanEntries, scanDemo } from './scanner.js';

const el = (id) => document.getElementById(id);
const fileInput = el('file-picker');
const folderInput = el('folder-picker');
const zone = el('dropzone');
let lastReport = null;
let busy = false;

function create(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = String(value);
  return node;
}
function updateBadge(text, kind='') {
  const badge=el('scan-badge');
  badge.className='chip ' + kind;
  badge.replaceChildren(create('span','tiny-dot'),document.createTextNode(text));
}
function render(report, isSample) {
  lastReport=report;
  el('report-placeholder').hidden=true;
  el('report-output').hidden=false;
  el('metric-files').textContent=report.files_scanned;
  el('metric-findings').textContent=report.findings.length;
  el('metric-skipped').textContent=report.coverage.skipped_files;
  el('finding-total').textContent=report.findings.length;
  updateBadge(report.coverage.skipped_files ? 'Partial coverage' :
    report.findings.length ? 'Review findings' : 'Scan complete',
    report.coverage.skipped_files ? 'warning' : report.findings.length ? 'danger' : '');
  const list=el('finding-list');
  list.replaceChildren();
  if (!report.findings.length) {
    list.append(create('div','result-clean',
      report.files_scanned
        ? 'No listed patterns detected in scanned files. This does not mean the files are secure.'
        : 'No files were scanned. Select supported text files to get meaningful results.'));
  } else {
    for(const item of report.findings.slice(0,500)) {
      const row=create('article','finding');
      row.setAttribute('role','listitem');
      const icon=create('span','finding-icon ' + item.severity,'!');
      const body=create('div','finding-body');
      const heading=create('div','finding-title',item.message);
      const location=create('div','finding-path',item.file+' · line '+item.line+' · '+item.rule);
      body.append(heading,location);
      const label=create('span','severity '+item.severity,item.severity.toUpperCase());
      row.append(icon,body,label);
      list.append(row);
    }
    if(report.findings.length>500) list.append(create('p','small muted','Showing first 500 findings. Export JSON for the complete local report.'));
  }
  const status=el('coverage-status');
  const complete=report.coverage.complete_selected_files;
  status.textContent=complete ? 'Selected files scanned' : 'Incomplete';
  status.className='coverage-state' + (complete ? '' : ' warn');
  el('coverage-desc').textContent=report.files_scanned+' of '+
    report.files_selected+' selected files scanned. '+
    (complete ? 'This is not a full application security audit.' :
      'Skipped or unsupported files may contain undetected vulnerabilities.');
  const skipped=el('skipped-list');
  skipped.replaceChildren();
  for (const item of report.coverage.skipped.slice(0,20)) {
    const row=create('div','skip-item');
    row.append(create('span','',item.file),create('span','',item.reason));
    skipped.append(row);
  }
  if(report.coverage.skipped_files>20) skipped.append(create('p','small muted','More skipped-file details are available in the exported report.'));
  el('report-footer').textContent=(isSample?'Synthetic demo scan. ':'Local-only scan. ')+
    'Matched values are never included in findings. Heuristic results only; no runtime protection is enabled.';
  el('results-panel').scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'nearest'});
}
function clear() {
  lastReport=null;
  fileInput.value='';
  folderInput.value='';
  el('report-output').hidden=true;
  el('report-placeholder').hidden=false;
  for(const id of ['metric-files','metric-findings','metric-skipped']) el(id).textContent='—';
  updateBadge('Ready to scan');
}
async function perform(work, isSample=false) {
  if(busy)return;
  busy=true;
  updateBadge('Scanning…');
  for(const button of ['run-demo','choose-files','choose-folder'])el(button).disabled=true;
  try {
    const report=await work();
    render(report,isSample);
  } catch(_) {
    updateBadge('Scan failed','danger');
    el('report-placeholder').hidden=false;
    el('report-output').hidden=true;
    el('report-placeholder').querySelector('p').textContent='Unable to process those files locally. Try a smaller selection.';
  } finally {
    busy=false;
    for(const button of ['run-demo','choose-files','choose-folder'])el(button).disabled=false;
  }
}
function scanSelected(files) {
  const entries=Array.from(files || []).map((file) => ({
    path:file.webkitRelativePath || file.name,
    size:file.size,
    text:() => file.text()
  }));
  if(entries.length)perform(() => scanEntries(entries));
}
el('run-demo').addEventListener('click',()=>perform(scanDemo,true));
el('choose-files').addEventListener('click',(event)=>{event.stopPropagation();fileInput.click()});
el('choose-folder').addEventListener('click',(event)=>{event.stopPropagation();folderInput.click()});
zone.addEventListener('click',(event)=>{if(!event.target.closest('button'))fileInput.click()});
zone.addEventListener('keydown',(event)=>{
  if((event.key==='Enter'||event.key===' ')&&event.target===zone){
    event.preventDefault();fileInput.click();
  }
});
fileInput.addEventListener('change',(event)=>scanSelected(event.target.files));
folderInput.addEventListener('change',(event)=>scanSelected(event.target.files));
for (const name of ['dragenter','dragover']) {
  zone.addEventListener(name, (event)=>{event.preventDefault();zone.classList.add('dragging')});
}
for(const name of ['dragleave','drop']) {
  zone.addEventListener(name, (event)=>{event.preventDefault();zone.classList.remove('dragging')});
}
zone.addEventListener('drop',(event)=>scanSelected(event.dataTransfer.files));
el('clear-results').addEventListener('click',clear);
el('export-report').addEventListener('click',()=>{
  if(!lastReport)return;
  const blob=new Blob([JSON.stringify(lastReport,null,2)+'\n'],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const anchor=document.createElement('a');
  anchor.href=url;
  anchor.download='devshield-redacted-preview-report.json';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
});
