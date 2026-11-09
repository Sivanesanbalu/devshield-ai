import test from 'node:test';
import assert from 'node:assert/strict';
import {MAX_FILE_BYTES, MAX_SELECTED_FILES, SAMPLE_FILES, scanEntries, scanText, scanDemo, supportedFile} from '../scanner.js';

function entry(path, text) {
  return {path,size:new TextEncoder().encode(text).byteLength,text:async()=>text};
}

test('safe sample scans 5 files, produces high and medium redacted findings', async () => {
  const report=await scanDemo();
  assert.equal(report.schema,'devshield.preview.v1');
  assert.equal(report.mode,'browser-local');
  assert.equal(report.files_scanned,5);
  assert.equal(report.coverage.skipped_files,0);
  assert.equal(report.coverage.complete_selected_files,true);
  assert.equal(report.summary.high,3);
  assert.equal(report.summary.medium,1);
  assert.equal(report.findings.length,4);
  const serialized=JSON.stringify(report);
  for(const file of SAMPLE_FILES){
    if(file.text.includes('synthetic-')){
      assert.equal(serialized.includes('synthetic-'),false,'Matched values must not leak');
    }
  }
});

test('detects quoted JSON/TOML strings and unquoted env assignments', async()=>{
  const files=[
    entry('settings.json','{"api_key": "test-example-not-real-12345678"}'),
    entry('settings.toml','password = "not-a-real-password-1234567"'),
    entry('.env','export CLIENT_SECRET=not-a-real-token-123456789')
  ];
  const report=await scanEntries(files);
  assert.deepEqual(report.findings.map(x=>x.rule),['DS003','DS003','DS006']);
  assert.equal(report.summary.high,3);
  assert.equal(JSON.stringify(report).includes('not-a-real-'),false);
});

test('finds private key header and client-side license debug indicators',()=>{
  const findings=scanText('-----BEGIN PRIVATE KEY-----\nconst debug = true;\nis_premium = false;\n','demo.ts');
  assert.deepEqual(findings.map(x=>x.rule),['DS001','DS004','DS005']);
  assert.deepEqual(findings.map(x=>x.line),[1,2,3]);
});

test('skipped, unknown and empty scans do not claim clean coverage',async()=>{
  const files=[
    entry('bundle.exe','binary'),
    {path:'oversized.ts',size:MAX_FILE_BYTES+1,text:async()=>{throw new Error('must never read');}},
    entry('clean.py','print("hi")')
  ];
  const report=await scanEntries(files);
  assert.equal(report.files_scanned,1);
  assert.equal(report.coverage.skipped_files,2);
  assert.equal(report.coverage.complete_selected_files,false);
  assert.equal((await scanEntries([])).coverage.complete_selected_files,false);
});

test('malformed text encoding and unreadable files remain incomplete',async()=>{
  const report=await scanEntries([
    entry('broken.py','api_key = "not-real-123456"\uFFFD'),
    {path:'unreadable.ts',size:50,text:async()=>{throw new Error('secret internal error')}}
  ]);
  assert.equal(report.files_scanned,0);
  assert.equal(report.coverage.skipped_files,2);
  assert.equal(JSON.stringify(report).includes('secret internal error'),false);
});

test('ignores unsupported filenames and enforces selection cap',async()=>{
  assert.equal(supportedFile('.env.production'),true);
  assert.equal(supportedFile('Dockerfile'),true);
  assert.equal(supportedFile('archive.zip'),false);
  const files=Array.from({length:MAX_SELECTED_FILES+1},(_,index)=>
    entry('file'+index+'.js','console.log("ok")'));
  const report=await scanEntries(files);
  assert.equal(report.files_scanned,MAX_SELECTED_FILES);
  assert.equal(report.coverage.skipped_files,1);
  assert.equal(report.coverage.complete_selected_files,false);
});
