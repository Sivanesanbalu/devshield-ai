// DevShield browser-only security scanning preview.
// Heuristic parity with the selected DS001-DS006 Python scanner rules.
// No file content is transmitted, stored or included in exported findings.
export const MAX_FILE_BYTES = 1_000_000;
export const MAX_SELECTED_FILES = 250;

const EXTENSIONS = new Set([
  '.py','.js','.jsx','.ts','.tsx','.json','.yaml','.yml','.env',
  '.properties','.java','.kt','.cs','.go','.rs','.html','.txt',
  '.config','.md','.markdown','.toml','.sh','.bash','.zsh',
  '.ini','.cfg','.conf','.xml','.tf','.tfvars','.sql','.php',
  '.rb','.swift','.dart','.vue','.svelte','.c','.h','.cpp',
  '.hpp','.ipynb'
]);
const BASENAMES = new Set(['Dockerfile','Makefile','.npmrc','.pypirc']);
const RULES = [
  {rule:'DS001',severity:'critical',message:'Private key material',
    pattern:/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/},
  {rule:'DS002',severity:'high',message:'AWS access key identifier',
    pattern:/(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])/},
  {rule:'DS003',severity:'high',message:'Potential embedded secret',
    pattern:/(?<![A-Za-z0-9_])["']?(?:api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|database[_-]?password|db[_-]?password|password)["']?\s*[:=]\s*(?:"[^"\r\n]{12,}"|'[^'\r\n]{12,}')/i},
  {rule:'DS004',severity:'medium',message:'Debug flag enabled',
    pattern:/\b(?:debuggable|debug)\s*[:=]\s*["']?true\b/i},
  {rule:'DS005',severity:'medium',message:'Potential client-side license bypass risk',
    pattern:/\b(?:license_valid|is_licensed|is_premium)\s*[:=]\s*(?:true|false)\b/i},
  {rule:'DS006',severity:'high',message:'Potential unquoted secret assignment',
    pattern:/^\s*(?:export\s+)?(?:api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|database[_-]?password|db[_-]?password|password)\s*[:=]\s*[A-Za-z0-9][A-Za-z0-9_+./=:@-]{11,}\s*(?:#.*)?$/i}
];

export const SAMPLE_FILES = Object.freeze([
  {path:'src/config.ts',text:'const api_key = "synthetic-demo-value-123456789";\n'},
  {path:'.env',text:'CLIENT_SECRET=synthetic-example-only-12345678\n'},
  {path:'docs/app.md',text:'password: "synthetic-example-only-987654321"\n'},
  {path:'src/license.ts',text:'const is_premium = true;\n'},
  {path:'src/safe.py',text:'print("no secrets here")\n'}
]);

export function supportedFile(path) {
  const basename = String(path ?? '').replace(/\\/g,'/').split('/').pop() || '';
  if (BASENAMES.has(basename) || basename.startsWith('.env')) return true;
  const i = basename.lastIndexOf('.');
  return i >= 0 && EXTENSIONS.has(basename.slice(i).toLowerCase());
}

export function scanText(content, path) {
  if (typeof content !== 'string') throw new TypeError('Content must be text');
  const findings = [];
  let number = 0;
  for (const line of content.split(/\r?\n/)) {
    number += 1;
    for (const check of RULES) {
      if (check.pattern.test(line)) {
        findings.push({file:path,line:number,rule:check.rule,
          severity:check.severity,message:check.message});
      }
    }
  }
  return findings;
}

function nameFor(entry) {
  const name = entry?.path || entry?.webkitRelativePath || entry?.name || 'unknown';
  return String(name).slice(0,400);
}

/**
 * Input is File-like objects {name/path, size, text(): Promise<string>}.
 * scanEntries never calls fetch, sends data off-device or logs source content.
 */
export async function scanEntries(entries) {
  if (!Array.isArray(entries)) throw new TypeError('Expected files array');
  const findings = [], skipped = [];
  let filesScanned = 0;
  const visible = entries.slice(0,MAX_SELECTED_FILES);
  for (const entry of visible) {
    const path = nameFor(entry);
    if (!supportedFile(path)) {
      skipped.push({file:path,reason:'Unsupported file type'});
      continue;
    }
    if (!Number.isFinite(entry?.size) || entry.size < 0 || entry.size > MAX_FILE_BYTES) {
      skipped.push({file:path,reason:'File too large or size unavailable'});
      continue;
    }
    try {
      const content = await entry.text();
      if (typeof content !== 'string' || content.includes('\0') || content.includes('\uFFFD')) {
        skipped.push({file:path,reason:'Unsupported text encoding'});
        continue;
      }
      // Text can grow if the entry is malicious or changes during read.
      if (new TextEncoder().encode(content).byteLength > MAX_FILE_BYTES) {
        skipped.push({file:path,reason:'File exceeds 1 MB'});
        continue;
      }
      findings.push(...scanText(content,path));
      filesScanned += 1;
    } catch (_) {
      skipped.push({file:path,reason:'Cannot read file'});
    }
  }
  for (const entry of entries.slice(MAX_SELECTED_FILES)) {
    skipped.push({file:nameFor(entry),reason:'250-file preview limit'});
  }
  const summary = {critical:0,high:0,medium:0,low:0};
  for (const finding of findings) summary[finding.severity] += 1;
  return {
    schema:'devshield.preview.v1',
    mode:'browser-local',
    generated_at:new Date().toISOString(),
    files_selected:entries.length,
    files_scanned:filesScanned,
    findings,
    summary,
    coverage:{
      skipped_files:skipped.length,
      skipped,
      complete_selected_files:skipped.length === 0 && filesScanned > 0,
      scope:'Selected supported text files only. Does not cover Git history, dependencies, binaries, excluded files or semantic vulnerabilities.'
    }
  };
}

export async function scanDemo() {
  return scanEntries(SAMPLE_FILES.map((file) => ({
    path:file.path,
    size:new TextEncoder().encode(file.text).byteLength,
    text:async () => file.text
  })));
}
