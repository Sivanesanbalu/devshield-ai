"""Small, deterministic local-first exposure scanner. Never executes inspected files."""
from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', 'dist', 'build', '__pycache__', '.next'}
TEXT_SUFFIXES = {'.py', '.js', '.jsx', '.ts', '.tsx', '.json', '.yaml', '.yml', '.env', '.properties', '.java', '.kt', '.cs', '.go', '.rs', '.html', '.txt', '.config'}
RULES = [
    ('DS001', 'critical', 'Private key material', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('DS002', 'high', 'AWS access key identifier', re.compile(r'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])')),
    ('DS003', 'high', 'Potential embedded secret', re.compile(r'''(?i)\b(?:api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']([^"'\r\n]{12,})["']''')),
    ('DS004', 'medium', 'Debug flag enabled', re.compile(r'(?i)\b(?:debuggable|debug)\s*[:=]\s*["\']?true\b')),
    ('DS005', 'medium', 'Potential client-side license bypass risk', re.compile(r'(?i)\b(?:license_valid|is_licensed|is_premium)\s*[:=]\s*(?:true|false)\b')),
]
SEVERITY = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            h.update(block)
    return h.hexdigest()

def eligible_files(root: Path):
    root = root.resolve()
    if root.is_file():
        yield root
        return
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(folder) / d).is_symlink())
        for name in sorted(files):
            p = Path(folder) / name
            if not p.is_symlink() and (p.suffix.lower() in TEXT_SUFFIXES or name.startswith('.env')):
                yield p

def scan(root: Path) -> dict:
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(str(root))
    findings = []
    count = 0
    for path in eligible_files(root):
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            continue
        count += 1
        content = path.read_bytes().decode('utf-8', 'replace')
        # No matched secret values are ever returned, printed, or persisted.
        for no, line in enumerate(content.splitlines(), 1):
            for rule_id, severity, title, pattern in RULES:
                if pattern.search(line):
                    findings.append({'rule': rule_id, 'severity': severity, 'message': title, 'file': str(path.relative_to(root) if root.is_dir() else path.name), 'line': no})
    return {'schema': 'devshield.scan.v1', 'files_scanned': count, 'findings': findings, 'summary': {s: sum(f['severity'] == s for f in findings) for s in SEVERITY}}

def release_manifest(root: Path) -> dict:
    if not root.is_dir():
        raise ValueError('release folder must be a directory')
    entries = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(folder)/d).is_symlink())
        for name in sorted(files):
            path = Path(folder)/name
            if path.is_symlink() or name == 'devshield-manifest.json':
                continue
            entries[path.relative_to(root).as_posix()] = sha256_file(path)
    return {'schema': 'devshield.manifest.v1', 'sha256': entries, 'warning': 'Unsigned hash manifest detects accidental modification only; publish signed manifest via a trusted channel.'}

def verify_manifest(root: Path, manifest: dict) -> dict:
    expected = manifest.get('sha256', {})
    if not isinstance(expected, dict):
        raise ValueError('invalid manifest')
    actual = release_manifest(root)['sha256']
    return {'verified': actual == expected, 'modified': sorted(k for k in (actual.keys() & expected.keys()) if actual[k] != expected[k]), 'missing': sorted(expected.keys() - actual.keys()), 'unexpected': sorted(actual.keys() - expected.keys())}
