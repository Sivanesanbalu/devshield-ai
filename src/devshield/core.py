"""Small, deterministic local-first exposure scanner. Never executes inspected files.

Important: heuristic coverage is incomplete by design; it is not a guarantee
that all secrets, vulnerabilities, or malicious code will be detected.
"""
from __future__ import annotations
import hashlib
import os
import re
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {
    '.git', 'node_modules', '.venv', 'venv', 'dist', 'build',
    '__pycache__', '.next'
}
TEXT_SUFFIXES = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.json', '.yaml', '.yml',
    '.env', '.properties', '.java', '.kt', '.cs', '.go', '.rs',
    '.html', '.txt', '.config', '.md', '.markdown', '.toml',
    '.sh', '.bash', '.zsh', '.ini', '.cfg', '.conf', '.xml',
    '.tf', '.tfvars', '.sql', '.php', '.rb', '.swift', '.dart',
    '.vue', '.svelte', '.c', '.h', '.cpp', '.hpp', '.ipynb'
}
TEXT_FILENAMES = {'Dockerfile', 'Makefile', '.npmrc', '.pypirc'}
SECRET_LABEL = (
    r'(?:api[_-]?key|client[_-]?secret|secret[_-]?key|'
    r'access[_-]?token|database[_-]?password|db[_-]?password|password)'
)
RULES = [
    ('DS001', 'critical', 'Private key material',
     re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('DS002', 'high', 'AWS access key identifier',
     re.compile(r'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])')),
    ('DS003', 'high', 'Potential embedded secret',
     re.compile(
         r"""(?i)(?<![A-Za-z0-9_])["']?""" + SECRET_LABEL +
         r"""["']?\s*[:=]\s*(?:"[^"\r\n]{12,}"|'[^'\r\n]{12,}')"""
     )),
    ('DS004', 'medium', 'Debug flag enabled',
     re.compile(r'(?i)\b(?:debuggable|debug)\s*[:=]\s*["\']?true\b')),
    ('DS005', 'medium', 'Potential client-side license bypass risk',
     re.compile(r'(?i)\b(?:license_valid|is_licensed|is_premium)\s*[:=]\s*(?:true|false)\b')),
    ('DS006', 'high', 'Potential unquoted secret assignment',
     re.compile(
         r'(?i)^\s*(?:export\s+)?' + SECRET_LABEL +
         r'\s*[:=]\s*[A-Za-z0-9][A-Za-z0-9_+./=:@-]{11,}\s*(?:#.*)?$'
     )),
]
SEVERITY = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def eligible_files(root: Path):
    """Return files eligible for heuristic scanning (excluding known vendor/build dirs).

    A directory scan never follows a symlink. File symlinks are reported as
    skipped rather than being silently treated as clean.
    """
    root = root.resolve()
    if root.is_file():
        yield root
        return
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs
            if d not in SKIP_DIRS and not (Path(folder) / d).is_symlink()
        )
        for name in sorted(files):
            path = Path(folder) / name
            if (path.suffix.lower() in TEXT_SUFFIXES or
                    name.startswith('.env') or name in TEXT_FILENAMES):
                yield path


def scan(root: Path) -> dict:
    """Scan eligible files without leaking matched values.

    Coverage exposes readable-file failures, oversized files and symlinks.
    Excluded directories and unsupported file types remain outside coverage.
    """
    root = Path(root).resolve()
    if not root.exists():
        raise FileNotFoundError(str(root))
    if not (root.is_file() or root.is_dir()):
        raise ValueError('expected a regular file or directory')

    findings = []
    skipped = []
    count = 0

    def label(path):
        return str(path.relative_to(root) if root.is_dir() else path.name)

    for path in eligible_files(root):
        file_label = label(path)
        if path.is_symlink():
            skipped.append({'file': file_label, 'reason': 'symlink'})
            continue
        try:
            if not path.is_file():
                skipped.append({'file': file_label, 'reason': 'not_regular_file'})
                continue
            # Read at most 1 MiB + 1 byte, even if the file grows after stat.
            with path.open('rb') as stream:
                content = stream.read(MAX_FILE_BYTES + 1)
        except OSError:
            skipped.append({'file': file_label, 'reason': 'unreadable'})
            continue
        if len(content) > MAX_FILE_BYTES:
            skipped.append({'file': file_label, 'reason': 'oversized'})
            continue
        if b'\x00' in content:
            # NUL bytes often indicate UTF-16 or binary data. Treat as
            # incomplete rather than reporting a misleading clean scan.
            skipped.append({'file': file_label, 'reason': 'unsupported_encoding'})
            continue
        count += 1
        for no, line in enumerate(content.decode('utf-8', 'replace').splitlines(), 1):
            for rule_id, severity, title, pattern in RULES:
                if pattern.search(line):
                    findings.append({
                        'rule': rule_id, 'severity': severity,
                        'message': title, 'file': file_label, 'line': no
                    })
    return {
        'schema': 'devshield.scan.v1',
        'files_scanned': count,
        'findings': findings,
        'summary': {
            level: sum(f['severity'] == level for f in findings)
            for level in SEVERITY
        },
        'coverage': {
            'eligible_files': count + len(skipped),
            'skipped_files': len(skipped),
            'skipped': skipped,
            'note': (
                'Coverage excludes configured vendor/build directories and '
                'unsupported file types; this is not a full security audit.'
            )
        }
    }


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
