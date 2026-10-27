"""Bounded, read-only release binary exposure assessment.

This is not a reverse-engineering prevention mechanism. Never emit matched values.
"""
from __future__ import annotations
import os
import re
from pathlib import Path

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_FILES = 5000
SKIP = {'.git', '.venv', 'node_modules', '__pycache__'}
EXTENSIONS = {'.exe', '.dll', '.sys', '.so', '.dylib', '.jar', '.apk', '.bin', '.pyd'}
RULES = (
    ('EX001', 'high', 'Private key marker embedded in release artifact', re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('EX002', 'medium', 'Debug or symbol path reference in released artifact', re.compile(rb'(?i)(?:[A-Z]:\\[^\x00\r\n]{1,180}\.pdb|/[^\x00\r\n]{1,180}\.pdb)')),
    ('EX003', 'medium', 'Potential internal service hostname in release artifact', re.compile(rb'(?i)\b(?:https?://)?[a-z0-9.-]{1,90}\.(?:internal|corp|local)(?::\d{2,5})?(?:/|\b)')),
)

def inspect_exposure(path: Path) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('expected a regular, non-symlink artifact')
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('artifact exceeds 64 MiB exposure analysis limit')
    data = path.read_bytes()
    findings = []
    for rule, severity, message, pattern in RULES:
        if pattern.search(data):
            findings.append({'rule': rule, 'severity': severity, 'message': message})
    return {'file': path.name, 'size_bytes': len(data), 'findings': findings,
            'note': 'Heuristic exposure indicators only; no values, paths, secrets, or matched bytes are disclosed.'}

def scan_exposure(root: Path) -> dict:
    root = Path(root).resolve()
    if not root.exists():
        raise FileNotFoundError(str(root))
    if root.is_file():
        files = [root]
    else:
        files = []
        for folder, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SKIP and not (Path(folder) / d).is_symlink())
            files.extend(Path(folder) / n for n in sorted(names) if Path(n).suffix.lower() in EXTENSIONS and not (Path(folder) / n).is_symlink())
            if len(files) > MAX_FILES:
                raise ValueError('too many release artifacts (limit 5000)')
    results, errors = [], []
    for file in files:
        label = file.relative_to(root).as_posix() if root.is_dir() else file.name
        try:
            entry = inspect_exposure(file)
            entry['file'] = label
            results.append(entry)
        except (OSError, ValueError) as exc:
            errors.append({'file': label, 'error': str(exc)})
    return {'schema': 'devshield.exposure.v1', 'files_inspected': len(results),
            'results': results, 'errors': errors}
