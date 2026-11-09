'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { normalizeFindings } = require('../diagnostics');

const ROOT = path.resolve('devshield-test-workspace');
const report = (findings) => ({ schema: 'devshield.scan.v1', findings });

test('accepts safe relative scanner paths and preserves redacted metadata', () => {
  const grouped = normalizeFindings(ROOT, report([
    { file: 'src/app.py', line: 4, severity: 'high', rule: 'DS003',
      message: 'Potential embedded secret' },
    { file: 'src/app.py', line: 7, severity: 'low', rule: 'DS004',
      message: 'Debug indicator' }
  ]));
  assert.equal(grouped.size, 1);
  const entries = grouped.get(path.resolve(ROOT, 'src/app.py'));
  assert.equal(entries.length, 2);
  assert.deepEqual(entries.map((x) => x.line), [4, 7]);
  assert.equal(entries[0].message, 'Potential embedded secret');
});

test('rejects traversal, absolute paths, and Windows drive paths', () => {
  const grouped = normalizeFindings(ROOT, report([
    { file: '../outside.py', line: 1, severity: 'high', rule: 'DS003', message: 'X' },
    { file: '/tmp/outside.py', line: 1, severity: 'high', rule: 'DS003', message: 'X' },
    { file: 'C:\\outside.py', line: 1, severity: 'high', rule: 'DS003', message: 'X' },
    { file: '.', line: 1, severity: 'high', rule: 'DS003', message: 'X' }
  ]));
  assert.equal(grouped.size, 0);
});

test('ignores malformed and hostile report entries without throwing', () => {
  const grouped = normalizeFindings(ROOT, report([
    null, {},
    { file: 'app.py', line: -1, severity: 'high', rule: 'DS003', message: 'X' },
    { file: 'app.py', line: 1.5, severity: 'high', rule: 'DS003', message: 'X' },
    { file: 'app.py', line: 1, severity: 'unexpected', rule: 'DS003', message: 'X' },
    { file: 'app.py', line: 1, severity: 'high', rule: null, message: 'X' }
  ]));
  assert.equal(grouped.size, 0);
});

test('rejects incompatible schema or invalid roots', () => {
  assert.throws(() => normalizeFindings(ROOT, {}), /Unexpected/);
  assert.throws(() => normalizeFindings('relative', report([])), /absolute/);
});
