'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { normalizeFindings } = require('../diagnostics');

test('real Python scanner JSON is accepted and never includes matched secret', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'devshield-vscode-'));
  const secret = 'devshield-test-secret-987654321';
  try {
    fs.writeFileSync(path.join(root, 'config.py'), 'api_key = "' + secret + '"\n');
    const python = process.env.DEVSHIELD_TEST_PYTHON || 'python3';
    const output = execFileSync(
      python, ['-m', 'devshield.cli', 'scan', root, '--fail-on', 'none'],
      { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 30000 }
    );
    assert.equal(output.includes(secret), false);
    const report = JSON.parse(output);
    assert.equal(report.schema, 'devshield.scan.v1');
    const grouped = normalizeFindings(root, report);
    const finding = grouped.get(path.join(root, 'config.py'));
    assert.equal(finding.length, 1);
    assert.equal(finding[0].rule, 'DS003');
    assert.equal(finding[0].severity, 'high');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
