'use strict';

const path = require('node:path');

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);

/**
 * Turn redacted DevShield findings into validated absolute file locations.
 * Reject path escapes and malformed lines; do not expose source line text.
 * Returned Map values are arrays of { line, severity, rule, message }.
 */
function normalizeFindings(workspaceRoot, report) {
  if (!report || report.schema !== 'devshield.scan.v1' ||
      !Array.isArray(report.findings)) {
    throw new Error('Unexpected DevShield scanner report');
  }
  if (typeof workspaceRoot !== 'string' || !path.isAbsolute(workspaceRoot)) {
    throw new Error('Workspace root must be absolute');
  }

  const root = path.resolve(workspaceRoot);
  const byFile = new Map();

  for (const finding of report.findings) {
    if (!finding || typeof finding.file !== 'string' ||
        !finding.file || finding.file.includes('\0') ||
        path.isAbsolute(finding.file) || path.win32.isAbsolute(finding.file) ||
        !Number.isSafeInteger(finding.line) || finding.line < 1 ||
        !VALID_SEVERITIES.has(finding.severity) ||
        typeof finding.rule !== 'string' ||
        typeof finding.message !== 'string') {
      continue;
    }
    const absolute = path.resolve(root, finding.file);
    const relative = path.relative(root, absolute);
    if (!relative || relative === '..' ||
        relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
      continue;
    }

    if (!byFile.has(absolute)) byFile.set(absolute, []);
    byFile.get(absolute).push({
      line: finding.line,
      severity: finding.severity,
      rule: finding.rule,
      message: finding.message
    });
  }
  return byFile;
}

module.exports = { normalizeFindings };
