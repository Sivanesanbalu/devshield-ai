'use strict';

const vscode = require('vscode');
const { execFile } = require('node:child_process');
const { normalizeFindings } = require('./diagnostics');

const MAX_OUTPUT_BYTES = 5 * 1024 * 1024;
const SEVERITY = Object.freeze({
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information
});

function runScanner(root, pythonPath, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile(
      pythonPath,
      ['-m', 'devshield.cli', 'scan', root, '--fail-on', 'none'],
      { cwd: root, timeout: timeoutMs, maxBuffer: MAX_OUTPUT_BYTES,
        windowsHide: true, shell: false },
      (error, stdout) => {
        if (error) {
          reject(new Error(
            'Scanner failed. Install devshield-security in the selected Python ' +
            'environment and confirm it runs from a terminal.'
          ));
          return;
        }
        try {
          const report = JSON.parse(stdout);
          if (!report || report.schema !== 'devshield.scan.v1' ||
              !Array.isArray(report.findings)) {
            throw new Error('invalid schema');
          }
          resolve(report);
        } catch (_) {
          reject(new Error('Scanner returned invalid JSON; no diagnostics were applied.'));
        }
      }
    );
  });
}

function activate(context) {
  const collection = vscode.languages.createDiagnosticCollection('DevShield');
  context.subscriptions.push(collection);
  let running = false;

  context.subscriptions.push(vscode.commands.registerCommand(
    'devshield.scanWorkspace',
    async () => {
      if (!vscode.workspace.isTrusted) {
        vscode.window.showWarningMessage(
          'DevShield requires a trusted workspace before running local Python.'
        );
        return;
      }
      const folders = vscode.workspace.workspaceFolders || [];
      if (!folders.length) {
        vscode.window.showWarningMessage('Open a folder to scan with DevShield.');
        return;
      }
      if (running) {
        vscode.window.showInformationMessage('A DevShield scan is already in progress.');
        return;
      }

      running = true;
      collection.clear();
      let scanned = 0;
      let findingsCount = 0;
      const errors = [];
      const settings = vscode.workspace.getConfiguration('devshield');
      const pythonPath = settings.get('pythonPath', 'python3');
      const seconds = settings.get('scanTimeoutSeconds', 30);
      const timeoutMs = (Number.isInteger(seconds) &&
        seconds >= 5 && seconds <= 120 ? seconds : 30) * 1000;

      try {
        await vscode.window.withProgress({
          location: vscode.ProgressLocation.Notification,
          title: 'DevShield: scanning workspace',
          cancellable: false
        }, async (progress) => {
          for (const folder of folders) {
            progress.report({ message: folder.name });
            try {
              const report = await runScanner(folder.uri.fsPath, pythonPath, timeoutMs);
              const grouped = normalizeFindings(folder.uri.fsPath, report);
              for (const [filename, findings] of grouped.entries()) {
                const diagnostics = findings.map((finding) => {
                  const line = finding.line - 1;
                  const diagnostic = new vscode.Diagnostic(
                    new vscode.Range(line, 0, line, 1),
                    finding.rule + ': ' + finding.message,
                    SEVERITY[finding.severity]
                  );
                  diagnostic.code = finding.rule;
                  diagnostic.source = 'DevShield';
                  return diagnostic;
                });
                collection.set(vscode.Uri.file(filename), diagnostics);
                findingsCount += diagnostics.length;
              }
              scanned += 1;
            } catch (error) {
              errors.push(folder.name + ': ' + error.message);
            }
          }
        });

        const result = 'DevShield scanned ' + scanned + '/' +
          folders.length + ' folders; ' + findingsCount + ' findings.';
        if (errors.length) {
          vscode.window.showWarningMessage(result + ' ' + errors.join(' '));
        } else {
          vscode.window.showInformationMessage(result + ' See the Problems panel.');
        }
      } finally {
        running = false;
      }
    }
  ));
}

function deactivate() {}

module.exports = { activate, deactivate };
