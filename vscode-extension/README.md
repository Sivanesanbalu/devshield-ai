# DevShield VS Code extension (developer preview)

This is an opt-in, local-only companion to the Python DevShield scanner.
It is NOT a published Marketplace extension and does not make DevShield
production-ready.

## Local usage

1. Install Python 3.10+ and the DevShield package from the repository root
   with: python -m pip install -e .
2. Open the vscode-extension directory in VS Code and press F5
   (Run > Start Debugging / Extension Development Host).
   In the new VS Code window, open the folder you want to scan.
3. Mark that workspace as trusted only if you trust its contents.
4. Run the Command Palette action: DevShield: Scan Workspace.
5. View redacted DS001-DS005 findings in the Problems panel.

The extension defaults to executing "python3 -m devshield.cli" from each
workspace folder. On Windows, or when using a virtual environment, configure
"devshield.pythonPath" to the full path of the Python interpreter where
devshield-security is installed. Configure "devshield.scanTimeoutSeconds"
for a per-folder timeout (5-120 seconds).

The extension sends no code to a remote service, invokes no shell,
and does not run Python in VS Code Restricted Mode. Scans happen only when
a user invokes the command. Errors are intentionally generic: stderr and
raw source lines are not shown or logged. Results are derived from the
existing scanner and remain heuristic, not a guarantee of security.

## Validate locally

From vscode-extension, run:

    npm run check
    npm test

There are no npm runtime dependencies. Node.js 20+ is used for tests.
For production extension publishing, separate publisher verification,
packaging, marketplace policy and security review are required.
