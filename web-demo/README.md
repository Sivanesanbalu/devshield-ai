# DevShield Live Lab — browser-only preview

This is a static, interactive developer preview. It can be deployed without
PostgreSQL, Redis, API credentials, or any server-side source processing.

**Not the production DevShield protection platform.** The in-browser rules
mirror selected DS001–DS006 Python heuristic rules; this does not provide
full Python/VS Code scanner parity or a security certification.

## How to test

1. Click "Run safe demo scan" to scan five synthetic files.
2. Expect 5 files scanned and 4 findings (3 high, 1 medium), 0 skipped.
3. Select your own text files or source folder (browser compatibility varies).
4. Review findings, severity, file names and line numbers. Match contents are
   intentionally redacted and never included in the JSON report.
5. Test an unsupported binary or >1 MB text file: coverage becomes incomplete.
6. Optionally export a redacted report JSON to your device.

## Privacy architecture

- All selected file bytes stay within your browser process. JavaScript uses
  the browser File API; there is no upload or backend endpoint.
- Content-Security-Policy prevents outbound fetch/XHR connections.
- Rendering uses DOM textContent for source-derived labels, preventing
  HTML interpretation of file names.
- No accounts, cookies, analytics, API credentials, localStorage, remote
  font providers, or third-party libraries are used.
- The website host necessarily receives ordinary page and asset requests,
  but no selected source content.
- File names appear only in your own report and exported JSON.

## Limitations

The scanner uses heuristic regular expressions and does NOT detect all
secrets, vulnerabilities, obfuscation or encoded keys. It cannot prevent
reverse engineering, apply quotas to your production API, scan repository
history, verify trusted binary signatures, or protect unguarded routes.
Folder selection depends on browser support. Unknown and oversized files
are explicitly marked skipped.

**Never put the local-only Python operations console or the protected API
demo on a public interface.** An Internet-exposed API requires reviewed
authentication, TLS, reliable quota enforcement and independent tests.

## Verify

    node --version  # Node 20+ recommended
    npm --prefix web-demo run check
    npm --prefix web-demo test

To preview locally:

    cd web-demo
    python3 -m http.server 8000 --bind 127.0.0.1

Then visit http://127.0.0.1:8000. Development HTTP only; public deployment
must serve HTTPS and the configured security headers.

## Release

Vercel root directory: web-demo; project name: devshield-scanner-preview.
Use a preview deployment from the reviewed feature branch. Do not assign
production aliases until the product security release gate is complete.
