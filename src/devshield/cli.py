"""Minimal runnable CLI for the published DevShield foundation subset."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .core import scan, release_manifest, verify_manifest, SEVERITY
from .exposure import scan_exposure

def main(argv=None):
    parser = argparse.ArgumentParser(prog="devshield")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="Scan local source for exposure indicators")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--fail-on", choices=["none", *SEVERITY], default="high")
    e = sub.add_parser("exposure-scan", help="Inspect release binary for exposure markers")
    e.add_argument("path")
    e.add_argument("--fail-on", choices=["none", *SEVERITY], default="high")
    m = sub.add_parser("manifest", help="Generate unsigned SHA-256 inventory")
    m.add_argument("path")
    m.add_argument("--output", required=True)
    v = sub.add_parser("verify", help="Check files against unsigned inventory")
    v.add_argument("path")
    v.add_argument("--manifest", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            report = scan(Path(args.path))
            findings = report["findings"]
        elif args.command == "exposure-scan":
            report = scan_exposure(Path(args.path))
            findings = [f for item in report["results"] for f in item["findings"]]
        elif args.command == "manifest":
            report = release_manifest(Path(args.path))
            Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            findings = []
        else:
            report = verify_manifest(Path(args.path), json.loads(Path(args.manifest).read_text(encoding="utf-8")))
            findings = []
        print(json.dumps(report, indent=2))
        if args.command == "verify":
            return 0 if report["verified"] else 1
        if hasattr(args, "fail_on") and args.fail_on != "none":
            return int(any(SEVERITY[f["severity"]] >= SEVERITY[args.fail_on] for f in findings))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.exit(2, f"devshield: {error}\n")

if __name__ == "__main__":
    raise SystemExit(main())
