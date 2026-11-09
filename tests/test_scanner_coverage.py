"""Regression tests for scanner blind spots and incomplete-coverage gate."""
import contextlib
import io
import json
from pathlib import Path

from devshield.cli import main
from devshield.core import MAX_FILE_BYTES, scan


def test_json_env_markdown_and_toml_secret_assignments(tmp_path: Path):
    fixtures = {
        "config.json": '{"api_key": "json-secret-example-123456789"}\n',
        ".env": "CLIENT_SECRET=env-example-token-123456789\n",
        "README.md": 'password: "markdown-secret-example-123456789"\n',
        "settings.toml": 'access_token = "toml-secret-example-123456789"\n',
    }
    for filename, value in fixtures.items():
        (tmp_path / filename).write_text(value, encoding="utf-8")
    report = scan(tmp_path)
    assert report["files_scanned"] == 4
    assert report["summary"]["high"] == 4
    assert report["coverage"]["skipped_files"] == 0
    assert {item["file"] for item in report["findings"]} == set(fixtures)
    assert {item["rule"] for item in report["findings"]} == {"DS003", "DS006"}
    rendered = json.dumps(report)
    for secret in ("json-secret-example", "env-example-token",
                   "markdown-secret-example", "toml-secret-example"):
        assert secret not in rendered


def test_oversized_and_unsupported_encoding_are_not_treated_as_clean(tmp_path: Path):
    (tmp_path / "big.py").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    (tmp_path / "unicode.toml").write_bytes("api_key = 'not-a-real-key'".encode("utf-16"))
    (tmp_path / "okay.py").write_text("print('hi')\n")
    report = scan(tmp_path)
    assert report["files_scanned"] == 1
    assert report["coverage"]["eligible_files"] == 3
    assert report["coverage"]["skipped_files"] == 2
    assert {item["reason"] for item in report["coverage"]["skipped"]} == {
        "oversized", "unsupported_encoding"
    }
    with contextlib.redirect_stdout(io.StringIO()):
        assert main(["scan", str(tmp_path), "--fail-on", "none"]) == 0
        assert main(["scan", str(tmp_path), "--fail-on", "none",
                     "--require-complete"]) == 3


def test_zero_eligible_files_fails_complete_gate(tmp_path: Path):
    (tmp_path / "ignore.exe").write_bytes(b"no eligible source")
    report = scan(tmp_path)
    assert report["files_scanned"] == 0
    assert report["coverage"]["eligible_files"] == 0
    with contextlib.redirect_stdout(io.StringIO()):
        assert main(["scan", str(tmp_path), "--require-complete",
                     "--fail-on", "none"]) == 3


def test_symlink_is_reported_as_skipped(tmp_path: Path):
    target = tmp_path / "data.py"
    target.write_text('print("okay")\n')
    alias = tmp_path / "alias.py"
    try:
        alias.symlink_to(target)
    except (NotImplementedError, OSError):
        import pytest
        pytest.skip("symlink creation not supported")
    report = scan(tmp_path)
    assert report["files_scanned"] == 1
    assert {"file": "alias.py", "reason": "symlink"} in report["coverage"]["skipped"]
