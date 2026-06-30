# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Support-bundle (#49) tests: the zip contents, the secret-free config summary, the status snapshot
built from the real models, and the log-tail redaction — with the hard rule that no raw message body
or secret reaches the bundle."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from messagefoundry import __version__
from messagefoundry.support import build_bundle, redact_log_line, redact_log_text
from messagefoundry.support.bundle import config_summary, status_snapshot
from messagefoundry.support.redact import REDACTION_PLACEHOLDER


def _members(zip_path: Path) -> dict[str, str]:
    with zipfile.ZipFile(zip_path) as zf:
        return {name: zf.read(name).decode("utf-8") for name in zf.namelist()}


def test_bundle_writes_expected_members(tmp_path: Path) -> None:
    out = tmp_path / "bundle.zip"
    result = build_bundle(out, config_dir=None, settings=None)
    assert Path(result.path) == out
    members = _members(out)
    assert "version.txt" in members
    assert "manifest.json" in members
    assert "status.json" in members
    assert "config-summary.json" in members
    # No app-log without settings/log_dir.
    assert "app-log.txt" not in members
    assert members["version.txt"].strip() == __version__


def test_bundle_version_and_manifest(tmp_path: Path) -> None:
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=None, now=1_700_000_000.0)
    members = _members(out)
    manifest = json.loads(members["manifest.json"])
    assert manifest["version"] == __version__
    assert manifest["generated_at"] == 1_700_000_000.0
    assert "phi_contract" in manifest
    assert "no raw message bodies" in manifest["phi_contract"]


def test_status_snapshot_uses_real_models() -> None:
    # No settings -> engine info from __version__, db None. Built from the REAL status models.
    snap = status_snapshot(None)
    assert snap["engine"]["version"] == __version__
    assert snap["engine"]["uptime_seconds"] == 0.0
    assert snap["db"] is None


def test_config_summary_counts_only_no_settings_values(tmp_path: Path) -> None:
    # A minimal valid config dir: one inbound + one outbound + a router + handler.
    cfg = tmp_path / "config"
    cfg.mkdir()
    secret_dir = "/srv/secret-internal-outdir"
    (cfg / "feed.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File\n"
        "inbound('IB_ACME_ADT', MLLP(port=2575), router='route')\n"
        f"outbound('OB_ACME_ADT', File(directory={secret_dir!r}))\n"
        "@router('route')\n"
        "def route(msg):\n"
        "    return ['handle']\n"
        "@handler('handle')\n"
        "def handle(msg):\n"
        "    return Send('OB_ACME_ADT', msg)\n",
        encoding="utf-8",
    )
    summary = config_summary(cfg)
    assert summary["loaded"] is True
    assert summary["counts"] == {"inbound": 1, "outbound": 1, "routers": 1, "handlers": 1}
    assert summary["inbound"] == [{"name": "IB_ACME_ADT", "type": "mllp"}]
    # The HARD RULE: no settings value (host/port/path) leaks into the summary.
    blob = json.dumps(summary)
    assert secret_dir not in blob
    assert "2575" not in blob


def test_config_summary_broken_config_reports_error(tmp_path: Path) -> None:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "bad.py").write_text("this is not valid python !!!\n", encoding="utf-8")
    summary = config_summary(cfg)
    assert summary["loaded"] is False
    assert "error" in summary


def test_log_tail_redacted_no_phi_no_secret(tmp_path: Path) -> None:
    # Build a fake settings object pointing at a log dir holding a line with PHI + a secret.
    from messagefoundry.config.settings import load_settings

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    leaky = (
        "2026-06-27 INFO routing message\n"
        "PID|1||123456^^^MR||DOE^JANE^Q||19800101|F\n"
        "MEFOR_STORE_ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "Authorization: Bearer abcdef0123456789abcdef0123456789\n"
        "blob mfb64:v1:SGVsbG9Xb3JsZEhlbGxvV29ybGQ=\n"
    )
    (log_dir / "engine.log").write_text(leaky, encoding="utf-8")

    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(f'[logging]\nlog_dir = "{log_dir.as_posix()}"\n', encoding="utf-8")
    settings = load_settings(config_path=toml)

    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=settings)
    members = _members(out)
    assert "app-log.txt" in members
    tail = members["app-log.txt"]
    # PHI patient name + MRN must be gone (HL7 PID segment collapsed).
    assert "DOE^JANE" not in tail
    assert "123456" not in tail
    # The secret VALUE is gone (the var NAME may remain so a reviewer sees which leaked).
    assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in tail
    # The bearer token value is gone.
    assert "abcdef0123456789abcdef0123456789" not in tail
    # The embedded base64 body is gone.
    assert "SGVsbG9Xb3JsZEhlbGxvV29ybGQ=" not in tail
    assert REDACTION_PLACEHOLDER in tail


def test_redact_hl7_segment() -> None:
    line = "got PID|1||999^^^MR||SMITH^JOHN||19700101|M and more"
    out = redact_log_line(line)
    assert "SMITH^JOHN" not in out
    assert "999" not in out
    assert out.startswith("got PID|")


def test_redact_mefor_secret_keeps_name() -> None:
    out = redact_log_line("env MEFOR_API_TOKEN=supersecretvalue123456789 loaded")
    assert "supersecretvalue123456789" not in out
    assert "MEFOR_API_TOKEN" in out  # the NAME is preserved for triage


def test_redact_text_preserves_line_count() -> None:
    text = "line one\nPID|1||x^^^MR||A^B||19700101|M\nline three"
    out = redact_log_text(text)
    assert len(out.splitlines()) == 3


def test_redact_plain_line_unchanged() -> None:
    # A short, ordinary log line with no secrets/PHI is left intact.
    line = "2026-06-27 INFO engine started on port 8765"
    assert redact_log_line(line) == line


def test_bundle_status_with_settings_db(tmp_path: Path) -> None:
    from messagefoundry.config.settings import load_settings

    db = tmp_path / "store.db"
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(f'[store]\npath = "{db.as_posix()}"\n', encoding="utf-8")
    settings = load_settings(config_path=toml)
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=settings)
    members = _members(out)
    status = json.loads(members["status.json"])
    assert status["engine"]["version"] == __version__
    # DbInfo from the real model, populated from the opened store.
    assert status["db"] is not None
    assert status["db"]["journal_mode"]
