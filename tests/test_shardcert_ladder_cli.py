# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""CLI-level tests for the shardcert ladder subcommands: the D2 soak-drain coupling and the D5 report
robustness / provenance / store-env logging. The live ladder never runs — ``run_drive_ladder`` /
``run_engine_ladder`` are monkeypatched to capture their kwargs, so these exercise the argument wiring and
the report/IO helpers WITHOUT a two-box fleet.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from harness import __main__ as hm
from harness.load.shardcert_ladder import build_consolidated_report

# --- D5 helpers (direct) -----------------------------------------------------


def test_write_json_report_creates_parent_dirs(tmp_path) -> None:
    path = tmp_path / "new" / "nested" / "report.json"
    hm._write_json_report(str(path), {"a": 1, "b": [2, 3]}, label="t")
    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8")) == {"a": 1, "b": [2, 3]}


def test_write_json_report_bad_path_warns_and_never_raises(tmp_path, capsys) -> None:
    # D5 P1: a bad --report-json path must NOT raise (a completed run's exit code must still return).
    afile = tmp_path / "afile"
    afile.write_text("x", encoding="utf-8")
    bad = afile / "sub" / "report.json"  # parent 'afile' is a FILE ⇒ mkdir raises OSError
    hm._write_json_report(str(bad), {"a": 1}, label="shardcert-drive-ladder")  # must not raise
    err = capsys.readouterr().err
    assert "WARNING could not write --report-json" in err
    assert not bad.exists()


def test_log_store_env_source_prints_keys_not_values(capsys) -> None:
    # D5 P3: KEY NAMES ONLY — a value (e.g. MEFOR_STORE_PASSWORD) must never appear (secrets rule).
    hm._log_store_env_source(
        "shardcert-engine-ladder",
        {"MEFOR_STORE_BACKEND": "sqlserver", "MEFOR_STORE_PASSWORD": "SUPERSECRET"},
    )
    err = capsys.readouterr().err
    assert "MEFOR_STORE_BACKEND" in err and "MEFOR_STORE_PASSWORD" in err
    assert "SUPERSECRET" not in err
    assert "sqlserver" not in err  # the backend VALUE is also not shown


def test_log_store_env_source_empty(capsys) -> None:
    hm._log_store_env_source("shardcert-engine-ladder", {})
    assert "(none set)" in capsys.readouterr().err


def test_git_commit_sha_is_str_or_none() -> None:
    sha = hm._git_commit_sha()
    assert sha is None or (isinstance(sha, str) and len(sha) >= 7)


# --- D2 soak-drain coupling (via main, run_*_ladder captured) -----------------


def _empty_report():
    return build_consolidated_report(
        shards=("a", "b", "c", "d"), dests=8, driver_count=4, sink_count=8, climb=[], soak=None
    )


def _patch_drive(monkeypatch) -> dict:
    captured: dict = {}

    async def _fake(**kw):
        captured.update(kw)
        return _empty_report()

    monkeypatch.setattr("harness.load.shardcert_ladder.run_drive_ladder", _fake)
    return captured


def _patch_engine(monkeypatch) -> dict:
    captured: dict = {}

    async def _fake(**kw):
        captured.update(kw)
        return SimpleNamespace(render=lambda: "engine ladder result")

    monkeypatch.setattr("harness.load.shardcert_ladder.run_engine_ladder", _fake)
    return captured


def test_drive_ladder_soak_drain_defaults_to_drain_timeout(monkeypatch, tmp_path) -> None:
    captured = _patch_drive(monkeypatch)
    rc = hm.main(
        [
            "shardcert-drive-ladder",
            "--engine-host",
            "127.0.0.1",
            "--rate-ladder",
            "24,28",
            "--coord-dir",
            str(tmp_path),
            "--drain-timeout",
            "150",
        ]
    )
    assert isinstance(rc, int)  # rc is the report's honest exit code
    assert captured["soak_drain_timeout"] == 150.0  # coupled to --drain-timeout, NOT the old 300.0


def test_engine_ladder_soak_drain_defaults_to_drain_timeout(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MEFOR_STORE_BACKEND", "sqlserver")
    captured = _patch_engine(monkeypatch)
    hm.main(
        [
            "shardcert-engine-ladder",
            "--rate-ladder",
            "24,28",
            "--sink-port",
            "9000",
            "--coord-dir",
            str(tmp_path),
            "--drain-timeout",
            "150",
        ]
    )
    assert captured["soak_drain_timeout"] == 150.0  # engine-half fallback coupling


def test_soak_drain_timeout_explicit_override_wins(monkeypatch, tmp_path) -> None:
    captured = _patch_drive(monkeypatch)
    hm.main(
        [
            "shardcert-drive-ladder",
            "--engine-host",
            "127.0.0.1",
            "--rate-ladder",
            "24,28",
            "--coord-dir",
            str(tmp_path),
            "--drain-timeout",
            "150",
            "--soak-drain-timeout",
            "42",
        ]
    )
    assert captured["soak_drain_timeout"] == 42.0  # explicit override beats the coupling


# --- D5 report-json write + provenance (via main) -----------------------------


def test_report_json_writes_provenance_and_creates_parents(monkeypatch, tmp_path) -> None:
    _patch_drive(monkeypatch)
    out = tmp_path / "reports" / "run.json"  # nested, non-existent parent
    rc = hm.main(
        [
            "shardcert-drive-ladder",
            "--engine-host",
            "127.0.0.1",
            "--rate-ladder",
            "24,28",
            "--coord-dir",
            str(tmp_path),
            "--run-id",
            "RID-123",
            "--report-json",
            str(out),
        ]
    )
    assert out.exists()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["run"]["run_id"] == "RID-123"
    assert isinstance(doc["run"]["generated_at"], str) and "T" in doc["run"]["generated_at"]
    assert doc["run"]["commit_sha"] is None or isinstance(doc["run"]["commit_sha"], str)
    assert rc == _empty_report().exit_code  # the honest exit code is returned


def test_report_json_bad_path_does_not_mask_exit_code(monkeypatch, tmp_path, capsys) -> None:
    _patch_drive(monkeypatch)
    afile = tmp_path / "afile"
    afile.write_text("x", encoding="utf-8")
    bad = afile / "sub" / "run.json"  # parent is a file ⇒ unwritable
    rc = hm.main(
        [
            "shardcert-drive-ladder",
            "--engine-host",
            "127.0.0.1",
            "--rate-ladder",
            "24,28",
            "--coord-dir",
            str(tmp_path),
            "--report-json",
            str(bad),
        ]
    )
    assert rc == _empty_report().exit_code  # a bad path did NOT raise or mask the exit code
    assert "WARNING could not write --report-json" in capsys.readouterr().err


def test_engine_ladder_logs_store_env_key_names_not_values(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setenv("MEFOR_STORE_BACKEND", "sqlserver")
    monkeypatch.setenv("MEFOR_STORE_PASSWORD", "TOPSECRETVALUE")
    monkeypatch.setenv("MEFOR_STORE_HOST", "db.example")
    _patch_engine(monkeypatch)
    hm.main(
        [
            "shardcert-engine-ladder",
            "--rate-ladder",
            "24,28",
            "--sink-port",
            "9000",
            "--coord-dir",
            str(tmp_path),
        ]
    )
    err = capsys.readouterr().err
    assert "store connection from ambient MEFOR_STORE_* env" in err
    assert "MEFOR_STORE_PASSWORD" in err  # the KEY is listed
    assert "TOPSECRETVALUE" not in err  # the VALUE never is (secrets rule)
