"""The ``check`` commit/CI gate: validate (required) + dryrun (gated) + advisory ruff/mypy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import messagefoundry.checks as checks
from messagefoundry.__main__ import main
from messagefoundry.checks import run_checks

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"
ADT_A01 = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def _out_json(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    return json.loads(capsys.readouterr().out)  # type: ignore[no-any-return]


def _check(report: dict[str, object], name: str) -> dict[str, object]:
    return next(c for c in report["checks"] if c["name"] == name)  # type: ignore[union-attr,index]


def test_check_clean_sample_passes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", "--config", str(SAMPLES_CONFIG), "--no-lint", "--json"]) == 0
    report = _out_json(capsys)
    assert report["ok"] is True
    validate = _check(report, "validate")
    assert validate["ok"] is True and validate["required"] is True
    # dryrun is skipped (no fixtures given) and never blocks
    assert _check(report, "dryrun")["skipped"] is True


def test_check_bad_config_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "bad.py").write_text("raise ValueError('boom')\n", encoding="utf-8")
    assert main(["check", "--config", str(tmp_path), "--no-lint", "--json"]) == 1
    report = _out_json(capsys)
    assert report["ok"] is False
    validate = _check(report, "validate")
    assert validate["ok"] is False and validate["required"] is True


def test_check_dryrun_gates_when_fixtures_present(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    msgs = tmp_path / "messages"
    msgs.mkdir()
    (msgs / "a.hl7").write_bytes(ADT_A01.encode("utf-8"))
    rc = main(
        ["check", "--config", str(SAMPLES_CONFIG), "--messages", str(msgs), "--no-lint", "--json"]
    )
    assert rc == 0
    dr = _check(_out_json(capsys), "dryrun")
    assert dr["required"] is True and dr["ok"] is True and dr["skipped"] is False


def test_check_dryrun_skipped_without_fixtures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    msgs = tmp_path / "messages"
    msgs.mkdir()  # empty — no *.hl7
    rc = main(
        ["check", "--config", str(SAMPLES_CONFIG), "--messages", str(msgs), "--no-lint", "--json"]
    )
    assert rc == 0
    dr = _check(_out_json(capsys), "dryrun")
    assert dr["skipped"] is True and dr["required"] is False


def test_check_dryrun_fails_on_bad_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    msgs = tmp_path / "messages"
    msgs.mkdir()
    (msgs / "bad.hl7").write_bytes(b"NOT-AN-HL7-MESSAGE\r")
    rc = main(
        ["check", "--config", str(SAMPLES_CONFIG), "--messages", str(msgs), "--no-lint", "--json"]
    )
    assert rc == 1
    report = _out_json(capsys)
    assert report["ok"] is False
    dr = _check(report, "dryrun")
    assert dr["ok"] is False and dr["required"] is True


def test_check_dryrun_fails_on_missing_messages_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An explicitly-given --messages that doesn't exist must fail, not silently skip (low-20).
    missing = tmp_path / "renamed-away"
    rc = main(
        [
            "check",
            "--config",
            str(SAMPLES_CONFIG),
            "--messages",
            str(missing),
            "--no-lint",
            "--json",
        ]
    )
    assert rc == 1
    dr = _check(_out_json(capsys), "dryrun")
    assert dr["ok"] is False and dr["required"] is True and dr["skipped"] is False


def test_check_dryrun_accepts_single_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A single .hl7 file is dry-run like the `dryrun` CLI accepts, not skipped (low-20).
    one = tmp_path / "a.hl7"
    one.write_bytes(ADT_A01.encode("utf-8"))
    rc = main(
        ["check", "--config", str(SAMPLES_CONFIG), "--messages", str(one), "--no-lint", "--json"]
    )
    assert rc == 0
    dr = _check(_out_json(capsys), "dryrun")
    assert dr["required"] is True and dr["ok"] is True and dr["skipped"] is False


def test_run_checks_skips_lint_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checks.shutil, "which", lambda _: None)
    report = run_checks(SAMPLES_CONFIG, messages_dir=None, run_lint=True)
    by_name = {r.name: r for r in report.results}
    for tool in ("ruff", "mypy"):
        assert by_name[tool].skipped is True and by_name[tool].required is False
    assert report.ok is True  # advisory skips never block


def test_run_checks_no_lint_excludes_tools() -> None:
    report = run_checks(SAMPLES_CONFIG, run_lint=False)
    names = {r.name for r in report.results}
    assert "ruff" not in names and "mypy" not in names
    assert "validate" in names and "dryrun" in names


def test_check_json_shape(capsys: pytest.CaptureFixture[str]) -> None:
    main(["check", "--config", str(SAMPLES_CONFIG), "--no-lint", "--json"])
    report = _out_json(capsys)
    assert set(report.keys()) == {"ok", "checks"}
    for c in report["checks"]:  # type: ignore[union-attr]
        assert set(c.keys()) == {"name", "ok", "required", "skipped", "detail"}
