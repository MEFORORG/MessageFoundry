# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ``check`` commit/CI gate: validate (required) + dryrun (gated) + advisory ruff/mypy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import messagefoundry.checks as checks
from messagefoundry.__main__ import main
from messagefoundry.checks import run_checks

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"
RESULTS_RELAY = Path(__file__).resolve().parents[1] / "samples" / "results_relay"
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


# --- per-feed fixture mapping (#11) ------------------------------------------
# A malformed body ERRORs against an HL7 inbound (peek fails) but routes fine against a text inbound
# (RawMessage, no parse). That asymmetry is a clean discriminator for "did the fixture run only
# against its mapped feed, or against every inbound?".
BAD_HL7 = b"NOT-AN-HL7-MESSAGE\r"


def _two_feed_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, router, File, ContentType\n"
        "inbound('IB_HL7', File(directory='in1'), router='r')\n"
        "inbound('IB_RAW', File(directory='in2'), router='r', content_type=ContentType.TEXT)\n"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    return cfg


def test_check_dryrun_pins_fixture_to_feed_subdir(tmp_path: Path) -> None:
    # A fixture under <messages>/IB_RAW/ is dry-run ONLY against IB_RAW (which treats it as text), so
    # it never reaches IB_HL7 (which would ERROR) — the check passes where all-×-all would fail.
    cfg = _two_feed_config(tmp_path)
    msgs = tmp_path / "messages"
    (msgs / "IB_RAW").mkdir(parents=True)
    (msgs / "IB_RAW" / "x.hl7").write_bytes(BAD_HL7)
    dr = next(
        r for r in run_checks(cfg, messages_dir=msgs, run_lint=False).results if r.name == "dryrun"
    )
    assert dr.ok and dr.required and not dr.skipped, dr.detail
    assert "feed-pinned" in dr.detail


def test_check_dryrun_unmapped_fixture_runs_every_inbound(tmp_path: Path) -> None:
    # A top-level fixture (no feed subdir) falls back to all-×-all, so it also hits IB_HL7 and errors.
    cfg = _two_feed_config(tmp_path)
    msgs = tmp_path / "messages"
    msgs.mkdir()
    (msgs / "x.hl7").write_bytes(BAD_HL7)
    dr = next(
        r for r in run_checks(cfg, messages_dir=msgs, run_lint=False).results if r.name == "dryrun"
    )
    assert not dr.ok and dr.required and not dr.skipped
    assert "IB_HL7" in dr.detail  # the error names the inbound the unmapped fixture reached


def test_check_dryrun_non_feed_subdir_falls_back_to_all(tmp_path: Path) -> None:
    # A subdir that names no inbound ('misc') is unmapped → all-×-all (not silently pinned to nothing),
    # so the malformed body still reaches IB_HL7 and errors. Also proves the recursive discovery (the
    # fixture lives only in a subdir, none at top level) doesn't skip the gate.
    cfg = _two_feed_config(tmp_path)
    msgs = tmp_path / "messages"
    (msgs / "misc").mkdir(parents=True)
    (msgs / "misc" / "x.hl7").write_bytes(BAD_HL7)
    dr = next(
        r for r in run_checks(cfg, messages_dir=msgs, run_lint=False).results if r.name == "dryrun"
    )
    assert not dr.ok and dr.required and not dr.skipped
    assert "IB_HL7" in dr.detail


def test_read_message_sets_maps_by_top_level_subdir(tmp_path: Path) -> None:
    from messagefoundry.pipeline.dryrun import read_message_sets

    (tmp_path / "IB_FOO" / "nested").mkdir(parents=True)
    (tmp_path / "IB_FOO" / "a.hl7").write_bytes(b"A")
    (tmp_path / "IB_FOO" / "nested" / "deep.hl7").write_bytes(b"D")  # nested under the feed
    (tmp_path / "top.hl7").write_bytes(b"T")
    (tmp_path / "misc").mkdir()
    (tmp_path / "misc" / "b.hl7").write_bytes(b"B")
    got = {
        label: target
        for label, _p, _raw, target in read_message_sets(tmp_path, ["IB_FOO", "IB_BAR"])
    }
    assert got["a.hl7"] == "IB_FOO"  # directly under a feed subdir → pinned
    assert got["deep.hl7"] == "IB_FOO"  # nested deeper under the feed subdir → still pinned to it
    assert got["top.hl7"] is None  # top-level → unmapped (all-×-all)
    assert got["b.hl7"] is None  # subdir that names no inbound → unmapped (fallback)


def test_read_message_sets_single_file_is_unmapped(tmp_path: Path) -> None:
    from messagefoundry.pipeline.dryrun import read_message_sets

    one = tmp_path / "a.hl7"
    one.write_bytes(ADT_A01.encode("utf-8"))
    got = read_message_sets(one, ["IB_FOO"])
    assert len(got) == 1 and got[0][0] == "a.hl7" and got[0][3] is None


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


def test_results_relay_template_passes_check() -> None:
    # The committed Wave-1 porting template must stay validate + dryrun green on every CI run.
    report = run_checks(RESULTS_RELAY, messages_dir=RESULTS_RELAY / "messages", run_lint=False)
    assert report.ok is True
    by_name = {r.name: r for r in report.results}
    assert by_name["validate"].ok and by_name["validate"].required
    dr = by_name["dryrun"]
    assert dr.required and dr.ok and not dr.skipped


def test_results_relay_template_transform_output() -> None:
    # Gate the authoring pattern itself (not just "it loads"): the transform must drop the cancelled
    # result, remap test codes, renumber OBX, fan out to both destinations, and collapse PID-3.
    from messagefoundry.config.wiring import load_config
    from messagefoundry.pipeline.dryrun import dry_run

    registry = load_config(RESULTS_RELAY)
    raw = (RESULTS_RELAY / "messages" / "oru_results.hl7").read_text(encoding="utf-8")
    result = dry_run(registry, raw)

    assert [d.to for d in result.deliveries] == ["OB_EHR_ORU", "FILE-OUT_LABCO_ORU"]
    out = result.deliveries[0].payload
    assert out.count("OBX|") == 3  # cancelled Potassium dropped; 3 results renumbered
    assert "GLUC^Glucose" in out and "SOD^Sodium" in out and "CHLOR^Chloride" in out
    assert "Potassium" not in out  # the OBX-11=X result is gone
    assert "MRN001^^^HOSP^MR" in out and "ACC555" not in out  # PID-3 collapsed to the MR id

    # the all-cancelled message relays nothing (FILTERED)
    cancelled = (RESULTS_RELAY / "messages" / "oru_all_cancelled.hl7").read_text(encoding="utf-8")
    assert dry_run(registry, cancelled).deliveries == []


def test_check_json_shape(capsys: pytest.CaptureFixture[str]) -> None:
    main(["check", "--config", str(SAMPLES_CONFIG), "--no-lint", "--json"])
    report = _out_json(capsys)
    assert set(report.keys()) == {"ok", "checks"}
    for c in report["checks"]:  # type: ignore[union-attr]
        assert set(c.keys()) == {"name", "ok", "required", "skipped", "detail"}
