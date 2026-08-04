# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ``check`` commit/CI gate: validate (required) + dryrun (gated) + advisory ruff/mypy."""

from __future__ import annotations

import json
import shutil
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


def test_check_dryrun_skips_a_not_deployed_inbound(tmp_path: Path) -> None:
    # #233 (ADR 0111): an unmapped fixture cross-products every inbound — but must NOT be run against a
    # feed nobody deployed. IB_HL7 is present-but-not-deployed here, so the malformed body (which would
    # ERROR against it) only ever reaches IB_RAW and the gate passes. Without the filter, every unmapped
    # fixture in the repo would be cross-producted against a feed the config says is not running.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, router, File, ContentType\n"
        "inbound('IB_HL7', File(directory='in1'), router='r', deployed=False)\n"
        "inbound('IB_RAW', File(directory='in2'), router='r', content_type=ContentType.TEXT)\n"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    msgs = tmp_path / "messages"
    msgs.mkdir()
    (msgs / "x.hl7").write_bytes(BAD_HL7)
    dr = next(
        r for r in run_checks(cfg, messages_dir=msgs, run_lint=False).results if r.name == "dryrun"
    )
    assert dr.ok and dr.required and not dr.skipped, dr.detail
    assert "1 run(s) clean" in dr.detail  # IB_RAW only — not the 2 runs an all-×-all would do


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
    for tool in ("ruff", "mypy", "ruff-security"):
        assert by_name[tool].skipped is True and by_name[tool].required is False
    assert report.ok is True  # advisory skips never block


def test_run_checks_no_lint_excludes_tools() -> None:
    report = run_checks(SAMPLES_CONFIG, run_lint=False)
    names = {r.name for r in report.results}
    assert {"ruff", "mypy", "ruff-security"}.isdisjoint(names)
    assert "validate" in names and "dryrun" in names


@pytest.mark.skipif(shutil.which("ruff") is None, reason="ruff advisory pass is run-if-installed")
def test_ruff_security_ignores_placeholder_token_fp() -> None:
    # ADR 0144 Increment 3: full `S` over the shipped samples trips S105 on the ADR-0015 body_secrets
    # placeholder token (_TOK_PASSWORD); the curated --ignore S105,S106,S107 suppresses that structural
    # false positive so the advisory pass reports clean (was ok=False carrying S105 under full `S`).
    report = run_checks(SAMPLES_CONFIG, messages_dir=None, run_lint=True)
    rs = {r.name: r for r in report.results}["ruff-security"]
    assert rs.required is False  # still advisory, never blocks
    assert rs.skipped is False and rs.ok is True
    assert "S105" not in rs.detail


def test_accepts_candidate_flags_leading_guard_filter_and_is_advisory(tmp_path: Path) -> None:
    """The accepts= advisory (ADR 0084) flags a @handler that OPENS with a guard-filter and cites the
    ADR, ignores a handler that filters only after real work, and never blocks (required=False)."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import handler, Send\n\n"
        "@handler('H_guard')\n"
        "def h_guard(msg):\n"
        "    if msg.field('MSH-9') != 'ADT':\n"
        "        return []\n"
        "    return [Send('OB_X', msg)]\n\n"
        "@handler('H_clean')\n"
        "def h_clean(msg):\n"
        "    out = msg\n"
        "    if out.field('X') == 'Y':\n"
        "        return []\n"
        "    return [Send('OB_X', out)]\n",
        encoding="utf-8",
    )
    res = checks._check_accepts_candidate(cfg)
    assert res.required is False and res.ok is True  # advisory: never blocks the gate
    assert res.skipped is False
    assert "h_guard" in res.detail and "h_clean" not in res.detail
    assert "0084" in res.detail


def test_accepts_candidate_flags_an_empty_tuple_guard_exactly_like_an_empty_list(
    tmp_path: Path,
) -> None:
    """``return ()`` is the same filter as ``return []`` and must be flagged the same (BACKLOG #341).

    Both empty containers partition to no deliveries, and the Steps lens has always recognized the pair
    together (ADR 0108 §6). This advisory recognized only the list form, making it the one place in the
    codebase that treated the two idioms differently — it silently under-flagged the tuple guard. The
    two handlers below are byte-identical apart from ``[]`` vs ``()``, so the assertion cannot pass by
    the flagger being inert: ``H_list`` must appear for the same reason ``H_tuple`` must."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import handler, Send\n\n"
        "@handler('H_tuple')\n"
        "def h_tuple(msg):\n"
        "    if msg.field('MSH-9') != 'ADT':\n"
        "        return ()\n"
        "    return [Send('OB_X', msg)]\n\n"
        "@handler('H_list')\n"
        "def h_list(msg):\n"
        "    if msg.field('MSH-9') != 'ADT':\n"
        "        return []\n"
        "    return [Send('OB_X', msg)]\n",
        encoding="utf-8",
    )
    res = checks._check_accepts_candidate(cfg)
    assert "h_tuple" in res.detail and "h_list" in res.detail
    assert res.required is False and res.skipped is False  # still advisory, still fired


def test_accepts_candidate_inert_without_leading_guard(tmp_path: Path) -> None:
    """A handler that does NOT open with a guard-filter yields a skipped no-op, still advisory."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import handler, Send\n\n"
        "@handler('H')\n"
        "def h(msg):\n"
        "    return [Send('OB', msg)]\n",
        encoding="utf-8",
    )
    res = checks._check_accepts_candidate(cfg)
    assert res.ok is True and res.required is False and res.skipped is True


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


# --- executable acceptance criteria: <fixture>.expect (Secure Development Standards §5 / R2) -------


def _delivering_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, File, Send\n"
        "inbound('IB_X', File(directory='in'), router='r')\n"
        "outbound('OB_X', File(directory='out'))\n"
        "@router('r')\n"
        "def r(m): return ['h']\n"
        "@handler('h')\n"
        "def h(m): return Send('OB_X', m)\n",
        encoding="utf-8",
    )
    return cfg


def _unrouted_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, router, File\n"
        "inbound('IB_X', File(directory='in'), router='r')\n"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    return cfg


def _run_dryrun(cfg: Path, msgs: Path) -> checks.CheckResult:
    results = run_checks(cfg, messages_dir=msgs, run_lint=False).results
    return next(r for r in results if r.name == "dryrun")


def _feed_fixture(tmp_path: Path, body: bytes, expect: str | None) -> Path:
    msgs = tmp_path / "messages" / "IB_X"
    msgs.mkdir(parents=True)
    (msgs / "a.hl7").write_bytes(body)
    if expect is not None:
        (msgs / "a.hl7.expect").write_text(expect, encoding="utf-8")
    return tmp_path / "messages"


def test_expect_received_matches_delivering_fixture(tmp_path: Path) -> None:
    cfg = _delivering_config(tmp_path)
    msgs = _feed_fixture(tmp_path, ADT_A01.encode("utf-8"), "RECEIVED\n")
    dr = _run_dryrun(cfg, msgs)
    assert dr.ok and dr.required, dr.detail
    assert "expectation-checked" in dr.detail


def test_expect_mismatch_fails(tmp_path: Path) -> None:
    cfg = _delivering_config(tmp_path)  # actually RECEIVED
    msgs = _feed_fixture(tmp_path, ADT_A01.encode("utf-8"), "FILTERED\n")
    dr = _run_dryrun(cfg, msgs)
    assert not dr.ok and dr.required
    assert "expected FILTERED" in dr.detail and "RECEIVED" in dr.detail


def test_expect_error_passes_for_malformed_message(tmp_path: Path) -> None:
    # A fixture that should dead-letter: assert ERROR, and the malformed HL7 makes it so → passes.
    cfg = _delivering_config(tmp_path)
    msgs = _feed_fixture(tmp_path, b"NOT-AN-HL7-MESSAGE\r", "ERROR")
    dr = _run_dryrun(cfg, msgs)
    assert dr.ok and dr.required, dr.detail


def test_expect_unrouted_is_case_insensitive(tmp_path: Path) -> None:
    cfg = _unrouted_config(tmp_path)  # router returns [] → UNROUTED
    msgs = _feed_fixture(tmp_path, ADT_A01.encode("utf-8"), "unrouted\n")
    dr = _run_dryrun(cfg, msgs)
    assert dr.ok and dr.required, dr.detail


def test_expect_processed_aliases_received(tmp_path: Path) -> None:
    cfg = _delivering_config(tmp_path)
    msgs = _feed_fixture(tmp_path, ADT_A01.encode("utf-8"), "PROCESSED\n")  # alias → RECEIVED
    dr = _run_dryrun(cfg, msgs)
    assert dr.ok, dr.detail


def test_expect_invalid_value_fails(tmp_path: Path) -> None:
    cfg = _delivering_config(tmp_path)
    msgs = _feed_fixture(tmp_path, ADT_A01.encode("utf-8"), "BOGUS")
    dr = _run_dryrun(cfg, msgs)
    assert not dr.ok and dr.required
    assert "invalid .expect" in dr.detail


def test_no_expect_keeps_default_semantics(tmp_path: Path) -> None:
    # Without a .expect sidecar a delivering fixture passes and is NOT expectation-checked.
    cfg = _delivering_config(tmp_path)
    msgs = _feed_fixture(tmp_path, ADT_A01.encode("utf-8"), None)
    dr = _run_dryrun(cfg, msgs)
    assert dr.ok and "expectation-checked" not in dr.detail


# --- posture check (#5): catch a custom env with no explicit posture at check time ----------------


def _config_repo(tmp_path: Path, toml_body: str) -> Path:
    """A minimal ADR-0017-shaped config repo: messagefoundry.toml at the root, modules under config/."""
    repo = tmp_path / "repo"
    cfg = repo / "config"
    cfg.mkdir(parents=True)
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, router, File\n"
        "inbound('IB_X', File(directory='in'), router='r')\n"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    (repo / "messagefoundry.toml").write_text(toml_body, encoding="utf-8")
    return cfg


def test_posture_fails_custom_env_without_posture(tmp_path: Path) -> None:
    # A CUSTOM env name (not dev/staging/prod) with no [ai].data_class/[ai].production is exactly the
    # serve-time foot-gun: require_posture() raises, so the check must FAIL and name the missing keys.
    cfg = _config_repo(tmp_path, '[ai]\nenvironment = "poc"\n')
    report = run_checks(cfg, run_lint=False)
    posture = next(r for r in report.results if r.name == "posture")
    assert posture.required and not posture.ok and not posture.skipped
    assert "handles_real_patient_data" in posture.detail and "production_instance" in posture.detail
    assert report.ok is False  # a required check failed -> the gate fails


def test_posture_ok_builtin_env(tmp_path: Path) -> None:
    # A built-in env name (dev) derives its posture, so the check passes without explicit keys.
    cfg = _config_repo(tmp_path, '[ai]\nenvironment = "dev"\n')
    report = run_checks(cfg, run_lint=False)
    posture = next(r for r in report.results if r.name == "posture")
    assert posture.required and posture.ok and not posture.skipped
    assert "dev" in posture.detail


def test_posture_ok_custom_env_with_explicit_posture(tmp_path: Path) -> None:
    # A custom name is fine once posture is set explicitly (decoupled from the name, ADR 0017).
    cfg = _config_repo(
        tmp_path,
        "security.handles_real_patient_data = false\nsecurity.production_instance = false\n"
        '[ai]\nenvironment = "poc"\n',
    )
    report = run_checks(cfg, run_lint=False)
    posture = next(r for r in report.results if r.name == "posture")
    assert posture.required and posture.ok and not posture.skipped


def test_posture_skips_without_service_toml(tmp_path: Path) -> None:
    # No messagefoundry.toml in the config tree (or CWD) -> skip gracefully, never error. The bare
    # samples/config dir has no service toml above it, so this also covers the common standalone case.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, router, File\n"
        "inbound('IB_X', File(directory='in'), router='r')\n"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    report = run_checks(cfg, run_lint=False)
    posture = next(r for r in report.results if r.name == "posture")
    assert posture.required and posture.ok and posture.skipped
    assert report.ok is True  # a skip never blocks


# --- reference-backend check (ADR 0006 "Backend support") -----------------------------------------
#
# The reference-set snapshot store ships on all three backends (SQL Server ported by BACKLOG #235). The
# allow-list gate STAYS for any future backend that leaves the protocol default False: a config declaring
# a Reference(...) against such a backend used to pass this whole gate and then raise on every
# reference(...) read at run time — post-ACK, forever. The gate refuses the pairing here, keyed on the
# DECLARED [store] backend, mirroring serve's start-time gate. The failing arm below monkeypatches the
# SQL Server class flag back to False to STAND IN for that future backend (the lazy class-flag resolution
# in store/base.py backend_supports_reference_sets makes the patch flow through).


# StoreSettings._require_server_db_fields rejects a bare `backend = "sqlserver"` (a server-DB backend must
# carry its connection essentials), so the check's fail-safe "settings did not load -> SKIP" arm would
# swallow the gate. A sqlserver toml therefore has to be a COMPLETE one — dummy values, never dialed: the
# check only reads the declared backend.
_SQLSERVER_TOML = (
    "[store]\n"
    'backend = "sqlserver"\n'
    'server = "db.example.invalid"\n'
    'database = "mefor"\n'
    'username = "mefor_svc"\n'
)


def _reference_repo(tmp_path: Path, toml_body: str, *, with_reference: bool) -> Path:
    """A config repo (messagefoundry.toml at the root, modules under config/), optionally declaring a
    reference set backed by a real CSV."""
    repo = tmp_path / "repo"
    cfg = repo / "config"
    cfg.mkdir(parents=True)
    csv = repo / "npi.csv"
    csv.write_text("key,value\nMED1,9991\n", encoding="utf-8")
    ref_line = (
        f"Reference('provider_npi', source=FileRef(path={str(csv)!r}))\n" if with_reference else ""
    )
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, router, File, Reference, FileRef\n"
        "inbound('IB_X', File(directory='in'), router='r')\n"
        f"{ref_line}"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    (repo / "messagefoundry.toml").write_text(toml_body, encoding="utf-8")
    return cfg


def _reference_check(cfg: Path) -> tuple[checks.CheckReport, checks.CheckResult]:
    report = run_checks(cfg, run_lint=False)
    return report, next(r for r in report.results if r.name == "reference-backend")


def test_check_fails_when_reference_set_declared_against_unsupporting_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE FAILING ARM, preserved past the #235 flip. SQL Server now supports reference sets, so fake the
    # one shape left to guard — a backend whose class flag is the allow-list default False — by patching
    # the SQL Server flag back off. Such a config must FAIL a required check, naming the set and the
    # backend, instead of passing the gate and breaking every reading message at run time.
    from messagefoundry.store.sqlserver import SqlServerStore

    monkeypatch.setattr(SqlServerStore, "supports_reference_sets", False)
    cfg = _reference_repo(tmp_path, _SQLSERVER_TOML, with_reference=True)
    report, result = _reference_check(cfg)
    assert result.required and not result.ok and not result.skipped
    assert "provider_npi" in result.detail and "sqlserver" in result.detail
    assert report.ok is False  # a required check failed -> the gate fails


def test_check_passes_reference_set_against_sqlserver_backend(tmp_path: Path) -> None:
    # THE #235 END STATE: the exact config that was this gate's headline bug — a Reference(...) against
    # [store] backend = "sqlserver" — now PASSES the required check, because the SQL Server store
    # implements the ADR 0006 snapshot store (reference/reference_version tables at SQLite/PG parity).
    cfg = _reference_repo(tmp_path, _SQLSERVER_TOML, with_reference=True)
    report, result = _reference_check(cfg)
    assert result.required and result.ok and not result.skipped
    assert "sqlserver" in result.detail  # the PASS detail names the declared backend
    assert report.ok is True


def test_reference_backend_check_skips_and_passes_appropriately(tmp_path: Path) -> None:
    # The three fail-safe arms (the _check_build convention), so the new REQUIRED check can never block
    # an existing green config.

    # (a) no messagefoundry.toml -> SKIP: a bare config dir declares no backend, and the SQLITE default
    # supports reference sets anyway.
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "c.py").write_text(
        "from messagefoundry import inbound, router, File\n"
        "inbound('IB_X', File(directory='in'), router='r')\n"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    _, result = _reference_check(bare)
    assert result.required and result.ok and result.skipped

    # (b) the default (SQLite) backend + a declared Reference(...) -> PASS (it ships the snapshot store).
    report, result = _reference_check(
        _reference_repo(tmp_path / "b", '[ai]\nenvironment = "dev"\n', with_reference=True)
    )
    assert result.required and result.ok and not result.skipped
    assert report.ok is True

    # (c) the sqlserver backend but NO Reference(...) -> PASS: the gate keys on DECLARATION, so an
    # existing SQL Server deployment that doesn't use reference sets is unaffected.
    report, result = _reference_check(
        _reference_repo(tmp_path / "c", _SQLSERVER_TOML, with_reference=False)
    )
    assert result.required and result.ok and not result.skipped
    assert report.ok is True


# --- #230 P4 (ADR 0104): the dryrun sub-check previews the engine's copy-on-Send posture ----------
#
# The gate resolves [pipeline].snapshot_on_send from this instance's messagefoundry.toml (same
# resolution as the posture check) and threads it into every dry_run; no resolvable settings -> the
# Settings-model default (ON), never a silent OFF. Copy-on-Send changes delivered BYTES only, so the
# sub-check's disposition expectations are unchanged by the threading.


def _fanout_repo(tmp_path: Path, toml_body: str | None) -> Path:
    """An ADR-0017-shaped repo whose handler is a divergent fan-out (mutate between two Sends)."""
    repo = tmp_path / "repo"
    cfg = repo / "config"
    cfg.mkdir(parents=True)
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, File, Send\n"
        "inbound('IB_X', File(directory='in'), router='r')\n"
        "outbound('OB_A', File(directory='outa'))\n"
        "outbound('OB_B', File(directory='outb'))\n"
        "@router('r')\n"
        "def r(m): return ['h']\n"
        "@handler('h')\n"
        "def h(m):\n"
        "    m['MSH-5'] = 'SYS_A'\n"
        "    first = Send('OB_A', m)\n"
        "    m['MSH-5'] = 'SYS_B'\n"
        "    return [first, Send('OB_B', m)]\n",
        encoding="utf-8",
    )
    if toml_body is not None:
        (repo / "messagefoundry.toml").write_text(toml_body, encoding="utf-8")
    return cfg


def _probe_repo(tmp_path: Path, toml_body: str | None) -> Path:
    """A repo whose handler Sends ONLY under an active copy-on-Send run context — the probe makes the
    setting's threading observable as a disposition (RECEIVED when ON, FILTERED when off). It pins the
    resolution path, not a supported authoring pattern (a real handler never branches on the flag)."""
    repo = tmp_path / "repo"
    cfg = repo / "config"
    cfg.mkdir(parents=True)
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, File, Send\n"
        "from messagefoundry.config.send_snapshot import snapshot_on_send_active\n"
        "inbound('IB_X', File(directory='in'), router='r')\n"
        "outbound('OB_A', File(directory='out'))\n"
        "@router('r')\n"
        "def r(m): return ['h']\n"
        "@handler('h')\n"
        "def h(m):\n"
        "    return Send('OB_A', m) if snapshot_on_send_active() else None\n",
        encoding="utf-8",
    )
    if toml_body is not None:
        (repo / "messagefoundry.toml").write_text(toml_body, encoding="utf-8")
    return cfg


_SNAPSHOT_OFF_TOML = "[pipeline]\nsnapshot_on_send = false\n"


def test_check_dryrun_disposition_identical_under_both_snapshot_postures(tmp_path: Path) -> None:
    # A divergent fan-out delivers different BYTES per posture but the same disposition (RECEIVED) —
    # threading the setting must leave the sub-check's expectations and summary line unchanged.
    msgs = _feed_fixture(tmp_path, ADT_A01.encode("utf-8"), "RECEIVED\n")
    details: list[str] = []
    for leg, toml_body in (("on", None), ("off", _SNAPSHOT_OFF_TOML)):
        cfg = _fanout_repo(tmp_path / leg, toml_body)
        dr = _run_dryrun(cfg, msgs)
        assert dr.ok and dr.required and not dr.skipped, dr.detail
        assert "expectation-checked" in dr.detail
        details.append(dr.detail)
    assert details[0] == details[1]


def test_check_dryrun_threads_engine_snapshot_posture_into_the_preview(tmp_path: Path) -> None:
    # The behavioral proof of the threading itself, via the probe handler's flag-keyed disposition.
    # (a) no messagefoundry.toml anywhere in the walk -> the Settings-model default (ON) -> RECEIVED.
    msgs_on = _feed_fixture(tmp_path / "on", ADT_A01.encode("utf-8"), "RECEIVED\n")
    dr = _run_dryrun(_probe_repo(tmp_path / "on", None), msgs_on)
    assert dr.ok and dr.required and not dr.skipped, dr.detail

    # (b) [pipeline].snapshot_on_send = false, discovered by the legacy upward-walk from config/ ->
    # the preview runs with the flag off -> the probe filters -> FILTERED.
    msgs_off = _feed_fixture(tmp_path / "off", ADT_A01.encode("utf-8"), "FILTERED\n")
    dr = _run_dryrun(_probe_repo(tmp_path / "off", _SNAPSHOT_OFF_TOML), msgs_off)
    assert dr.ok and dr.required and not dr.skipped, dr.detail


def test_check_dryrun_honors_explicit_service_config(tmp_path: Path) -> None:
    # AC-6 shape: run_checks(service_config=...) reads THAT file (no upward-walk finds one here — the
    # toml lives outside the config tree under a non-default name), so the off-posture must come from
    # the explicit path alone.
    cfg = _probe_repo(tmp_path, None)
    toml = tmp_path / "elsewhere" / "svc.toml"
    toml.parent.mkdir()
    toml.write_text(_SNAPSHOT_OFF_TOML, encoding="utf-8")
    msgs = _feed_fixture(tmp_path, ADT_A01.encode("utf-8"), "FILTERED\n")
    results = run_checks(cfg, messages_dir=msgs, run_lint=False, service_config=toml).results
    dr = next(r for r in results if r.name == "dryrun")
    assert dr.ok and dr.required and not dr.skipped, dr.detail
