# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DAST ingress-plane pass (ADR 0155, increment 2), inside the required test legs.

THE SAME INVERSION AS INCREMENT 1. ``.github/workflows/dast.yml`` runs the pass nightly with a
randomized budget and is advisory. What must not rot is the pass's ABILITY TO FAIL, so it lives here:
one seeded, deterministic run against a real engine, every canary proven to trip its own detector,
and the oracle's branches pinned one by one. A change that blinds a detector reds a pull request.

STRICT XFAILS ARE THE DEFECT REGISTER. Every engine defect this pass has found is tolerated by the
run only because the policy names it, and each named one has a strict xfail below. The day a defect
is fixed its xfail passes, strict turns that into a failure, and the policy entry has to come out --
so a tolerated finding cannot outlive its defect.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.mllpcodec import frame
from messagefoundry.transports.mllp import _HANDLER_FAILURE_NAK_TEXT
from scripts.security.dast_ingress_sweep import (
    KNOWN_DEFECT_DISCRIMINATORS,
    Budget,
    Case,
    CaseResult,
    _judge,
    catalogue,
    classify_replies,
    evaluate,
    load_policy,
    main,
    mutation_cases,
    reference_frames,
    run_case,
)
from scripts.security.dast_ingress_target import CANARIES, CANARY_DETECTOR, ingress_target

_REPO = Path(__file__).resolve().parents[1]
_POLICY_PATH = _REPO / "scripts" / "security" / "dast-ingress-policy.json"
_CAP = 65536


def _policy() -> dict[str, Any]:
    return load_policy(_POLICY_PATH)


def _budget(**overrides: Any) -> Budget:
    return replace(Budget.from_policy(_policy()), **overrides)


def _case(plane: str, name: str) -> Case:
    return next(c for c in catalogue("ZZTESTSENTINEL", _CAP) if c.plane == plane and c.name == name)


async def _run_alone(case: Case, budget: Budget, **posture: float) -> CaseResult:
    settings = dict(_policy()["posture"], canary_stall_seconds=1.0) | posture
    async with ingress_target(settings) as target:
        return await run_case(target, case, budget)


@pytest.fixture(scope="module")
def clean_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[int, dict[str, Any]]:
    """One seeded run against a real engine, shared by every test that reads its receipt."""
    receipt_path = tmp_path_factory.mktemp("dast-ingress") / "receipt.json"
    code = main(["--policy", str(_POLICY_PATH), "--receipt", str(receipt_path)])
    return code, json.loads(receipt_path.read_text(encoding="utf-8"))


# =====================================================================================================
# The pass against the real engine
# =====================================================================================================


def test_the_pass_is_clean_against_the_real_engine(clean_run: tuple[int, dict[str, Any]]) -> None:
    code, receipt = clean_run
    untolerated = [f for f in receipt["findings"] if f not in receipt["known_defect_findings"]]
    assert code == 0, untolerated
    assert receipt["verdict"] == "PASS"


def test_the_receipt_names_what_it_examined(clean_run: tuple[int, dict[str, Any]]) -> None:
    """Every detector must have been ARMED, not merely silent: cases on every plane, both reply
    kinds seen, a liveness probe per case, a log watch that saw records, and a resource phase."""
    _code, receipt = clean_run
    floors = _policy()["floors"]
    for plane, floor in floors["cases_per_plane"].items():
        assert receipt["planes"][plane]["cases"] >= floor, plane
    mllp_totals = receipt["planes"]["mllp"]
    assert mllp_totals["accepted_replies"] >= floors["min_mllp_accepted_replies"]
    assert mllp_totals["rejected_replies"] >= floors["min_mllp_rejected_replies"]
    assert receipt["liveness_probes"] == len(receipt["cases"])
    assert receipt["log"]["records_seen"] >= 1
    assert receipt["resources"]["passes"] >= 1
    assert receipt["mutation_cases"] == _policy()["mutations"]


def test_the_receipt_carries_no_message_content(clean_run: tuple[int, dict[str, Any]]) -> None:
    """Section 9: the receipt travels as a CI artifact, so it carries counts, never a body."""
    _code, receipt = clean_run
    text = json.dumps(receipt)
    assert "ZZDASTSENTINEL" not in text
    assert "MSH|" not in text and "ISA*" not in text


def test_every_tolerated_defect_still_reproduces_in_the_run(
    clean_run: tuple[int, dict[str, Any]],
) -> None:
    """A policy entry whose defect the run no longer sees is a tolerance with nothing to tolerate."""
    _code, receipt = clean_run
    seen = {f["known_defect"] for f in receipt["known_defect_findings"]}
    assert seen == set(_policy()["known_defects"]), seen


# =====================================================================================================
# Every detector has a positive control that must fire
# =====================================================================================================


@pytest.mark.parametrize("canary", CANARIES)
def test_each_canary_trips_its_own_detector(canary: str, tmp_path: Path) -> None:
    receipt_path = tmp_path / f"{canary}.json"
    code = main(["--policy", str(_POLICY_PATH), "--canary", canary, "--receipt", str(receipt_path)])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    detector = CANARY_DETECTOR[canary]
    fired = [f for f in receipt["findings"] if f["detector"] == detector]
    assert code == 1, receipt["findings"]
    assert len(fired) >= _policy()["canary"]["floors"][canary], receipt["findings"]


def test_every_detector_has_a_canary() -> None:
    from scripts.security.dast_ingress_sweep import DETECTORS

    assert set(CANARY_DETECTOR.values()) == set(DETECTORS)


async def test_the_stall_bound_fires_when_the_frame_deadline_is_off() -> None:
    """The stall half of the time detector, controlled by SUPPORTED configuration: with
    ``max_frame_seconds`` off, a peer trickling inside a frame is never closed, and the case must say
    so. Without this, a stall check that could not fire would pass every slowloris case."""
    result = await _run_alone(
        _case("mllp", "slowloris-in-frame"), _budget(stall_close_seconds=1.0), max_frame_seconds=0
    )
    assert any(f["detector"] == "time" for f in result.findings), result.findings


def test_a_blind_canary_exits_2_not_1() -> None:
    receipt = {"canary": "no-reply", "findings": []}
    code, messages = evaluate(receipt, _policy())
    assert code == 2
    assert "blind" in messages[0]


def test_the_leak_canary_floors_heap_and_handles_separately() -> None:
    heap_only = {"detector": "resources", "plane": "all", "case": "heap", "detail": "x"}
    code, _ = evaluate({"canary": "leak", "findings": [heap_only]}, _policy())
    assert code == 2, "a heap finding alone must not certify the handle instrument"


def test_a_floor_breach_exits_2(clean_run: tuple[int, dict[str, Any]]) -> None:
    _code, receipt = clean_run
    policy = _policy()
    policy["floors"]["cases_per_plane"]["mllp"] = 10_000
    code, messages = evaluate(dict(receipt), policy)
    assert code == 2
    assert any("floor unmet" in m for m in messages)


def test_a_blind_log_watch_exits_2(clean_run: tuple[int, dict[str, Any]]) -> None:
    _code, receipt = clean_run
    blind = dict(receipt, log={"records_seen": 0, "sentinel_hits": 0})
    code, _ = evaluate(blind, _policy())
    assert code == 2


def test_a_missing_policy_fails_closed(tmp_path: Path) -> None:
    assert main(["--policy", str(tmp_path / "absent.json")]) == 2


def test_a_known_defect_never_silences_liveness_time_or_log() -> None:
    # Judged on the canary path only because it needs no floors; the split happens first either way.
    receipt: dict[str, Any] = {
        "canary": "no-reply",
        "findings": [
            {
                "detector": d,
                "plane": "mllp",
                "case": "c",
                "detail": "x",
                "known_defect": "alphanumeric-field-separator",
            }
            for d in ("reply", "liveness", "time", "log_body")
        ],
    }
    evaluate(receipt, _policy())
    tolerated = {f["detector"] for f in receipt["known_defect_findings"]}
    assert tolerated == {"reply"}


# =====================================================================================================
# The oracle, branch by branch
# =====================================================================================================


def _result(plane: str = "mllp", frames: int = 1, **kw: Any) -> CaseResult:
    return CaseResult("c", plane, "catalogue", frames, kw.pop("overflow", False), **kw)


def _ack(code: str) -> bytes:
    """A framed reply, built with the ENGINE's own framer so the oracle is tested against real bytes."""
    return frame(f"MSH|^~\\&|A|B|C|D|20260101||ACK|X|P|2.5.1\rMSA|{code}|X\r")


#: The listener's handler-fault NAK (BACKLOG #1619), built from the engine's own constant.
_FAULT = frame(f"MSH|^~\\&|A|B|C|D|20260101||ACK|X|P|2.5.1\rMSA|AE|X|{_HANDLER_FAILURE_NAK_TEXT}\r")


@pytest.mark.parametrize(
    ("result", "got", "detector"),
    [
        (_result(rows=1), b"", "reply"),  # silence
        (_result(rows=1), _ack("AA") * 2, "reply"),  # a spare reply
        (_result(rows=1), frame(b"MSH|^~\\&|\rMSA\r"), "reply"),  # no readable MSA-1
        (_result(rows=0), _ack("AA"), "count_and_log"),  # accepted and dropped
        (_result(rows=1, error_rows=0), _ack("AR"), "count_and_log"),  # NAK with no ERROR row
        (_result(plane="tcp", rows=1), b"x", "reply"),  # a reply from a listener that never replies
        (_result(plane="tcp", rows=0), b"", "count_and_log"),  # a raw-TCP frame silently dropped
        (_result(frames=0, overflow=True), b"", "count_and_log"),  # oversize with no event
        (_result(rows=1, error_rows=1), _FAULT, "reply"),  # a handler fault, however well-formed
    ],
)
def test_the_oracle_names_each_violation(result: CaseResult, got: bytes, detector: str) -> None:
    _judge(result, got)
    assert detector in {f["detector"] for f in result.findings}, result.findings


def test_the_oracle_is_silent_on_a_correct_exchange() -> None:
    accepted = _result(rows=1)
    _judge(accepted, _ack("AA"))
    rejected = _result(rows=1, error_rows=1)
    _judge(rejected, _ack("AR"))
    oversize = _result(frames=0, overflow=True, oversize_events=1)
    _judge(oversize, b"")
    assert not (accepted.findings or rejected.findings or oversize.findings)


def test_classify_replies_reads_msa_1() -> None:
    assert classify_replies(_ack("AA") + _ack("AE") + _ack("AR") + _ack("CA")) == (2, 2, 0, 0, None)
    assert classify_replies(_ack("AA") + _FAULT) == (1, 1, 0, 1, 1)


def test_frames_after_a_handler_fault_are_unanswered_by_design() -> None:
    """The listener closes after a fault NAK, so a third frame's silence is not a second finding."""
    result = _result(frames=3, rows=1, error_rows=1, accepted=0)
    _judge(result, _ack("AA") + _FAULT)
    assert result.handled == 2
    details = [f["detail"] for f in result.findings if f["detector"] == "reply"]
    assert len(details) == 1 and "inbound handler" in details[0], result.findings


def test_the_frame_oracle_follows_the_decoder() -> None:
    body = b"MSH|^~\\&|A\r"
    assert len(reference_frames("mllp", b"\x0b" + body + b"\x1c", _CAP)[0]) == 1  # trailer optional
    assert len(reference_frames("mllp", body + b"\x1c\r", _CAP)[0]) == 0  # no start byte: noise
    assert reference_frames("mllp", b"\x0b" + b"A" * (_CAP + 1), _CAP)[1]  # overflow
    assert len(reference_frames("tcp", b"\x02a\x03\x02b\x03", _CAP)[0]) == 2


def test_mutations_are_seeded_and_deterministic() -> None:
    assert mutation_cases(318, 12, _CAP, "S") == mutation_cases(318, 12, _CAP, "S")
    assert mutation_cases(318, 12, _CAP, "S") != mutation_cases(319, 12, _CAP, "S")


def test_x12_mutations_still_form_interchanges() -> None:
    """An edit inside the fixed-width ISA stops any interchange forming, so a mutator that touched it
    would leave the X12 parse path unreached with nothing noticing."""
    x12 = [c for c in mutation_cases(318, 48, _CAP, "S") if c.plane == "x12"]
    decoded = sum(len(reference_frames("x12", c.payload, _CAP)[0]) for c in x12)
    # Measured 5 of 12 at seed 318 once the ISA and IEA were held fixed, against 0 of 6 before. The
    # rest are edits that legitimately break the interchange (a terminator inserted, a segment cut).
    assert decoded >= len(x12) // 3, (decoded, len(x12))


def test_the_at_cap_case_is_at_the_cap_and_not_over_it() -> None:
    frames, overflow = reference_frames("mllp", _case("mllp", "exactly-at-cap").payload, _CAP)
    assert not overflow
    assert [len(f) for f in frames] == [_CAP]


def test_a_known_defect_cannot_hide_a_second_defect_in_the_same_case() -> None:
    """One defective frame among three may explain ONE missing reply and row, never three."""
    from scripts.security.dast_ingress_sweep import _explained

    one_short = _result(frames=3, handled=3, rows=2, accepted=2)
    all_short = _result(frames=3, handled=3, rows=0, accepted=0)
    assert _explained(one_short, 1)
    assert not _explained(all_short, 1)


async def test_a_blank_segment_among_pipelined_frames_is_answered_like_any_other() -> None:
    """Before BACKLOG #1594 a blank segment faulted the handler, which NAKed and closed, so a frame
    pipelined after it went unanswered. Now every frame gets the runner's own reply and a row."""
    good = frame(b"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|G1|P|2.5.1\rPID|1\r")
    blank = _case("mllp", "blank-segment").payload
    for name, payload in (("blank-first", blank + good), ("blank-last", good + blank)):
        result = await _run_alone(Case(name, "mllp", payload), _budget())
        assert (result.handled, result.accepted, result.rows, result.faults) == (2, 2, 2, 0), result
        assert not result.findings, result.findings


def test_a_handler_fault_is_never_tolerated() -> None:
    """No known defect faults the handler any more, so a handler-fault NAK is a finding on every
    frame, the blank-segment frame included, and no count of known frames explains it."""
    from scripts.security.dast_ingress_sweep import _explained, known_defect_for

    faulted = _result(rows=1, error_rows=1)
    _judge(faulted, _FAULT)
    assert faulted.faults == 1 and faulted.findings, faulted
    well_formed = reference_frames("mllp", _case("mllp", "well-formed").payload, _CAP)[0]
    blank = reference_frames("mllp", _case("mllp", "blank-segment").payload, _CAP)[0]
    assert known_defect_for(well_formed) == ("", 0)
    assert known_defect_for(blank) == ("", 0)
    assert not _explained(faulted, 1)


def test_each_known_defect_discriminator_matches_its_catalogue_case() -> None:
    """A tolerance keyed on a condition no catalogue case carries would tolerate nothing, and one keyed
    on a condition EVERY case carries would tolerate everything."""
    cases = {c.name: c for c in catalogue("ZZTESTSENTINEL", _CAP) if c.plane == "mllp"}
    anchors = {"alphanumeric-field-separator": "letter-field-separator"}
    assert set(anchors) == set(KNOWN_DEFECT_DISCRIMINATORS) == set(_policy()["known_defects"])
    for defect, case_name in anchors.items():
        hit = KNOWN_DEFECT_DISCRIMINATORS[defect]
        assert any(map(hit, reference_frames("mllp", cases[case_name].payload, _CAP)[0])), defect
        assert not any(map(hit, reference_frames("mllp", cases["well-formed"].payload, _CAP)[0]))


# =====================================================================================================
# Engine defects this pass found, one strict xfail each (see the module docstring)
# =====================================================================================================


# Defect 1, a blank segment faulting the inbound handler, is FIXED by BACKLOG #1594. Its strict
# xfails became the two plain tests below, so a regression reds instead of passing quietly.


async def test_a_blank_segment_is_accepted_and_recorded() -> None:
    """The face that decodes: the empty line is dropped, so the frame is ACKed with a non-ERROR row."""
    result = await _run_alone(_case("mllp", "blank-segment"), _budget())
    assert (result.accepted, result.rejected, result.faults) == (1, 0, 0), result
    assert (result.rows, result.error_rows) == (1, 0), result
    assert not result.findings, result.findings


async def test_a_blank_segment_that_fails_utf8_decode_gets_the_runners_own_nak() -> None:
    """The face that fails UTF-8 decode: one NAK and one ERROR row. ``faults == 0`` tells the
    runner's own NAK apart from the listener's handler-fault AE, which a sender would retry."""
    result = await _run_alone(_case("mllp", "blank-segment-invalid-utf8"), _budget())
    assert (result.accepted, result.rejected, result.faults) == (0, 1, 0), result
    assert (result.rows, result.error_rows) == (1, 1), result
    assert not result.findings, result.findings


@pytest.mark.xfail(
    strict=True,
    reason=(
        "ENGINE DEFECT: a message whose MSH-1 is a letter or digit is accepted, and the ACK echoes "
        "that separator, so MSA-1 (itself letters) cannot be read back by the sender."
    ),
)
async def test_an_alphanumeric_field_separator_gets_a_readable_reply() -> None:
    result = await _run_alone(_case("mllp", "letter-field-separator"), _budget())
    assert not result.findings, result.findings


_TRICKLE = Case("trickle", "tcp", b"\x02", stall=True, trickle=b"ISA*00*" * 40)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "ENGINE GAP: the raw-TCP listener has no frame deadline (max_frame_seconds is MLLP-only), "
        "so a peer trickling one byte inside receive_timeout holds its slot indefinitely."
    ),
)
async def test_the_raw_tcp_listener_closes_a_trickling_peer() -> None:
    result = await _run_alone(_TRICKLE, _budget(stall_close_seconds=1.0))
    assert not result.findings, result.findings


@pytest.mark.xfail(
    strict=True,
    reason=(
        "ENGINE GAP: the X12 listener has no frame deadline (max_frame_seconds is MLLP-only), so a "
        "peer trickling an interchange inside receive_timeout holds its slot indefinitely."
    ),
)
async def test_the_x12_listener_closes_a_trickling_peer() -> None:
    trickle = replace(_TRICKLE, plane="x12", payload=b"ISA")
    result = await _run_alone(trickle, _budget(stall_close_seconds=1.0))
    assert not result.findings, result.findings


# =====================================================================================================
# The nightly job: advisory by placement, and its canaries gate its scan
# =====================================================================================================


def _ingress_job() -> dict[str, Any]:
    from tests._workflow_contexts import load_workflow

    job: dict[str, Any] = dict(load_workflow("dast.yml"))["jobs"]["dast-ingress"]
    return job


def test_the_ingress_job_installs_no_scanner() -> None:
    """Its can-go-red half is checked for every dast.yml job by
    tests/test_dast_auth_sweep.py::test_the_dast_job_can_actually_go_red."""
    for step in _ingress_job()["steps"]:
        run = str(step.get("run", ""))
        assert "pip install" not in run.replace("uv pip install --system --constraint", ""), step


def test_the_ingress_canaries_run_first_and_demand_exit_1() -> None:
    runs = [str(step.get("run", "")) for step in _ingress_job()["steps"]]
    canary = next(i for i, run in enumerate(runs) if "--canary" in run)
    scan = next(
        i for i, run in enumerate(runs) if "dast_ingress_sweep.py" in run and "--canary" not in run
    )
    assert canary < scan
    for name in CANARIES:
        assert name in runs[canary], name
    assert "-ne 1" in runs[canary] and "::error::" in runs[canary]


def test_the_ingress_job_is_not_required_and_its_name_is_unique() -> None:
    from tests._workflow_contexts import WORKFLOWS, context_of, jobs_of, required_contexts

    name = _ingress_job()["name"]
    assert "${{" not in name
    assert name not in required_contexts()
    elsewhere = [
        (path.name, key)
        for path in sorted(WORKFLOWS.glob("*.yml"))
        for key, job in jobs_of(path.name).items()
        if context_of(key, job) == name and key != "dast-ingress"
    ]
    assert not elsewhere, elsewhere
