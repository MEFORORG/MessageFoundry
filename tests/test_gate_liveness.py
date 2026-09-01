# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for scripts/quality/liveness.py.

The core of this file is a replay of the three real incidents that motivated the check. A liveness
gate that cannot catch the failures it was built for is itself a dead gate, so each historical bug is
reconstructed from what CI actually reported at the time and asserted to be caught.

Equally important, and easier to get wrong: the check must NOT fire on good news. A clean repository
legitimately reports zero clones and zero new complexity, and a PR touching no covered code
legitimately has no diff coverage. Those cases are asserted to pass.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _load() -> ModuleType:
    path = _ROOT / "scripts" / "quality" / "liveness.py"
    assert path.is_file(), f"liveness script not found at {path}"
    spec = importlib.util.spec_from_file_location("gate_liveness", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


liveness = _load()


def _job(result: str = "success", receipt: dict | None = None) -> dict:
    outputs = {"receipt": json.dumps(receipt)} if receipt is not None else {}
    return {"result": result, "outputs": outputs}


def _healthy(signal: str, units: int = 10, **extra) -> dict:
    return {
        "signal": signal,
        "status": "measured",
        "units": units,
        "unit_name": "things",
        "evidence": f"{signal} ran",
        **extra,
    }


def _healthy_mutation() -> dict:
    """Mutation is the one signal with a MANDATORY breakdown, so its healthy receipt carries one.
    Numbers are the real ones from run 30315798347: 87 + 19 + 355 + 0 = 461."""
    return _healthy(
        "mutation", units=461, killed=87, survived=19, no_tests=355, other=0, killed_reported=87
    )


def _all_healthy() -> dict:
    needs = {s: _job(receipt=_healthy(s)) for s in liveness.EXPECTED_SIGNALS}
    needs["mutation"] = _job(receipt=_healthy_mutation())
    return needs


# --------------------------------------------------------------------------------------------
# Replay of the three real incidents. These are the tests that justify the check existing.
# --------------------------------------------------------------------------------------------


def test_incident_mutation_crashed_but_job_was_green() -> None:
    """mutmut 2.5.1 crashed on Python 3.14 before generating a single mutant. `|| true` made the job
    report SUCCESS in 37 seconds, and it stayed green for months (run 30248096425)."""
    needs = _all_healthy()
    needs["mutation"] = _job(result="success")  # green, and no receipt at all

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["mutation"]
    assert "NO liveness receipt" in violations[0]["message"]


def test_incident_diff_coverage_produced_an_empty_report_silently() -> None:
    """The shallow-fetch bug: diff-cover truncated its report on open, then died. `|| true` ate the
    error, the `-f` guard passed on the 0-byte file, and the summary looked clean. If the job
    naively records that as 'measured', units=0 must expose it."""
    needs = _all_healthy()
    needs["coverage"] = _job(receipt={**_healthy("coverage"), "units": 0})

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["coverage"]
    assert "nothing was examined" in violations[0]["message"]


def test_incident_killed_count_did_not_reconcile() -> None:
    """The `grep -c ': killed'` bug. The gate genuinely RAN -- 461 mutants really were processed --
    so execution proof alone passes it. CI reported killed=0 survived=19 no_tests=355, summing to
    374 rather than 461."""
    needs = _all_healthy()
    needs["mutation"] = _job(
        receipt=_healthy("mutation", units=461, killed=0, survived=19, no_tests=355, other=0)
    )

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["mutation"]
    assert "does not reconcile" in violations[0]["message"]
    assert "374" in violations[0]["message"] and "461" in violations[0]["message"]


def test_the_sum_check_alone_cannot_validate_the_killed_count() -> None:
    """HONESTY TEST -- documents a real limit rather than papering over it.

    The workflow derives `killed = total - listed`, so `killed + survived + no_tests + other == total`
    reduces to `survived + no_tests + other == listed`: total cancels, and any derived killed value
    satisfies it. This asserts that blindness explicitly, so nobody mistakes the sum for protection
    of the killed count. The independent cross-check below is what actually protects it.
    """
    # A wildly wrong killed value that is nonetheless self-consistent with listed = 19+355+0 = 374.
    needs = _all_healthy()
    needs["mutation"] = _job(
        receipt=_healthy(
            "mutation", units=374 + 999, killed=999, survived=19, no_tests=355, other=0
        )
    )

    violations, _ = liveness.verify(needs)

    assert violations == [], "the sum check is blind here -- that is the point of this test"


def test_a_killed_count_disagreeing_with_mutmuts_own_counter_is_caught() -> None:
    """The check that DOES protect the killed count: two independent derivations must agree.
    `killed` is total-minus-listed; `killed_reported` is mutmut's own progress counter."""
    needs = _all_healthy()
    needs["mutation"] = _job(
        receipt=_healthy(
            "mutation", units=461, killed=0, survived=19, no_tests=355, other=0, killed_reported=87
        )
    )

    violations, _ = liveness.verify(needs)

    messages = " ".join(v["message"] for v in violations)
    assert "disagrees with mutmut's own counter" in messages
    assert "derived 0" in messages and "reported 87" in messages


def test_a_missing_breakdown_is_a_violation_not_a_silent_skip() -> None:
    """Otherwise the reconciliation is opt-in from the receipt side: thin the payload and the check
    quietly stops running -- this control's own failure mode, one level up."""
    needs = _all_healthy()
    needs["mutation"] = _job(receipt=_healthy("mutation", units=461))

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["mutation"]
    assert "no usable breakdown" in violations[0]["message"]


def test_the_corrected_killed_count_reconciles() -> None:
    """The real numbers from run 30315798347 after the fix: 87 + 19 + 355 = 461, and mutmut's own
    counter agrees with the derived 87."""
    needs = _all_healthy()
    needs["mutation"] = _job(
        receipt=_healthy(
            "mutation", units=461, killed=87, survived=19, no_tests=355, other=0, killed_reported=87
        )
    )

    violations, accepted = liveness.verify(needs)

    assert violations == []
    assert any(r["signal"] == "mutation" for r in accepted)


# --------------------------------------------------------------------------------------------
# It must not fire on good news.
# --------------------------------------------------------------------------------------------


def test_a_clean_repo_with_zero_findings_still_passes() -> None:
    """Liveness counts what was EXAMINED, not what was found. A repo with no clones at all must not
    trip the check -- otherwise the gate fires on good news and gets muted."""
    needs = _all_healthy()
    needs["clone"] = _job(
        receipt={
            "signal": "clone",
            "status": "measured",
            "units": 234,
            "unit_name": "files analysed",
            "evidence": "jscpd analysed 234 files, found 0 clones",
            "clones": 0,
        }
    )

    violations, _ = liveness.verify(needs)
    assert violations == []


def test_an_honest_not_applicable_passes() -> None:
    """The real diff-coverage case on PRs #18 and #19: no lines with coverage information, because
    neither PR touched `messagefoundry/`. Saying so is the difference between this and the silent
    empty report above."""
    needs = _all_healthy()
    needs["coverage"] = _job(
        receipt={
            "signal": "coverage",
            "status": "not-applicable",
            "reason": "no lines with coverage information in this diff",
        }
    )

    violations, accepted = liveness.verify(needs)

    assert violations == []
    assert any(r["status"] == "not-applicable" for r in accepted)


def test_not_applicable_without_a_reason_is_rejected() -> None:
    """Otherwise 'not-applicable' becomes a free pass and the check is worthless."""
    needs = _all_healthy()
    needs["coverage"] = _job(
        receipt={"signal": "coverage", "status": "not-applicable", "reason": "  "}
    )

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["coverage"]
    assert "no reason given" in violations[0]["message"]


def test_a_skipped_job_owes_no_receipt() -> None:
    """coverage is PR-only, so it is legitimately skipped on the nightly cron."""
    needs = _all_healthy()
    needs["coverage"] = {"result": "skipped", "outputs": {}}

    violations, _ = liveness.verify(needs)
    assert violations == []


def test_a_cancelled_job_with_no_receipt_owes_nothing() -> None:
    """A run-level cancel never started the job, so there is nothing to account for.

    This is the arm that must stay green. `gate liveness` carries `if: always()`, which GitHub
    evaluates true under cancellation, so it runs during a genuine run-level cancel. Reddening
    there would blame a session for something nobody caused.
    """
    needs = _all_healthy()
    needs["coverage"] = {"result": "cancelled", "outputs": {}}

    violations, _ = liveness.verify(needs)
    assert violations == []


def test_a_timeout_killed_job_is_caught_not_excused() -> None:
    """BACKLOG #1410. A `timeout-minutes` kill lands as `cancelled`, and the job DID run.

    The receipt below is the real payload, copied from the `toJSON(needs)` dump in the liveness
    job logs of PRs 708, 711, 712 and 719 (jobs 99561662542, 99584522330, 99586438353,
    99689286541), where `diff-coverage (advisory)` was killed at its cap on every one. The gate
    reported itself dead, correctly, and `verify` discarded it unread because the result string
    said `cancelled`. Every one of those four runs reported `gate liveness (advisory)` as SUCCESS.
    """
    needs = _all_healthy()
    needs["coverage"] = _job(
        result="cancelled",
        receipt={
            "signal": "coverage",
            "status": "failed",
            "reason": "coverage.xml was not produced; the measurement never happened",
        },
    )

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["coverage"]
    assert "reported ITSELF dead" in violations[0]["message"]


def test_a_cancelled_job_cannot_launder_itself_as_not_applicable() -> None:
    """The rider on #1410. Making `cancelled` examinable reopens the laundering hole.

    A job killed mid-measurement has no more standing to declare itself inapplicable than a
    crashed one does, and the `failure` arm already blocks that route.
    """
    needs = _all_healthy()
    needs["coverage"] = _job(
        result="cancelled",
        receipt={
            "signal": "coverage",
            "status": "not-applicable",
            "reason": "no lines with coverage information in this diff",
        },
    )

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["coverage"]
    assert "did not finish is dead" in violations[0]["message"]


def test_a_failed_job_still_owes_a_receipt() -> None:
    """A crashed job must be visible as a dead gate, not quietly excused."""
    needs = _all_healthy()
    needs["clone"] = _job(result="failure")

    violations, _ = liveness.verify(needs)
    assert [v["signal"] for v in violations] == ["clone"]


def test_a_failed_job_cannot_launder_itself_as_not_applicable() -> None:
    """The softest receipt must not excuse the hardest failure. Every step in these jobs is
    continue-on-error, so if this passed nothing anywhere would be red."""
    needs = _all_healthy()
    needs["coverage"] = _job(
        result="failure",
        receipt={
            "signal": "coverage",
            "status": "not-applicable",
            "reason": "coverage.xml was not produced",
        },
    )

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["coverage"]
    assert "dead, not inapplicable" in violations[0]["message"]


# --------------------------------------------------------------------------------------------
# The check must not go blind itself.
# --------------------------------------------------------------------------------------------


def test_a_renamed_or_removed_job_is_caught() -> None:
    """If a signal's job is renamed and EXPECTED_SIGNALS is not updated, the gate would silently
    stop being checked -- the same class of failure one level up."""
    needs = _all_healthy()
    del needs["complexity"]

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["complexity"]
    assert "renamed" in violations[0]["message"]


def test_a_malformed_receipt_is_caught() -> None:
    needs = _all_healthy()
    needs["clone"] = {"result": "success", "outputs": {"receipt": "{not json"}}

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["clone"]
    assert "not valid JSON" in violations[0]["message"]


def test_a_gate_reporting_itself_dead_is_a_violation() -> None:
    needs = _all_healthy()
    needs["mutation"] = _job(
        receipt={"signal": "mutation", "status": "failed", "reason": "mutmut exited 1"}
    )

    violations, _ = liveness.verify(needs)

    assert [v["signal"] for v in violations] == ["mutation"]
    assert "reported ITSELF dead" in violations[0]["message"]


def test_an_unparseable_needs_blob_fails_loudly(capsys: pytest.CaptureFixture[str]) -> None:
    """A liveness check that silently verifies nothing is the exact bug it guards against."""
    rc = liveness.main(["verify", "--needs-json", "{not json"])

    assert rc == 2
    assert "could not run" in capsys.readouterr().out.lower()


def test_every_expected_signal_is_a_real_job_in_the_workflow() -> None:
    """EXPECTED_SIGNALS must track the workflow, or the check silently stops covering a gate."""
    import yaml

    workflow = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "quality-advisory.yml").read_text(encoding="utf-8")
    )
    for signal in liveness.EXPECTED_SIGNALS:
        assert signal in workflow["jobs"], f"{signal!r} is expected but no such job exists"


# --------------------------------------------------------------------------------------------
# Receipt construction + exit codes.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("units", [0, -1, None])
def test_measured_requires_positive_units(units: int | None) -> None:
    with pytest.raises(liveness.Violation, match="requires units > 0"):
        liveness.build_receipt("clone", "measured", units, "files", "jscpd ran", "")


def test_measured_requires_evidence() -> None:
    with pytest.raises(liveness.Violation, match="requires evidence"):
        liveness.build_receipt("clone", "measured", 5, "files", "   ", "")


def test_not_applicable_requires_a_reason() -> None:
    with pytest.raises(liveness.Violation, match="requires a reason"):
        liveness.build_receipt("coverage", "not-applicable", None, "", "", "  ")


def test_record_writes_a_single_line_to_github_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The receipt travels through a job output, so it must be one line of compact JSON."""
    out = tmp_path / "gh_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))

    rc = liveness.main(
        [
            "record",
            "--signal",
            "mutation",
            "--status",
            "measured",
            "--units",
            "461",
            "--unit-name",
            "mutants processed",
            "--evidence",
            "mutmut progress line 461/461",
            "--extra",
            '{"killed":87,"survived":19,"no_tests":355,"other":0}',
        ]
    )
    written = out.read_text(encoding="utf-8")

    assert rc == 0
    assert written.count("\n") == 1, "the receipt must be a single line"
    payload = json.loads(written.split("=", 1)[1])
    assert payload["units"] == 461 and payload["killed"] == 87


def test_verify_exits_non_zero_only_on_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "s.md"))

    assert liveness.main(["verify", "--needs-json", json.dumps(_all_healthy())]) == 0

    broken = _all_healthy()
    broken["mutation"] = _job(result="success")
    assert liveness.main(["verify", "--needs-json", json.dumps(broken)]) == 1


def test_summary_names_the_offending_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    summary = tmp_path / "s.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    broken = _all_healthy()
    broken["mutation"] = _job(result="success")

    liveness.main(["verify", "--needs-json", json.dumps(broken)])
    text = summary.read_text(encoding="utf-8")

    assert "`mutation`" in text
    assert "without proving they measured anything" in text


def test_annotation_escapes_workflow_command_metacharacters() -> None:
    line = liveness._annotation({"signal": "clone", "message": "100% broken\nsecond line"})
    assert "100%25 broken%0Asecond line" in line
    assert line.count("\n") == 0


def test_non_mapping_outputs_does_not_crash_verify() -> None:
    """A job whose ``outputs`` is a string, not a mapping, must not take the gate down.

    THIS TEST EXISTS BECAUSE NOTHING ELSE DEFENDS THAT LINE. `verify` reads a JSON blob
    GitHub interpolates, so a malformed or truncated payload can hand it a string. The
    `isinstance(outputs, dict)` guard in liveness.py keeps the read total; reverting it to
    `(job.get("outputs") or {}).get("receipt", "")` leaves EVERY OTHER TEST IN THIS FILE
    GREEN -- measured, all 30 -- so without this test the guard is undefended and the next
    tidying pass silently restores an AttributeError that replaces the gate's verdict with
    a stack trace. A guard no test can miss is the only kind that survives.
    """
    needs = _all_healthy()
    needs["coverage"] = {"result": "skipped", "outputs": "receipt"}

    violations, _oks = liveness.verify(needs)

    assert not [v for v in violations if v.get("signal") == "coverage"]
