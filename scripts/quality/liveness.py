"""Gate liveness: prove each advisory quality job actually MEASURED something.

Three defects across two of quality-advisory.yml's gates, all green the whole time. Two are the same
failure -- a gate measuring nothing -- and the third is its close cousin, a gate that measured
correctly and published a wrong number:

  * diff-coverage MEASURED NOTHING -- a `git fetch --depth=1` re-shallowed the clone and destroyed
    diff-cover's merge base. diff-cover truncates its report file before it can fail, so `|| true`
    swallowed the error and the summary rendered an empty section reading as "nothing uncovered".
  * mutation MEASURED NOTHING -- `mutmut<3` resolved to 2.5.1, which crashes on Python 3.14 before
    generating a single mutant. `|| true` made the job report success in 37 seconds, for months.
  * mutation PUBLISHED A WRONG NUMBER -- `grep -c ': killed'` searched for a line mutmut never
    prints, so a healthy 461-mutant run reported "Killed 0". Execution proof alone would pass this
    one; it needs the reconciliation rules below.

The rubric's anti-metric rule (Code_Quality_Standards.md section 4.1) guards against trusting a
NUMBER too much. Nothing guarded against trusting a GREEN CHECK THAT NEVER RAN. This is that control.

THE DISTINCTION THAT MAKES THIS WORK: liveness is not "the gate found something". A clean repository
legitimately has zero clones and zero new complexity, and demanding a non-zero finding count would
make the check fire on good news. Liveness is *proof the measurement was performed* -- a count of
units EXAMINED (mutants processed, files scanned, changed lines analysed), which is non-zero whenever
the tool actually ran, regardless of what it concluded.

A job may also honestly declare it had nothing to measure (`not-applicable` + a reason). That is the
diff-coverage case on a PR touching no covered code: an explicit "no lines with coverage information
in this diff" PASSES, while a silent empty report FAILS. Saying why is the whole difference.

Two subcommands:
  record  -- a job emits its receipt (one compact JSON line, written to $GITHUB_OUTPUT)
  verify  -- the liveness job reads every receipt out of `toJSON(needs)` and rules on them
"""

import argparse
import json
import os
import sys
from typing import Any

# Signals that must account for themselves. A job absent from this map is not checked; a job here
# that RAN and produced no receipt is a liveness violation -- that is the "green check that never
# ran" case, and it is the whole reason this file exists.
EXPECTED_SIGNALS = {
    "complexity": "cyclomatic-complexity triage (ruff C901)",
    "clone": "duplication / clone detection (jscpd)",
    "coverage": "diff-coverage visibility (diff-cover)",
    "mutation": "test-signal proof (mutmut)",
}

MEASURED = "measured"
NOT_APPLICABLE = "not-applicable"
FAILED = "failed"
_STATUSES = (MEASURED, NOT_APPLICABLE, FAILED)

# Job results that mean "this job did not run", so no receipt is owed. Anything else -- including
# `failure` -- owes one: a job that crashed still has to be visible as a dead gate rather than
# quietly absent.
_DID_NOT_RUN = ("skipped", "cancelled")


class Violation(Exception):
    """A liveness rule was broken. Carries the human-facing message."""


def _fail(signal: str, message: str) -> dict[str, str]:
    return {"signal": signal, "message": message}


# --------------------------------------------------------------------------------------------
# record
# --------------------------------------------------------------------------------------------


def build_receipt(
    signal: str,
    status: str,
    units: int | None,
    unit_name: str,
    evidence: str,
    reason: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble and validate one receipt. Raises rather than emitting a malformed one."""
    if signal not in EXPECTED_SIGNALS:
        raise Violation(f"unknown signal {signal!r}; expected one of {sorted(EXPECTED_SIGNALS)}")
    if status not in _STATUSES:
        raise Violation(f"unknown status {status!r}; expected one of {_STATUSES}")

    receipt: dict[str, Any] = {"signal": signal, "status": status}
    if status == MEASURED:
        if units is None or units <= 0:
            raise Violation(
                f"{signal}: status={MEASURED} requires units > 0 (got {units!r}). Units count what "
                "was EXAMINED, not what was found -- if the tool ran, this is non-zero."
            )
        if not evidence.strip():
            raise Violation(
                f"{signal}: status={MEASURED} requires evidence naming what proves it ran"
            )
        receipt["units"] = units
        receipt["unit_name"] = unit_name or "units"
        receipt["evidence"] = evidence.strip()
    else:
        if not reason.strip():
            raise Violation(
                f"{signal}: status={status} requires a reason. An unexplained silent gate is exactly "
                "what this check exists to catch."
            )
        receipt["reason"] = reason.strip()
    if extra:
        receipt.update(extra)
    return receipt


# --------------------------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------------------------


def _consistency_violations(receipt: dict[str, Any]) -> list[str]:
    """Cross-field checks: a gate can run correctly and still report a wrong derived number.

    TWO checks, because the obvious one is weaker than it looks. The workflow derives
    `killed = total - listed`, so asserting `killed + survived + no_tests + other == total` reduces
    algebraically to `survived + no_tests + other == listed` -- total cancels, and the killed count
    is never validated at all. That sum only proves every LISTED mutant carries a recognised status.
    Useful (it catches mutmut adding a status we do not classify) but blind to the exact bug it was
    written for.

    So the killed count is reconciled against mutmut's OWN counter, parsed from its progress line --
    a genuinely independent measurement that a derived number cannot satisfy by construction.

    The breakdown is MANDATORY for mutation. Returning early on a missing key would make the whole
    check opt-in from the receipt side: thin the payload and the reconciliation silently stops
    running, which is this control's own failure mode one level up.
    """
    problems: list[str] = []
    if receipt.get("signal") != "mutation" or receipt.get("status") != MEASURED:
        return problems

    total = receipt.get("units")
    parts = {k: receipt.get(k) for k in ("killed", "survived", "no_tests", "other")}
    missing = [k for k, v in parts.items() if not isinstance(v, int)]
    if missing:
        problems.append(
            f"mutation receipt carries no usable breakdown (missing/non-numeric: {', '.join(missing)}), "
            "so the parts-add-up check could not run. A signal with a known breakdown must report it."
        )
        return problems

    summed = sum(int(v) for v in parts.values())
    if summed != total:
        detail = ", ".join(f"{k}={v}" for k, v in parts.items())
        problems.append(
            f"mutation breakdown does not reconcile: {detail} sums to {summed}, but {total} mutants "
            "were processed -- a mutant carries a status nothing here classifies."
        )

    # The independent cross-check. `killed_reported` comes from mutmut's own progress counter; the
    # workflow derives `killed` a completely different way (total minus listed). Agreement between
    # two independent derivations is what actually protects the number.
    reported = receipt.get("killed_reported")
    if (
        isinstance(reported, int)
        and isinstance(parts["killed"], int)
        and reported != parts["killed"]
    ):
        problems.append(
            f"killed count disagrees with mutmut's own counter: derived {parts['killed']}, mutmut "
            f"reported {reported}. One of the two is wrong (this is the shape of the `killed=0` bug)."
        )
    return problems


def verify(needs: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    """Rule on every expected signal. Returns (violations, accepted receipts)."""
    violations: list[dict[str, str]] = []
    accepted: list[dict[str, Any]] = []

    for signal, description in sorted(EXPECTED_SIGNALS.items()):
        job = needs.get(signal)
        if job is None:
            violations.append(
                _fail(
                    signal,
                    f"no job named {signal!r} among this workflow's needs -- the signal was renamed "
                    f"or removed without updating EXPECTED_SIGNALS ({description}).",
                )
            )
            continue

        result = str(job.get("result", "")).lower()
        if result in _DID_NOT_RUN:
            continue  # legitimately did not run (e.g. coverage is PR-only)

        raw = (job.get("outputs") or {}).get("receipt", "")
        if not str(raw).strip():
            violations.append(
                _fail(
                    signal,
                    f"job finished with result={result!r} but emitted NO liveness receipt. This is "
                    f"the silent-gate case: {description} reported a conclusion without recording "
                    "that it measured anything.",
                )
            )
            continue

        try:
            receipt = json.loads(raw)
        except json.JSONDecodeError as exc:
            violations.append(
                _fail(signal, f"liveness receipt is not valid JSON ({exc}): {raw[:200]!r}")
            )
            continue

        status = receipt.get("status")
        if status == MEASURED:
            units = receipt.get("units")
            if not isinstance(units, int) or units <= 0:
                violations.append(
                    _fail(
                        signal,
                        f"claims status={MEASURED} but units={units!r} -- nothing was examined",
                    )
                )
                continue
            for problem in _consistency_violations(receipt):
                violations.append(_fail(signal, problem))
            accepted.append(receipt)
        elif status == NOT_APPLICABLE:
            if not str(receipt.get("reason", "")).strip():
                violations.append(_fail(signal, f"status={NOT_APPLICABLE} with no reason given"))
                continue
            if result == "failure":
                # A job that DIED has no standing to declare itself inapplicable. Without this, the
                # softest possible receipt launders a hard failure into a pass -- and every step in
                # these jobs is continue-on-error, so nothing else would be red either.
                violations.append(
                    _fail(
                        signal,
                        f"job result={result!r} but the receipt claims {NOT_APPLICABLE} "
                        f"({receipt.get('reason')!r}). A failed gate is dead, not inapplicable.",
                    )
                )
                continue
            accepted.append(receipt)
        elif status == FAILED:
            violations.append(
                _fail(
                    signal, f"the gate reported ITSELF dead: {receipt.get('reason', '(no reason)')}"
                )
            )
        else:
            violations.append(_fail(signal, f"unknown status {status!r} in receipt"))

    return violations, accepted


def render_summary(violations: list[dict[str, str]], accepted: list[dict[str, Any]]) -> str:
    lines = ["## Gate liveness", ""]
    if violations:
        lines += [
            f"**{len(violations)} gate(s) reported a conclusion without proving they measured "
            "anything.** A green advisory check that never ran is worse than a red one — it looks "
            "like good news.",
            "",
            "| Signal | Problem |",
            "| --- | --- |",
        ]
        for v in violations:
            lines.append(f"| `{v['signal']}` | {v['message']} |")
        lines.append("")
    else:
        lines += ["Every gate that ran proved it measured something. ✅", ""]

    if accepted:
        lines += ["| Signal | Status | Examined | Evidence |", "| --- | --- | --- | --- |"]
        for r in sorted(accepted, key=lambda x: str(x.get("signal"))):
            if r.get("status") == MEASURED:
                examined = f"{r.get('units')} {r.get('unit_name', 'units')}"
                note = str(r.get("evidence", ""))
            else:
                examined = "—"
                note = f"*not applicable:* {r.get('reason', '')}"
            lines.append(f"| `{r.get('signal')}` | {r.get('status')} | {examined} | {note} |")
        lines.append("")

    lines += [
        "<sub>Liveness is proof a measurement happened, not proof it found anything — a clean repo "
        "legitimately reports zero findings. A gate with nothing to measure passes by saying so.</sub>",
        "",
    ]
    return "\n".join(lines)


def _annotation(violation: dict[str, str]) -> str:
    message = violation["message"].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return f"::error title=Dead quality gate ({violation['signal']})::{message}"


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------


def _write_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        print(f"{name}={value}")
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def _append_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        sys.stderr.write(text)
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("record", help="emit one liveness receipt")
    rec.add_argument("--signal", required=True, choices=sorted(EXPECTED_SIGNALS))
    rec.add_argument("--status", required=True, choices=_STATUSES)
    rec.add_argument("--units", type=int, default=None, help="how many things were EXAMINED")
    rec.add_argument("--unit-name", default="units")
    rec.add_argument("--evidence", default="", help="what proves the tool actually ran")
    rec.add_argument("--reason", default="", help="why there was nothing to measure")
    rec.add_argument("--extra", default="", help="optional JSON object merged into the receipt")

    ver = sub.add_parser("verify", help="rule on every gate's receipt")
    ver.add_argument("--needs-json", required=True, help="the workflow's toJSON(needs) blob")

    args = parser.parse_args(argv)

    if args.command == "record":
        extra = json.loads(args.extra) if args.extra.strip() else None
        receipt = build_receipt(
            signal=args.signal,
            status=args.status,
            units=args.units,
            unit_name=args.unit_name,
            evidence=args.evidence,
            reason=args.reason,
            extra=extra,
        )
        # Compact + single-line: this travels through a GitHub Actions job output.
        _write_output("receipt", json.dumps(receipt, separators=(",", ":")))
        return 0

    try:
        needs = json.loads(args.needs_json)
    except json.JSONDecodeError as exc:
        # Fail loud: an unreadable needs blob means this check verified NOTHING, which is precisely
        # the condition it exists to detect. Never pass silently here.
        print(f"::error title=Gate liveness could not run::needs JSON did not parse ({exc})")
        _append_summary(
            "## Gate liveness\n\n**Could not run** — the `needs` payload did not parse, so no gate "
            "was checked. Treated as a failure, because a liveness check that silently verifies "
            "nothing is the exact bug it guards against.\n"
        )
        return 2

    violations, accepted = verify(needs)
    for violation in violations:
        print(_annotation(violation))
    _append_summary(render_summary(violations, accepted))

    for receipt in sorted(accepted, key=lambda x: str(x.get("signal"))):
        print(f"ok: {receipt.get('signal')} -> {json.dumps(receipt, separators=(',', ':'))}")

    # Non-zero on violation. This job is advisory and NOT a required check, so a red mark here
    # blocks no merge -- it is simply the loudest honest way to say a gate stopped measuring.
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
