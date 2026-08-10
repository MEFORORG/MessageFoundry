#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Mechanical margin check for a CI step that carries its own ``timeout-minutes`` (BACKLOG #344).

**The failure this exists for is a timeout with ZERO assertion failures**, which reads as a broken
branch when nothing is broken. A run was killed at 26:07 against a 26:00 cap with every test passing;
the leg had already been sitting at a 1.006x margin and nothing said a word, while the comment beside
the cap asserted "~2x headroom" -- a figure that matched no leg. The remaining margin is a SHARED
budget across every PR that lands: three PRs each adding a minute of Windows time reproduce that kill,
individually blameless. An instruction to "re-check the margin when the suite grows" is the wrong
mechanism for a failure whose only symptom is silence, so this is a check.

**The case for a computed gate over a re-read is evidential here, not a matter of diligence.** Across
the CI-triage cluster this item came from, seven published claims were retracted -- margin figures,
pool sizes, a runner count read off an endpoint that could not see the runners. Not one was caught by
re-reading. Every one was caught by something that could return "no".

THE THREE TRAPS, each of which has already cost this repo a wrong number:

1. **Time the STEP, not the JOB.** The job runs minutes longer and is capped separately; three
   sessions misread job durations as step durations while triaging this. This script is handed one
   step's elapsed and one step's cap and never sees a job.
2. **Key on the STEP's own conclusion.** Filtering on the JOB's conclusion deletes the tightest rows
   by construction: a step that nearly exhausts its cap is the most likely to push its job into
   ``job_timeout``, so the job is cancelled while the step itself concluded success. That single
   substitution reproduces a published maximum of 24:35 where the truth was 25:51.
3. **A recorded maximum is a LOWER BOUND when its pool was censored.** The runs that would have
   exceeded a cap were killed at it and dropped for not concluding success, so they are missing from
   exactly the tail being measured. ``step_margin_baseline.toml`` records which rows are censored and
   this script prints the caveat instead of silently dividing by them.

WHAT THE INSTRUMENT ACTUALLY MEASURES, so it is not read as more (SDS-3.8). Elapsed is the interval
between two ``--mark`` calls made in the steps ADJACENT to the one being measured. That is the step's
own duration PLUS the two step transitions around it, i.e. an UPPER bound on the step. So the margin
reported is a LOWER bound on the true margin -- the error runs toward firing early, never toward a
false green, which is the only direction a watchdog may be wrong in.

WHY THE CLOCK IS HERE AND NOT IN THE WORKFLOW SHELL. The obvious spelling is
``echo "T0=$(date +%s)" >> "$GITHUB_ENV"``, and it puts a Windows path through a bash redirection on
two of the three legs -- a construct that cannot be exercised on a laptop and whose failure mode is a
silently missing variable, i.e. a check that stops measuring while still reporting. Marking through
this script keeps every path operation in Python, where the tests below reach it.

Stdlib only, and no network: it must run identically on a hosted runner and on a laptop.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

#: A GitHub Actions step outcome, as `steps.<id>.outcome` reports it. A step killed by its own
#: `timeout-minutes` reports `failure`; a step the job cap cancelled reports `cancelled`; a step whose
#: `if:` was false reports `skipped`.
_OUTCOMES: Final[frozenset[str]] = frozenset({"success", "failure", "cancelled", "skipped"})

#: Below this ratio of cap-to-elapsed the step is reported LOW and the check exits non-zero. Not a
#: round number chosen for looking safe: 1.30 sits under every leg's sized margin (the caps are set at
#: ~1.35x a measured anchor and land at 1.54x-1.87x over the measured maxima), so it fires when a run
#: has moved toward its cap rather than every time a runner has a slow morning.
DEFAULT_MIN_MARGIN: Final[float] = 1.30

_BASELINE: Final[Path] = Path(__file__).resolve().parent / "step_margin_baseline.toml"


class MarginError(Exception):
    """Could not measure. Never confused with a clean result: it exits 2, not 0 and not 1."""


@dataclass(frozen=True)
class Baseline:
    """One recorded (step x leg) maximum, with its pool and whether it is right-censored."""

    step: str
    leg: str
    max_passing_seconds: int
    censored: bool
    censored_by: str
    source: str


@dataclass(frozen=True)
class Verdict:
    """What the check concluded, and the exit code that follows from it.

    ``code`` is one of:

    * ``OK`` -- a success-concluded step with margin at or above the floor.
    * ``LOW`` -- a success-concluded step whose margin is under the floor. THE GATE. Exit 1.
    * ``CENSORED`` -- the step did not conclude success, so its elapsed is a lower bound and NO
      margin is claimed. Exit 0: the step's own failure already reds the job, and printing a healthy
      ratio here would be a compensating control resting on a false premise.
    * ``NO OBSERVATION`` -- the step did not run (a docs-only PR skips it). Exit 0, and the summary
      says so in words. A skipped leg reading as a healthy margin is the negative control this whole
      check would otherwise fail: an empty scan and a clean scan must not look alike.
    """

    code: str
    exit_code: int
    headline: str
    notes: list[str] = field(default_factory=list)


def parse_clock(text: str) -> int:
    """``mm:ss`` or ``hh:mm:ss`` to seconds. Raises on anything else -- a silently-zero duration would
    read as an infinite margin, which is the one wrong answer this must never give."""
    parts = text.strip().split(":")
    if not (2 <= len(parts) <= 3) or not all(p.isdigit() for p in parts):
        raise MarginError(f"not a duration: {text!r} (want mm:ss or hh:mm:ss)")
    seconds = 0
    for p in parts:
        seconds = seconds * 60 + int(p)
    return seconds


def format_clock(seconds: float) -> str:
    """Seconds to ``mm:ss``, which is how every measurement of this in the repo is written."""
    whole = int(round(seconds))
    return f"{whole // 60}:{whole % 60:02d}"


def load_baselines(path: Path = _BASELINE) -> list[Baseline]:
    """Read the recorded maxima. A missing or malformed file is a refusal, not a default."""
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MarginError(f"cannot read the baseline {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise MarginError(f"baseline {path} is not valid TOML: {exc}") from exc
    rows: list[Baseline] = []
    for entry in raw.get("baseline", []):
        try:
            rows.append(
                Baseline(
                    step=str(entry["step"]),
                    leg=str(entry["leg"]),
                    max_passing_seconds=parse_clock(str(entry["max_passing"])),
                    censored=bool(entry["censored"]),
                    censored_by=str(entry.get("censored_by", "")),
                    source=str(entry["source"]),
                )
            )
        except KeyError as exc:
            raise MarginError(f"baseline row is missing {exc}: {entry!r}") from exc
    if not rows:
        raise MarginError(f"baseline {path} records no rows -- refusing to check against nothing")
    return rows


def find_baseline(rows: list[Baseline], step: str, leg: str) -> Baseline:
    """The row for this (step x leg), or a refusal.

    FAIL CLOSED on a missing row, deliberately. A gated step nobody has sized is precisely the state
    this item is about, and defaulting to "no baseline, carry on" would let one appear silently.
    """
    for row in rows:
        if row.step == step and row.leg == leg:
            return row
    known = ", ".join(sorted(f"{r.step} @ {r.leg}" for r in rows))
    raise MarginError(
        f"no recorded maximum for {step!r} on {leg!r}. Either the workflow gained a capped step that "
        f"nobody has sized, or a leg was renamed. Add a row to step_margin_baseline.toml with its "
        f"pool and its date. Known rows: {known}"
    )


def decide(
    *,
    elapsed_seconds: float | None,
    cap_seconds: int,
    outcome: str,
    baseline: Baseline,
    min_margin: float = DEFAULT_MIN_MARGIN,
) -> Verdict:
    """The whole judgement, as a pure function so it can be tested and self-checked."""
    if outcome not in _OUTCOMES:
        raise MarginError(f"unknown step outcome {outcome!r} (expected one of {sorted(_OUTCOMES)})")
    if cap_seconds <= 0:
        raise MarginError(f"cap must be positive, got {cap_seconds}s")

    if outcome == "skipped":
        return Verdict(
            code="NO OBSERVATION",
            exit_code=0,
            headline=(
                f"the step did not run on this leg, so there is NO margin observation. "
                f"Cap {format_clock(cap_seconds)}."
            ),
            notes=[
                "A skipped step is not a healthy margin, and this line exists so it cannot be read "
                "as one -- an empty scan and a clean scan must not look alike."
            ],
        )

    if elapsed_seconds is None or elapsed_seconds <= 0:
        raise MarginError(
            f"the step concluded {outcome!r} but its elapsed time is {elapsed_seconds!r}. A zero or "
            "missing duration would compute as an infinite margin, so this refuses instead."
        )

    notes = _baseline_notes(elapsed_seconds, baseline, censored_observation=outcome != "success")

    if outcome != "success":
        return Verdict(
            code="CENSORED",
            exit_code=0,
            headline=(
                f"the step concluded {outcome} after at least {format_clock(elapsed_seconds)} "
                f"against a cap of {format_clock(cap_seconds)}, so its duration is a LOWER BOUND "
                "and no margin is claimed for it."
            ),
            notes=[
                "The step's own failure already reds this job. Printing a margin ratio over a "
                "truncated observation would be a compensating control resting on a false premise.",
                *notes,
            ],
        )

    margin = cap_seconds / elapsed_seconds
    pct = 100.0 * elapsed_seconds / cap_seconds
    shape = (
        f"{format_clock(elapsed_seconds)} of a {format_clock(cap_seconds)} cap "
        f"({pct:.1f}% of the cap, margin {margin:.3f}x, floor {min_margin:.2f}x)"
    )
    if margin < min_margin:
        return Verdict(
            code="LOW",
            exit_code=1,
            headline=f"MARGIN LOW: {shape}",
            notes=[
                "Raising the cap is NOT the fix and this check must not be read as asking for one. "
                "A cap sized against the work is the fix; the underlying runner slowness is its own "
                "item. What this line establishes is that the margin moved, at the point it moved, "
                "instead of on the day a green suite is killed with zero failing assertions.",
                *notes,
            ],
        )
    return Verdict(code="OK", exit_code=0, headline=f"margin OK: {shape}", notes=notes)


def _baseline_notes(
    elapsed_seconds: float, baseline: Baseline, *, censored_observation: bool
) -> list[str]:
    """What this run says about the RECORD, which is a different question from the cap.

    A run that exceeds the recorded maximum has not necessarily used up its margin -- it has aged the
    record. Saying so here is the mechanism the item asks for: the table was published wrong twice
    because nothing read it.
    """
    notes: list[str] = []
    recorded = baseline.max_passing_seconds
    if baseline.censored:
        notes.append(
            f"the recorded maximum {format_clock(recorded)} is RIGHT-CENSORED, so it is a lower "
            f"bound and any ratio against it flatters itself. Censored by: {baseline.censored_by}"
        )
    if elapsed_seconds > recorded and not censored_observation:
        notes.append(
            f"RE-DERIVE: this run took {format_clock(elapsed_seconds)}, which EXCEEDS the recorded "
            f"maximum of {format_clock(recorded)} for this leg. The record has rotted, and a cap "
            f"sized against it is sized against a smaller suite. Recorded {baseline.source}"
        )
    else:
        notes.append(
            f"recorded maximum for this leg: {format_clock(recorded)}"
            f"{' (censored)' if baseline.censored else ''}; this run is "
            f"{100.0 * elapsed_seconds / recorded:.1f}% of it. {baseline.source}"
        )
    return notes


#: The live control, run on EVERY invocation. A gate that has never been red is a claim, not a
#: control -- and this one's whole job is to return "no" on a condition that has never yet occurred in
#: this repo, so nothing else would ever demonstrate that it can. Both arms are printed into the job
#: summary, so a reader sees the refusal happen rather than being told it would.
_CONTROL_BASELINE: Final[Baseline] = Baseline(
    step="<control>",
    leg="<control>",
    max_passing_seconds=600,
    censored=False,
    censored_by="",
    source="a fixed synthetic pair compiled into this script; it measures nothing about any leg.",
)


def self_check(min_margin: float = DEFAULT_MIN_MARGIN) -> list[str]:
    """Prove the check can return BOTH answers, here, now, on this runner.

    Raises :class:`MarginError` if either arm disagrees -- which exits 2 rather than 0, because a
    check that cannot demonstrate its own refusal has not measured anything.
    """
    cap = 600
    red = decide(
        elapsed_seconds=540,
        cap_seconds=cap,
        outcome="success",
        baseline=_CONTROL_BASELINE,
        min_margin=min_margin,
    )
    green = decide(
        elapsed_seconds=60,
        cap_seconds=cap,
        outcome="success",
        baseline=_CONTROL_BASELINE,
        min_margin=min_margin,
    )
    if red.code != "LOW" or red.exit_code != 1:
        raise MarginError(
            f"the margin check's own NEGATIVE control did not fire: 9:00 against a 10:00 cap is "
            f"1.111x, under the {min_margin:.2f}x floor, and it returned {red.code!r} "
            f"(exit {red.exit_code}). The gate cannot go red, so its green means nothing."
        )
    if green.code != "OK" or green.exit_code != 0:
        raise MarginError(
            f"the margin check's POSITIVE control did not pass: 1:00 against a 10:00 cap is 10.000x "
            f"and it returned {green.code!r}. The gate reds unconditionally, which is the same as "
            "no gate."
        )
    return [
        f"control (negative): 9:00 against a 10:00 cap -> 1.111x -> {red.code}, exit {red.exit_code}",
        f"control (positive): 1:00 against a 10:00 cap -> 10.000x -> {green.code}, "
        f"exit {green.exit_code}",
    ]


def summary_block(
    *, step: str, leg: str, verdict: Verdict, controls: list[str], min_margin: float
) -> str:
    """The Markdown appended to ``$GITHUB_STEP_SUMMARY``.

    It prints WHAT IT SCANNED -- the step, the leg, the cap, the elapsed and the floor -- rather than
    a bare verdict, because a summary that says only "OK" is indistinguishable from a summary that
    scanned nothing.
    """
    lines = [
        f"### CI step margin -- `{step}` on `{leg}`",
        "",
        f"**{verdict.code}** -- {verdict.headline}",
        "",
    ]
    lines += [f"- {n}" for n in verdict.notes]
    lines += [
        "",
        f"<details><summary>the check's own controls (floor {min_margin:.2f}x)</summary>",
        "",
    ]
    lines += [f"- {c}" for c in controls]
    lines += [
        "",
        "These two run on every invocation. The first is the check refusing on demand: without it a "
        "green line here would be a claim rather than a measurement.",
        "</details>",
        "",
    ]
    return "\n".join(lines)


#: The pseudo-label meaning "read the clock now" rather than "read a recorded mark".
NOW: Final[str] = "now"


def clock_dir(explicit: str | None = None) -> Path:
    """Where marks live. ``$RUNNER_TEMP`` on a runner (wiped with the job), the system temp otherwise."""
    if explicit:
        return Path(explicit)
    env = os.environ.get("RUNNER_TEMP")
    return Path(env) if env else Path(tempfile.gettempdir())


def _mark_path(label: str, directory: Path) -> Path:
    if not label or not label.replace("-", "").replace("_", "").isalnum():
        raise MarginError(f"not a usable mark label: {label!r} (letters, digits, - and _ only)")
    return directory / f"step-margin-{label}.mark"


def write_mark(label: str, directory: Path, *, at: float | None = None) -> float:
    """Record the wall clock under ``label``. Called from a step ADJACENT to the one being measured."""
    stamp = time.time() if at is None else at
    directory.mkdir(parents=True, exist_ok=True)
    _mark_path(label, directory).write_text(f"{stamp:.3f}\n", encoding="utf-8")
    return stamp


def read_mark(label: str, directory: Path) -> float:
    """A mark, or a refusal.

    A MISSING MARK IS NEVER A ZERO. That substitution is how a timing check quietly stops measuring
    while still printing a verdict -- the elapsed becomes an epoch-sized number or a negative one, and
    either produces a ratio that looks like an answer.
    """
    if label == NOW:
        return time.time()
    path = _mark_path(label, directory)
    try:
        return float(path.read_text(encoding="utf-8").strip())
    except OSError as exc:
        raise MarginError(
            f"no mark {label!r} at {path}: the step that records it did not run, or ran on a "
            f"different machine. Refusing to guess an elapsed time."
        ) from exc
    except ValueError as exc:
        raise MarginError(f"mark {label!r} at {path} is not a timestamp") from exc


def _emit(text: str, destination: Path | None) -> None:
    if destination is None:
        return
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(text)


def _summary_destination(explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit)
    env = os.environ.get("GITHUB_STEP_SUMMARY")
    return Path(env) if env else None


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--mark", help="record the clock under this label and exit; nothing else runs")
    ap.add_argument("--step", help="the step's `name:` exactly as ci.yml spells it")
    ap.add_argument("--leg", help="the matrix leg, e.g. windows-2025")
    ap.add_argument("--cap-minutes", type=int, help="that step's timeout-minutes")
    ap.add_argument(
        "--outcome",
        help="steps.<id>.outcome for THAT STEP -- never the job's conclusion (see the module docstring)",
    )
    ap.add_argument("--since", help="the mark taken before the step")
    ap.add_argument("--until", help=f"the mark taken after it, or {NOW!r}")
    ap.add_argument(
        "--elapsed-seconds", type=float, help="the duration directly, instead of a mark pair"
    )
    ap.add_argument("--min-margin", type=float, default=DEFAULT_MIN_MARGIN)
    ap.add_argument("--baseline", type=Path, default=_BASELINE)
    ap.add_argument("--clock-dir", help="where marks live; defaults to $RUNNER_TEMP")
    ap.add_argument("--summary-file", help="defaults to $GITHUB_STEP_SUMMARY when that is set")
    return ap


def _elapsed(args: argparse.Namespace) -> float | None:
    if args.elapsed_seconds is not None:
        return float(args.elapsed_seconds)
    if args.since is None or args.until is None:
        return None
    directory = clock_dir(args.clock_dir)
    return read_mark(args.until, directory) - read_mark(args.since, directory)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.mark:
        try:
            stamp = write_mark(args.mark, clock_dir(args.clock_dir))
        except (MarginError, OSError) as exc:
            print(f"step-margin: cannot record mark {args.mark!r}: {exc}", file=sys.stderr)
            return 2
        print(f"step-margin: marked {args.mark!r} at {stamp:.3f}")
        return 0

    missing = [n for n in ("step", "leg", "cap_minutes", "outcome") if getattr(args, n) is None]
    if missing:
        print(
            f"step-margin: could not measure: --{', --'.join(m.replace('_', '-') for m in missing)} "
            "is required in check mode",
            file=sys.stderr,
        )
        return 2

    try:
        controls = self_check(args.min_margin)
        baseline = find_baseline(load_baselines(args.baseline), args.step, args.leg)
        verdict = decide(
            elapsed_seconds=_elapsed(args),
            cap_seconds=args.cap_minutes * 60,
            outcome=args.outcome,
            baseline=baseline,
            min_margin=args.min_margin,
        )
    except MarginError as exc:
        print(f"step-margin: could not measure: {exc}", file=sys.stderr)
        return 2  # never 0, never confused with a clean result, never 1 (which means LOW)

    print(f"step-margin [{args.step} @ {args.leg}] {verdict.code}: {verdict.headline}")
    for note in verdict.notes:
        print(f"  {note}")
    for control in controls:
        print(f"  {control}")
    _emit(
        summary_block(
            step=args.step,
            leg=args.leg,
            verdict=verdict,
            controls=controls,
            min_margin=args.min_margin,
        ),
        _summary_destination(args.summary_file),
    )
    return verdict.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
