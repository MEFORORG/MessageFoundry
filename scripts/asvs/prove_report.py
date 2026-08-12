# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Run ``scorecard.py --prove-absences`` from CI and report WHAT IT SCANNED.

``--prove-absences`` shipped on 2026-08-07 and, measured on 2026-08-09, ran in **no workflow in
either repo** (0 references under ``.github/`` in the engine and in the vault). A mode nothing
invokes cannot go red whatever is inside it, so the 276 absence claims on the record were exactly as
strong after that merge as before it. This module is the wiring, and it exists as a script rather
than as shell inside the workflow for three reasons, each of which was a defect somewhere first:

1. **The prover's total is derived from the prover's own loop.** ``_run_prove_absences`` does lead
   with ``saw N absence claim(s)``, but that ``N`` is ``findings.checked_absences`` -- a counter
   incremented INSIDE the proving loop. It is the right denominator for the counters printed beside
   it, which were measured on the same pass, and it is the wrong instrument for the question *did
   this pass walk the whole record*: a prover that stopped after two claims prints ``saw 2``, which
   is internally consistent and indistinguishable from a two-claim scorecard. A total that shrinks
   along with the pass cannot detect the pass shrinking, so the check has to come from outside the
   loop -- which is the next point. (The counters themselves still do not close to that total, and
   deliberately: a static-screened claim may *also* raise a SUSPECT problem, and eight outcomes raise
   a problem while incrementing no counter. See ``Findings.proved_absences`` for the identity.)
2. **The census must not share the prover's arithmetic.** :func:`census` reads the TOML with plain
   ``tomllib`` and deliberately does **not** call ``scorecard.load_scorecard``. A total derived from
   the loader would agree with the loader by construction -- the same "value generated from the thing
   it validates" defect the ``mutation`` field exists to close, arriving through the fix. Two
   independent counts are what make :func:`reconcile` able to say anything at all.
3. **Exit codes do not survive a shell pipeline.** Advisory-versus-blocking, and instrument-failure
   versus finding, are three outcomes that must stay distinguishable; deciding that in ``run:`` YAML
   is how ``$?``-after-a-pipe bugs are born (SDS-3.8).

**Advisory applies to FINDINGS, never to the INSTRUMENT.** A claim that will not prove is reported
and, until adoption is non-zero, does not fail the job (:data:`EXIT_FINDINGS` is returned only under
``--strict``). A run that could not obtain a scorecard, could not run the prover, or could not
reconcile its own numbers returns :data:`EXIT_INSTRUMENT` unconditionally -- the rule
``scorecard.py`` already states for its own loader failure ("could not measure -- never 0, never
confused with clean").

**Per-claim detail is suppressed by default because this repo is public.** The prover's problem
lines name the cell and the control that would not prove, which is a ranked list of the weakest
controls on the record -- the same disclosure that got the "verdict-attributed anchor manifest"
rejected in the 2026-08-08 tracking-rework diagnosis. Counts are safe and are always printed;
``--detail`` opts the lines in, and is only appropriate where the run log is private.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import os
import re
import subprocess  # nosec B404 - fixed argv, no shell; see _invoke_prover
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCORECARD_PY = HERE / "scorecard.py"

#: Clean: the instrument ran, and either found nothing or is in advisory mode.
EXIT_OK = 0
#: Findings, under ``--strict`` only. The ratchet Stream C / the owner flips once adoption is real.
EXIT_FINDINGS = 1
#: The instrument could not measure. NEVER suppressed by advisory mode, and never 0.
EXIT_INSTRUMENT = 2

#: Parses ``_run_prove_absences``'s one summary line. Coupled to that format ON PURPOSE and with a
#: hard failure on a miss: if that line is reformatted, this must go red rather than quietly report
#: zeros. An unparseable instrument is an instrument failure, not a clean run.
#:
#: `.*?` after the prefix spans the `saw N absence claim(s);` total that summary carries, which this
#: module deliberately does NOT read: the whole reason :func:`census` exists is that a loop-derived
#: total cannot check the loop (module docstring, point 1). Deliberately narrow tolerance -- it
#: absorbs a leading insertion without becoming loose enough to match arbitrary text, which selftest
#: limb L7 asserts by feeding it exactly that.
_SUMMARY_RE = re.compile(
    r"prove-absences:.*?proved\s+(?P<proved>\d+)\s+by mutation;\s*"
    r"(?P<screened>\d+)\s+static-screened;\s*"
    r"(?P<skipped>\d+)\s+skipped;\s*"
    r"(?P<problems>\d+)\s+problem"
)


@dataclass(frozen=True)
class Census:
    """The claim population, counted independently of the prover (see the module docstring)."""

    cells: int
    cells_with_claims: int
    claims: int
    #: ``observable`` AND ``mutation_path``: the prover attempts a live execution proof.
    provable: int
    #: ``mutation_path`` only: the prover applies the coarse static backstop. A screen, not a proof.
    static_only: int
    #: No ``mutation_path``: the prover SKIPS it. This is the population the whole exercise is about.
    unprovable: int
    #: ``observable`` authored but ``mutation_path`` left empty. The prover's first branch keys on
    #: ``mutation_path``, so such a claim is skipped SILENTLY and its observable never runs -- an
    #: authoring slip that looks identical to a claim nobody has touched. Reported separately.
    orphan_observable: int
    #: Whitespace-only ``mutation_path``. Truthy to the loader (which does not strip) and empty to a
    #: reader. Named so the two cannot disagree without someone being told.
    blank_mutation_path: int


def census(scorecard: Path) -> Census:
    """Count the absence-claim population straight from the TOML.

    Deliberately not ``scorecard.load_scorecard``: this number's whole job is to be checkable against
    the prover's, which means it must not come from the prover's own loader.
    """
    data = tomllib.loads(scorecard.read_text(encoding="utf-8"))
    cells = data.get("cell", [])
    claims = provable = static_only = unprovable = orphan = blank = 0
    cells_with_claims = 0
    for cell in cells:
        absences = cell.get("absence", [])
        if absences:
            cells_with_claims += 1
        for a in absences:
            claims += 1
            # `str(...)` with no strip, matching `load_scorecard` in scorecard.py exactly -- the
            # classification has to agree with what the prover will actually branch on. Named, not
            # cited by line: this comment previously pinned `scorecard.py:339-340`, which resolved in
            # PR #304 and resolves to unrelated docstring prose here, because the port moved the
            # loader. An anchor that has to be re-checked by hand decays the first time either file
            # moves, and nothing in the repo checks a line citation inside a Python comment.
            raw_path = str(a.get("mutation_path", ""))
            raw_obs = str(a.get("observable", ""))
            if raw_path and not raw_path.strip():
                blank += 1
            if not raw_path:
                unprovable += 1
                if raw_obs:
                    orphan += 1
            elif raw_obs:
                provable += 1
            else:
                static_only += 1
    return Census(
        cells=len(cells),
        cells_with_claims=cells_with_claims,
        claims=claims,
        provable=provable,
        static_only=static_only,
        unprovable=unprovable,
        orphan_observable=orphan,
        blank_mutation_path=blank,
    )


@dataclass(frozen=True)
class ProverResult:
    """What the prover subprocess reported."""

    returncode: int
    proved: int
    screened: int
    skipped: int
    problems: int
    problem_lines: tuple[str, ...]
    stdout: str
    stderr: str


def _invoke_prover(
    scorecard: Path, root: Path, python: str, timeout: float
) -> tuple[int, str, str]:
    """Run ``scorecard.py --prove-absences`` as a subprocess and hand back the raw streams."""
    proc = subprocess.run(  # nosec B603 - fixed argv, no shell; paths come from argparse
        [
            python,
            str(SCORECARD_PY),
            "--scorecard",
            str(scorecard),
            "--root",
            str(root),
            "--prove-absences",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def parse_prover(returncode: int, stdout: str, stderr: str) -> ProverResult | None:
    """Parse the prover's summary line. ``None`` means the output did not contain one at all, which
    is an instrument failure and never a clean run."""
    m = _SUMMARY_RE.search(stdout)
    if m is None:
        return None
    lines = tuple(
        ln.strip()[5:].strip() for ln in stderr.splitlines() if ln.strip().startswith("FAIL")
    )
    return ProverResult(
        returncode=returncode,
        proved=int(m.group("proved")),
        screened=int(m.group("screened")),
        skipped=int(m.group("skipped")),
        problems=int(m.group("problems")),
        problem_lines=lines,
        stdout=stdout,
        stderr=stderr,
    )


def reconcile(c: Census, r: ProverResult) -> list[str]:
    """Check the prover's four counters against the independent census.

    This is the prover's own accounting identity (stated once, on ``scorecard.Findings``) evaluated
    against a census the prover did not produce: the residual ``claims - (proved + screened +
    skipped)`` is the number of claims that raised a problem and incremented no counter. Anything
    that makes it negative, or larger than the reported problem count, means the two sides are not
    describing the same population -- which is the only way to notice a prover that stopped
    iterating, since its own summary looks identical either way.

    The bound is ``residual <= problems`` and NOT ``residual == problems``, deliberately: a
    static-screened claim can also raise a SUSPECT problem, so a problem and a problem-only claim are
    different things. Tightening this to equality would make an honest SUSPECT finding look like a
    stalled prover.
    """
    bad: list[str] = []
    if r.skipped != c.unprovable:
        bad.append(
            f"prover skipped {r.skipped} claims but {c.unprovable} carry no `mutation_path` -- the "
            "prover skips exactly those, so these must be equal"
        )
    if r.proved > c.provable:
        bad.append(
            f"prover proved {r.proved} claims but only {c.provable} carry both `observable` and "
            "`mutation_path`"
        )
    if r.screened > c.static_only:
        bad.append(
            f"prover static-screened {r.screened} claims but only {c.static_only} carry a "
            "`mutation_path` without an `observable`"
        )
    residual = c.claims - (r.proved + r.screened + r.skipped)
    if residual < 0:
        bad.append(
            f"prover accounted for {r.proved + r.screened + r.skipped} outcomes across only "
            f"{c.claims} claims -- more outcomes than claims"
        )
    elif residual > r.problems:
        bad.append(
            f"{residual} claims produced no outcome counter but only {r.problems} problem(s) were "
            "reported -- claims went missing between the scorecard and the prover"
        )
    return bad


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_head(root: Path) -> str:
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return proc.stdout.strip() or "unknown"


def _emit_summary(lines: list[str]) -> None:
    """Append to the GitHub job summary when running under Actions; a no-op elsewhere."""
    dest = os.environ.get("GITHUB_STEP_SUMMARY")
    if not dest:
        return
    with open(dest, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _report(
    scorecard: Path, root: Path, c: Census, r: ProverResult, *, detail: bool, strict: bool
) -> None:
    """Print the census, the prover's own counters, and the adoption rate.

    This block is the whole point of the module: a run that scanned nothing and a run that scanned
    everything and found nothing must not print the same thing.
    """
    pct = (100.0 * (c.provable + c.static_only) / c.claims) if c.claims else 0.0
    mode = "STRICT (findings fail the job)" if strict else "ADVISORY (findings report only)"
    out = [
        "ASVS prove-absences",
        f"  mode                 : {mode}",
        f"  scorecard            : {scorecard} (sha256 {_sha256(scorecard)[:16]})",
        f"  root                 : {root} (HEAD {_git_head(root)})",
        f"  cells                : {c.cells}",
        f"  cells with claims    : {c.cells_with_claims}",
        f"  absence claims SEEN  : {c.claims}",
        f"    live-provable      : {c.provable} (observable + mutation_path)",
        f"    static-screen only : {c.static_only} (mutation_path, no observable)",
        f"    NOT provable       : {c.unprovable} (no mutation_path -- the prover skips these)",
        f"    orphan observable  : {c.orphan_observable} (observable authored, mutation_path empty "
        "-- SILENTLY skipped)",
        f"    blank mutation_path: {c.blank_mutation_path} (whitespace-only)",
        f"  prover reported      : proved {r.proved} / static-screened {r.screened} / "
        f"skipped {r.skipped} / problems {r.problems} (exit {r.returncode})",
        f"  reconciliation       : {'OK' if not reconcile(c, r) else 'MISMATCH'}",
        f"  ADOPTION             : {c.provable + c.static_only} of {c.claims} claims "
        f"({pct:.1f}%) can be proved or screened at all",
    ]
    print("\n".join(out))

    if r.problems:
        if detail:
            for line in r.problem_lines:
                print(f"  FAIL {line}", file=sys.stderr)
        else:
            print(
                f"  {r.problems} problem line(s) SUPPRESSED -- they name the cell and the control "
                "that would not prove, and this repo's run logs are public. Re-run with --detail "
                "where the log is private.",
                file=sys.stderr,
            )

    _emit_summary(
        [
            "### ASVS `--prove-absences`",
            "",
            f"Mode: **{mode.split(' (')[0]}**. Scorecard `{_sha256(scorecard)[:16]}`, "
            f"root HEAD `{_git_head(root)}`.",
            "",
            "| what | n |",
            "|---|---:|",
            f"| absence claims seen | {c.claims} |",
            f"| live-provable (observable + mutation_path) | {c.provable} |",
            f"| static-screen only (mutation_path only) | {c.static_only} |",
            f"| not provable (no mutation_path -- skipped) | {c.unprovable} |",
            f"| orphan observable (silently skipped) | {c.orphan_observable} |",
            f"| proved by mutation | {r.proved} |",
            f"| static-screened | {r.screened} |",
            f"| problems | {r.problems} |",
            "",
            f"**Adoption: {c.provable + c.static_only} of {c.claims} ({pct:.1f}%).** A claim with no "
            "`observable` is *not yet proven by execution* -- never *proven vacuous*.",
        ]
    )


def run(args: argparse.Namespace) -> int:
    scorecard = Path(args.scorecard)
    root = Path(args.root)
    if not scorecard.is_file():
        # Fail closed. This is the limb that fires when the vault scorecard could not be obtained,
        # and it must never be mistaken for "nothing to report".
        print(
            f"error: scorecard not found at {scorecard} -- refusing to report a pass on a run that "
            "scanned nothing",
            file=sys.stderr,
        )
        _emit_summary(
            [
                "### ASVS `--prove-absences` DID NOT RUN",
                "",
                "No scorecard input was available, so **zero** absence claims were scanned. This "
                "run is not evidence about any claim.",
            ]
        )
        return EXIT_INSTRUMENT
    if not root.is_dir():
        print(f"error: --root {root} is not a directory", file=sys.stderr)
        return EXIT_INSTRUMENT

    try:
        c = census(scorecard)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        print(f"error: could not read the scorecard: {exc}", file=sys.stderr)
        return EXIT_INSTRUMENT

    try:
        rc, stdout, stderr = _invoke_prover(scorecard, root, args.python, args.timeout)
    except subprocess.TimeoutExpired:
        print(f"error: the prover did not finish within {args.timeout}s", file=sys.stderr)
        return EXIT_INSTRUMENT

    if rc == EXIT_INSTRUMENT:
        print(f"error: the prover could not measure (exit 2):\n{stderr}", file=sys.stderr)
        return EXIT_INSTRUMENT

    r = parse_prover(rc, stdout, stderr)
    if r is None:
        print(
            "error: the prover printed no summary line -- its output could not be parsed, so this "
            f"run measured nothing checkable. stdout was:\n{stdout}",
            file=sys.stderr,
        )
        return EXIT_INSTRUMENT

    _report(scorecard, root, c, r, detail=args.detail, strict=args.strict)

    mismatches = reconcile(c, r)
    if mismatches:
        for m in mismatches:
            print(f"  RECONCILE {m}", file=sys.stderr)
        return EXIT_INSTRUMENT

    if r.problems and args.strict:
        return EXIT_FINDINGS
    return EXIT_OK


# --- the fail-on-purpose harness ------------------------------------------------------------------
#
# Everything above is a report, and a report is the easiest thing in the world to have quietly stop
# working. These limbs make the wiring go RED on purpose and assert that it did -- including the
# advisory/strict split and the detail suppression, both of which are controls in their own right and
# neither of which is exercised by tests/test_asvs_scorecard.py (those test `prove_absences` and the
# `main` CLI, not this module's policy). Run it locally with `python scripts/asvs/prove_report.py
# selftest`; the workflow runs it before it believes anything the report says.

_SCANNER = "def scan(p):\n    return 'clean'\n"
_OBS_TEST = "from scanner import scan\n\n\ndef test_clean():\n    assert scan('x') == 'clean'\n"
_MUTATION = 'def scan(p): return "infected"'


def _fixture(tree: Path, mutation_path: str, observable: str) -> Path:
    """A two-file tree plus a one-claim scorecard. Modelled on the fixtures in
    tests/test_asvs_scorecard.py so the shape is one the prover is already known to handle."""
    tree.mkdir(parents=True, exist_ok=True)
    (tree / "scanner.py").write_text(_SCANNER, encoding="utf-8")
    (tree / "unrelated.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tree / "test_scanner.py").write_text(_OBS_TEST, encoding="utf-8")
    sc = tree.parent / f"{tree.name}-scorecard.toml"
    # TOML LITERAL strings (single quotes) throughout: `_MUTATION` contains double quotes, and a
    # basic-string fixture silently produced an unparseable scorecard whose only symptom was the
    # instrument limb firing on every case -- L1-L3 red, L4 green, which reads like a broken prover
    # rather than a broken fixture. Caught by running it; kept as a comment so it stays caught.
    sc.write_text(
        "[[cell]]\n"
        "id = '1.1.1'\n"
        "level = 1\n"
        "verdict = 'fail'\n"
        "residual = 'selftest fixture'\n"
        "[[cell.absence]]\n"
        "pattern = 'irrelevant-to-proving'\n"
        "positive_control = 'irrelevant-to-proving'\n"
        f"mutation = '{_MUTATION}'\n"
        f"mutation_path = '{mutation_path}'\n"
        f"observable = '{observable}'\n",
        encoding="utf-8",
    )
    return sc


def _limb(name: str, got: int, want: int, detail: str = "") -> bool:
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: exit {got} (wanted {want}) {detail}")
    return ok


def selftest(args: argparse.Namespace) -> int:
    """Prove the wiring can go red, and that each outcome is DISTINCT from the others."""
    del args
    ok = True
    with tempfile.TemporaryDirectory(prefix="asvs_prove_selftest_") as td:
        base = Path(td)

        # L1 -- the mutation shadows `scan`, so the observable goes red and the claim BITES.
        biting = _fixture(base / "biting", "scanner.py", "test_scanner.py::test_clean")
        ns = argparse.Namespace(
            scorecard=str(biting),
            root=str(base / "biting"),
            python=sys.executable,
            timeout=300.0,
            detail=False,
            strict=False,
        )
        ok &= _limb("L1 biting claim, advisory", run(ns), EXIT_OK, "-- proved by mutation")

        # L2 -- the mutation lands in a file the observable never imports, so it reddens nothing.
        # ADVISORY: reported, exit 0. This is the limb that proves advisory is a real state.
        nonbiting = _fixture(base / "inert", "unrelated.py", "test_scanner.py::test_clean")
        ns = argparse.Namespace(
            scorecard=str(nonbiting),
            root=str(base / "inert"),
            python=sys.executable,
            timeout=300.0,
            detail=False,
            strict=False,
        )
        ok &= _limb("L2 non-biting claim, advisory", run(ns), EXIT_OK, "-- reported, not fatal")

        # L3 -- the SAME fixture under --strict must fail. One flag is the whole ratchet, and if it
        # does not bite then "advisory" was never a choice, it was the only behaviour.
        ns = argparse.Namespace(
            scorecard=str(nonbiting),
            root=str(base / "inert"),
            python=sys.executable,
            timeout=300.0,
            detail=False,
            strict=True,
        )
        ok &= _limb("L3 non-biting claim, strict", run(ns), EXIT_FINDINGS, "-- the ratchet bites")

        # L4 -- no scorecard at all: the no-input limb. Must be 2 (instrument), never 0 and never 1;
        # advisory mode must NOT be able to turn a run that scanned nothing into a pass.
        ns = argparse.Namespace(
            scorecard=str(base / "does-not-exist.toml"),
            root=str(base / "biting"),
            python=sys.executable,
            timeout=300.0,
            detail=False,
            strict=False,
        )
        ok &= _limb("L4 missing scorecard, advisory", run(ns), EXIT_INSTRUMENT, "-- fails closed")

        # L5 -- the census must SEE the claim. A report that says 0 claims when there is 1 is the
        # exact failure this module exists to make impossible, and it would pass L1-L4 unnoticed.
        c = census(biting)
        seen_ok = (c.claims, c.provable, c.unprovable) == (1, 1, 0)
        print(f"  [{'PASS' if seen_ok else 'FAIL'}] L5 census sees the claim: {c}")
        ok &= seen_ok

        # L6 -- the disclosure control, attacked rather than assumed. Without --detail the problem
        # text must NOT reach the log; with --detail it must. A suppression nobody tried to defeat is
        # a claim, not a control.
        for detail, want in ((False, False), (True, True)):
            r = _invoke_prover(nonbiting, base / "inert", sys.executable, 300.0)
            parsed = parse_prover(*r)
            assert parsed is not None, "L6 could not parse the prover output"
            buf_out, buf_err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
                _report(
                    nonbiting,
                    base / "inert",
                    census(nonbiting),
                    parsed,
                    detail=detail,
                    strict=False,
                )
            leaked = "UNPROVEN" in (buf_out.getvalue() + buf_err.getvalue())
            limb_ok = leaked == want
            print(
                f"  [{'PASS' if limb_ok else 'FAIL'}] L6 detail={detail}: "
                f"claim text {'present' if leaked else 'suppressed'} (wanted "
                f"{'present' if want else 'suppressed'})"
            )
            ok &= limb_ok

        # L7 -- a prover whose summary line stopped matching must be an INSTRUMENT failure, not a
        # report of zeros. This is the coupling to `_run_prove_absences`'s print format, and it is
        # the one that decays silently: reformat that line and, without this, every future run would
        # report "0 claims, 0 problems" and read exactly like a healthy record.
        unparseable = parse_prover(0, "prove-absences ran, trust me", "") is None
        print(
            f"  [{'PASS' if unparseable else 'FAIL'}] L7 unparseable summary -> instrument failure"
        )
        ok &= unparseable

        # L8 -- reconciliation must catch a prover that stopped iterating. Its own summary line looks
        # identical whether it walked 276 claims or 2, so this is the ONLY thing standing between a
        # half-run prover and a green report. Attacked directly: 276 claims, 2 skipped.
        stalled = reconcile(
            Census(
                cells=345,
                cells_with_claims=209,
                claims=276,
                provable=0,
                static_only=0,
                unprovable=276,
                orphan_observable=0,
                blank_mutation_path=0,
            ),
            ProverResult(
                returncode=0,
                proved=0,
                screened=0,
                skipped=2,
                problems=0,
                problem_lines=(),
                stdout="",
                stderr="",
            ),
        )
        caught = len(stalled) > 0
        print(
            f"  [{'PASS' if caught else 'FAIL'}] L8 stalled prover caught: {len(stalled)} mismatch(es)"
        )
        ok &= caught

    print(f"selftest: {'ALL LIMBS PASS' if ok else 'FAILED'}")
    return EXIT_OK if ok else EXIT_FINDINGS


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="census the claims, run the prover, reconcile, report")
    r.add_argument("--scorecard", required=True)
    r.add_argument("--root", default=".", help="tree the mutations are applied to (the engine)")
    r.add_argument("--python", default=sys.executable)
    r.add_argument("--timeout", type=float, default=3600.0)
    r.add_argument(
        "--detail",
        action="store_true",
        help="print the per-claim problem lines. ONLY where the run log is private -- they rank the "
        "weakest controls on the record.",
    )
    r.add_argument(
        "--strict",
        action="store_true",
        help="findings fail the job. Off while adoption is zero; this is the whole ratchet.",
    )
    r.set_defaults(func=run)

    s = sub.add_parser("selftest", help="make the wiring go red on purpose and assert that it did")
    s.set_defaults(func=selftest)

    args = ap.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
