# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Was an anchor's line number RIGHT AT THE COMMIT THE CELL STAMPS AS VERIFIED?

BACKLOG #1344. ``scorecard.py`` answers a different question, correctly: does the token still resolve
in the CURRENT tree, and does the recorded line still agree? A disagreement there is ordinary staleness
-- the file moved on and the record did not.

**This tool asks whether the number was ever right at all.** For each anchor it reads the cited file at
the cell's own ``verified_at`` commit and looks for the token there. That separates two populations a
current-tree check renders identically:

    at the recorded line     ordinary staleness -- the anchor was correct when it was written
    elsewhere in the file    THE FIELD WAS NEVER VERIFIED AT ANY REF
    absent entirely          the recorded commit itself is wrong

**WHY THIS MATTERS.** Re-deriving a line fixes a STALE anchor completely. It fixes a BORN-WRONG one only
cosmetically, and it overwrites the old number -- the very evidence that it was never right.

***BUT THE WITNESS IS NOT DESTROYED, AND THE ITEM THAT COMMISSIONED THIS TOOL ASSUMED IT WAS.***
BACKLOG #1344 carries an expiry reading *"this stops being right if the anchors are repaired without
recording their born-wrong status, at which point the population is gone and this row cannot be
re-derived."* **That is false, and measurably so: the scorecard is version-controlled, so every prior
state of every anchor survives.** Point ``--scorecard`` at a historical copy and the population is
recoverable at any ref::

    git -C <vault> show <ref>^:docs/security/asvs-scorecard.toml > /tmp/pre.toml
    python scripts/asvs/anchor_provenance.py --scorecard /tmp/pre.toml --root <engine>

***AND MEASURING THE LIVE RECORD ALONE GIVES THE WRONG ANSWER IN THE ALARMING DIRECTION, which is why
this paragraph is here rather than in a commit message.*** A mass re-anchor re-derives lines against a
RECENT tree, which moves them FURTHER from the older commits the cells stamp -- so a repair *raises* the
apparent born-wrong rate. Measured across one such repair: 42.0 percent before it, 60.5 percent after,
on the same 2,091 anchors and the same engine history. **Read the live record on its own and you will
report an inflated figure as a finding.** Run the pre-repair copy as a control, always.

A recovered figure is still a FLOOR rather than a total: repairs before the one you rewind past have
already overwritten their own witnesses. Say "at least", not "exactly".

**THE MATCHING SEMANTICS ARE MIRRORED FROM ``check_anchors``, DELIBERATELY, RATHER THAN INVENTED.** A
second, silently different definition of "does this token resolve" would produce a born-wrong population
that is really a disagreement between two matchers. Same substring count, same uniqueness rule, same
offset-derived line. Where this tool differs it is only in WHICH TREE it reads.

**IT PROPOSES NO REPAIRS, for the reason ``check_anchors`` gives at its own GONE branch:** a tool cannot
tell a moved token from a retired one from a removed control, and the single affordance of suggesting a
replacement is what manufactures silent corruption. This one reports and stops.

**OUTPUT IS SPLIT BY DISCLOSURE, NOT BY CONVENIENCE.** The summary is counts only and is safe to paste
anywhere. Per-cell detail names cell identifiers and file paths, whose pairing is exactly the
enumeration CLAUDE.md section 12 keeps vaulted, so it is written only where ``--detail`` points and
never to stdout.

***A REFUSAL IS THE THIRD STREAM, AND THE CLAIM ABOVE WAS FALSE UNTIL IT WAS COVERED TOO.*** The reader
that turns the record into cells refuses by NAMING the graded row it rejected, so an unguarded call
would publish that identifier -- and, on one branch, the whole grading vocabulary -- to stderr on the
first malformed record. Neither half of the split above reaches it, which is the point: a reader
auditing this tool against a two-part enumeration ticks both halves and never looks for a third
(SDS-3.6). So the one refusal that has an exception in hand quotes its CLASS and never its message,
and a property that held only while every record loaded is now a property of the tool (SDS-3.7).
*Not "every refusal here", which is the shape this very paragraph warns against:* of the seven refusals
in ``main`` the other six have no exception to quote, and a reader auditing that universal against the
first one they reach finds a path and a git exit code instead, and cannot tell a scoped claim from a
broken one.

THE HYPOTHESIS THIS EXISTS TO TEST CHEAPLY. The item offers one explanation for the whole population --
that the numbers were read from a LATER tree than the commit the cell stamps -- and states it as a
hypothesis rather than a finding. Its falsifiable form is "find a single later ref at which the recorded
lines resolve". ``--at <ref>`` answers that in one run: if a candidate ref resolves the born-wrong
population, the hypothesis is supported; if none does, it is refuted cheaply.

Usage::

    python scripts/asvs/anchor_provenance.py --scorecard <vault>/docs/security/asvs-scorecard.toml \\
        --root <engine checkout> [--at <ref>] [--detail out.json]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scorecard import Cell, load_scorecard  # noqa: E402

#: A born-wrong anchor is one whose token is UNIQUE at the recorded commit and sits at a DIFFERENT line.
#: Uniqueness is what makes the line number load-bearing; without it the anchor resolves from anywhere
#: and "wrong line" means nothing. Mirrors ``check_anchors``'s own reasoning.
AT_LINE = "at_line"
BORN_WRONG = "born_wrong"
AMBIGUOUS = "ambiguous_at_birth"
ABSENT = "absent_at_birth"
PATH_GONE = "path_absent_at_birth"
UNREADABLE = "commit_unreadable"
NO_COMMIT = "cell_records_no_commit"

#: The two that mean "this anchor was never verified where the record says it was". Kept as a named set
#: rather than spelled out at each site, so a later verdict change cannot drift between them.
NEVER_VERIFIED = frozenset({BORN_WRONG, ABSENT, PATH_GONE})


@dataclass(frozen=True)
class AnchorVerdict:
    cell: str
    path: str
    recorded_line: int
    actual_line: int | None
    verdict: str
    ref: str


def _blob(root: Path, ref: str, path: str, cache: dict[tuple[str, str], str | None]) -> str | None:
    """File content at a ref, or None when the path does not exist there.

    A MISSING PATH AND AN UNREADABLE REF ARE DIFFERENT ANSWERS and the caller must not merge them: the
    first says the anchor pointed at a file that did not exist yet, the second says the stamp itself
    cannot be resolved. Distinguished by asking git about the ref separately.
    """
    key = (ref, path)
    if key in cache:
        return cache[key]
    # git is read-only here and every argument is a ref or path the scorecard authored, never a
    # caller-supplied executable.
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only git
        # Explicit UTF-8: ``text=True`` alone decodes with the LOCALE encoding, so a source file
        # carrying any non-ASCII byte would be mangled and its token offsets shifted.
        ["git", "-C", str(root), "show", f"{ref}:{path}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    cache[key] = proc.stdout if proc.returncode == 0 else None
    return cache[key]


def _ref_exists(root: Path, ref: str, cache: dict[str, bool]) -> bool:
    if ref in cache:
        return cache[ref]
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; cat-file -e only tests a ref
        ["git", "-C", str(root), "cat-file", "-e", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    cache[ref] = proc.returncode == 0
    return cache[ref]


def classify(text: str, expect: str, recorded_line: int) -> tuple[str, int | None]:
    """Mirror of ``check_anchors``'s locator, applied to whichever tree the caller opened.

    Substring count for the uniqueness rule; the line derived from the character offset rather than by
    scanning lines, because tokens spanning a newline are real and a per-line scan misses every one.
    """
    occurrences = text.count(expect)
    if occurrences == 0:
        return ABSENT, None
    if occurrences > 1:
        return AMBIGUOUS, None
    actual = text.count("\n", 0, text.index(expect)) + 1
    return (AT_LINE if actual == recorded_line else BORN_WRONG), actual


def audit(cells: list[Cell], root: Path, override_ref: str | None = None) -> list[AnchorVerdict]:
    blob_cache: dict[tuple[str, str], str | None] = {}
    ref_cache: dict[str, bool] = {}
    out: list[AnchorVerdict] = []
    for cell in cells:
        ref = override_ref or cell.verified_at
        for anchor in cell.evidence:
            if not ref:
                out.append(AnchorVerdict(cell.id, anchor.path, anchor.line, None, NO_COMMIT, ""))
                continue
            if not _ref_exists(root, ref, ref_cache):
                out.append(AnchorVerdict(cell.id, anchor.path, anchor.line, None, UNREADABLE, ref))
                continue
            text = _blob(root, ref, anchor.path, blob_cache)
            if text is None:
                out.append(AnchorVerdict(cell.id, anchor.path, anchor.line, None, PATH_GONE, ref))
                continue
            verdict, actual = classify(text, anchor.expect, anchor.line)
            out.append(AnchorVerdict(cell.id, anchor.path, anchor.line, actual, verdict, ref))
    return out


def summarise(verdicts: list[AnchorVerdict]) -> str:
    counts = Counter(v.verdict for v in verdicts)
    total = len(verdicts)
    lines = [f"anchors examined: {total}"]
    for name in (AT_LINE, BORN_WRONG, ABSENT, PATH_GONE, AMBIGUOUS, UNREADABLE, NO_COMMIT):
        n = counts.get(name, 0)
        pct = f"{100.0 * n / total:.1f}%" if total else "n/a"
        lines.append(f"  {name:<24} {n:>6}  {pct}")

    # THE DIRECTION IS THE ITEM'S OWN EVIDENCE AND IT IS REPORTED RATHER THAN ASSERTED. Random
    # transcription scatters both ways; a population skewed one way is a mechanism. Printing the split
    # lets a reader judge that instead of taking the claim on trust.
    # Paired as concrete ints rather than carried as verdicts, so the None case is excluded ONCE at the
    # boundary instead of being re-asserted at each use. A born-wrong verdict always carries a line by
    # construction, but relying on that invariant three lines later is how it stops being one.
    drift = [
        (v.recorded_line, v.actual_line)
        for v in verdicts
        if v.verdict == BORN_WRONG and v.actual_line is not None
    ]
    if drift:
        higher = sum(1 for recorded, actual in drift if recorded > actual)
        lower = sum(1 for recorded, actual in drift if recorded < actual)
        lines.append("")
        lines.append(f"born-wrong direction: recorded HIGHER than actual {higher}, LOWER {lower}")
        deltas = sorted(abs(recorded - actual) for recorded, actual in drift)
        lines.append(
            f"  |delta| min {deltas[0]}, median {deltas[len(deltas) // 2]}, max {deltas[-1]}"
        )
    never = sum(counts.get(k, 0) for k in NEVER_VERIFIED)
    unread = counts.get(UNREADABLE, 0) + counts.get(NO_COMMIT, 0)
    lines.append("")
    lines.append(f"anchors that were NOT verifiable at the cell's own recorded commit: {never}")
    # THE NUMBER ABOVE IS THE ONE A READER CARRIES AWAY, AND IT SUMS ONLY BUCKETS THAT REQUIRED A
    # SUCCESSFUL READ. Excluding UNREADABLE from NEVER_VERIFIED is right -- an unresolvable stamp is
    # a different fact from a born-wrong anchor -- but it means a run that read NOTHING closes with a
    # reassuring zero. Printing the denominator it did not examine, always and including when it is
    # zero, is what stops that line being taken as a verdict over the whole population.
    lines.append(
        f"anchors whose recorded commit could not be read, so the line above did not "
        f"examine them: {unread}"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scorecard", type=Path, required=True)
    ap.add_argument(
        "--root",
        type=Path,
        required=True,
        help="engine checkout whose history the anchors are read against",
    )
    ap.add_argument(
        "--at",
        help="test one candidate ref for EVERY cell instead of each cell's own verified_at. This is "
        "the falsifiable form of the later-tree hypothesis: if a single ref resolves the born-wrong "
        "population, the hypothesis is supported; if none does, it is refuted.",
    )
    ap.add_argument(
        "--detail",
        type=Path,
        help="write the per-cell record here. It names cell identifiers beside file paths, which is "
        "the pairing CLAUDE.md section 12 keeps vaulted -- point this INSIDE the vault, never at the "
        "engine tree.",
    )
    args = ap.parse_args(argv)

    if not args.scorecard.is_file():
        sys.stderr.write(f"scorecard not found: {args.scorecard}\n")
        return 2
    if not (args.root / ".git").exists():
        sys.stderr.write(f"--root is not a git checkout: {args.root}\n")
        return 2

    # THE ROOT MUST NOT BE THE TREE THAT STORES THE RECORD, and scorecard.py refuses the same pairing
    # in verify mode for the same reason: resolving anchors against the repository that holds the
    # scorecard produces a self-consistent, wrong answer, and the vault carries its own copy of the
    # engine sources for exactly that trap to fall into.
    try:
        if args.scorecard.resolve().is_relative_to(args.root.resolve()):
            sys.stderr.write(
                "REFUSING: --root contains the scorecard. Anchors resolved against the repository "
                "that stores the record are self-consistent and wrong. Point --root at the engine.\n"
            )
            return 2
    except (OSError, ValueError):
        pass

    # THE REF PAIR IS PART OF THE MEASUREMENT, SO AN UNRESOLVABLE HEAD IS A REFUSAL. On a repo with
    # no commits ``git rev-parse HEAD`` exits 128 and still ECHOES THE LITERAL ``HEAD`` ON STDOUT, so
    # an unchecked read stamps ``engine=HEAD`` -- which reads as a deliberate value rather than as a
    # failure, and passes review forever. An empty string would at least have invited a second look.
    rev = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; rev-parse takes no input
        ["git", "-C", str(args.root), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    if rev.returncode != 0:
        sys.stderr.write(
            f"REFUSING: cannot resolve HEAD in {args.root} (exit {rev.returncode}). The engine ref "
            "is part of this measurement, and git echoes the literal 'HEAD' on this failure, so an "
            "unchecked read would stamp engine=HEAD and look deliberate.\n"
        )
        return 3
    head = rev.stdout.strip()

    # THE READER'S OWN DIAGNOSTIC IS ASSESSMENT CONTENT, so this refusal quotes the exception's CLASS
    # and nothing else. Nine of the ten refusals in ``load_scorecard`` open by naming the graded row
    # they rejected and one lists the entire grading vocabulary, so an unguarded call would have
    # printed a graded row's identifier on the first malformed record -- to stderr, which is where a
    # run log and a pasted terminal both come from. That is the enumeration CLAUDE.md section 12 keeps
    # vaulted, arriving by the one path ``--detail`` does not gate. Measured before the guard:
    # ``cell 'ZZ.SENTINEL.9': verdict 'bogus' not one of [...]``, the row and all six grading words.
    #
    # ``except Exception`` IS BROAD ON PURPOSE and the narrower clause is the trap, not the safer
    # option. ``load_scorecard`` subscripts the record directly in a dozen places, so a row missing
    # ``id`` raises KeyError, a non-numeric ``line`` raises ValueError QUOTING THE VALUE, and a
    # document that is not TOML raises from tomllib -- none of which an enumeration written from the
    # ScorecardError raises would have named. A longer list would only be a fresher incomplete one
    # (SDS-3.6), over a record that lives in another repository and is not this module's to enumerate.
    # This wraps ONE call whose only job is turning the record into cells, and there is no second
    # input inside it whose triage would differ.
    #
    # THE CLASS IS ENOUGH, AND WITHHOLDING THE MESSAGE THEREFORE COSTS THE READER NO TRIAGE. It is
    # the whole difference between "the file never became a record" (fix the syntax, the permissions,
    # the path) and "the record parsed and a row is malformed" (fix the row) -- and it carries nothing
    # FROM the record, which the message does. The detail stays where the record lives, readable by
    # the verifier run there. Print the exception any other way -- interpolated, logged, or handed to
    # anything that walks its attributes -- and the disclosure has MOVED rather than closed:
    # ``TOMLDecodeError.doc`` and ``UnicodeDecodeError.args[1]`` each hold the WHOLE document.
    #
    # 3 RATHER THAN 2, and the two are not interchangeable here. This tool's 2 means the invocation
    # is unusable and is decidable from the arguments alone -- it is argparse's own code, shared with
    # three checks that run before any work. The ``is_file`` guard above already passed, a git
    # subprocess has already run, and what failed is the first act of the measurement: the tool
    # started and will not publish a number, which is exactly what 3 says at its other three sites.
    # The counter-argument is real and is recorded rather than suppressed: you cannot fix a malformed
    # record by re-typing the command, which is a property the other 3s do not share.
    #
    # TWO SIBLINGS IN THIS DIRECTORY ANSWER 2 TO THE SAME QUESTION, and they are named here because an
    # argument that dismisses only the far precedent reads as complete while the near ones sit one
    # `ls` away. ``scorecard.py``'s ``_run_status`` returns 2 when the record will not load and its
    # docstring says so; ``prove_report.py`` calls its 2 ``EXIT_INSTRUMENT``. NEITHER BINDS, and for a
    # reason that is checkable rather than stylistic: both define 0/1/2 and NO 3, so 2 is the only
    # refusal code either of them has and their choice carries no information about a vocabulary that
    # has a third. This tool does have one, and it already means "started and will not publish a
    # number" at three other sites. Fusing a malformed record into 2 would merge a caller's mistake
    # with a record defect under a code no poller can split, which is the cost the siblings pay and
    # this tool does not have to.
    #
    # EXIT 1 REMAINS REACHABLE IN THIS FUNCTION AND THAT IS NOT CLOSED HERE. The ``git`` subprocess
    # above raises FileNotFoundError when git is off PATH, and ``--detail``'s ``write_text`` below
    # raises OSError AFTER the summary has printed -- both exit 1, which this contract defines
    # nowhere. Neither carries record content, so neither is this item's disclosure defect; they are
    # recorded at the guard that strengthens the contract rather than left for a reader to discover
    # that the paragraph above describes an invariant the function does not yet hold.
    try:
        cells = load_scorecard(args.scorecard)
    except Exception as exc:
        sys.stderr.write(
            f"REFUSING: the scorecard at {args.scorecard} would not load "
            f"({type(exc).__name__}). The reader's own message is WITHHELD: it CAN name the graded "
            "row it rejected and CAN list the grading vocabulary in full, and this stream reaches a "
            "public log. Read the detail where the record lives, with the verifier there.\n"
        )
        return 3

    verdicts = audit(cells, args.root, args.at)
    if not verdicts:
        sys.stderr.write("REFUSING to report a clean run over zero anchors\n")
        return 3

    # A RUN THAT READ NOTHING IS NOT A CLEAN RUN, AND IT LOOKED EXACTLY LIKE ONE. With every anchor
    # unreadable the summary closed on "NOT verifiable ...: 0" at exit 0, with a REAL sha in the
    # header, because the ref pair resolves fine in a checkout whose history simply lacks the stamped
    # commits -- a shallow clone, a rewritten history, or the wrong sibling checkout.
    unread = sum(1 for v in verdicts if v.verdict in (UNREADABLE, NO_COMMIT))
    if unread == len(verdicts):
        sys.stderr.write(
            f"REFUSING: all {unread} anchors' recorded commits could not be read in {args.root}. "
            "The summary would close on a zero that examined nothing, and the engine ref in the "
            "header resolves either way, so the header cannot tell the two runs apart. Check the "
            "root is the engine checkout and that its history reaches the recorded commits.\n"
        )
        return 3

    # NO NUMBER HERE IS A FACT WITHOUT THE PAIR IT WAS MEASURED AGAINST -- the same rule the scorecard's
    # own verify header states. Printed as part of the measurement, not as decoration.
    print(
        f"# anchor-provenance scorecard={args.scorecard} engine={head[:12]} at={args.at or 'per-cell'}"
    )
    print(summarise(verdicts))

    if args.detail:
        args.detail.write_text(
            json.dumps([v.__dict__ for v in verdicts], indent=1, sort_keys=True), encoding="utf-8"
        )
        print(f"\nper-cell detail written to {args.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
