# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

**IT EMITS THE WITNESS AS DATA AND DOES NOT WRITE IT.** ``--annotate`` produces a payload for the ASVS
writer, adding a per-anchor ``never_verified`` table to each anchor the control ref finds was not
verifiable where the record says it was. Landing it belongs to the seat that holds the record; this tool
only derives it. Three properties make the emission safe to hand over:

* ``--control-ref`` is REQUIRED, and is resolved to a sha that every annotation carries. The pre-repair
  ref is part of the measurement -- see the inflation paragraph above -- so a run cannot default to the
  working tree, and the ref cannot survive only in an operator's shell history.
* The payload BODY comes from the LIVE record and only the annotation from the control ref. Copying the
  control record's own cell would write its pre-repair line numbers back, undoing repairs while claiming
  to annotate them. Anchors are matched by ``path`` and ``expect``, never by line, because the line is
  what a repair changes.
* An anchor already carrying the annotation is counted and SKIPPED. A second pass under a different
  control ref would otherwise overwrite the first pass's witness, which is this item's own defect
  arriving through its fix.

Usage::

    python scripts/asvs/anchor_provenance.py --scorecard <vault>/docs/security/asvs-scorecard.toml \\
        --root <engine checkout> [--control-ref <ref>] [--at <ref>] [--detail out.json] \\
        [--annotate payload.json]
"""

from __future__ import annotations

import argparse
import copy
import datetime
import json
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scorecard import (  # noqa: E402
    ANCHOR_AMBIGUOUS,
    ANCHOR_GONE,
    Anchor,
    Cell,
    load_scorecard,
    locate_anchor,
)

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

#: The per-anchor key ``--annotate`` lands the witness under. NAMED FOR THE CLAIM, not for one of its
#: three causes: ``born_wrong`` would be a lie on the two ABSENT verdicts, which are the same claim about
#: the record reached by a different route. The status inside says which route.
#:
#: Nothing in ``scorecard.py`` reads this back, deliberately. It is a witness, not a control -- a key the
#: gate consumed would make the record's own history load-bearing on a gate run, and BACKLOG #1369 is
#: what happens when a writer instruction gets stored as a record field.
ANNOTATION_KEY = "never_verified"


@dataclass(frozen=True)
class AnchorVerdict:
    cell: str
    path: str
    #: THE TOKEN, carried so a verdict can identify its own anchor without the record in hand. Placement
    #: matches on ``path`` plus this and never on the line, because the line is what a repair changes --
    #: matching on it would miss exactly the repaired anchors whose witness is most at risk.
    expect: str
    recorded_line: int
    actual_line: int | None
    verdict: str
    ref: str


def _show(repo: Path, spec: str) -> str | None:
    """``git show <spec>`` as text, or None when git refused it. One caller for two questions.

    Used for engine sources at a stamped commit and for the record itself at a control ref. Those are
    different repositories asking the same thing, and a second copy of this subprocess is a second place
    for the decoding to drift.
    """
    # git is read-only here and every argument is a ref or path the scorecard authored, never a
    # caller-supplied executable.
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only git
        # Explicit UTF-8: ``text=True`` alone decodes with the LOCALE encoding, so a source file
        # carrying any non-ASCII byte would be mangled and its token offsets shifted.
        ["git", "-C", str(repo), "show", spec],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.stdout if proc.returncode == 0 else None


def _blob(root: Path, ref: str, path: str, cache: dict[tuple[str, str], str | None]) -> str | None:
    """File content at a ref, or None when the path does not exist there.

    A MISSING PATH AND AN UNREADABLE REF ARE DIFFERENT ANSWERS and the caller must not merge them: the
    first says the anchor pointed at a file that did not exist yet, the second says the stamp itself
    cannot be resolved. Distinguished by asking git about the ref separately.
    """
    key = (ref, path)
    if key not in cache:
        cache[key] = _show(root, f"{ref}:{path}")
    return cache[key]


def _repo_root(inside: Path) -> Path | None:
    """The git checkout containing a path, or None. The record lives in ITS OWN repository, and the
    control ref is a fact about that one rather than about the engine tree ``--root`` names."""
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only git
        ["git", "-C", str(inside), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
    )
    return Path(proc.stdout.strip()) if proc.returncode == 0 and proc.stdout.strip() else None


def _resolve_commit(repo: Path, ref: str) -> str | None:
    """A ref as a full sha, or None when git cannot resolve it.

    THE SHA IS THE POINT. ``HEAD~1``, a branch or a tag names a different commit next week, so a record
    carrying the NAME carries nothing a later reader can check. Resolving here is what turns a remembered
    control into a recorded one.
    """
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; rev-parse takes no input
        ["git", "-C", str(repo), "rev-parse", f"{ref}^{{commit}}"], capture_output=True, text=True
    )
    return proc.stdout.strip() if proc.returncode == 0 else None


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
    """``scorecard.locate_anchor`` applied to whichever tree the caller opened, then NAMED for here.

    This used to be a hand-copied mirror of ``check_anchors``'s locator, and the copy was deliberate:
    a second, silently different definition of "does this token resolve" would produce a born-wrong
    population that is really a disagreement between two matchers. It now CALLS the one definition
    instead of mirroring it, which is the same intent with the drift removed rather than watched.

    What stays local is the naming. This tool's verdicts answer a different question -- was the line
    right at the commit the cell stamps -- so ``at_line`` and ``born_wrong`` have no counterpart in
    the locator, and the locator must not learn them.
    """
    found = locate_anchor(text, expect)
    if found.status == ANCHOR_GONE:
        return ABSENT, None
    if found.status == ANCHOR_AMBIGUOUS:
        return AMBIGUOUS, None
    return (AT_LINE if found.line == recorded_line else BORN_WRONG), found.line


def _row(
    cell: Cell, anchor: Anchor, verdict: str, ref: str, actual: int | None = None
) -> AnchorVerdict:
    """One verdict, assembled from the cell and the anchor it is about. Six positional fields spelled
    out at four call sites is where the fifth one gets an argument in the wrong slot."""
    return AnchorVerdict(
        cell=cell.id,
        path=anchor.path,
        expect=anchor.expect,
        recorded_line=anchor.line,
        actual_line=actual,
        verdict=verdict,
        ref=ref,
    )


def audit(cells: list[Cell], root: Path, override_ref: str | None = None) -> list[AnchorVerdict]:
    blob_cache: dict[tuple[str, str], str | None] = {}
    ref_cache: dict[str, bool] = {}
    out: list[AnchorVerdict] = []
    for cell in cells:
        ref = override_ref or cell.verified_at
        for anchor in cell.evidence:
            if not ref:
                out.append(_row(cell, anchor, NO_COMMIT, ""))
                continue
            if not _ref_exists(root, ref, ref_cache):
                out.append(_row(cell, anchor, UNREADABLE, ref))
                continue
            text = _blob(root, ref, anchor.path, blob_cache)
            if text is None:
                out.append(_row(cell, anchor, PATH_GONE, ref))
                continue
            verdict, actual = classify(text, anchor.expect, anchor.line)
            out.append(_row(cell, anchor, verdict, ref, actual))
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


def _cells_from(record_text: str, name: str) -> list[Cell]:
    """The record's cells, read by ``load_scorecard`` from whichever TEXT the caller has.

    THE ONE READER, DELIBERATELY. A control-ref run holds the record as a git blob and a live run holds
    it as a file, and a second parser for the blob would be a second definition of what a cell is --
    the same drift ``classify``'s docstring refuses for the anchor locator. A temp copy is the cheap way
    to keep one definition; it is deleted before this returns.
    """
    with tempfile.TemporaryDirectory() as tmp:
        copied = Path(tmp) / name
        copied.write_text(record_text, encoding="utf-8")
        return load_scorecard(copied)


def _repairs_declared(record_text: str) -> int:
    """How many cells in this record declare an anchor repair.

    THE FLOOR CAVEAT, MADE COUNTABLE. Every repair at or before the ref being measured has already
    overwritten its own witness, so what the run finds is what survived them -- "at least", never
    "exactly". A caveat in prose is not the same artifact as a number a reader can compare between two
    refs, and the tool that has the record open is the one that can print it.

    ``anchor_repair`` is a WRITER instruction that persists into the record (BACKLOG #1369), which is
    a defect on its own row and is exactly why it is legible here: nothing else in the record says a
    repair happened.
    """
    return sum(1 for c in tomllib.loads(record_text).get("cell", []) if c.get("anchor_repair"))


@dataclass
class Annotation:
    """What ``--annotate`` did with the never-verified population, counted by outcome.

    Every count is reported. A payload row is only half the answer: the anchors this could NOT annotate
    are the ones whose witness a repair already destroyed, and dropping them would leave a clean-looking
    file over a population it failed to place.
    """

    payload: list[dict[str, Any]] = field(default_factory=list)
    placed: int = 0
    already: int = 0
    cell_gone: int = 0
    anchor_gone: int = 0
    ambiguous: int = 0

    @property
    def found(self) -> int:
        """Anchors the control ref found were not verifiable at their own stamped commit.

        DERIVED, not counted alongside. The per-cell loop puts every such anchor in exactly one of the
        buckets above, so a hand-maintained total is a second bookkeeping site that a later bucket can
        silently drift from -- and the drift would show up as a refusal that fires on the wrong runs.
        """
        return self.placed + self.already + self.cell_gone + self.anchor_gone + self.ambiguous


def _witness(
    v: AnchorVerdict, control_sha: str, engine_head: str, derived_on: str
) -> dict[str, Any]:
    """The annotation for one anchor, self-sufficient by design.

    It carries the ref pair it was derived under rather than pointing at a commit message. The item this
    tool serves exists because a previous population's born-wrong status survived ONLY in a commit
    message, which is a witness nobody can query and the next repair does not touch.

    ``found_line`` is OMITTED rather than nulled on the two ABSENT verdicts. TOML has no null, so a
    placeholder would render as a number or a string and read as a measurement.
    """
    row: dict[str, Any] = {"status": v.verdict, "recorded_line": v.recorded_line}
    if v.actual_line is not None:
        row["found_line"] = v.actual_line
    row["at"] = v.ref
    row["control_scorecard"] = control_sha
    row["engine_head"] = engine_head
    row["derived_on"] = derived_on
    return row


def annotate(
    verdicts: list[AnchorVerdict],
    live_cells: dict[str, dict[str, Any]],
    *,
    control_sha: str,
    engine_head: str,
    derived_on: str,
) -> Annotation:
    """A writer payload that adds the witness to the LIVE record and changes nothing else.

    THE BODY COMES FROM THE LIVE CELL, and the alternative is the trap. Building each row from the
    CONTROL record -- which is where the classification came from -- would carry that record's older
    verdict, residual, stamps and line numbers back into the live file: an annotation pass that silently
    reverts the repairs it is documenting. So the control ref decides WHICH anchors are annotated and the
    live record supplies every byte that gets written.

    Anchors are matched on ``path`` plus ``expect``. A repair changes the LINE, so line-matching would
    fail on exactly the repaired anchors; a re-anchor to a different token is a real loss and is counted
    as one rather than guessed at.
    """
    result = Annotation()
    by_cell: dict[str, list[AnchorVerdict]] = {}
    for v in verdicts:
        if v.verdict in NEVER_VERIFIED:
            by_cell.setdefault(v.cell, []).append(v)

    for cell_id, rows in by_cell.items():
        live = live_cells.get(cell_id)
        if live is None:
            result.cell_gone += len(rows)
            continue
        # Copied, never mutated in place: the caller's parse is also what a later comparison reads.
        cell = copy.deepcopy(live)
        entries: list[dict[str, Any]] = cell.get("evidence") or []
        touched = 0
        for v in rows:
            hits = [
                i
                for i, e in enumerate(entries)
                if (e.get("path"), e.get("expect")) == (v.path, v.expect)
            ]
            if not hits:
                result.anchor_gone += 1
                continue
            if len(hits) > 1:
                result.ambiguous += 1
                continue
            if ANNOTATION_KEY in entries[hits[0]]:
                # A SECOND PASS MUST NOT OVERWRITE THE FIRST PASS'S WITNESS. That is this item's own
                # defect one field over: the earlier annotation may have been derived under an earlier
                # control ref, so replacing it destroys a record of a population that is no longer
                # reachable. Counted so the skip is visible rather than inferred from a short payload.
                result.already += 1
                continue
            entries[hits[0]][ANNOTATION_KEY] = _witness(v, control_sha, engine_head, derived_on)
            touched += 1
        if touched:
            result.payload.append(cell)
            result.placed += touched
    return result


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
        "--control-ref",
        help="derive the population from the record as it stood at this ref of the repository that "
        "HOLDS it, rather than from the working tree. A mass re-anchor inflates the apparent rate, so "
        "the pre-repair ref is part of the measurement. Resolved to a sha and recorded.",
    )
    ap.add_argument(
        "--detail",
        type=Path,
        help="write the per-cell record here. It names cell identifiers beside file paths, which is "
        "the pairing CLAUDE.md section 12 keeps vaulted -- point this INSIDE the vault, never at the "
        "engine tree.",
    )
    ap.add_argument(
        "--annotate",
        type=Path,
        help="write a scorecard-writer payload here, adding the per-anchor witness to the LIVE record "
        "without changing anything else. Requires --control-ref. Names cell identifiers beside file "
        "paths, so point it INSIDE the vault, never at the engine tree. This tool does not apply it.",
    )
    args = ap.parse_args(argv)

    # THE ANNOTATION'S TWO ARGUMENT REFUSALS, before any work, because both are decidable from the
    # arguments alone -- which is what this tool's 2 means.
    if args.annotate and not args.control_ref:
        sys.stderr.write(
            "REFUSING: --annotate needs --control-ref. A repair RAISES the apparent rate (42.0 "
            "percent before one real repair, 60.5 after), so an annotation derived from the working "
            "tree records an inflated population, and a ref remembered in a shell history is not "
            "recorded at all.\n"
        )
        return 2
    if args.annotate and args.at:
        sys.stderr.write(
            "REFUSING: --annotate with --at. --at judges every cell against ONE ref instead of its "
            "own recorded commit, which is the later-tree hypothesis test. Its answers are not claims "
            "about what the record says it verified, so writing one into the record would assert "
            "something the run never measured.\n"
        )
        return 2

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
    #
    # Resolved through the same helper the control ref uses. This was an inline ``rev-parse`` beside a
    # general helper that already did the job, which is how two refusal styles for one question end up
    # in one function -- and the helper is the safer of the two here, because it returns the sha ONLY on
    # a zero exit, so the echoed literal cannot reach a caller at all.
    head = _resolve_commit(args.root, "HEAD") or ""
    if not head:
        sys.stderr.write(
            f"REFUSING: cannot resolve HEAD in {args.root}. The engine ref is part of this "
            "measurement, and git echoes the literal 'HEAD' on this failure, so an unchecked read "
            "would stamp engine=HEAD and look deliberate.\n"
        )
        return 3

    # THE CONTROL REF IS RESOLVED HERE, IN THE REPOSITORY THAT HOLDS THE RECORD -- not the engine tree
    # ``--root`` names. Two repositories are in play and their refs are not interchangeable; reading the
    # record at an ENGINE sha would resolve to nothing or, worse, to some unrelated commit.
    control_sha = ""
    control_text: str | None = None
    if args.control_ref:
        vault = _repo_root(args.scorecard.parent)
        rel = ""
        if vault is not None:
            try:
                rel = args.scorecard.resolve().relative_to(vault.resolve()).as_posix()
            except (OSError, ValueError):
                rel = ""
        if vault is None or not rel:
            sys.stderr.write(
                f"REFUSING: cannot locate {args.scorecard} inside a git repository, so --control-ref "
                "has nothing to resolve against. The control ref is a ref of the repository that "
                "HOLDS the record.\n"
            )
            return 2
        resolved = _resolve_commit(vault, args.control_ref)
        if resolved is None:
            sys.stderr.write(
                f"REFUSING: {args.control_ref!r} does not resolve to a commit in {vault}.\n"
            )
            return 3
        control_sha = resolved
        control_text = _show(vault, f"{control_sha}:{rel}")
        if control_text is None:
            sys.stderr.write(
                f"REFUSING: {rel} does not exist at {control_sha[:12]}. A ref that predates the "
                "record cannot be its control.\n"
            )
            return 3

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
    # THE WITHHOLDING IS UNCONDITIONAL, AND ITS REASON IS DELIBERATELY NOT A CLAIM ABOUT THE
    # DESTINATION. An earlier wording asserted flatly that this stream reaches a public log.
    # Measured 2026-09-01: NO workflow invokes this tool -- .github/ does not mention it, and the
    # only tracked references are two sibling scripts' prose, its own tests and the tooling
    # manifest. That sentence was false while the behaviour it justified was correct, which is the
    # SDS-3.7 shape: a reader who checks the premise finds it false, and the apparent remedy is to
    # stop withholding. The durable reason is that this is a CLI and its stderr goes wherever the
    # caller sends it -- a redirect, a paste, or a future workflow, which the sibling
    # anchor_report.py already has in .github/workflows/asvs-anchor-report.yml.
    #
    # THE READ IS INSIDE THE GUARD TOO, and for the same reason rather than for tidiness: a record that
    # does not decode raises UnicodeDecodeError, whose ``args[1]`` holds the WHOLE document, and an
    # unguarded read would put that on stderr under exit 1 -- a code this contract defines nowhere.
    # ONE read serves both the load and the repair count below, so the two cannot come from different
    # states of a working tree several sessions share.
    try:
        record_text = (
            control_text if control_text is not None else args.scorecard.read_text(encoding="utf-8")
        )
        cells = _cells_from(record_text, args.scorecard.name)
    except Exception as exc:
        where = f" at {control_sha[:12]}" if control_sha else ""
        sys.stderr.write(
            f"REFUSING: the scorecard at {args.scorecard}{where} would not load "
            f"({type(exc).__name__}). The reader's own message is WITHHELD: it CAN name the graded "
            "row it rejected and CAN list the grading vocabulary in full, and nothing here can "
            "know where this stream ends up. Read the detail where the record lives, with the verifier there.\n"
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
    # own verify header states. Printed as part of the measurement, not as decoration. The control ref
    # joins the pair: the same engine history over two states of the record gives two different rates.
    print(
        f"# anchor-provenance scorecard={args.scorecard} "
        f"control={control_sha[:12] or 'working-tree'} engine={head[:12]} "
        f"at={args.at or 'per-cell'}"
    )
    print(summarise(verdicts))
    repairs = _repairs_declared(record_text)
    print(
        f"\ncells in this record declaring an anchor repair: {repairs}. Every repair at or before this "
        "state already overwrote its own witness, so the count above is a FLOOR -- read it as 'at "
        "least'."
    )

    if args.detail:
        args.detail.write_text(
            json.dumps([v.__dict__ for v in verdicts], indent=1, sort_keys=True), encoding="utf-8"
        )
        print(f"\nper-cell detail written to {args.detail}")

    if args.annotate:
        return _write_annotation(args.scorecard, args.annotate, verdicts, control_sha, head)
    return 0


def _write_annotation(
    scorecard: Path,
    destination: Path,
    verdicts: list[AnchorVerdict],
    control_sha: str,
    head: str,
) -> int:
    """Derive the witness under the control ref, place it on the LIVE record, and write the payload.

    Separate from ``main`` because it needs the live record a second time -- the control run read the
    blob, and the payload body must come from the file as it stands now.

    Takes the two paths rather than the parsed arguments: under mypy strict a ``Namespace`` attribute is
    ``Any``, so a mistyped flag name would type-check here and fail at run time.
    """
    try:
        live_cells = {
            str(c["id"]): c
            for c in tomllib.loads(scorecard.read_text(encoding="utf-8")).get("cell", [])
        }
    except Exception as exc:
        # Class only, for the reason the load guard states: a TOML failure can carry the whole document.
        sys.stderr.write(
            f"REFUSING: the LIVE record at {scorecard} would not parse ({type(exc).__name__}), "
            "so there is nothing to annotate. The control ref loaded, so this is the working tree.\n"
        )
        return 3

    result = annotate(
        verdicts,
        live_cells,
        control_sha=control_sha,
        engine_head=head,
        derived_on=datetime.date.today().isoformat(),
    )

    # A POPULATION FOUND AND PLACED NOWHERE MUST NOT BE WRITTEN AS AN EMPTY FILE. An empty payload
    # applies cleanly and reads afterwards as "nothing was ever born wrong", which is the opposite of
    # what the run found. ``already`` is excluded from the trigger on purpose: a run that placed nothing
    # because the record already carries every witness has succeeded, and refusing it would make the
    # second run of a completed pass look like a failure.
    if result.found and not result.placed and not result.already:
        sys.stderr.write(
            f"REFUSING: {result.found} anchor(s) were not verifiable at their own recorded commit and "
            "NONE could be placed on the live record. An empty payload would read as 'nothing was born "
            "wrong'. Check --scorecard names the live record this annotation is for.\n"
        )
        return 3

    destination.write_text(json.dumps(result.payload, indent=1), encoding="utf-8")
    print(
        f"\nannotation written to {destination}: {result.placed} anchor(s) across "
        f"{len(result.payload)} cell(s). Apply it with scripts/asvs/apply.py where the record lives; "
        "this tool does not write the record."
    )
    print(f"  already carried a witness, left alone      {result.already}")
    print(f"  cell no longer in the live record          {result.cell_gone}")
    print(f"  anchor no longer in the live cell          {result.anchor_gone}")
    print(f"  token not unique in the live cell          {result.ambiguous}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
