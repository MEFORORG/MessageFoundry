# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WHICH SECURITY-SCORECARD ANCHORS STOPPED RESOLVING WHEN THE ENGINE CODE MOVED?

BACKLOG #1405. An **anchor** is a citation from one graded requirement to a line of engine code. The
**scorecard** is the record those requirements live in, and it is not tracked in this repository. The
**verifier** (``scorecard.py``) is the instrument that reads the record; a graded row exists whether
or not any job is running.

**Measured 2026-08-31: no workflow in this repository commits or pushes a change to the scorecard.**
Two workflows reference it, and both only as INPUT to the verifier. So there is no writer anywhere in
the merge path, and an anchor breaks silently -- most often **because the code got better and the fix
deleted the line the anchor quoted**. The engine is not less secure when that happens and the record
is not broken; the evidence went stale, and nothing noticed.

**WHAT THIS ADDS THAT ``scorecard.py --root ... --corpus ...`` DID NOT, because the detection itself
was already there.** ``check_anchors`` has always found a token that is GONE or AMBIGUOUS. Three
things stopped it being usable as an engine-side report, and this module fixes those rather than
re-implementing the check:

1. **It names the graded row in every finding.** Cell identifiers paired with file paths enumerate
   what IS covered over a closed requirement set, which hands out what is NOT by subtraction. This
   repository's run logs are public, so that output cannot go in one. See the disclosure rule below.
2. **Verify mode requires a ``--corpus``** and re-runs completeness, pinning and absence checks. Those
   are questions about the RECORD, answered where the record lives. "Did this engine change break a
   citation" is a question about the ENGINE, and it needs no corpus.
3. **It has no notion of a change.** :func:`changed_paths` narrows the population to files a given
   range touched, so a run can say what THIS change broke rather than what is outstanding overall.

**IT REPORTS. IT DOES NOT REWRITE, and that is a constraint rather than an omission.** An anchor that
MOVED and an anchor that was WRONG WHEN WRITTEN need different responses from a human, and a tool
cannot tell them apart -- ``check_anchors`` sets out the four causes of a vanished token at its own
GONE branch, and only two of them are re-anchors. Silently re-pointing one hides the other two.
``anchor_provenance.py`` is the tool that separates moved from born-wrong, and it also proposes
nothing.

**AN EMPTY RESULT FROM A SOURCE THIS COULD NOT READ IS UNKNOWN, NOT ZERO.** A missing scorecard, an
unparseable one, a record carrying no anchors, or a git range that would not resolve are all
:data:`EXIT_INSTRUMENT`. None of them may print "nothing stale": a clean-looking zero off a broken
read is the exact failure this item exists to prevent.

Usage::

    python scripts/asvs/anchor_report.py --scorecard <vault>/docs/security/asvs-scorecard.toml \\
        --root <engine checkout> [--changed-since <ref>] [--strict]
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess  # nosec B404 - fixed argv, no shell; see _git
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# The sibling verifier, imported by PATH rather than as a package: ``scripts/asvs`` has no
# ``__init__.py``, and the vault runs these tools as bare scripts from its own working directory.
# Inserting this file's own directory is what makes ``import scorecard`` resolve there as well as
# here -- the same line, for the same reason, as ``anchor_provenance.py``.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scorecard import (  # noqa: E402
    ANCHOR_AMBIGUOUS,
    ANCHOR_GONE,
    ANCHOR_LOCATED,
    Cell,
    ScorecardError,
    load_scorecard,
    locate_anchor,
)

#: The instrument ran and either found nothing or is in advisory mode.
EXIT_OK = 0
#: Anchors that no longer resolve, under ``--strict`` only. Advisory by default, matching
#: ``prove_report.py``: the finding is about a record this repository cannot edit, so failing an
#: engine pull request on it would block work nobody on that pull request can unblock.
EXIT_FINDINGS = 1
#: The instrument could not measure. NEVER suppressed by advisory mode, and never 0.
EXIT_INSTRUMENT = 2

#: The cited file is not in the engine tree at all. Kept apart from :data:`ANCHOR_GONE` because the
#: two have different first questions -- "was this file moved or deleted" against "was this statement
#: rewritten" -- and merging them costs a reader the answer.
PATH_MISSING = "path_missing"

#: Every outcome that means the citation no longer reaches the code it claims to. ``ambiguous`` is
#: here because a token occurring more than once locates nothing: the anchor cannot fail, so it
#: certifies nothing, which is the reason ``check_anchors`` treats it as fatal rather than as drift.
UNRESOLVED = (PATH_MISSING, ANCHOR_GONE, ANCHOR_AMBIGUOUS)


@dataclass(frozen=True)
class AnchorOutcome:
    """One anchor's result, carrying NO cell identifier -- see the disclosure rule below.

    The omission is structural rather than a filter applied on the way out. A field that exists is a
    field a later edit can print, and every suppression this repository has lost was lost that way.
    """

    path: str
    status: str


#: THE DISCLOSURE RULE, stated once where the type is defined. The ASVS VOCABULARY is public: anchor,
#: scorecard, verifier, stale. The CONTENT is not. A path-to-requirement map enumerates what is
#: covered over a closed domain, so publishing it hands out the gaps by subtraction. This module
#: therefore reports COUNTS and FILE PATHS and never a requirement identifier, a verdict, or a
#: coverage figure -- and there is deliberately no flag to opt back in, because the safe place to read
#: per-row detail is the verifier, run where the record lives.


def audit(cells: list[Cell], root: Path) -> list[AnchorOutcome]:
    """Resolve every anchor against ``root``, using the verifier's own locator.

    ``scorecard.locate_anchor`` is called rather than mirrored. A second definition of "does this
    token resolve" would make any disagreement between this report and the gate a disagreement
    between two matchers instead of a fact about the record, and this repository has already paid for
    that class of defect elsewhere.
    """
    text_cache: dict[Path, str | None] = {}
    out: list[AnchorOutcome] = []
    for cell in cells:
        for anchor in cell.evidence:
            target = root / anchor.path
            if target not in text_cache:
                text_cache[target] = (
                    target.read_text(encoding="utf-8", errors="replace")
                    if target.is_file()
                    else None
                )
            text = text_cache[target]
            if text is None:
                out.append(AnchorOutcome(anchor.path, PATH_MISSING))
                continue
            out.append(AnchorOutcome(anchor.path, locate_anchor(text, anchor.expect).status))
    return out


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    # Read-only git, fixed argv, no shell. Every argument is a ref the caller named or a literal.
    return subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only git
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )


def changed_paths(root: Path, since: str) -> set[str] | None:
    """Repository-relative paths the range ``since...HEAD`` touched, or None when git would not say.

    **None is not an empty set and the caller must not merge them.** An empty set means the range
    resolved and touched nothing; None means the question was never answered. Reporting "no anchors
    in the changed files" off a failed ``git diff`` is the same clean-looking zero this whole module
    exists to refuse, and it is the cheaper mistake to make because the output looks identical.
    """
    proc = _git(root, "diff", "--name-only", f"{since}...HEAD")
    if proc.returncode != 0:
        return None
    return {line.strip().replace("\\", "/") for line in proc.stdout.splitlines() if line.strip()}


def _head(root: Path) -> str:
    # `git rev-parse HEAD` ECHOES THE LITERAL "HEAD" on failure, so an unchecked read stamps a
    # header that reads as a deliberate value. anchor_provenance.py records the same trap.
    proc = _git(root, "rev-parse", "HEAD")
    return proc.stdout.strip() if proc.returncode == 0 else "unresolved"


def summarise(
    outcomes: list[AnchorOutcome],
    *,
    scorecard: Path,
    root: Path,
    changed: set[str] | None,
    since: str | None,
) -> list[str]:
    """The whole report: counts, then the files carrying an anchor that no longer resolves."""
    counts = Counter(o.status for o in outcomes)
    unresolved = [o for o in outcomes if o.status in UNRESOLVED]
    digest = hashlib.sha256(scorecard.read_bytes()).hexdigest()[:16]
    lines = [
        # NO NUMBER HERE IS A FACT WITHOUT THE PAIR IT WAS MEASURED AGAINST. The scorecard is
        # identified by content digest rather than by a ref: it lives in a different repository, so a
        # ref printed here would name a commit the reader cannot resolve from this one.
        f"# asvs-anchor-report scorecard=sha256:{digest} engine={_head(root)[:12]}",
        "ASVS anchor report -- does each citation still reach the code it names?",
        f"  scorecard          : {scorecard}",
        f"  engine root        : {root}",
        f"  anchors examined   : {len(outcomes)}",
        f"  resolving          : {counts.get(ANCHOR_LOCATED, 0)}",
        f"  NOT RESOLVING      : {len(unresolved)}",
        f"    file missing     : {counts.get(PATH_MISSING, 0)} (the cited file is not in this tree)",
        f"    token gone       : {counts.get(ANCHOR_GONE, 0)} (file is here, the quoted text is not)",
        f"    ambiguous        : {counts.get(ANCHOR_AMBIGUOUS, 0)} (occurs more than once, so it "
        "locates nothing)",
    ]

    if since is not None:
        # BOTH TOTALS, ALWAYS. A subset printed alone gets quoted as the whole, and the two differ by
        # every anchor an EARLIER change broke -- which is most of them on a record nothing maintains.
        if changed is None:
            lines.append(
                f"  changed since      : {since} -- GIT WOULD NOT ANSWER, so the narrowing below is "
                "absent rather than empty"
            )
        else:
            hit = sorted({o.path for o in unresolved if o.path in changed})
            lines.append(f"  changed since      : {since} ({len(changed)} path(s) in the range)")
            lines.append(
                f"  NOT RESOLVING in a file THIS range touched : {len(hit)} of "
                f"{len({o.path for o in unresolved})} affected file(s)"
            )

    if unresolved:
        per_file = Counter(o.path for o in unresolved)
        lines.append("")
        lines.append(
            f"files carrying at least one anchor that no longer resolves ({len(per_file)}):"
        )
        # Sorted by count then path so the ordering is stable across runs and reviewable in a diff.
        lines.extend(f"  {n:>3}  {path}" for path, n in sorted(per_file.items(), key=_file_key))
        lines.append("")
        lines.append(
            "REPORTED, NOT REPAIRED. A vanished token has four causes and only two are re-anchors: "
            "it moved, it was renamed, THE GAP IT CERTIFIED WAS CLOSED (retire the anchor), or the "
            "control it named was removed (re-score). Read the row before touching the citation."
        )
    return lines


def _file_key(item: tuple[str, int]) -> tuple[int, str]:
    path, n = item
    return (-n, path)


def _refuse(message: str) -> int:
    sys.stderr.write(f"REFUSING: {message}\n")
    return EXIT_INSTRUMENT


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # REQUIRED, with no default. The record is not in this repository, so a default would name a path
    # here and quietly measure the wrong tree -- or nothing at all -- while printing a full report.
    ap.add_argument(
        "--scorecard",
        type=Path,
        required=True,
        help="the assessment record. It lives in a separate repository; there is no default",
    )
    ap.add_argument(
        "--root", type=Path, required=True, help="the engine checkout the anchors point into"
    )
    ap.add_argument(
        "--changed-since",
        metavar="REF",
        help="also report how many unresolved anchors sit in files REF...HEAD touched",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help=f"exit {EXIT_FINDINGS} when any anchor no longer resolves (default: report only)",
    )
    args = ap.parse_args(argv)

    if not args.scorecard.is_file():
        return _refuse(
            f"no scorecard at {args.scorecard}. This run read nothing, so it is not evidence about "
            "any anchor. It must not print a zero."
        )
    if not args.root.is_dir():
        return _refuse(f"--root {args.root} is not a directory")

    # THE ROOT MUST NOT BE THE TREE THAT STORES THE RECORD. `scorecard.verify` refuses the same
    # pairing for the same reason, and the refusal is repeated rather than referenced because this
    # entry point never reaches that function: anchors resolved against the repository that holds the
    # record are self-consistent and wrong, and the vault carries its own tracked copy of the engine
    # sources for exactly that trap to fall into. Containment, not same-repository -- the sanctioned
    # run has both checkouts in one workspace.
    try:
        if args.scorecard.resolve().is_relative_to(args.root.resolve()):
            return _refuse(
                f"--root {args.root} CONTAINS the scorecard {args.scorecard}, so the anchors would "
                "be resolved against the tree that holds the record instead of the engine. That "
                "produces a self-consistent, wrong answer. Pass the engine checkout as the root."
            )
    except (OSError, ValueError):
        # A path that will not resolve is a question this cannot answer, and an unanswered safety
        # question is not a pass.
        return _refuse(f"could not resolve {args.scorecard} against {args.root} to compare them")

    try:
        cells = load_scorecard(args.scorecard)
    except (ScorecardError, OSError, ValueError) as exc:
        # ValueError covers tomllib.TOMLDecodeError, which subclasses it. A record this could not
        # parse is an instrument failure, never an empty record.
        return _refuse(f"the scorecard at {args.scorecard} could not be read: {exc}")

    outcomes = audit(cells, args.root)
    if not outcomes:
        return _refuse(
            f"the scorecard at {args.scorecard} carries ZERO anchors. A report over an empty "
            "population would close on a reassuring zero that examined nothing."
        )

    changed = changed_paths(args.root, args.changed_since) if args.changed_since else None
    if args.changed_since and changed is None:
        # Reported inside the summary rather than fatal: the anchor population was read successfully,
        # so the main answer stands. Only the narrowing is unavailable, and it says so in its own row.
        sys.stderr.write(
            f"NOTE: git could not resolve {args.changed_since}...HEAD in {args.root}, so the "
            "changed-file narrowing is UNKNOWN rather than empty.\n"
        )

    print(
        "\n".join(
            summarise(
                outcomes,
                scorecard=args.scorecard,
                root=args.root,
                changed=changed,
                since=args.changed_since,
            )
        )
    )

    if any(o.status in UNRESOLVED for o in outcomes) and args.strict:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
