# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every statement of the write-collision share must name the population it is a share OF.

THE FAILURE THIS EXISTS FOR, and it is measured rather than imagined. One 30-day measurement is
recorded in the table at ``docs/WORKTREE-GATE.md``: 166 sessions ran with their cwd in the shared
primary, 6,075 of *their* Edit/Write calls (44%) landed in that primary's tree, and 4,010 (29%)
landed in a sibling worktree by absolute path. Both data rows are scoped to those sessions, so the
two percentages are TWO NUMERATORS OVER ONE DENOMINATOR -- roughly 13,800 calls -- with the
remaining ~27% landing outside the repository altogether.

On 2026-08-13 that denominator was stated correctly in exactly ONE place in this repository
(``docs/WORKTREES.md``, the 44% sentence) and loosely in fourteen others, including the gate's own
docstring, a string printed to an operator mid-deletion, and this suite. A bare "29% of writes"
does not read as ambiguous -- the reader supplies the wider denominator and is never corrected.

WHY A BAN ON THE LOOSE FORM, not a required spelling. The scope can be carried by an attribution
clause after the figure, by a lead-in sentence before it, or by a possessive. Pinning one wording
would go red on a rewrite that harms no reader. What must never return is the unscoped form.

THREE PROPERTIES ARE LOAD-BEARING, each with the measurement that fixed it:

* WHOLE-FILE, never line-by-line. Two live sites wrapped between ``of`` and its noun, one of them
  ``scripts/hooks/worktree_gate.ps1`` -- the sentence that justified the target-path design. A
  line-oriented scan cannot see either.
* A POSSESSIVE NAMING THE REPO IS REJECTED OUTRIGHT. "29% of *this repo's* Edit/Write calls" does
  not omit a population, it asserts the WRONG one, so no amount of nearby context redeems it. This
  is also the shape that defeated the first version of this pattern, which allowed only "the" and
  "all" as noise and so could not see the single most consequential site.
* THE WINDOW IS SMALL AND LOOKS BOTH WAYS. Both orders occur in this corpus: the population follows
  the figure in the scripts and precedes it in ``docs/WORKTREES.md``. 200 characters covers the
  correctly-scoped site, whose marker sits ~90 characters back. It deliberately does NOT reach the
  table in ``docs/WORKTREE-GATE.md`` from that file's own restatement 794 characters below it -- a
  window wide enough to cover that distance would let any file with the table in it say anything.

WHAT IT CANNOT CATCH, stated because an unstated limit reads as coverage. The noun list is an
allowlist: "44% of edits", "44% of tool calls" and a spelled-out "forty-four percent" are invisible.
So is a PARAPHRASE carrying no digits -- "one write in three" was a real site here and no
percentage-keyed scan will ever see it. Widen the list when a new spelling appears; do not read a
green run as proof that none exists.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]

# "N% of <up to three modifier words> <writes-noun>". \s+ spans the newline a wrapped line puts
# mid-phrase.
#
# THE MODIFIER RUN IS OPEN, NOT AN ALLOWLIST, and that is the whole point. The first version of this
# pattern listed the determiners it expected -- all, the, their, its, this repo's -- and ONE ADJECTIVE
# defeated it: "~29% of this repo's REAL Edit/Write calls", the wording that stood in this suite's own
# sibling until it was corrected, did not match at all. The single wrongest sentence in the repository
# was the one sentence the guard could not see. An allowlist decides in advance which words a defect
# is allowed to contain, which is not a thing anyone can know.
#
# TWO BARS KEEP IT HONEST. `durable` excludes the store-transaction family (ADR 0084 and the cost-model
# tests say "63% of the hub's durable writes" about SQLite transactions, a different subject). `body`
# and `bytes` exclude "77% of the body bytes this message writes", where `writes` is a verb. The
# three-token cap does the rest: five words of noun phrase cannot reach the noun.
#
# The lookbehind stops "49.44%" in the benchmark corpus from being read as a bare "44%".
_SHARE = re.compile(
    r"(?<![\d.])~?\*{0,2}\d+\s*%\*{0,2}\s+of\s+"
    r"(?P<qualifier>(?:(?!durable\b|body\b|bytes\b)[\w'’-]+\s+){0,3})"
    r"(?:file\s+writes|Edit/Write\s+calls|write\s+calls|writes)\b",
    re.IGNORECASE,
)

# A qualifier that names the repository as the denominator. Affirmatively wrong, not merely vague.
_WRONG_POPULATION = re.compile(r"\b(?:this|the)\s+repo's\b", re.IGNORECASE)

# The population marker: a session word AND an anchor tying it to the primary checkout. Both are
# required, so "by other sessions" and a stray mention of the primary each fail on their own.
_SESSIONS = re.compile(r"\bsessions?\b", re.IGNORECASE)
_PRIMARY = re.compile(r"primary|shared\s+checkout|\b166\b", re.IGNORECASE)

_WINDOW = 200

# A closed-record QUOTATION may keep its original wrong denominator -- rewriting archived text
# falsifies it as history -- but only when a correction stands with it. So a `> **CORRECTION`
# blockquote that itself names the population discharges the site, and nothing else does. The
# window is generous because the correction follows the quoted paragraph rather than the figure,
# and the correction must carry the population marker itself, so this cannot be satisfied by an
# unrelated correction that happens to sit nearby.
_CORRECTION = re.compile(r">\s*\*\*CORRECTION\b", re.IGNORECASE)
_CORRECTION_WINDOW = 1500

# Unrelated measurements that merely happen to be a share of something. Benchmarks quote CPU
# percentages in the same shape; they are a different subject and are not in scope here.
_EXEMPT_PREFIXES = ("docs/benchmarks/",)

# This module plants the defective sentences on purpose, in the negative controls below. Named
# explicitly rather than pattern-excluded, so the exemption is one file and cannot quietly grow.
_SELF = "tests/test_write_share_denominator.py"


def _tracked_text_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=_REPO, capture_output=True, check=True
    ).stdout.decode("utf-8", errors="replace")
    return [
        p
        for p in out.split()
        if p != _SELF
        and not p.startswith(_EXEMPT_PREFIXES)
        and not p.lower().endswith((".png", ".jpg", ".gif", ".ico", ".pdf", ".db", ".zip"))
    ]


def _is_scoped(text: str, match: re.Match[str]) -> bool:
    """Does the figure name the population it is a share of?"""
    if match.group("qualifier") and _WRONG_POPULATION.search(match.group("qualifier")):
        return False
    lo = max(0, match.start() - _WINDOW)
    window = " ".join(text[lo : match.end() + _WINDOW].split())
    if _SESSIONS.search(window) and _PRIMARY.search(window):
        return True
    return _has_correction(text, match)


def _has_correction(text: str, match: re.Match[str]) -> bool:
    """Is this an archived quotation whose wrong denominator is corrected in place?"""
    tail = text[match.end() : match.end() + _CORRECTION_WINDOW]
    hit = _CORRECTION.search(tail)
    if hit is None:
        return False
    block = " ".join(tail[hit.start() :].split())
    return bool(_SESSIONS.search(block) and _PRIMARY.search(block))


def _unscoped_sites() -> tuple[list[str], int, int]:
    """Return (offending 'path:line: quote' strings, files scanned, figure sites found)."""
    offenders: list[str] = []
    scanned = 0
    sites = 0
    for rel in _tracked_text_files():
        try:
            text = (_REPO / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        scanned += 1
        for m in _SHARE.finditer(text):
            sites += 1
            if not _is_scoped(text, m):
                line = text.count("\n", 0, m.start()) + 1
                offenders.append(f"{rel}:{line}: {' '.join(m.group(0).split())!r}")
    return offenders, scanned, sites


def test_no_copy_states_the_share_without_naming_its_population() -> None:
    offenders, scanned, sites = _unscoped_sites()
    assert not offenders, (
        f"scanned {scanned} tracked files and found {sites} share-of-writes claims; "
        "these do not name the population the share is OF:\n  " + "\n  ".join(offenders) + "\n"
        "The 44% and the 29% are shares of the Edit/Write calls made by the 166 sessions whose cwd "
        "was the shared primary, NOT of every write in the repo. Name whose writes, or the next "
        "reader supplies a denominator and supplies the wrong one. Counts: docs/WORKTREE-GATE.md."
    )


def test_the_scan_actually_reaches_the_corpus() -> None:
    """A pattern that matches nothing passes everything. Pin that it still finds the real sites."""
    _, scanned, sites = _unscoped_sites()
    assert scanned > 500, f"only {scanned} tracked files scanned; the corpus walk is broken"
    assert sites >= 10, (
        f"only {sites} share-of-writes claims found across the repo. This figure is stated in the "
        "gate docstring, both worktree scripts, this suite's sibling and four docs, so a count in "
        "single digits means the pattern stopped matching rather than that the corpus got cleaner."
    )


def test_the_authoritative_table_is_reachable_and_still_scopes_both_rows() -> None:
    """The whole ban rests on this table. If it moves, the deny text points at nothing."""
    gate_doc = (_REPO / "docs" / "WORKTREE-GATE.md").read_text(encoding="utf-8")
    for needle in ("166", "6,075", "4,010"):
        assert needle in gate_doc, f"docs/WORKTREE-GATE.md no longer states {needle}"
    assert gate_doc.count("| Their Edit/Write calls") == 2, (
        "the two data rows no longer both open with 'Their'. That possessive is the entire "
        "evidence that the 44% and the 29% share one denominator; without it the table stops "
        "settling the question this gate enforces."
    )


@pytest.mark.parametrize(
    "sentence",
    [
        # The store-transaction family: a different subject that shares the surface shape.
        "63% of the hub's durable writes buy no delivered message",
        "`wasted == 32` for the hub -- 63% of its durable writes",
        # `writes` as a VERB, not a noun.
        "the routed rows alone are 20 of the 26 copies: 77% of the body bytes this message writes.",
        # A decimal percentage in the benchmark corpus, which must not read as a bare "44%".
        "delivered 49.44% and slope +115.1",
    ],
)
def test_the_pattern_does_not_fire_on_a_different_subject(sentence: str) -> None:
    """False positives are the expensive failure: a guard that cries wolf gets deleted.

    Widening the modifier run to catch an adjective also widened the reach toward these, so each is
    pinned. If one of them starts matching, the fix is a narrower bar, never an exemption for the
    file it happens to live in.
    """
    assert _SHARE.search(sentence) is None, (
        f"the pattern now fires on {sentence!r}, which is not the write-collision measurement. "
        "Tighten the bars in _SHARE rather than exempting the path."
    )


@pytest.mark.parametrize(
    ("sentence", "scoped"),
    [
        # The historical defects, verbatim in shape.
        ("29% of writes on this repo come from a session elsewhere", False),
        ("Over 30 days, 29% of this repo's Edit/Write calls came from a session", False),
        ("44% of all file writes still landed in the primary's tree", False),
        # An ADJECTIVE inside the modifier run. This exact wording stood in
        # tests/test_worktree_gate.py and the first version of _SHARE could not see it at all.
        ("~29% of this repo's real Edit/Write calls come from a session in the primary", False),
        ("44% of the repo's total file writes landed there", False),
        # Attribution present but naming a DIFFERENT population.
        ("29% of writes by other sessions landed in a sibling", False),
        # A bare CORRECTION marker does not discharge a site; it must state the population.
        ("29% of writes on this repo\n\n> **CORRECTION** the wording above was loose.", False),
        # An archived quotation kept verbatim, with a correction that names the denominator.
        (
            "is 29% of writes on this repo, by the project's own measurement.\n\n"
            "> **CORRECTION 2026-08-13 -- wrong denominator.**\n"
            "> It is a share of the calls made by the 166 sessions whose cwd was the shared primary.",
            True,
        ),
        # The corrected forms actually used in this repository, both orders.
        (
            "29% of the Edit/Write calls made by sessions sitting in the primary wrote elsewhere",
            True,
        ),
        ("29% of the writes made by sessions sitting in the primary land in a sibling", True),
        (
            "166 sessions ran with their cwd in the shared primary, and 44% of all their file "
            "writes landed in the primary's tree",
            True,
        ),
    ],
)
def test_the_pattern_rejects_what_it_exists_to_reject(sentence: str, scoped: bool) -> None:
    """Negative controls. Without these the ban above is a claim about a regex nobody exercised."""
    m = _SHARE.search(sentence)
    assert m is not None, f"the pattern no longer recognises a share-of-writes claim: {sentence!r}"
    assert _is_scoped(sentence, m) is scoped, (
        f"expected scoped={scoped} for {sentence!r}. A pattern broadened until it stops "
        "discriminating is a green that means nothing; one narrowed until it rejects the "
        "corpus's own corrected wording fails the repository it guards."
    )
