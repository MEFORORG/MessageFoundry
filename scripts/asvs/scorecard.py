# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS scorecard as data (ADR 0156) — derive the count, verify the evidence, fail closed.

The score used to live in prose. On 2026-08-01 one re-anchoring session re-derived the headline count
six times, found twelve residuals of record that were false at HEAD (five of them *absence* claims that
had quietly stopped being true), and found ten cells missing from an enumeration that described itself
as "arithmetic-checked and complete". That last one survived because the arithmetic closed to 345 and
closure was read as proof.

**Closure only proves the four buckets sum. It does not prove every cell landed in one.** That is the
whole reason :func:`check_completeness` exists and asserts against the corpus rather than the total.

This module is deliberately data-free: it takes the scorecard and the ASVS corpus as paths, so the
public repo can unit-test it against a fixture while the vault runs it against the real posture data
(ADR 0156 §7). It adds no dependency — ``tomllib`` is stdlib.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import io
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tokenize
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal, get_args

Verdict = Literal["pass", "partial", "fail", "na", "needs-review", "unverified"]

#: What KIND of artifact an evidence anchor resolves INTO. Derived at check time from where the token
#: lands, never authored: it is a property of the landing site, not a judgement about the cell.
#:
#: - ``code``  — a Python file, outside every docstring and ``#`` comment.
#: - ``doc``   — a Python file, inside a docstring (the first statement of a module, class or
#:   function) or inside a ``#`` comment.
#: - ``foreign`` — not a Python file at all: ``.md``, ``.ts``, ``.js``, ``.yml``, ``.toml``, …
#:
#: **``doc`` is a LABEL, never a demotion**, and nothing here consumes it as one. The split is
#: rendered so the record stops presenting every anchor as if it were code evidence; it is
#: deliberately NOT wired into :func:`check_completeness`, into any verdict, or into the exit code.
#:
#: Measured 2026-08-09, vault ``origin/main`` 1a59e4a1's scorecard against engine tree c383eeab —
#: quoted as a (file x ref) pair because a count is a fact about one, and this programme has already
#: produced three wrong-base errors by dropping the qualifier:
#:
#: - 1,980 anchors; 1,979 located; **1,479 code, 233 doc (173 docstring + 60 comment), 267 foreign**
#:   (197 ``.md``, 17 ``.ts``, 16 ``.js``, 13 ``.yml``, 8 ``.toml``, the rest scattered).
#: - So **500 of 1,979 (25.3%) resolve into prose or a non-Python file**, which no structural or
#:   executable scheme reaches, ever.
#: - **17 of 343 evidenced cells carry NO code anchor at all** and rest entirely on documentation,
#:   which for a documentation requirement is the correct ground: 1.4.3, 2.1.2, 3.1.1, 3.5.5, 11.1.1,
#:   12.2.2, 13.1.1-13.1.4, 13.4.3, 14.1.2, 15.1.1, 15.1.2, 15.1.4, 15.2.1, 16.1.1. That figure was
#:   derived here independently and agrees exactly with the 2026-08-09 recut analysis, which is why
#:   the label is stated as a label rather than hedged.
AnchorForm = Literal["code", "doc", "foreign"]

#: Every verdict state, in the order :data:`Verdict` declares them — DERIVED from the type, never
#: retyped beside it. A hand-written second list is how the gate's summary line came to enumerate five
#: states against its own stated total of six-states-worth of cells (BACKLOG #1012): the line printed
#: `pass / partial / fail / na / unverified`, summing to 344 while stating 345, and `needs-review`
#: simply had no landing site. Deriving the enumeration from the type means a seventh verdict added to
#: :data:`Verdict` appears in every rendered breakdown on the same commit, or nothing renders at all.
VERDICT_ORDER: Final[tuple[str, ...]] = get_args(Verdict)

#: The scoring buckets. ``unverified`` is deliberately first-class (ADR 0156 §5): a cell inherited from
#: an earlier assessment and never re-read against the requirement text is NOT a Pass, and conflating
#: the two is what let ~219 unchecked verdicts hide inside a headline.
VERDICTS: Final[frozenset[str]] = frozenset(VERDICT_ORDER)

#: ASVS 5.0 defines only three verdicts — verified, exception, and non-applicable-with-rationale. The
#: strings "partially implemented" and "not implemented" appear nowhere in it, and the one prominent
#: OSS ASVS tool declines to model partial too. Everything here beyond pass/fail/na is OUR extension,
#: defined in docs/ASVS-ASSESSMENT-METHOD.md §1 — an undefined grade is one two assessors apply
#: differently, which is exactly how 11.7.1, 3.7.3 and 5.4.3 each changed verdict in a single day.
LOCAL_EXTENSION_VERDICTS: Final[frozenset[str]] = frozenset(
    {"partial", "needs-review", "unverified"}
)

#: A verdict that has actually been reached. `unverified` and `needs-review` are NOT among them:
#: the first was never re-verified against the requirement text, the second was and was left open on
#: purpose. NOTE the first is re-verification DEBT, not unassessed surface -- the earlier lineage did
#: grade those cells, against the verb as paraphrased in our own scorecards rather than against the
#: pinned text. "Never examined" overstates it and misdescribes the lineage.
DECIDED_VERDICTS: Final[frozenset[str]] = frozenset({"pass", "partial", "fail", "na"})

#: A verdict whose cell has been READ against the requirement text. Not the same set as
#: :data:`DECIDED_VERDICTS`, and the difference is `needs-review`: that cell was examined and then
#: left open on purpose, so it belongs in survey PROGRESS while staying out of the verdict counts.
#:
#: Survey progress used `DECIDED_VERDICTS` until the scorecard acquired its first `needs-review` cell
#: (11.4.4, the V7/V11 baseline sweep). The page then reported "123 of 345 read … 222 have not"
#: directly above its own table saying 221 unverified — two numbers for one quantity, on the page
#: that IS the record. The bug had been latent since the renderer was written: with zero
#: `needs-review` cells the two sets are identical, so no test and no CI run could tell them apart.
EXAMINED_VERDICTS: Final[frozenset[str]] = DECIDED_VERDICTS | {"needs-review"}

#: RETIRED 2026-08-09. There was an ``ANCHOR_WINDOW = 40`` here: a token found within 40 lines of its
#: recorded position passed silently, beyond it the anchor failed. It is gone rather than widened,
#: because measurement showed it could not do the job its docstring claimed.
#:
#: It could not disambiguate. ``check_anchors`` rejects a multi-occurrence token as AMBIGUOUS and
#: ``continue``s BEFORE any window test, so by the time a window could apply the token is unique, and a
#: unique token is located by searching for it. The window's own justification named the
#: ``UPDATE sessions SET revoked_at=`` pair, 19 lines apart — the exact case the uniqueness guard now
#: rejects first.
#:
#: What it actually did was decide, on an arbitrary threshold, which stale line numbers to keep quiet
#: about. Measured on 2026-08-09 against a green record: of 1,980 anchors, 731 (36.9%) resolved ONLY
#: because of the window, median offset 9, p90 30, MAX 39 — one line from the cliff, three days after a
#: re-anchor pass reset the whole distribution by hand-retyping 130 integers. A tolerance that is 37%
#: spent three days after a reset is not a tolerance; it is a decaying budget whose next expiry is one
#: insertion above a hot file away.
#:
#: So the line number left the decision path entirely: uniqueness locates the evidence, and the
#: recorded line is reported output that an advisory corrects. See :func:`check_anchors`.


class ScorecardError(Exception):
    """A defect in the scorecard itself — malformed, incomplete, or contradicting the corpus."""


@dataclass(frozen=True)
class Anchor:
    """A claim that some token exists in the tree, at roughly a known place.

    ``sym`` and ``ctx`` are OPTIONAL and additive. ``None`` means *not asserted*; an empty string means
    *asserted to be nothing* — module level for ``sym``, unnested for ``ctx``. Those are different
    claims and a single ``str`` default would silently merge them, turning every un-backfilled anchor
    into an assertion that it sits at module level and unnested. See :func:`derive_sym_ctx`.
    """

    path: str
    line: int
    expect: str
    #: Enclosing symbol, dotted (``ClassName.method``). ``""`` = module level, ``None`` = not asserted.
    sym: str | None = None
    #: Block-node chain from the symbol inward (``Try.body``, ``Try.body>If.orelse``). ``""`` =
    #: unnested, ``None`` = not asserted.
    ctx: str | None = None


@dataclass(frozen=True)
class Absence:
    """A claim that something does NOT exist, plus the proof the search could have seen it.

    A grep naming the wrong token returns zero and reads exactly like proof — that is how five false
    absence claims survived for weeks. So an absence claim is only admissible with a
    ``positive_control`` that must still match; if the control goes quiet the search has gone blind and
    the claim is void, regardless of what the pattern returns.

    ``mutation`` closes the hole the control does not: it is the realistic REINTRODUCTION this pattern
    claims to exclude, and the pattern must actually fire on it. A whole chapter of claims was once
    authored as prose narrations of shell commands — ``"rg -n 'tar.extractall' -> exit 1 (zero hits)"``
    where the field wanted ``tar\\.extractall\\(``. The field's type is ``str`` and prose is a valid
    ``str``, so the shape permitted it and only a detector caught it. Requiring the pattern to match a
    stated reintroduction makes prose *unwritable* rather than merely detectable.

    Do NOT derive ``mutation`` from ``pattern``. A value generated from the thing it validates
    satisfies the check by construction, which would make this the most authoritative-looking vacuous
    gate in the file — the same defect class it exists to close, arriving through the fix.

    ``mutation_path`` and ``observable`` feed the ``--prove-absences`` mode (:func:`prove_absences`),
    which closes a mode the pattern check cannot see: a ``mutation`` that matches its pattern, whose
    control speaks and whose corpus is quiet, yet **changes nothing observable when applied** — a
    reintroduction raised into a swallowing handler, a field nobody reads, a flag nobody branches on.
    ``re.search(pattern, mutation)`` proves the mutation is *well-formed*; it never proves it *bites*.

    - ``mutation_path`` — the file the reintroduction lands in, relative to ``root``.
    - ``observable`` — the named artifact that must go red when the mutation is applied: a
      ``tests/test_x.py::test_y`` pytest node id. When both fields are set the mode PROVES the claim
      by execution — it runs the observable on a scratch copy of the tree (baseline must be green),
      applies the mutation, and requires the observable to FAIL (and to fail as a test failure, not a
      collection/usage error, which fails closed). When only ``mutation_path`` is set the mode falls
      back to a coarse static backstop.

    Both fields default empty, and their absence means **"not yet proven by execution"** — never
    "proven vacuous". They are opt-in per claim because a live proof spawns a pytest subprocess per
    claim; a claim with neither field is reported as SKIPPED, not failed.

    Honest limits of the proving mode, stated so they are not overclaimed:

    - Application is **append-based**: the mutation text is appended to the scratch target, so it
      breaks a fixture by *redefinition shadowing*. That faithfully reddens a well-formed
      reintroduction in a fixture; it does not reproduce every in-function reintroduction a real claim
      might describe.
    - The static backstop is a **coarse same-file heuristic** — a ``raise`` in the mutation landing
      lexically in a ``try`` whose every handler swallows (bare/``Exception``, log-only body). It
      proves **nothing** in general: it cannot see a swallow in a *caller* rather than at the landing
      site, so it would miss the very cross-file instance that motivated this item. It is a screen,
      not a proof, and must not be written up as one.
    """

    pattern: str
    positive_control: str
    mutation: str
    mutation_path: str = ""
    observable: str = ""


@dataclass(frozen=True)
class Blocker:
    """Why a ``fail`` cannot be closed by our own work, and WHEN that was last actually true.

    A bare ``fail`` cannot distinguish two very different states: one we have not got to, and one no
    amount of correct code can move. Prose in ``residual`` can say which, but prose carries no date,
    so the second kind rots invisibly — the blocking condition is external and can lift without
    anyone noticing. That is not hypothetical here: the ASVS 12.1.5 retirement decision (G19,
    2026-08-11) rested on a DoH probe finding no counterparty publishing an ECHConfig, and at ruling
    time that measurement was three weeks old with **no recorded cadence for re-running it**. The one
    fact that would reverse the decision was going stale with nobody watching.

    So the unblock half is mandatory, not optional. ``unblock_signal`` states what would change in
    the world; ``unblock_probe`` is the executable procedure that detects it; ``checked_on`` is when
    that probe last ran; ``recheck_days`` is how long that answer stays good. Together they make
    staleness a computable property rather than something a reader has to notice.

    **Deliberately NOT a seventh verdict value.** A new verdict would change the denominator and
    every renderer, and every existing count in every document would silently mean something else.
    **Deliberately not ``na`` either:** ASVS 5.0 dropped 4.0's clause that let a documented exclusion
    preserve a compliance claim, so ``na`` buys nothing here and misdescribes what was assessed — the
    requirement applies, it was assessed, and it failed.

    **Honest limit, stated so it is not overclaimed:** overdue blockers are REPORTED, not enforced.
    Making a stale probe red the gate would block unrelated pull requests on a calendar date, which
    buys attention at a cost nobody agreed to. The count is printed by ``--status`` so it is visible
    where humans and CI already look. Promoting it to a hard failure is a one-line change in
    :func:`verify` and a deliberate decision, not an oversight.
    """

    #: Short slug for the external thing that blocks it, e.g. ``cpython-stdlib``, ``no-counterparty``.
    blocked_by: str
    #: Prose: why our own work cannot close it.
    reason: str
    #: The measurement or citation backing ``reason`` — not an assertion.
    evidence: str
    #: What would have to change in the world for this to become closable.
    unblock_signal: str
    #: The executable procedure that detects ``unblock_signal``. A signal nobody can test is a wish.
    unblock_probe: str
    #: ISO date ``unblock_probe`` last ran. This is the field that makes staleness computable.
    checked_on: str
    #: How many days ``checked_on`` stays good before the probe owes a re-run.
    recheck_days: int

    def days_overdue(self, today: datetime.date) -> int:
        """Days past the re-probe deadline; 0 when still current. Never negative."""
        due = datetime.date.fromisoformat(self.checked_on) + datetime.timedelta(
            days=self.recheck_days
        )
        return max(0, (today - due).days)


@dataclass(frozen=True)
class Cell:
    id: str
    level: int
    verdict: Verdict
    residual: str = ""
    posture: str = "single"
    last_verified: str = ""
    verified_at: str = ""
    reviewed_by: str = ""
    #: Owner has closed this cell: it is excluded from surveys, sweeps and rescores, and the loader
    #: refuses it if the verdict has moved off the pin recorded alongside. Modelled on the Cell rather
    #: than left as loose TOML so the renderer can surface it — a closure nobody can see is one a pass
    #: will walk straight past, which is how this cell moved four times in eighteen days.
    decision_closed: bool = False
    decision_closed_on: str = ""
    decision_closed_by: str = ""
    #: Set when this cell's verdict is held down by something outside the project's control. See
    #: :class:`Blocker` — the point of it is the re-probe cadence, not the excuse.
    blocker: Blocker | None = None
    evidence: tuple[Anchor, ...] = ()
    absence: tuple[Absence, ...] = ()

    @property
    def is_inherited(self) -> bool:
        """A verdict carried from an earlier assessment, never re-read against the requirement text."""
        return self.verdict == "unverified" or not self.last_verified


@dataclass
class Findings:
    """What a verification pass found. Empty ``problems`` is the only pass condition."""

    problems: list[str] = field(default_factory=list)
    #: Reported, never fatal. A UNIQUE evidence token that merely MOVED is not a broken claim — see
    #: :func:`check_anchors`. These still print, because letting them accumulate silently is how the
    #: recorded line numbers rot; they just do not red the gate.
    advisories: list[str] = field(default_factory=list)
    #: The SAME advisories, counted by PRODUCER. This list holds five different facts and the summary
    #: line used to divide its LENGTH by an anchor count while calling the result "anchors carrying a
    #: stale line number". Only one producer means that.
    #:
    #: One anchor can contribute THREE (line drift, then a sym mismatch, then a ctx mismatch), and
    #: :func:`prove_absences` contributes a scratch-tree advisory that is not about an anchor at all,
    #: so the ratio was not merely imprecise — it could exceed 100%. Driven with a single well-formed
    #: anchor whose line number was CORRECT, the sentence printed ``2 of 1 anchors (200.0%)``.
    #:
    #: Measured 2026-08-18 against the live record: injecting ONE wrong ``sym`` moved the printed
    #: sentence from 183 to **184 of 2090 anchors carry a stale line number** while 183 still did.
    #: The 184th was a displacement, which is a different fact about a different property, and the
    #: label absorbed it silently.
    #:
    #: **The defect is invisible exactly when the data is clean.** With zero sym/ctx mismatches on the
    #: record the length and the line-drift count coincide, so no test over real data and no green CI
    #: run can tell them apart — the same shape as the anchor denominators, which agree at 2,090 only
    #: while GONE and AMBIGUOUS are both zero. Keys: ``line``, ``sym``, ``ctx``, ``unparseable``,
    #: ``scratch``.
    #:
    #: **Never append to :attr:`advisories` directly — call :meth:`advise`.** The counter and the list
    #: are two records of one event, and the pairing is what the summary divides by. Five call sites
    #: maintaining it by hand is five chances to add a sixth that forgets, which would print a
    #: too-LOW stale count with no error, no traceback and nothing that goes red.
    advisory_kinds: Counter[str] = field(default_factory=Counter)
    checked_anchors: int = 0
    #: The POPULATION of absence claims a pass looked at. Set by BOTH :func:`check_absences` and
    #: :func:`prove_absences` — the two passes read the same population, and without it neither one's
    #: outcome counters can be reconciled against anything. A run that scanned 276 claims and a run
    #: that scanned zero otherwise print counter sets that look equally plausible.
    checked_absences: int = 0
    skipped_anchors: int = 0
    #: Derived :data:`AnchorForm` of every anchor that LOCATED, plus an ``undetermined`` bucket for a
    #: Python file that would not parse or tokenize. Anchors that did not locate (GONE or AMBIGUOUS)
    #: are absent from this counter entirely — there is no landing site to classify — so its total is
    #: ``checked_anchors`` minus those, and the summary prints both numbers rather than either alone.
    anchor_forms: Counter[str] = field(default_factory=Counter)
    #: Anchors carrying a ``sym`` or a ``ctx``, so the summary can say how much of the record the
    #: structural check actually reached. Backfill is Stream D's; until it lands this is small, and a
    #: check that silently covers 3 of 1,980 anchors while printing like a whole-corpus result is the
    #: exact overstatement this pass has been correcting everywhere else.
    checked_sym_ctx: int = 0
    #: Populated only by :func:`prove_absences`. ``proved_absences`` counts claims whose observable
    #: went red under the applied mutation (a live proof); ``static_screened`` counts claims that took
    #: the static backstop (a screen, not a proof); ``skipped_absences`` counts claims carrying no
    #: ``mutation_path`` (nothing to apply).
    #:
    #: **These three do NOT sum to the population, and that is why ``checked_absences`` above must be
    #: printed beside them.** The arithmetic that closes is::
    #:
    #:     checked_absences - proved_absences - static_screened - skipped_absences
    #:         == claims that ended in a problem-only branch
    #:
    #: A PROBLEM-ONLY BRANCH raises a problem and increments no counter at all. There are EIGHT of
    #: them today, in the order :func:`_prove_one` can reach them — a ``mutation_path`` that escapes
    #: the tree, one that is not a file, a mutation that is not valid Python, a mutation that
    #: redefines a symbol with a signature the target does not declare (those two are
    #: :func:`_screen_mutation`, and the reason a refusal is problem-only rather than counted is
    #: argued there), a baseline that is not green, a scratch target that did not restore after the
    #: mutated run, an UNPROVEN mutated-green, and a mutated run that errored rather than failed.
    #:
    #: **The identity does not depend on that eight.** It holds for any number of problem-only
    #: branches, which is what makes it safe to add one; the count is an aid to the reader and the
    #: only thing a new branch falsifies. It is asserted by
    #: ``test_prove_absences_counters_close_against_the_population``, which computes BOTH sides from a
    #: real run rather than checking the left side against a typed-in constant.
    #:
    #: Note that ``len(problems)`` is NOT the right-hand side: a SUSPECT finding rides along with a
    #: claim already counted in ``static_screened``, so problems and claims are different populations.
    proved_absences: int = 0
    static_screened: int = 0
    skipped_absences: int = 0

    def advise(self, kind: str, message: str) -> None:
        """Record an advisory AND what produced it, in one act that cannot half-happen.

        The list and the counter are two records of one event. Appending to one by hand and
        incrementing the other by hand is a pairing maintained by discipline, and the failure is
        silent in the direction that matters: an untagged advisory still prints its own DRIFT line,
        so the run looks complete while the summary divides by a numerator that is too low.
        """
        self.advisory_kinds[kind] += 1
        self.advisories.append(message)

    @property
    def located_anchors(self) -> int:
        """Anchors that resolved to a landing site, so they COULD carry a line-drift advisory.

        Single-sourced because it is printed twice on two streams — :func:`form_summary` says
        "anchor(s) that located" on stdout, the stale-line sentence divides by it on stderr. Derived
        twice, a future bucket in :attr:`anchor_forms` that is not a located anchor moves one of them
        and not the other, both stay self-consistent, and nothing compares them. That is the shape
        this whole change exists to close, so it must not be reintroduced one level up.
        """
        return self.anchor_forms.total()

    @property
    def ok(self) -> bool:
        return not self.problems


def corpus_digest(path: Path) -> str:
    """SHA-256 of the corpus file, so the pin is checkable rather than asserted.

    The corpus MUST come from the tagged ``v5.0.0_release`` asset. ``master`` is the bleeding-edge
    branch and a rolling "latest" release republishes identical filenames, so an unpinned fetch moves
    versions silently. Our first corpus was fetched from ``master`` and happened to be byte-identical
    to the release — luck, not method, which is why this is now recorded and verified.
    """
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_corpus(path: Path) -> dict[str, int]:
    """Map ``req_id`` (V-stripped) to level, from the OWASP ASVS 5.0.0 flat JSON.

    The corpus is the external anchor. Before it was held, every verdict in this project reasoned from
    the requirement verb *as paraphrased in our own scorecards* — a closed loop that produced a cell
    scored against a requirement ASVS had deleted.
    """
    import json

    if not path.is_file():
        raise ScorecardError(
            f"ASVS corpus not found at {path} — cannot check completeness without it"
        )
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    reqs = raw["requirements"] if isinstance(raw, dict) else raw
    return {str(r["req_id"]).lstrip("V"): int(r["L"]) for r in reqs}


def load_scorecard(path: Path) -> list[Cell]:
    if not path.is_file():
        # Fail closed, never skip (ADR 0156 §6). Skipping is exactly what the doc-drift guards do
        # today, and it is why a green CI proves nothing about these documents.
        raise ScorecardError(
            f"scorecard not found at {path} — refusing to report a pass on a missing file"
        )
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    cells: list[Cell] = []
    for raw in data.get("cell", []):
        verdict = str(raw.get("verdict", "")).lower()
        if verdict not in VERDICTS:
            raise ScorecardError(
                f"cell {raw.get('id')!r}: verdict {verdict!r} not one of {sorted(VERDICTS)}"
            )
        # ASVS 5.0's assessment chapter is "should" throughout with exactly ONE "must": a
        # non-applicable requirement must be noted with its reason. So an `na` without a rationale is
        # not a lax entry — it is the single thing the standard actually requires, omitted.
        if verdict == "na" and not str(raw.get("residual", "")).strip():
            raise ScorecardError(
                f"cell {raw.get('id')!r}: verdict 'na' requires a written rationale in `residual` — "
                "recording the reason for non-applicability is the one MUST in ASVS 5.0's assessment "
                "chapter (docs/ASVS-ASSESSMENT-METHOD.md §1)"
            )
        # A cell the OWNER has closed is not re-scorable by a survey, sweep or agent. The stop was
        # written in prose first and prose is not a gate: the reason this cell needed closing at all
        # is that four different passes each believed they were doing careful work, and a rationale
        # they could read was never what stopped them. `decision_closed_verdict` pins the verdict as
        # of the ruling, so a later verdict change is DETECTABLE rather than merely discouraged.
        #
        # Deliberately not a warning. The cost of a false stop is one conversation with the owner; the
        # cost of a silent re-score is a posture document that disagrees with the record and is
        # discovered months later by a reader — which has already happened here, four times in
        # eighteen days on the one cell this rule was written for.
        if raw.get("decision_closed") is True:
            pinned = str(raw.get("decision_closed_verdict", "")).lower()
            if not pinned:
                raise ScorecardError(
                    f"cell {raw.get('id')!r}: `decision_closed = true` without "
                    "`decision_closed_verdict` — the pin is what makes the closure checkable, so a "
                    "closure without one is a comment, not a control"
                )
            if verdict != pinned:
                raise ScorecardError(
                    f"cell {raw.get('id')!r}: verdict is {verdict!r} but this cell is CLOSED at "
                    f"{pinned!r} (`decision_closed = true`, closed "
                    f"{raw.get('decision_closed_on', 'date not recorded')} by "
                    f"{raw.get('decision_closed_by', 'owner')}). Re-scoring a closed cell needs an "
                    "explicit owner instruction — not a sweep's own judgement. If you hold one, move "
                    "the pin in the SAME commit and say so in the message; if you do not, revert the "
                    "verdict. See `decision_reopen_requires` on the cell"
                )
        for a in raw.get("absence", []):
            if not str(a.get("mutation", "")).strip():
                raise ScorecardError(
                    # NO LITERAL CODE EXAMPLE HERE. This module is inside the corpus that absence
                    # patterns are searched over, so an illustrative call in this string becomes a
                    # real corpus hit and reads as FALSE. The first draft used one and broke two
                    # live claims (5.2.5, 5.3.3) the moment they were backfilled: the guidance for
                    # a check contaminated the check. The Absence docstring carries the example in
                    # escaped-regex form, which cannot self-match.
                    f"cell {raw.get('id')!r}: absence claim {a.get('pattern')!r} has no `mutation` — "
                    "state the realistic reintroduction this pattern excludes, so the pattern can "
                    "be proved capable of firing. Author it from what the code would look like if "
                    "the thing came back; do NOT derive it from the pattern, which makes the check "
                    "vacuous. See the Absence docstring for a worked example"
                )
        # A blocker record is admissible ONLY as a complete set. A partial one -- a reason with no
        # probe, or a probe with no date -- reads as diligence and carries none: it is exactly the
        # "compensating control resting on a false premise" shape, arriving through the fix. So every
        # field is required, and the two computable ones are type-checked here rather than at the
        # point of use, where a bad value would surface as a traceback in a renderer.
        blocker: Blocker | None = None
        if (rb := raw.get("blocker")) is not None:
            if verdict != "fail":
                raise ScorecardError(
                    f"cell {raw.get('id')!r}: a `blocker` is only meaningful on verdict 'fail' (got "
                    f"{verdict!r}). A blocked PARTIAL is a real thing, but admitting one here needs "
                    "its own ruling -- widening this is a decision, not a default"
                )
            missing = [
                k
                for k in (
                    "blocked_by",
                    "reason",
                    "evidence",
                    "unblock_signal",
                    "unblock_probe",
                    "checked_on",
                    "recheck_days",
                )
                if not str(rb.get(k, "")).strip()
            ]
            if missing:
                raise ScorecardError(
                    f"cell {raw.get('id')!r}: `blocker` is missing {missing} -- a partial blocker "
                    "record is a comment, not a control. The unblock half is the whole point: a "
                    "signal nobody can probe, or a probe with no date, cannot go stale visibly"
                )
            try:
                datetime.date.fromisoformat(str(rb["checked_on"]))
            except ValueError as exc:
                raise ScorecardError(
                    f"cell {raw.get('id')!r}: `blocker.checked_on` must be an ISO date "
                    f"(YYYY-MM-DD), got {rb['checked_on']!r}"
                ) from exc
            if int(rb["recheck_days"]) < 1:
                raise ScorecardError(
                    f"cell {raw.get('id')!r}: `blocker.recheck_days` must be >= 1; a cadence of "
                    "zero or less never comes due, which is the same as having none"
                )
            blocker = Blocker(
                blocked_by=str(rb["blocked_by"]),
                reason=str(rb["reason"]),
                evidence=str(rb["evidence"]),
                unblock_signal=str(rb["unblock_signal"]),
                unblock_probe=str(rb["unblock_probe"]),
                checked_on=str(rb["checked_on"]),
                recheck_days=int(rb["recheck_days"]),
            )
        cells.append(
            Cell(
                id=str(raw["id"]),
                level=int(raw["level"]),
                verdict=verdict,  # type: ignore[arg-type]
                blocker=blocker,
                residual=str(raw.get("residual", "")),
                posture=str(raw.get("posture", "single")),
                decision_closed=raw.get("decision_closed") is True,
                decision_closed_on=str(raw.get("decision_closed_on", "")),
                decision_closed_by=str(raw.get("decision_closed_by", "")),
                last_verified=str(raw.get("last_verified", "")),
                verified_at=str(raw.get("verified_at", "")),
                reviewed_by=str(raw.get("reviewed_by", "")),
                evidence=tuple(
                    Anchor(
                        path=str(e["path"]),
                        line=int(e["line"]),
                        expect=str(e["expect"]),
                        # `.get(...)` WITHOUT a "" default, deliberately: absent must stay None. An
                        # empty string is the assertion "module level" / "unnested", so defaulting to
                        # it would turn all 1,980 un-backfilled anchors into that claim overnight and
                        # light up every anchor that is legitimately inside a function.
                        sym=None if e.get("sym") is None else str(e["sym"]),
                        ctx=None if e.get("ctx") is None else str(e["ctx"]),
                    )
                    for e in raw.get("evidence", [])
                ),
                absence=tuple(
                    Absence(
                        pattern=str(a["pattern"]),
                        positive_control=str(a["positive_control"]),
                        # No default. A missing mutation must be authored, not inferred — see the
                        # Absence docstring on why deriving one from the pattern is worse than none.
                        mutation=str(a["mutation"]),
                        # Optional, and deliberately NOT refused at load. A hard requirement here would
                        # void every already-authored absence claim (none carry these yet), and their
                        # re-authoring is out of this script's reach (ADR 0156 §7). Absent means "not
                        # yet proven by execution", surfaced by --prove-absences, not "proven vacuous".
                        mutation_path=str(a.get("mutation_path", "")),
                        observable=str(a.get("observable", "")),
                    )
                    for a in raw.get("absence", [])
                ),
            )
        )
    return cells


def count(cells: list[Cell]) -> Counter[str]:
    """The count is COMPUTED. No document states one; documents render this (ADR 0156 §2)."""
    return Counter(c.verdict for c in cells)


def verdict_breakdown(cells: list[Cell]) -> tuple[list[tuple[str, int]], int]:
    """Every verdict state with its count, plus the total those counts must close to.

    **The one place a rendered distribution is assembled**, because two places is how the gate's
    summary and ``--status`` came to disagree: the summary enumerated five states (BACKLOG #1012) and
    ``--status`` six, over the same population, in the same module. Both now call this.

    The reconciliation is not decorative and it is not an ``assert`` (which ``-O`` deletes): the
    components come from a :class:`Counter` keyed on whatever verdict each cell CARRIES, the total
    comes from ``len(cells)``, and they are therefore two independent readings of one population. A
    cell whose verdict is outside :data:`VERDICT_ORDER` lands in neither component and the totals
    part, which is exactly the shape #1012 describes — a state present in the data with no landing
    site in the enumeration. :func:`load_scorecard` refuses such a verdict on the way in, so this is a
    second fence behind the first, and it is the fence that survives the enumeration being edited.
    """
    n = count(cells)
    parts = [(v, n[v]) for v in VERDICT_ORDER]
    total = len(cells)
    rendered = sum(c for _, c in parts)
    if rendered != total:
        unplaced = sorted(set(n) - set(VERDICT_ORDER))
        raise ScorecardError(
            f"verdict breakdown does not reconcile: the states enumerated sum to {rendered} but "
            f"there are {total} cells. {len(unplaced)} verdict(s) have no landing site in "
            f"VERDICT_ORDER: {', '.join(unplaced) or '<none — the arithmetic itself is wrong>'}. "
            "Refusing to print a distribution that cannot be reconciled against its own total."
        )
    return parts, total


def check_completeness(cells: list[Cell], corpus: dict[str, int]) -> list[str]:
    """Every corpus id appears exactly once, and nothing outside the corpus appears at all.

    **This is the check whose absence cost ten cells.** An enumeration that closes to the right total
    can still be missing entries; only comparing against the corpus detects that.
    """
    problems: list[str] = []
    seen = Counter(c.id for c in cells)

    for dupe, n in sorted((i, n) for i, n in seen.items() if n > 1):
        problems.append(
            f"completeness: {dupe} appears {n} times — each requirement gets exactly one cell"
        )

    missing = sorted(set(corpus) - set(seen), key=_sort_key)
    if missing:
        problems.append(
            f"completeness: {len(missing)} requirement(s) in the ASVS corpus have NO cell — "
            f"the count cannot be correct while a cell is absent: {', '.join(missing)}"
        )

    unknown = sorted(set(seen) - set(corpus), key=_sort_key)
    if unknown:
        problems.append(
            f"completeness: {len(unknown)} cell(s) are not ASVS 5.0.0 requirement ids "
            f"(retired in 5.0, or a typo): {', '.join(unknown)}"
        )

    for c in cells:
        want = corpus.get(c.id)
        if want is not None and c.level != want:
            problems.append(f"{c.id}: level {c.level} but the corpus says L{want}")

    # A DECIDED verdict with no evidence at all is the conflation this whole tool exists to prevent:
    # a guess wearing a verdict's clothes. The method is explicit — every non-`unverified` cell carries
    # at least one anchor — but nothing enforced it, because `check_anchors` iterates the evidence a
    # cell HAS. A cell with none is not checked and fails nothing; the gate could only ever validate
    # evidence that existed, never assert that it must. Measured when this landed: 14 of 59 decided
    # cells carried zero anchors AND zero absence claims, several inherited from the prose lineage
    # where the verdict was reached but never anchored.
    unevidenced = sorted(
        (c.id for c in cells if c.verdict in DECIDED_VERDICTS and not c.evidence and not c.absence),
        key=_sort_key,
    )
    if unevidenced:
        problems.append(
            f"evidence: {len(unevidenced)} decided cell(s) carry NO anchor and NO absence claim, so "
            "nothing about them is verified — either anchor them or return them to `unverified`, "
            f"which is what an unevidenced verdict actually is: {', '.join(unevidenced)}"
        )
    return problems


#: Suffixes this module will submit to Python structural analysis. Everything else is ``foreign`` by
#: construction — no `ast` and no `tokenize` reaches a `.md`, `.ts`, `.yml` or `.toml` file, ever.
PYTHON_SUFFIXES: Final[frozenset[str]] = frozenset({".py", ".pyi"})


def _prose_spans(text: str) -> list[tuple[int, int]] | None:
    """Character-offset spans of the docstrings and ``#`` comments in one Python source.

    ``None`` means the source could not be analysed — it does not parse, or does not tokenize. The
    caller must report that as UNDETERMINED rather than defaulting, because the default that feels
    natural is ``code`` and it would silently inflate the one number this split exists to deflate.

    **A docstring is identified STRUCTURALLY — the first statement of a module, class or function, via
    ``ast`` — and never by looking at the string's contents.** That is the whole design, and the
    alternative was measured and rejected: a token mask ("does this text look like code?") misfiles the
    Content-Security-Policy fragments in ``messagefoundry_webconsole/_security.py`` and the entire SQL
    Server and Postgres DDL as prose. Those are long, quoted, space-separated strings that read as
    English to a mask while being the literal subject of the control their cell cites. Position cannot
    make that mistake, and not because it is a better mask — because it never asks the question. A
    string that is not the first statement of a scope is not a docstring, whatever it reads like.

    Comments come from ``tokenize`` rather than a ``#`` scan, so a ``#`` inside a string literal is
    not mistaken for one — which the CSP and URL fragments in the live record depend on.
    """
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)

    def offset(row: int, col: int) -> int:
        return line_starts[row - 1] + col

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    # Row pairs, not character columns: `ast` reports `col_offset` as a UTF-8 BYTE offset, which
    # disagrees with the character offsets everything else here uses the moment a line holds a
    # non-ASCII character. So `ast` is asked only WHICH string is a docstring, and `tokenize` — whose
    # columns are characters — supplies the span.
    doc_rows: set[tuple[int, int]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.body:
            continue
        first = node.body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
            and first.end_lineno is not None
        ):
            doc_rows.add((first.lineno, first.end_lineno))

    spans: list[tuple[int, int]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT or (
                tok.type == tokenize.STRING and (tok.start[0], tok.end[0]) in doc_rows
            ):
                spans.append((offset(*tok.start), offset(*tok.end)))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return None
    return spans


def _form_from_spans(
    path: str, spans: list[tuple[int, int]] | None, start: int
) -> AnchorForm | None:
    """Classify one landing site against pre-computed spans (see :func:`anchor_form`)."""
    if Path(path).suffix not in PYTHON_SUFFIXES:
        return "foreign"
    if spans is None:
        return None
    # The token's START decides, not any overlap. An `expect` that begins in code and runs into a
    # trailing lint-suppression comment is code; the OVERLAP rule calls it doc and reclassified 57 of
    # 1,712 live Python anchors that way when both were measured on 2026-08-09. (The suppression
    # directive is named in words, not written literally: ruff parses one in any comment, and this
    # module is also inside the corpus that absence patterns grep over.)
    return "doc" if any(lo <= start < hi for lo, hi in spans) else "code"


def anchor_form(path: str, text: str, start: int) -> AnchorForm | None:
    """The derived ``form`` of one anchor: where does its token actually land?

    ``path`` is the anchor's repo-relative path, ``text`` the file's contents as the anchor check read
    them, ``start`` the character offset of the match. ``None`` means undetermined — a Python file
    that would not parse — and is never silently folded into ``code``.

    This answers a question the record has been getting wrong by omission: **a quarter of its anchors
    resolve into prose or a non-Python file, and no structural or executable check reaches any of them,
    ever.** The record presented all of them as code evidence. Naming the form does not change a single
    verdict and must not: see :data:`AnchorForm` for the measurement and for why ``doc`` is a label
    rather than a demotion.
    """
    if Path(path).suffix not in PYTHON_SUFFIXES:
        return "foreign"
    return _form_from_spans(path, _prose_spans(text), start)


# --- sym + ctx: WHERE in the file's structure the token sits ---------------------------------------

#: The block-bearing fields of every statement that can nest another, and **the single source of truth
#: for both derivation and validation.** A `ctx` value is well-formed exactly when every element names
#: a key here and one of its fields, so a typo cannot produce a chain that silently never matches.
#: One table, two consumers — the alternative is a validator and a deriver that disagree, which is the
#: same defect shape as a gate whose check and whose error message were written separately.
_BLOCK_FIELDS: Final[dict[str, tuple[str, ...]]] = {
    "Try": ("body", "handlers", "orelse", "finalbody"),
    "TryStar": ("body", "handlers", "orelse", "finalbody"),
    "If": ("body", "orelse"),
    "For": ("body", "orelse"),
    "AsyncFor": ("body", "orelse"),
    "While": ("body", "orelse"),
    "With": ("body",),
    "AsyncWith": ("body",),
    "Match": ("cases",),
}

#: Nodes that nest a statement but are never reached by a name of their own: an ``ExceptHandler``
#: comes only via ``Try.handlers``, a ``match_case`` only via ``Match.cases``.
#:
#: **Kept separate from :data:`_TRANSPARENT` on purpose, and the separation was earned by a failed
#: injection.** "Can the walk descend into this?" and "does it contribute a chain element?" are two
#: questions, and a first cut answered both from one set. That made the second one UNTESTABLE:
#: deleting ``ExceptHandler`` from the transparent set silently stopped the walk DESCENDING rather
#: than starting to RECORD, the chain came out identical by a different route, and an injection that
#: should have reddened a test changed nothing observable. Two tables, two behaviours, both drivable.
_DESCEND_ONLY: Final[dict[str, tuple[str, ...]]] = {
    "ExceptHandler": ("body",),
    "match_case": ("body",),
}

#: Nodes descended through WITHOUT contributing an element — recording them would double every
#: handler chain (``Try.handlers>ExceptHandler.body``) for no added discrimination. Must name every
#: key of :data:`_DESCEND_ONLY`; a test asserts that, because the two are independent by design and
#: nothing else would notice them drifting apart.
_TRANSPARENT: Final[frozenset[str]] = frozenset({"ExceptHandler", "match_case"})

#: Nodes that OPEN A SYMBOL: they contribute a name to ``sym`` and RESET ``ctx``, because a block
#: chain is meaningful only within the symbol that contains it.
_SCOPE_NODES: Final = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

_SYM_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z_]\w*(\.[A-Za-z_]\w*)*")


def _block_fields(node: ast.AST) -> tuple[str, ...]:
    """Which fields the walk may descend into. DESCENT ONLY — whether the step is recorded is
    :data:`_TRANSPARENT`'s question, asked separately in :func:`sym_ctx_at`."""
    if isinstance(node, (ast.Module, *_SCOPE_NODES)):
        return ("body",)
    name = type(node).__name__
    return _BLOCK_FIELDS.get(name) or _DESCEND_ONLY.get(name, ())


def _next_block(node: ast.AST, line: int) -> tuple[str, ast.AST] | None:
    """The (field, child) one level in that contains `line`, or ``None`` at the innermost node."""
    for fieldname in _block_fields(node):
        for child in getattr(node, fieldname, None) or []:
            lo = getattr(child, "lineno", None)
            hi = getattr(child, "end_lineno", None)
            if lo is not None and hi is not None and lo <= line <= hi:
                return fieldname, child
    return None


def derive_sym_ctx(text: str, line: int) -> tuple[str, str] | None:
    """The enclosing symbol and block chain at `line`. ``None`` when the source will not parse.

    ``sym`` is dotted and outermost-first (``SqlServerStore.route_handoff``), ``""`` at module level.
    ``ctx`` is the chain of block statements between the symbol and the line, joined by ``>``
    (``Try.body``, ``Try.body>If.orelse``), ``""`` when unnested.

    **``ctx``, NOT raw indentation, and the difference is the whole reason this field is shaped this
    way.** Cell 12.3.5 carries the identical 4-versus-8 indent mismatch as 10.5.4 and is a non-event —
    a hand-trimming slip, with ``ctx`` unchanged at both ends. Indentation flags it and would have to
    be triaged; ``ctx`` correctly does not fire, because nothing about the statement's position in the
    control flow changed. An indentation check would have spent a person's attention on a whitespace
    edit while claiming to be a structural signal.

    Containment is decided by LINE, so a one-line compound (``if x: y = 1``) attributes the line to the
    ``If`` rather than to the assignment inside it. `ast` reports ``col_offset`` as a UTF-8 BYTE offset,
    which disagrees with the character offsets the rest of this module uses the moment a line holds a
    non-ASCII character; line granularity has no such failure mode and every real anchor is a statement
    on its own line.

    **For a multi-line ``expect`` the line is the token's FIRST line**, matching what the drift
    advisory reports. Any backfill must derive at the same line or the 42 multi-line tokens in the
    record will mismatch by construction — not because anything moved, but because the two ends
    measured different lines.
    """
    tree = parse_or_none(text)
    return None if tree is None else sym_ctx_at(tree, line)


def parse_or_none(text: str) -> ast.Module | None:
    """``ast.parse`` that reports failure as a value. Callers must surface it, never default it."""
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def sym_ctx_at(tree: ast.Module, line: int) -> tuple[str, str]:
    """The symbol/chain walk itself, split from parsing so a file is parsed once per run and not
    once per anchor — ``settings.py`` alone carries 218 anchors."""
    sym: list[str] = []
    ctx: list[str] = []
    node: ast.AST = tree
    while True:
        step = _next_block(node, line)
        if step is None:
            break
        fieldname, child = step
        name = type(node).__name__
        if not isinstance(node, (ast.Module, *_SCOPE_NODES)) and name not in _TRANSPARENT:
            ctx.append(f"{name}.{fieldname}")
        if isinstance(child, _SCOPE_NODES):
            sym.append(child.name)
            ctx.clear()  # a block chain is meaningful only INSIDE the symbol that holds it
        node = child
    return ".".join(sym), ">".join(ctx)


def malformed_sym_ctx(sym: str | None, ctx: str | None) -> str | None:
    """Why these values could never match anything, or ``None`` if they are well-formed.

    Well-formedness is checked against :data:`_BLOCK_FIELDS`, the same table the deriver walks, so a
    chain that is accepted here is one the deriver can actually produce. This is the only part of the
    sym/ctx feature that is FATAL rather than advisory, and the reason is that it is a defect in the
    RECORD rather than a fact about the code: no amount of engine movement can cause it, the fix is
    unambiguous, and an unmatchable chain otherwise sits there advising forever.
    """
    if sym is not None and sym and not _SYM_RE.fullmatch(sym):
        return f"sym {sym!r} is not a dotted Python identifier path"
    if ctx is None or not ctx:
        return None
    for element in ctx.split(">"):
        node, _, fieldname = element.partition(".")
        if node not in _BLOCK_FIELDS:
            return (
                f"ctx element {element!r} names {node!r}, which is not a block statement this "
                f"deriver can produce (known: {', '.join(sorted(_BLOCK_FIELDS))})"
            )
        if fieldname not in _BLOCK_FIELDS[node]:
            return (
                f"ctx element {element!r} names field {fieldname!r}, which {node} does not have "
                f"(known: {', '.join(_BLOCK_FIELDS[node])})"
            )
    return None


def check_anchors(cells: list[Cell], root: Path, findings: Findings) -> None:
    """Open every evidence anchor and assert its token still resolves, and resolves UNAMBIGUOUSLY.

    **Two outcomes, and they are not the same event.** A token that is GONE or AMBIGUOUS reds the gate:
    the claim it supported may now be false, or cannot be checked. A token that is unique and present
    but sits at a different line is an ADVISORY: the evidence is exactly where searching for it says it
    is, and only the recorded number is stale. Conflating the two is what made this gate red every
    morning for a reason nobody had to act on — and a gate in that state is one whose next real finding
    gets waved through. There was one underneath: a cell asserting a control was absent that had since
    been built.

    **Uniqueness is not pedantry; it is the whole locator.** An ``expect`` that occurs many times in its
    file resolves from almost anywhere: with ``await conn.rollback()`` appearing 101 times in one
    module, any line in that file sits near some occurrence, so the anchor cannot fail and certifies
    nothing. Two such anchors sat in this scorecard as evidence for weeks. Because uniqueness now does
    the locating alone, it is the strictest rule here.

    It also closes a defect in the REPAIR path rather than the detection path. A re-anchor to the
    nearest occurrence can silently install a *stale-but-resolving* anchor that passes forever. That
    happened live: after ADR 0154 landed, ``UPDATE sessions SET revoked_at=`` had two occurrences 19
    lines apart — one the keep-N revoke, one a different method entirely — and a positional check would
    have accepted the wrong one. A repair is exactly where suspicion lapses, because the tool has just
    proved it works. Rejecting the ambiguity outright is what makes the repair safe.

    **What this still cannot see, stated so nobody reads more into a green than is there.** ``expect``
    is matched as a substring of the file, so a statement that moves into a ``try``, into a different
    function, or under a different condition still resolves. The anchor certifies *this token exists in
    this file, once* — not *this control operates on the path the cell describes*. A cell can therefore
    be green here and wrong: measured 2026-08-09 on 15.3.1, which was ``pass`` with every anchor
    resolving while the control it named had a hole, found only by executing the code.

    Each anchor that LOCATES is also given a derived :data:`AnchorForm` (:func:`anchor_form`) and
    counted into ``findings.anchor_forms``. That is reporting only — no branch here reads it, and no
    verdict depends on it.
    """
    # Per-run caches. 1,980 live anchors concentrate onto ~224 distinct files (`settings.py` alone
    # carries 218), so both the read and the parse are re-done an order of magnitude more often than
    # there are files to do them on.
    text_cache: dict[Path, str] = {}
    spans_cache: dict[Path, list[tuple[int, int]] | None] = {}
    ast_cache: dict[Path, ast.Module | None] = {}
    for c in cells:
        for a in c.evidence:
            target = root / a.path
            if not target.is_file():
                findings.problems.append(f"{c.id}: evidence path {a.path} does not exist")
                continue
            if target not in text_cache:
                text_cache[target] = target.read_text(encoding="utf-8", errors="replace")
            text = text_cache[target]
            findings.checked_anchors += 1
            occurrences = text.count(a.expect)
            if occurrences > 1:
                findings.problems.append(
                    f"{c.id}: {a.path}:{a.line} anchor is AMBIGUOUS — {a.expect!r} occurs "
                    f"{occurrences} times in the file, so the line number is not load-bearing and a "
                    "re-anchor cannot be checked. Cite a longer token that appears exactly once"
                )
                continue
            if occurrences == 0:
                # DELIBERATE NON-AFFORDANCE: this branch does NOT propose a replacement anchor, and
                # must not be "improved" to fuzzy-match a nearby similar line and suggest one. That
                # single affordance is what manufactures silent corruption, because a GONE token has
                # FOUR possible causes and only two of them are re-anchors:
                #
                #   (a) moved beyond detection, control intact   -> re-anchor          (mechanical)
                #   (b) renamed or refactored, control intact    -> re-anchor          (judgment)
                #   (c) THE GAP THIS ANCHOR CERTIFIED WAS CLOSED -> RETIRE the anchor, rewrite the
                #       residual; the verdict may IMPROVE
                #   (d) the control was removed or weakened      -> the claim is broken; RE-SCORE
                #
                # Worked example of (c), measured 2026-08-09: cell 3.7.5 anchored
                # `pyproject.toml:311 testpaths = ["tests"]`. BACKLOG #1027 widened testpaths to
                # include the web console package, so the token vanished -- but the anchor existed to
                # certify an EXCLUSION (the bucket-drift guard does not run), and that exclusion had
                # just been CLOSED, because the guard's test sits inside the path #1027 added. A
                # re-anchor to the new line would have pointed the anchor at the code that closed the
                # gap while the residual still narrated the gap: a stale-but-resolving anchor,
                # green forever, asserting the opposite of the truth. It was retired instead.
                #
                # A human distinguishes (a)-(d) by reading the cell. A tool cannot, so this one says
                # what it found and stops. Reporting candidate locations would be acceptable;
                # recommending one is not.
                findings.problems.append(
                    f"{c.id}: {a.path}:{a.line} no longer contains {a.expect!r} anywhere in the file "
                    "— the evidence is GONE. Re-read the cell before touching the anchor: the token "
                    "may have moved, been renamed, had the gap it certified CLOSED (retire it), or "
                    "had its control removed (re-score). Do not re-anchor by default"
                )
                continue
            # Unique, and therefore LOCATED: past the guard above, the token occurs exactly once in
            # this file, so its presence alone pins the evidence and the line number proves nothing
            # extra. Derive where it actually is and report any disagreement with the record.
            #
            # DERIVED FROM THE CHARACTER OFFSET, NOT BY SCANNING LINES. 42 of the ~1,980 ``expect``
            # tokens span a newline, because the old check matched against joined text and nothing
            # forbade it. A per-line scan finds none of those and raises on the lookup; counting
            # newlines before the match handles a multi-line token as naturally as a single-line one.
            start = text.index(a.expect)
            # Derived form of the landing site. Only anchors that reached here are classified: a GONE
            # or AMBIGUOUS token has no single landing site, so inventing a form for it would be a
            # made-up number in a split whose whole purpose is to stop the record overstating itself.
            if target not in spans_cache:
                spans_cache[target] = (
                    _prose_spans(text) if Path(a.path).suffix in PYTHON_SUFFIXES else None
                )
            findings.anchor_forms[
                _form_from_spans(a.path, spans_cache[target], start) or "undetermined"
            ] += 1
            actual = text.count("\n", 0, start) + 1
            if actual != a.line:
                # The ONLY producer the summary's "carry a stale line number" sentence describes.
                findings.advise(
                    "line",
                    f"{c.id}: {a.path} — {a.expect!r} is unique and present, recorded at line "
                    f"{a.line} but actually at {actual} (offset {actual - a.line:+d}). "
                    "Advisory: the line is a navigation aid, not the proof",
                )
            _check_sym_ctx(c.id, a, text, actual, ast_cache, target, findings)


def _check_sym_ctx(
    cell_id: str,
    a: Anchor,
    text: str,
    actual: int,
    ast_cache: dict[Path, ast.Module | None],
    target: Path,
    findings: Findings,
) -> None:
    """Validate a recorded ``sym``/``ctx`` against where the token now sits.

    **THIS IS A DISPLACEMENT SIGNAL, NOT A DEFECT DETECTOR; its security-relevant precision measured
    0 of 1 on the only datum the corpus offers, because 10.5.4's red was a HARDENING.** The change
    that moved that statement into a ``try`` made the code safer, and a structural check fired on it.
    Read this field as "your reasoning about this cell is stale, go re-read it" — never as "something
    is wrong here". A signal described as a defect detector, in the place people read it, will be
    quoted as one, and this one would then be quoted at 0% precision.

    That is why a mismatch is an ADVISORY and not a problem. The only fatal outcome is a value that is
    malformed (:func:`malformed_sym_ctx`) — a defect in the record, which no engine movement can cause.

    **ADDITIVE to the line-drift advisory, never a replacement.** The two catch different things and
    neither dominates: a token can move hundreds of lines without leaving its symbol (drift fires,
    sym/ctx does not), and a token can be welded into a new ``try`` or ``if`` without moving at all
    (sym/ctx fires, drift does not).

    Measured 2026-08-09, vault ``origin/main`` 1a59e4a1's anchors against engine tree ``4667e945``,
    over the 1,712 Python anchors that locate and parse. **The region is the innermost node the
    ``(sym, ctx)`` PAIR pins** — both fields must match, so the pair is only as loose as its tighter
    half:

    - **536 of 1,712 (31.3%)** sit in a region spanning MORE than the 81 lines the retired +/-40
      window covered. For those, sym/ctx alone is the LOOSER of the two signals.
    - Region spans: median 33, p90 567, max 9,799.
    - 1,403 of 1,712 are unnested (``ctx == ""``) and 280 are at module level (``sym == ""``), so for
      most anchors the pair reduces to "which function is this in".

    **The 38.4% / 639 figure this work was briefed with is reproducible, under a LOOSER definition:**
    scoring the region as the enclosing SYMBOL only, ignoring the ``ctx`` refinement, gives **634** at
    this ref against that brief's 639. Both definitions support the same conclusion and it is the only
    one that matters here — replacing drift with sym/ctx would lose detection on roughly a third of
    the record — so this stays additive either way.
    """
    if a.sym is None and a.ctx is None:
        return  # not asserted. Absence of the field is not an assertion that the region is empty.
    findings.checked_sym_ctx += 1
    problem = malformed_sym_ctx(a.sym, a.ctx)
    if problem:
        findings.problems.append(
            f"{cell_id}: {a.path}:{a.line} {problem}. A chain this deriver cannot produce would "
            "advise forever without ever matching, so it is refused rather than left to rot"
        )
        return
    if Path(a.path).suffix not in PYTHON_SUFFIXES:
        findings.problems.append(
            f"{cell_id}: {a.path}:{a.line} records sym/ctx on a non-Python file, which has no "
            "enclosing symbol and no block structure — no derivation can ever confirm or deny it"
        )
        return
    if target not in ast_cache:
        ast_cache[target] = parse_or_none(text)
    tree = ast_cache[target]
    if tree is None:
        findings.advise(
            "unparseable",
            f"{cell_id}: {a.path} — sym/ctx recorded but the file will not parse, so neither could "
            "be derived. Advisory: UNDETERMINED, which is not the same as agreeing",
        )
        return
    got_sym, got_ctx = sym_ctx_at(tree, actual)
    if a.sym is not None and a.sym != got_sym:
        findings.advise(
            "sym",
            f"{cell_id}: {a.path} — {a.expect!r} recorded sym={a.sym!r} but now sits in "
            f"sym={got_sym!r} (line {actual}). Advisory: DISPLACEMENT, not a defect — re-read the "
            "cell's reasoning, do not assume anything is wrong",
        )
    if a.ctx is not None and a.ctx != got_ctx:
        findings.advise(
            "ctx",
            f"{cell_id}: {a.path} — {a.expect!r} recorded ctx={a.ctx!r} but now sits in "
            f"ctx={got_ctx!r} (line {actual}). Advisory: DISPLACEMENT, not a defect — the control "
            "flow around this token changed, which may be a HARDENING (10.5.4 was)",
        )


def check_absences(cells: list[Cell], root: Path, findings: Findings) -> None:
    """An absence is proven only when its pattern is quiet AND its positive control still speaks."""
    corpus_files = _python_sources(root)
    for c in cells:
        for a in c.absence:
            findings.checked_absences += 1
            # Before asking what the corpus says, ask whether the pattern is a pattern at all. A prose
            # narration greps to nothing and is indistinguishable from a true absence.
            if not re.search(a.pattern, a.mutation):
                findings.problems.append(
                    f"{c.id}: absence claim is INERT — {a.pattern!r} does not match its own stated "
                    f"reintroduction {a.mutation!r}, so it would stay quiet if the thing came back"
                )
                continue
            control = _grep_count(a.positive_control, corpus_files)
            if control == 0:
                findings.problems.append(
                    f"{c.id}: absence claim is BLIND — its positive control {a.positive_control!r} "
                    f"matches nothing, so a zero result for {a.pattern!r} proves nothing"
                )
                continue
            hits = _grep_count(a.pattern, corpus_files)
            if hits:
                findings.problems.append(
                    f"{c.id}: absence claim is FALSE — {a.pattern!r} now matches {hits} time(s); "
                    f"the thing recorded as missing exists"
                )


def _python_sources(root: Path) -> list[Path]:
    out: list[Path] = []
    for pkg in ("messagefoundry", "messagefoundry_webconsole", "harness", "scripts"):
        base = root / pkg
        if base.is_dir():
            out.extend(
                p
                for p in base.rglob("*.py")
                if ".venv" not in p.parts and "__pycache__" not in p.parts
            )
    return out


def _grep_count(pattern: str, files: list[Path]) -> int:
    rx = re.compile(pattern)
    return sum(1 for f in files if rx.search(f.read_text(encoding="utf-8", errors="replace")))


# --- proving an absence by mutation (--prove-absences) --------------------------------------------
#
# check_absences proves a mutation is well-formed (its pattern fires on it). It cannot prove the
# mutation BITES: applied, does anything observable go red? A reintroduction raised into a swallowing
# handler passes every check in check_absences and changes nothing. This mode closes that hole by
# EXECUTING the claim — mutate a scratch copy of the tree, run the named observable, require it to go
# red — and it fails closed on every code that is not an honest test failure, so a typo'd node or an
# already-red observable can never masquerade as "the control bit". The whole pass runs inside a
# TemporaryDirectory scratch copy, so it never mutates `root` and never trips the committed-tree scan
# on itself.


def _scratch_ignore(dirpath: str, names: list[str]) -> set[str]:
    """Names to skip when copying `root` into the scratch tree. Beyond the usual VCS/venv/cache noise
    this refuses secrets and posture data — ``.env*``, ``*.db`` and its WAL sidecars (the local
    store), and the vault's ``docs/security`` tree (ADR 0156 §7). The vault runs this module against
    the REAL tree, so a scratch copy carrying those would spill them into a world-default temp dir,
    which CLAUDE.md §9 forbids this module reading at all. Public-repo runs never see them (no
    committed ``.env``/``*.db``, ``docs/security`` absent), so this is defence for the vault run."""
    ignored = set(
        shutil.ignore_patterns(
            ".git",
            ".venv",
            "__pycache__",
            "node_modules",
            ".env",
            ".env.*",
            "*.db",
            "*.db-wal",
            "*.db-shm",
        )(dirpath, names)
    )
    # `docs/security` is path-specific, not a basename glob: skip a `security` entry only directly
    # under `docs`, leaving any unrelated `security` elsewhere in the tree copied.
    if Path(dirpath).name == "docs" and "security" in names:
        ignored.add("security")
    return ignored


def _copy_scratch(root: Path, dest: Path) -> Path:
    """Copy `root` into `dest`, skipping VCS/venv/cache dirs and — defensively, for the vault run —
    secrets, the local store, and vault posture data (:func:`_scratch_ignore`). Never writes to
    `root`."""
    shutil.copytree(root, dest, ignore=_scratch_ignore)
    return dest


def _is_within_tree(rel: str) -> bool:
    """True only for a repo-relative path with no anchor and no ``..`` component — one that cannot
    escape the scratch copy when joined onto it. ``mutation_path`` comes from the authored scorecard,
    so it is untrusted for this purpose: an absolute or ``..``-bearing value is refused, not resolved."""
    p = Path(rel)
    if p.is_absolute() or p.anchor:
        return False
    return ".." not in p.parts


def _apply_mutation(scratch: Path, mutation_path: str, mutation: str) -> None:
    """Append the reintroduction to the scratch target — redefinition shadowing is what makes a
    well-formed reintroduction actually break an observable. Never called against `root`."""
    target = scratch / mutation_path
    with target.open("a", encoding="utf-8") as fh:
        fh.write("\n" + mutation + "\n")


def _run_node(scratch: Path, node_id: str, python: str, timeout: float) -> int:
    """Run one pytest node inside the scratch copy and return its exit code.

    Invoked with ``--rootdir <scratch>`` and ``cwd=scratch`` and ``-o addopts=`` so no repo
    ``conftest``/``pyproject``/addopts leaks into the child run, and ``-p no:cacheprovider`` so it
    writes nothing back. A timeout is treated as a non-{0,1} code — fail closed, never a proof.
    """
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; python is sys.executable, node id is scorecard-authored not shell-interpreted
            [
                python,
                "-m",
                "pytest",
                "-q",
                "--rootdir",
                str(scratch),
                "-p",
                "no:cacheprovider",
                "-o",
                "addopts=",
                node_id,
            ],
            cwd=scratch,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124  # non-zero and non-1: fails closed as a PROVE-ERROR, never counted as a proof
    return proc.returncode


def _handler_swallows(handler: ast.ExceptHandler) -> bool:
    """A handler that catches broadly (bare or ``Exception``/``BaseException``) with a log-only/``pass``
    body and no re-raise — the shape that eats a reintroduced exception."""
    caught = handler.type
    if not (
        caught is None
        or (isinstance(caught, ast.Name) and caught.id in {"Exception", "BaseException"})
    ):
        return False
    if any(isinstance(n, ast.Raise) for stmt in handler.body for n in ast.walk(stmt)):
        return False  # a re-raise is not a swallow
    return all(isinstance(stmt, (ast.Pass, ast.Expr)) for stmt in handler.body)


def _landing_swallows(source: str) -> bool:
    """True if `source` contains a ``try`` whose EVERY handler swallows (see :func:`_handler_swallows`).

    A coarse same-file heuristic — it proves nothing in general and cannot see a swallow in a caller.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    return any(
        isinstance(node, ast.Try)
        and bool(node.handlers)
        and all(_handler_swallows(h) for h in node.handlers)
        for node in ast.walk(tree)
    )


# --- pre-flight screens on the MUTATION itself ----------------------------------------------------
#
# The proving loop counts ``mutated == 1`` as "the control bit". That is only sound if the observable
# went red because of the SEMANTIC change the claim describes. Application is append-based, so a
# reintroduction breaks the target by REDEFINITION SHADOWING -- and two mutations that shadow nothing
# semantic still redden the observable, at exit 1, indistinguishably from a surgical proof:
#
#   * WRONG ARITY. ``def scan(p)`` reintroduced as ``def scan()`` raises ``TypeError`` at every call
#     site. Every test touching it fails, exit 1, counted as PROVED. The claim proved that calling a
#     function with the wrong number of arguments breaks it -- which is true of every function in the
#     repository and evidence about no control at all. This is the "wrecking ball that reads as a
#     surgical ablation" case, and it is not hypothetical here: the mutation is authored in a TOML
#     file in a DIFFERENT REPOSITORY from the signature it copies, with nothing keeping the two in
#     step (8 signature edits across the anchored surface in 149 commits).
#   * A MUTATION THAT DOES NOT PARSE. Appending invalid Python breaks import of the target. When the
#     observable imports it at module scope pytest reports a COLLECTION error (exit 2) and the
#     existing fail-closed branch catches it -- but an import inside the test body surfaces as an
#     ordinary test failure at exit 1, and is counted as a proof.
#
# NOT IMPLEMENTED, DELIBERATELY: a blanket refusal of ``raise`` in a mutation. That rule belongs to a
# schema of typed mutation kinds where an "ablate" limb weakens a control and must never throw. This
# module has no kinds -- every mutation is a REINTRODUCTION -- and a reintroduction that raises is an
# anticipated, legitimate shape: the static backstop above exists precisely to flag one landing in a
# swallowing handler, with two tests pinning that behaviour. Banning `raise` would delete the case the
# backstop was written for.


def _toplevel(source: str) -> tuple[dict[str, ast.arguments], set[str]] | None:
    """Top-level function signatures by name, plus every top-level name bound. ``None`` if `source`
    does not parse.

    TOP LEVEL ONLY, and that is the point rather than a simplification: the mutation is APPENDED to
    the module, so it can only shadow a module-level binding. A method inside a class body is not
    reachable by this mechanism and must not be compared against.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    sigs: dict[str, ast.arguments] = {}
    bound: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sigs[node.name] = node.args
            bound.add(node.name)
        elif isinstance(node, ast.ClassDef):
            bound.add(node.name)
        elif isinstance(node, ast.Assign):
            bound.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            bound.add(node.target.id)
    return sigs, bound


def _signature(args: ast.arguments) -> tuple[object, ...]:
    """The call-compatible shape of a signature: what a CALL SITE can observe.

    Parameter NAMES are included, not just counts -- a rename breaks every keyword call, which is the
    same wrecking-ball failure as a wrong count and is invisible to an arity-only comparison. Default
    values are compared by COUNT and never by value: a mutation legitimately changes what a default
    IS (that can be the whole reintroduction), while changing how many there are moves the arity.
    """
    return (
        tuple(p.arg for p in args.posonlyargs),
        tuple(p.arg for p in args.args),
        tuple(p.arg for p in args.kwonlyargs),
        args.vararg.arg if args.vararg else None,
        args.kwarg.arg if args.kwarg else None,
        len(args.defaults),
        sum(1 for d in args.kw_defaults if d is not None),
    )


def _screen_mutation(a: Absence, cell_id: str, target: Path, findings: Findings) -> bool:
    """Refuse a mutation that would redden the observable for a reason other than the change it
    claims. ``False`` means refused, and a PROVE-ERROR has been recorded.

    Runs on the live-proof AND the static-screen path: a mutation whose signature does not match the
    symbol it shadows is a defective claim whether or not anyone executes it.

    A REFUSAL IS PROBLEM-ONLY: it appends a PROVE-ERROR and increments NO counter, which is why the
    accounting identity on :class:`Findings` still closes. That was a choice between three options and
    the other two are worse. Folding a refusal into ``static_screened`` would be a lie about kind:
    that counter says "this claim's evidence is a screen rather than a proof", and a refused claim
    carries no evidence at all -- inflating it would make the instrument report more coverage than it
    has, which is the exact overstatement this module keeps correcting. Giving refusals their own
    counter would be arbitrary: every one of the problem-only branches has an equal claim to one, and
    the reason none of them has one is that the PROBLEM is the record. So a refusal joins them.
    """
    if target.suffix != ".py":
        return True  # nothing to parse; the append is opaque text by design
    mutation = _toplevel(a.mutation)
    if mutation is None:
        findings.problems.append(
            f"{cell_id}: absence claim PROVE-ERROR — the mutation is not valid Python, so applying it "
            f"breaks import of {a.mutation_path} rather than reintroducing anything. An observable "
            "that imports inside a test body reddens at exit 1 and would be counted as a proof"
        )
        return False
    source = _toplevel(target.read_text(encoding="utf-8", errors="replace"))
    if source is None:
        # The TARGET does not parse. Not this claim's defect, and not something to refuse it over --
        # leave it to execution, where the baseline will already be red and fail closed.
        return True
    mut_sigs, _ = mutation
    src_sigs, _ = source
    for name, margs in mut_sigs.items():
        real = src_sigs.get(name)
        if real is None:
            continue  # shadows no module-level function of that name; nothing to compare
        if _signature(margs) != _signature(real):
            findings.problems.append(
                f"{cell_id}: absence claim PROVE-ERROR — the mutation redefines {name}() with a "
                f"different signature than {a.mutation_path} declares "
                f"({_signature(margs)} vs {_signature(real)}). Applied, that raises TypeError at "
                "every call site, so the observable would go red for the arity and not for the "
                "reintroduction — a wrecking ball wearing the shape of a surgical proof. Copy the "
                "live signature; the mutation lives in a different repository from the symbol it "
                "shadows, so nothing else keeps the two in step"
            )
            return False
    return True


def _inventory(tree: Path) -> dict[str, int]:
    """Relative path -> size for every file in the scratch tree, skipping derived bytecode.

    The pristine copy is reused across claims, so something has to notice if a pytest run WROTE into
    it -- residue from claim N would otherwise be attributed to claim N+1's mutation. Names and sizes
    are a stat-only sweep, roughly two orders of magnitude cheaper than the copy it replaces.
    Honest residual: it cannot see a same-length in-place rewrite.
    """
    out: dict[str, int] = {}
    for p in tree.rglob("*"):
        if p.is_file() and "__pycache__" not in p.parts:
            out[str(p.relative_to(tree))] = p.stat().st_size
    return out


def _drop_pycache(target: Path) -> None:
    """Remove the bytecode cache beside a restored file.

    Belt and braces. CPython invalidates a ``.pyc`` on either source mtime or size, and a restore
    changes both relative to the mutated run, so this should never be load-bearing -- but the cost of
    being wrong is a stale module silently serving a mutation that was already reverted, which is a
    false proof, and the fix is one directory removal.
    """
    shutil.rmtree(target.parent / "__pycache__", ignore_errors=True)


def _prove_one(
    a: Absence,
    cell_id: str,
    root: Path,
    scratch: Path,
    findings: Findings,
    baselines: dict[str, int],
    *,
    python: str,
    timeout: float,
) -> None:
    if not a.mutation_path:
        # Nothing to apply. Reported, not failed: opt-in per claim (a live proof spawns a subprocess).
        findings.skipped_absences += 1
        return
    if not _is_within_tree(a.mutation_path):
        # mutation_path is authored data. An absolute path or a `..` escape would let _apply_mutation
        # write outside the scratch copy (and the is_file probe below read outside `root`), defeating
        # the 'never touches root' guarantee. Refuse it rather than resolve it.
        findings.problems.append(
            f"{cell_id}: absence claim PROVE-ERROR — mutation_path {a.mutation_path!r} is not a "
            "repo-relative path inside the tree (it is absolute or contains '..'), so applying the "
            "mutation could escape the scratch copy"
        )
        return
    target_in_root = root / a.mutation_path
    if not target_in_root.is_file():
        findings.problems.append(
            f"{cell_id}: absence claim PROVE-ERROR — mutation_path {a.mutation_path!r} is not a file "
            "in the tree, so the mutation cannot be applied"
        )
        return

    if not _screen_mutation(a, cell_id, target_in_root, findings):
        return

    if a.observable:
        # Baselines are CACHED BY NODE ID. The baseline is a property of the pristine tree and the
        # node, and the tree is pristine by construction at this point -- re-running it per claim
        # re-measured a constant, at one pytest subprocess each. Two claims naming the same observable
        # now pay for one baseline.
        baseline = baselines.get(a.observable)
        if baseline is None:
            baseline = _run_node(scratch, a.observable, python, timeout)
            baselines[a.observable] = baseline
        if baseline != 0:
            # An already-red or uncollectable observable cannot attribute its red to the mutation.
            findings.problems.append(
                f"{cell_id}: absence claim PROVE-ERROR — observable {a.observable!r} is not green on "
                f"the pristine tree (pytest exit {baseline}); a red or uncollectable baseline cannot "
                "be attributed to the mutation"
            )
            return
        # SAVE / APPLY / RUN / RESTORE against ONE pristine copy, rather than a fresh copytree per
        # claim (measured at roughly 1.2s a copy). `finally` so a crash in the run cannot leave the
        # shared tree mutated -- that would silently poison every later claim, which is the hazard the
        # per-claim copy was buying protection from and the reason the restore is verified below.
        target_in_scratch = scratch / a.mutation_path
        original = target_in_scratch.read_bytes()
        try:
            _apply_mutation(scratch, a.mutation_path, a.mutation)
            mutated = _run_node(scratch, a.observable, python, timeout)
        finally:
            target_in_scratch.write_bytes(original)
            _drop_pycache(target_in_scratch)
        if target_in_scratch.read_bytes() != original:
            # Asserted, not assumed. A restore that silently did not happen turns every subsequent
            # claim's result into a fact about the previous claim's mutation.
            findings.problems.append(
                f"{cell_id}: absence claim PROVE-ERROR — the scratch copy of {a.mutation_path} did "
                "not restore after the mutated run, so no later claim in this pass is attributable"
            )
            return
        if mutated == 1:
            findings.proved_absences += 1  # live proof: the control bit
        elif mutated == 0:
            findings.problems.append(
                f"{cell_id}: absence claim UNPROVEN — applying the mutation to {a.mutation_path} left "
                f"observable {a.observable!r} green (pytest exit 0); the mutation changes nothing the "
                "control catches, so this claim is syntax without behaviour"
            )
        else:
            # exit 2/3/4/5/...: collection or usage error. NEVER a proof — a typo'd node or a mutation
            # that merely breaks import must not masquerade as the control biting.
            findings.problems.append(
                f"{cell_id}: absence claim PROVE-ERROR — mutated run of {a.observable!r} errored "
                f"(pytest exit {mutated}) rather than failing; a collection or usage error must not "
                "count as the control biting"
            )
        return

    # Static backstop: mutation_path but no observable. A screen, not a proof (see Absence docstring).
    findings.static_screened += 1
    if re.search(r"\braise\b", a.mutation) and _landing_swallows(
        target_in_root.read_text(encoding="utf-8", errors="replace")
    ):
        findings.problems.append(
            f"{cell_id}: absence claim SUSPECT (static heuristic) — its reintroduction raises into "
            f"{a.mutation_path}, which has a try/except that swallows (bare or Exception, log-only "
            "body), so a live raise there may be caught and prove nothing. Supply an `observable` to "
            "prove it by execution"
        )


def prove_absences(
    cells: list[Cell],
    root: Path,
    *,
    python: str = sys.executable,
    timeout: float = 120.0,
) -> Findings:
    """Prove each absence claim BITES: apply its mutation to a scratch copy and require its observable
    to go red. Fails closed on anything that is not an honest baseline-green / mutated-fail pair.

    This is separate from :func:`verify` and opt-in (``--prove-absences``) because it spawns a pytest
    subprocess per provable claim. It never touches `root`.
    """
    findings = Findings()
    resolved_root = root.resolve()
    #: Baseline exit code per observable node id. See the caching note in :func:`_prove_one`.
    baselines: dict[str, int] = {}
    with tempfile.TemporaryDirectory(prefix="asvs_prove_") as td_base:
        base = Path(td_base)
        # ONE pristine copy for the whole pass. It was one per claim, which re-copied the entire tree
        # to apply a few lines and then threw it away -- at 1.2s a copy that is pure overhead
        # proportional to adoption, and adoption is the thing this mode exists to grow.
        generation = 0
        scratch = _copy_scratch(resolved_root, base / f"tree_{generation}")
        inventory = _inventory(scratch)
        for c in cells:
            for a in c.absence:
                # The POPULATION, recorded before any outcome branch, so it is right whichever branch
                # this claim takes. Without it the outcome counters float free of what was scanned.
                findings.checked_absences += 1
                _prove_one(
                    a,
                    c.id,
                    resolved_root,
                    scratch,
                    findings,
                    baselines,
                    python=python,
                    timeout=timeout,
                )
                # Reusing one tree is only sound while the tree stays pristine. A test that writes
                # into it leaves residue that the NEXT claim's mutated run would be blamed for, so the
                # reuse is CHECKED rather than assumed: on any change beyond the file just restored,
                # rebuild and say so. Cached baselines are dropped with it -- they were measured
                # against a tree that no longer exists.
                now = _inventory(scratch)
                if now != inventory:
                    generation += 1
                    scratch = _copy_scratch(resolved_root, base / f"tree_{generation}")
                    inventory = _inventory(scratch)
                    baselines.clear()
                    # NOT an anchor fact at all. Counted apart because it used to land in the
                    # numerator of a sentence about anchors, under --prove-absences.
                    findings.advise(
                        "scratch",
                        f"{c.id}: the scratch tree was written to during this claim's run, so it was "
                        "rebuilt and cached baselines were dropped. The claim's own result stands; "
                        "an observable that writes into the tree it is measuring is worth a look",
                    )
    return findings


def _sort_key(cell_id: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in cell_id.split("."))
    except ValueError:  # a malformed id sorts last rather than crashing the report
        return (9_999,)


def load_meta(path: Path) -> dict[str, str]:
    """The ``[scorecard]`` table: version pin, corpus digest, and the assessment anchor commit."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return {k: str(v) for k, v in data.get("scorecard", {}).items()}


def check_pinning(scorecard: Path, corpus: Path) -> list[str]:
    """The scorecard must declare which ASVS version it scores, and pin the corpus by digest.

    **ASVS requirement IDs are not stable across versions** — bare ``1.2.5`` is *Architecture* in
    4.0.3 and *Encoding and Sanitization* in 5.0.0 — and OWASP's referencing guidance prefers
    ``v<version>-<chapter>.<section>.<requirement>``. A document-level version field satisfies that
    pinning, so a scorecard keyed on bare ids cannot silently re-point when ASVS updates.
    """
    problems: list[str] = []
    data = tomllib.loads(scorecard.read_text(encoding="utf-8"))
    meta = data.get("scorecard", {})

    if not str(meta.get("asvs_version", "")).strip():
        problems.append(
            "pinning: [scorecard].asvs_version is missing — bare requirement ids re-point across "
            "ASVS versions, so the scorecard must say which version its ids mean"
        )
    anchor = str(meta.get("anchor_commit", "")).strip()
    # actions/checkout resolves `ref:` as a BRANCH OR TAG name unless it is a full 40-char hash, so an
    # abbreviated anchor fails with "A branch or tag with the name ... could not be found" -- a gate
    # failing for a reason with nothing to do with what it measures. Caught in CI twice; refused here.
    if anchor and not re.fullmatch(r"[0-9a-f]{40}", anchor):
        problems.append(
            f"pinning: [scorecard].anchor_commit {anchor!r} must be a FULL 40-character SHA -- an "
            "abbreviated hash is not resolvable by actions/checkout, which treats a short ref as a "
            "branch or tag name"
        )

    declared = str(meta.get("corpus_sha256", "")).strip()
    actual = corpus_digest(corpus)
    if not declared:
        problems.append(
            f"pinning: [scorecard].corpus_sha256 is missing — the corpus digest is {actual}"
        )
    elif declared != actual:
        problems.append(
            f"pinning: corpus digest mismatch — declared {declared[:16]}…, actual {actual[:16]}…. "
            "The ASVS corpus changed underneath the scorecard; re-verify before trusting any verdict"
        )
    return problems


def verify(scorecard: Path, corpus: Path, root: Path) -> Findings:
    # THE ROOT IS PART OF THE MEASUREMENT, so the refusal lives here rather than in `main`, where only
    # the CLI would get it. A scorecard sitting INSIDE the tree being checked means the anchors are
    # resolved against the repository that stores the record instead of the engine — a self-consistent
    # answer about the wrong tree, which is the hardest kind to notice.
    #
    # Measured 2026-08-18 from the vault, which carries its own tracked copy of `messagefoundry/`:
    # the engine root gave 183 stale / 0 fatal, the vault root gave 1273 stale / 269 fatal. Neither
    # printed which tree it read.
    #
    # DELIBERATELY containment, NOT "same repository". The vault's own CI runs from the vault root
    # with `--root engine` and `--scorecard docs/security/asvs-scorecard.toml`; those share a
    # workspace, so a same-repo test would refuse the sanctioned run and the gate would fail closed
    # forever on its own correct invocation. `vault/engine` does not CONTAIN
    # `vault/docs/security/asvs-scorecard.toml`, so containment passes it and still catches the
    # default-to-cwd case.
    if scorecard.resolve().is_relative_to(root.resolve()):
        raise ScorecardError(
            f"--root {root} CONTAINS the scorecard {scorecard}, so the evidence anchors would be "
            "resolved against the tree that holds the record instead of the engine. That produces a "
            "self-consistent, wrong answer. Pass the engine checkout as the root."
        )
    findings = Findings()
    cells = load_scorecard(scorecard)
    findings.problems.extend(check_pinning(scorecard, corpus))
    findings.problems.extend(check_completeness(cells, load_corpus(corpus)))
    check_anchors(cells, root, findings)
    check_absences(cells, root, findings)
    return findings


def _headline_caveat(unexamined: int) -> list[str]:
    """The "why there is no headline score" blockquote, in the version that is TRUE right now.

    This used to be one unconditional string, and it outlived its own premise. It said *"a count that
    folds in cells not yet re-verified"* and *"until the baseline sweep completes"* — both load-bearing
    on there BEING unverified cells. The sweep completed (345/345, 0 unverified) and the paragraph kept
    printing, so the document disclaimed its own numbers on a ground that measurement had already
    retired. A caveat resting on a false premise is the defect ASSESSMENT-METHOD warns about, and it is
    worse than a missing caveat: a reader who checks the premise and finds it false discards the whole
    warning, including the half that is still true.

    So it forks. The debt branch is the original, unchanged. The complete branch keeps the part that
    does NOT depend on re-verification debt — a count over heterogeneous requirements is not a security
    measure, and a movement in it has several causes of which only one is improvement (§2.2) — and adds
    the denominator, because a reader who is going to compute a percentage anyway should compute the
    same one twice rather than invent it.
    """
    if unexamined:
        return [
            "> **There is deliberately no headline score here.** A count that folds in cells not yet",
            "> re-verified is an average over verdicts reached from a paraphrase, not a measurement. Those",
            "> cells were graded by the earlier lineage — against the requirement verb as restated in our",
            "> own scorecards, because the ASVS 5.0.0 text was not held until 2026-07-31. That is",
            "> re-verification debt, not unassessed surface.",
            "> Until the baseline sweep completes, the honest number is the one above:",
            "> how much of the survey is done. Verdict counts below cover **examined cells only** unless",
            "> stated otherwise.",
        ]
    return [
        "> **The baseline sweep is COMPLETE — every verdict below was reached against the pinned",
        "> requirement text, not a paraphrase.** The re-verification debt this section used to warn",
        "> about is discharged, so the counts are a measurement and the table is the record.",
        "> **There is still deliberately no single headline score**, for a reason that does not expire:",
        "> a count over requirements that differ wildly in scope and cost is not a security measure, and",
        "> a movement in it has several possible causes of which only one is improvement — a cell can",
        "> move because scope was re-declared, because an earlier reading was corrected, or because the",
        "> pinned corpus changed, all with zero lines of engine code touched (see ASSESSMENT-METHOD",
        "> §2.2 before quoting any delta as progress).",
        "> If you are going to normalise anyway, normalise once and say which: **N/A cells are out of the",
        "> declared scope with a written rationale**, so the applicable denominator is the total minus",
        "> N/A, and `needs-review` carries no verdict and belongs in neither numerator.",
    ]


#: How each verdict state renders in the current-state table: the *State* cell, the emphasis wrapped
#: around its count, and the *Meaning* cell. Keyed by verdict and consumed by walking
#: :data:`VERDICT_ORDER`, so the table's rows and the total below them are read off ONE enumeration.
#: The six rows used to be six hand-written f-strings above a hand-written Total, which is the same
#: shape as the gate summary line BACKLOG #1012 was filed against — six statements of a distribution
#: with nothing relating them to each other or to the population.
_VERDICT_ROW: Final[dict[str, tuple[str, str, str]]] = {
    "pass": ("Pass", "", "verb satisfied by a shipped default or a refusing gate"),
    "partial": (
        "Partial",
        "",
        "control exists but ships off, warns, or covers part of the surface",
    ),
    "fail": ("Fail", "", "no implementing control in any configuration"),
    "na": ("N/A", "", "does not apply on the declared scope, with a written rationale"),
    "needs-review": (
        "Needs review",
        "",
        "examined; verdict contested or blocked on a decision",
    ),
    "unverified": (
        "**Unverified**",
        "**",
        "**not re-verified against the requirement text — not a Pass**",
    ),
}


def _verdict_rows(parts: list[tuple[str, int]]) -> list[str]:
    """The table body for :func:`render_current`, one row per verdict state, no exceptions.

    A state with no entry in :data:`_VERDICT_ROW` REFUSES rather than being skipped. Skipping is what
    the old hand-written block did implicitly, and a table whose rows silently stop summing to its own
    Total is the defect this whole path exists to make impossible.
    """
    rows: list[str] = []
    for verdict, n in parts:
        row = _VERDICT_ROW.get(verdict)
        if row is None:
            raise ScorecardError(
                f"verdict {verdict!r} is declared in VERDICT_ORDER but has no row in _VERDICT_ROW, "
                "so the rendered table would omit it while its cells still counted toward the "
                "Total. Add the row rather than letting the state render nowhere."
            )
        label, emphasis, meaning = row
        rows.append(f"| {label} | {emphasis}{n}{emphasis} | {meaning} |")
    return rows


@dataclass(frozen=True)
class BaseSpread:
    """How many distinct engine trees the record's verdicts were actually read against.

    **The line this replaces named ONE commit and implied the record sat on it.** The rendered entry
    point led with ``**Anchor commit:** <sha>`` in bold, which reads as *the* base of the assessment.
    Measured 2026-08-18 against the live record: 345 cells carry **24 distinct** ``verified_at`` SHAs,
    the widest 501 commits behind engine ``origin/main`` and the narrowest 6, and **exactly 2 of 345
    sit at ``anchor_commit`` itself**. So the bolded ref described 0.6% of the record.

    That is not a formatting complaint. A reader who takes the anchor commit as the base will date the
    whole record by it, and be wrong in both directions at once -- too new for the 74-cell cohort 424
    commits back, too old for the cells verified last week.

    ``anchor_commit`` is not thereby useless and is still rendered: it is where the EVIDENCE was last
    re-read, which is a real and different fact from where each VERDICT was decided. What changes is
    that it stops being presented as the record's single base.

    ``behind`` is empty when distance could not be measured -- no engine tree, no git, or a ref that
    does not resolve there. Empty means NOT MEASURED and is rendered as such, never as zero: a
    silently-omitted distance would restore the same one-number impression this exists to remove.
    """

    #: Distinct non-empty ``verified_at`` values across all cells.
    refs: int
    #: Cells carrying a ``verified_at`` at all.
    with_ref: int
    #: Cells carrying none. Their verdict has no recorded base, which is a different gap from a stale one.
    without_ref: int
    #: Cells whose ``verified_at`` equals ``anchor_commit``.
    at_anchor: int
    #: Total cells, so every figure above is readable against its denominator without leaving the line.
    total: int
    #: ``ref -> commits behind the root's HEAD``. EMPTY means not measured, never zero.
    behind: dict[str, int] = field(default_factory=dict)


def base_spread(cells: list[Cell], anchor_sha: str) -> BaseSpread:
    """The :class:`BaseSpread` derivable from the record alone — no git, no engine tree, no network.

    Split from the distance measurement on purpose: this half is pure and total, so it renders
    identically in a unit test and in CI, and the half that can fail to measure is the half that is
    allowed to be absent.
    """
    refs = {c.verified_at for c in cells if c.verified_at}
    with_ref = sum(1 for c in cells if c.verified_at)
    return BaseSpread(
        refs=len(refs),
        with_ref=with_ref,
        without_ref=len(cells) - with_ref,
        # Compared on the recorded prefix, because `verified_at` is normalised to 40 characters by
        # the vault's `asvs-verified-at.py` while `anchor_commit` is written short. Comparing the raw
        # strings would report 0 at-anchor cells forever, and 0 is exactly the answer this figure is
        # meant to make surprising -- it would look like a finding rather than a units error.
        at_anchor=sum(
            1
            for c in cells
            if c.verified_at
            and anchor_sha
            and (c.verified_at.startswith(anchor_sha) or anchor_sha.startswith(c.verified_at))
        ),
        total=len(cells),
    )


def ref_distances(root: Path, refs: set[str]) -> dict[str, int]:
    """``ref -> commits between it and the root's HEAD``, skipping every ref that does not resolve.

    Read-only and best-effort by design. A ref that does not resolve in this checkout is OMITTED
    rather than recorded as 0 — see :class:`BaseSpread`, where absent means not measured.
    """
    out: dict[str, int] = {}
    for ref in refs:
        n = _git(root, "rev-list", "--count", f"{ref}..HEAD")
        if n is not None and n.isdigit():
            out[ref] = int(n)
    return out


def _base_line(anchor_sha: str, spread: BaseSpread | None) -> str:
    """The header line naming what the record's verdicts were decided against.

    Falls back to the old single-commit form when no spread is supplied, so a caller that has only the
    cells still renders something true rather than something absent.
    """
    method = "**Method:** `docs/ASVS-ASSESSMENT-METHOD.md`"
    if spread is None:
        return f"**Anchor commit:** `{anchor_sha}` · {method}"
    bits = [
        f"**Verdict bases:** {spread.refs} distinct engine tree(s) across "
        f"{spread.with_ref} of {spread.total} cell(s)"
    ]
    # NO COMMIT DISTANCE IN THE RENDERED LINE, and leaving it out is the correction rather than an
    # omission. The first version printed "spanning N to M commit(s) behind the checked tree", where
    # the checked tree is engine `main` -- which MOVES. Measured against one real `verified_at`:
    #
    #     distance to origin/main      459
    #     distance to origin/main~1    458
    #     distance to origin/main~2    457
    #
    # So EVERY engine commit changes this line, and this line is COMMITTED. The render-drift gate
    # would then be red on every unrelated engine merge -- a gate whose resting state is red, which is
    # the exact antipattern filed as BACKLOG #320 the same day, reintroduced by its own author.
    #
    # A committed artifact may only carry facts derived from the RECORD, which change when the record
    # changes. The distance is genuinely useful and is not discarded: it prints to stderr in the verify
    # summary, where it is read by a human and committed by nobody.
    if spread.without_ref:
        bits.append(f"{spread.without_ref} cell(s) record no base at all")
    # The anchor stays, demoted to what it actually is: where the EVIDENCE was last re-read, with the
    # share of the record that sits there stated so it cannot be read as the record's base.
    bits.append(
        f"evidence last re-anchored at `{anchor_sha}`, where {spread.at_anchor} of "
        f"{spread.total} cell(s) sit"
    )
    return " · ".join(bits) + f" · {method}"


def render_current(cells: list[Cell], *, anchor_sha: str, spread: BaseSpread | None = None) -> str:
    """The generated entry point — survey progress FIRST, verdict counts second.

    **Phase 0 of the fix (ADR 0156 / ASSESSMENT-METHOD §4).** A headline count computed over cells
    that were never re-verified against the requirement text is not a measurement; it is an average
    over verdicts reached from a paraphrase, and publishing it is what made every subsequent
    re-verification read as a *reversal* rather than as *progress*. On 2026-08-01, 76% of that day's
    verdict changes were cells whose verdict had never been checked against the pinned text.

    So this leads with how much of the survey is done, and reports `unverified` separately from
    `pass` — which is also what ASVS asks for: a summary of **every requirement checked**, not
    exceptions only.
    """
    parts, total = verdict_breakdown(cells)
    # EXAMINED, not DECIDED: a `needs-review` cell was read and then parked, so it is survey progress
    # even though it carries no verdict. Counting it as unread made this line contradict the table
    # below it (see EXAMINED_VERDICTS).
    examined = [c for c in cells if c.verdict in EXAMINED_VERDICTS and c.last_verified]
    unexamined = total - len(examined)
    pct = (100.0 * len(examined) / total) if total else 0.0
    inherited = sum(1 for c in cells if c.verdict in DECIDED_VERDICTS and not c.last_verified)

    lines = [
        "<!-- GENERATED by scripts/asvs/scorecard.py — do not edit. Edit asvs-scorecard.toml. -->",
        "",
        "# ASVS 5.0 L3 — current state",
        "",
        _base_line(anchor_sha, spread),
        "",
        "## Survey progress",
        "",
        f"**{len(examined)} of {total} requirements have been verified against the pinned ASVS "
        f"requirement text ({pct:.1f}%).** {unexamined} carry a verdict that has not been re-verified "
        "against it.",
        "",
        *_headline_caveat(unexamined),
        "",
        "| State | Count | Meaning |",
        "|---|---:|---|",
        *_verdict_rows(parts),
        f"| **Total** | **{total}** | |",
        "",
    ]
    if inherited:
        lines += [
            f"WARNING: **{inherited} cell(s) carry a decided verdict with no `last_verified` date** — "
            "inherited from an earlier assessment and never re-verified against the requirement text. "
            "Treat as not-yet-re-verified.",
            "",
        ]
    lines += [
        "## Open cells",
        "",
        "| Cell | L | Verdict | Reviewed | Residual |",
        "|---|---|---|---|---|",
    ]
    open_states = {"partial", "fail", "needs-review"}
    for c in sorted((c for c in cells if c.verdict in open_states), key=lambda c: _sort_key(c.id)):
        seen = c.last_verified or "—"
        lines.append(f"| {c.id} | L{c.level} | **{c.verdict}** | {seen} | {c.residual[:150]} |")

    # Closed cells render even though they are not "open", and the reason is a defect this renderer
    # caused. 11.7.1 was closed by owner decision while it was a `fail`, so its STOP text surfaced
    # here — then the same ruling moved it to `na`, it dropped out of `open_states`, and the record's
    # rendered face went silent about the one cell that had just been the subject of a ruling. A
    # closure that is visible only while the verdict happens to be open is not a closure.
    closed = sorted((c for c in cells if c.decision_closed), key=lambda c: _sort_key(c.id))
    if closed:
        lines += [
            "",
            "## Closed by owner decision — do not re-score",
            "",
            "These cells are **excluded from surveys, sweeps and rescores**, whatever a pass's own",
            "instructions say. Re-scoring one needs an explicit owner instruction; the loader refuses",
            "a closed cell whose verdict has moved off its pin, so this is enforced, not advisory.",
            "",
            "| Cell | L | Verdict | Closed | By |",
            "|---|---|---|---|---|",
        ]
        for c in closed:
            when = c.decision_closed_on or "—"
            who = c.decision_closed_by or "owner"
            lines.append(f"| {c.id} | L{c.level} | **{c.verdict}** | {when} | {who} |")
    return chr(10).join(lines) + chr(10)


# --- provenance: every answer carries the refs it was measured at ---------------------------------
#
# A count is a fact about a (file x ref) PAIR. Drop the ref and two readings taken from different
# places print identically — which is exactly how this programme produced three wrong-base errors in
# one working thread on 2026-08-08/09: one in an adjudication, one in the correction of that
# adjudication, and one in a DAG-ancestry check that cannot answer "did this land" under squash-merge.
# Each cost a full re-measurement cycle. A query tool without ref stamping would INDUSTRIALISE that
# failure, because cheap answers get quoted more, not less.
#
# THE REQUIREMENT IS NOT FRESHNESS. IT IS THAT THE FRESHNESS CLAIM IS NEVER SILENT. Those come apart,
# and separating them dissolves the problem with zero network: the error that motivated this was not
# reading a stale ref, it was reading a stale ref while the output said nothing about it.

#: Seconds any single git probe may take before it is abandoned. `--status` is meant to be run in a
#: loop; a probe that can hang is a probe that gets removed.
_GIT_TIMEOUT: Final[float] = 5.0


@dataclass(frozen=True)
class RepoStamp:
    """Where a tree actually is, and how much it knows about where it should be.

    Every field is ALWAYS POPULATED. Degradation is a loud labelled value in the field, never an
    omitted field — an absent qualifier is what produced all three wrong-base errors, where the number
    was right and the ref was unnamed.
    """

    #: Short commit, or ``NO-GIT`` when the path is not inside a work tree.
    sha: str
    #: Whole-tree dirty. A measurement taken against uncommitted changes is not reproducible and must
    #: not look like one that is.
    dirty: bool
    #: ``CURRENT`` | ``BEHIND <n>`` | ``AHEAD <n>`` | ``DIVERGED`` | ``NO-UPSTREAM`` | ``NO-GIT`` |
    #: ``UNRESOLVED``. The last two are extensions and they exist BECAUSE of the never-silent rule:
    #: calling a non-repo ``NO-UPSTREAM`` would be a false statement (it implies a repo), and calling a
    #: comparison that git refused ``CURRENT`` would be the exact silence this field exists to break.
    freshness: str
    #: The ref the freshness was measured AGAINST, or ``none``. Named because "BEHIND 37" is not a
    #: claim until you know behind WHAT: on a feature branch the branch's own upstream and the
    #: canonical line are different questions with different answers.
    upstream: str
    #: Humanised age of ``FETCH_HEAD``, or ``NEVER-FETCHED``. NOT decoration: ``BEHIND 0`` from a
    #: six-hour-old fetch and ``BEHIND 0`` from a one-minute-old fetch are different claims and must
    #: not print identically.
    remote_knowledge: str

    def ref(self) -> str:
        return f"{self.sha}+dirty" if self.dirty else self.sha


def _git(repo: Path, *args: str) -> str | None:
    """One read-only git probe. ``None`` on any failure — missing git, not a repo, non-zero, timeout.

    NEVER runs a command that writes. There is deliberately no ``--fetch`` mode in this module: a
    fetch mutates remote-tracking refs, which a query tool run in a loop has no business doing, and on
    this machine the vault remote is intermittently unauthenticated, so a network dependency here
    would fire constantly and the tool would be bypassed inside a day. A bypassed tool is worse than
    none, because its absence gets read as nobody needing it. Refreshing is ``git fetch``, by hand,
    which is a different act performed on purpose.
    """
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; every subcommand is read-only
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=_GIT_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _humanise_age(seconds: float) -> str:
    if seconds < 90:
        return f"{int(seconds)}s"
    if seconds < 90 * 60:
        return f"{int(seconds / 60)}m"
    if seconds < 48 * 3600:
        return f"{int(seconds / 3600)}h"
    return f"{int(seconds / 86400)}d"


def _remote_knowledge(repo: Path, now: float) -> str:
    """How old the last-fetched remote knowledge is, from the mtime of ``FETCH_HEAD``. No network.

    ``FETCH_HEAD`` can live in either the per-worktree git dir or the common one depending on git
    version and who last fetched, so both are probed and the NEWEST is reported. Reporting the older
    of the two would overstate staleness; reporting only one would miss a fetch entirely, and a missed
    fetch reads as ``NEVER-FETCHED``, which is the loudest possible wrong answer.
    """
    newest: float | None = None
    for which in ("--git-dir", "--git-common-dir"):
        # `--path-format` is git 2.31+. Falling back to the relative form matters more than it looks:
        # without it an older git would yield no path, `NEVER-FETCHED`, and a confidently wrong
        # "nobody has ever fetched here" — the loudest possible wrong answer from this field.
        out = _git(repo, "rev-parse", "--path-format=absolute", which) or _git(
            repo, "rev-parse", which
        )
        if not out:
            continue
        try:
            mtime = (repo / out / "FETCH_HEAD").stat().st_mtime
        except OSError:
            continue
        newest = mtime if newest is None else max(newest, mtime)
    if newest is None:
        return "NEVER-FETCHED"
    return _humanise_age(max(0.0, now - newest))


def _freshness(repo: Path) -> tuple[str, str]:
    """``(freshness, upstream)`` for a work tree, using ZERO network.

    ``git rev-list --left-right --count HEAD...<upstream>`` counts against the LAST-FETCHED
    remote-tracking ref, which is a purely local object. Measured against the vault checkout whose
    stale ref caused the original error in this programme: ``BEHIND 37``, remote knowledge 23 minutes
    old. That pair would have stopped the error dead, with no network call.

    The upstream is the branch's own ``@{upstream}`` when it has one, and ``origin/main`` otherwise —
    and WHICHEVER was used is returned, because on a feature branch those are different questions.
    """
    upstream = _git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    if not upstream:
        upstream = "origin/main" if _git(repo, "rev-parse", "--verify", "origin/main") else ""
    if not upstream:
        return "NO-UPSTREAM", "none"
    counts = _git(repo, "rev-list", "--left-right", "--count", f"HEAD...{upstream}")
    parts = counts.split() if counts else []
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        # The ref name exists but git would not compare against it (a pruned or corrupt
        # remote-tracking ref). Labelled, never quietly rendered as CURRENT.
        return "UNRESOLVED", upstream
    ahead, behind = int(parts[0]), int(parts[1])
    if ahead and behind:
        return "DIVERGED", upstream
    if behind:
        return f"BEHIND {behind}", upstream
    if ahead:
        return f"AHEAD {ahead}", upstream
    return "CURRENT", upstream


def repo_stamp(path: Path, *, now: float | None = None) -> RepoStamp:
    """Stamp the work tree containing `path`. Pure read: no fetch, no write, no network."""
    repo = path if path.is_dir() else path.parent
    sha = _git(repo, "rev-parse", "--short", "HEAD")
    if sha is None:
        # Not a work tree at all. NOT reported as NO-UPSTREAM: that would imply a repo exists and is
        # simply untracked, which is a different and false statement.
        return RepoStamp("NO-GIT", False, "NO-GIT", "none", "NEVER-FETCHED")
    porcelain = _git(repo, "status", "--porcelain")
    freshness, upstream = _freshness(repo)
    return RepoStamp(
        sha=sha,
        dirty=bool(porcelain),
        freshness=freshness,
        upstream=upstream,
        remote_knowledge=_remote_knowledge(repo, time.time() if now is None else now),
    )


def provenance_lines(scorecard: Path, root: Path, *, now: float | None = None) -> list[str]:
    """The non-suppressible provenance header. Every query answer carries the refs it was measured at.

    **One deviation from the spec's literal shape, and it is deliberate — do not "fix" it back.** The
    spec draws ONE ``freshness`` and ONE ``remote-knowledge`` under a line naming TWO repositories.
    The scorecard and the engine are separate checkouts (the vault's own CI checks out the engine into
    a subdirectory and runs with ``--root engine``), and a single freshness field covering both would
    itself be an unnamed qualifier — the reader could not tell which repo it described. That is the
    precise defect the field exists to prevent, so the group is emitted PER REPO and labelled. No
    mandated field is renamed, dropped, or given a value outside its stated set.

    ``upstream=`` is likewise additive: "BEHIND 37" is not a claim until you know behind what.
    """
    return provenance_from(
        repo_stamp(scorecard, now=now), repo_stamp(root, now=now), label="asvs-status"
    )


def provenance_from(sc: RepoStamp, en: RepoStamp, *, label: str) -> list[str]:
    """:func:`provenance_lines` with the stamps already taken, and a caller-chosen label.

    Split out so VERIFY mode can emit the same header without paying for a second pair of stamps —
    each :func:`repo_stamp` shells out to git up to seven times, and the verify path already needs
    both stamps for the stale-anchor sentence. One pair, two consumers.

    ``label`` exists because the header names the mode that produced it. A verify run printing
    ``asvs-status`` would misattribute its own numbers to the query command.
    """
    generated = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
    return [
        f"# {label} scorecard={sc.ref()} engine={en.ref()}",
        f"#   scorecard: freshness={sc.freshness} upstream={sc.upstream} "
        f"remote-knowledge={sc.remote_knowledge}",
        f"#   engine:    freshness={en.freshness} upstream={en.upstream} "
        f"remote-knowledge={en.remote_knowledge}",
        f"#   generated={generated}",
    ]


def status_lines(cells: list[Cell]) -> list[str]:
    """``--status`` proper: what the scorecard SAYS, computed on every call and cached nowhere.

    Nothing here is persisted, because a cached query result would be document number 69 in a corpus
    where 68 documents assert a tally and approximately one is correct — stale in the same way, for
    the same reason, with more authority because a tool produced it.

    **This is a pure read of the scorecard and it names what it therefore cannot see.** Whether an
    anchor still RESOLVES is a fact about the engine tree, costs a 40-second pass, and is what
    :func:`verify` is for. Printing a structural tally under a heading that implies resolution health
    would be the same overstatement the summary line was just corrected for.
    """
    parts, total = verdict_breakdown(cells)
    examined = sum(1 for c in cells if c.verdict in EXAMINED_VERDICTS and c.last_verified)
    inherited = sum(1 for c in cells if c.verdict in DECIDED_VERDICTS and not c.last_verified)
    closed = sum(1 for c in cells if c.decision_closed)
    anchors = sum(len(c.evidence) for c in cells)
    anchored_cells = sum(1 for c in cells if c.evidence)
    paths = {a.path for c in cells for a in c.evidence}
    absences = sum(len(c.absence) for c in cells)
    provable = sum(1 for c in cells for a in c.absence if a.observable)
    unevidenced = sum(
        1 for c in cells if c.verdict in DECIDED_VERDICTS and not c.evidence and not c.absence
    )
    pct = (100.0 * examined / total) if total else 0.0
    # Externally-blocked fails, and -- the part that matters -- whether anyone has re-probed the
    # thing blocking them lately. Printed even when the count is zero, so "no blockers" and "the
    # blocker section was dropped from the renderer" cannot look alike.
    blocked = [c for c in cells if c.blocker is not None]
    today = datetime.date.today()
    overdue = [
        (c.id, c.blocker.days_overdue(today))
        for c in blocked
        if c.blocker is not None and c.blocker.days_overdue(today) > 0
    ]
    blocker_line = f"blocked {len(blocked)} fail cell(s) held by an external condition"
    if overdue:
        blocker_line += "; RE-PROBE OVERDUE: " + ", ".join(
            f"{cid} by {n}d" for cid, n in sorted(overdue, key=lambda x: -x[1])
        )
    elif blocked:
        blocker_line += "; all re-probes current"
    return [
        f"cells {total}: " + ", ".join(f"{c} {v}" for v, c in parts),
        blocker_line,
        f"examined {examined} of {total} ({pct:.1f}%) against the pinned text; "
        f"{inherited} decided with no last_verified; {closed} closed by owner decision",
        f"evidence {anchors} anchors in {anchored_cells} cells over {len(paths)} paths; "
        f"{unevidenced} decided cells carry neither an anchor nor an absence claim",
        f"absence {absences} claims, {provable} of them carrying an observable "
        "(the rest cannot be proved by execution)",
        "NOT CHECKED here: whether any anchor still resolves, whether any absence claim is still "
        "true, and completeness against the corpus. --status is a pure read of the scorecard; run "
        "verify for those",
    ]


def form_summary(findings: Findings) -> list[str]:
    """The derived-``form`` split, printed beside the resolved count — WITH its denominator.

    A bare "1,479 code" is unreadable: unreadable against what? So this prints the population it
    classified, the population it could not, and the population it never saw, on the principle that a
    broken run and a clean run must not look alike. The parts sum to ``checked_anchors`` by
    construction and the reader can check that without leaving the line.

    **Nothing downstream consumes this.** It is the record's rendered face telling the truth about
    what its evidence is made of, which is not the same act as scoring it. ``doc`` and ``foreign``
    anchors are not weaker claims — they are claims no structural or executable check can ever reach,
    which is a fact about the CHECK, not about the cell.
    """
    n = findings.anchor_forms
    located = findings.located_anchors
    unlocated = findings.checked_anchors - located
    prose = n["doc"] + n["foreign"]
    pct = (100.0 * prose / located) if located else 0.0
    out = [
        f"  form of the {located} anchor(s) that located: {n['code']} code, "
        f"{n['doc']} doc (docstring or # comment), {n['foreign']} foreign (not a Python file), "
        f"{n['undetermined']} undetermined (Python that would not parse)"
    ]
    if unlocated:
        out.append(
            f"  {unlocated} further anchor(s) did NOT locate (GONE or AMBIGUOUS, reported below) and "
            "carry no form: there is no landing site to classify"
        )
    covered = findings.checked_sym_ctx
    out.append(
        f"  sym/ctx asserted on {covered} of {findings.checked_anchors} anchor(s)"
        + (
            "; the rest assert neither, and absence of the field is NOT agreement"
            if covered < findings.checked_anchors
            else ""
        )
    )
    out.append(
        f"  {prose} of {located} ({pct:.1f}%) resolve into prose or a non-Python file, which no "
        "structural or executable check reaches, ever. That is a LABEL and not a demotion -- "
        "documentation is legitimate ground for a documentation requirement -- and it feeds no "
        "verdict, no completeness check and no exit code here"
    )
    return out


def _run_prove_absences(scorecard: Path, root: Path) -> int:
    """The ``--prove-absences`` entry point: execute-prove every absence claim (see
    :func:`prove_absences`). Needs no corpus — it applies mutations, it does not grep for patterns."""
    try:
        cells = load_scorecard(scorecard)
    except ScorecardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2  # could not measure — never 0, never confused with "clean"
    findings = prove_absences(cells, root)
    # `saw N` is the denominator, and it comes FIRST because the parts are unreadable without it: a
    # run over 276 claims and a run over zero otherwise print counter sets that look equally
    # plausible. The three outcome counters deliberately do not sum to it -- eight problem-only
    # outcomes increment nothing -- so the remainder is derivable and the gap is the point rather
    # than a rounding error. See `Findings.proved_absences` for the closing arithmetic.
    print(
        f"prove-absences: saw {findings.checked_absences} absence claim(s); "
        f"proved {findings.proved_absences} by mutation; "
        f"{findings.static_screened} static-screened; {findings.skipped_absences} skipped; "
        f"{len(findings.problems)} problem(s)"
    )
    # Advisories are reported, never fatal -- but they have to be REPORTED. A scratch tree rebuilt
    # mid-pass is the only signal that an observable wrote into the tree it was measuring, and it
    # would otherwise be visible nowhere at all: `ok` ignores advisories and the summary counts them
    # in nothing.
    for a in findings.advisories:
        print(f"  NOTE {a}", file=sys.stderr)
    for p in findings.problems:
        print(f"  FAIL {p}", file=sys.stderr)
    return 0 if findings.ok else 1


def _run_status(scorecard: Path, root: Path) -> int:
    """The ``--status`` entry point: provenance first, then what the scorecard says. No corpus needed.

    Exit 0 on a successful read and 2 when the scorecard cannot be loaded. NEVER 1 — this is a query,
    not a gate, and a query that borrows the gate's failure code will eventually be wired into CI as
    one. The gate is :func:`verify`.
    """
    for line in provenance_lines(scorecard, root):
        print(line)
    try:
        cells = load_scorecard(scorecard)
    except ScorecardError as exc:
        # The provenance header is already out, so even this failure is attributable to a ref.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for line in status_lines(cells):
        print(line)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify or render the ASVS scorecard (ADR 0156).")
    ap.add_argument("--scorecard", type=Path, required=True)
    # Not required: --prove-absences applies mutations and never greps for patterns, so it needs no
    # corpus. Verify mode still does; that is enforced after parsing, not by argparse.
    ap.add_argument("--corpus", type=Path, required=False)
    # DEFAULT None, not Path.cwd(), so verify mode can tell "the caller chose this tree" from "the
    # caller said nothing and got wherever the shell happened to be". Those printed identically and
    # the difference is a factor of seven.
    #
    # Measured 2026-08-18. The vault carries its own tracked copy of `messagefoundry/` (279 files,
    # last touched 2026-07-26) because the publish machinery maintains one. Run from the vault, which
    # is where the record lives and therefore where a person naturally runs this:
    #
    #     --root <engine>   ->   183 of 2090 stale,    0 fatal, exit 0
    #     --root <default>  ->  1273 of 2033 stale,  269 fatal, exit 1
    #
    # Both self-consistent, both silent about which tree they read. `--status` then printed
    # `engine=<the vault's own commit>` labelled `freshness=CURRENT` -- the one field that would have
    # exposed the substitution inherited it, because the substituted tree really was current.
    ap.add_argument(
        "--root",
        type=Path,
        default=None,
        help="tree the evidence anchors point into (REQUIRED to verify; defaults to cwd elsewhere)",
    )
    ap.add_argument("--render", type=Path, help="write the generated CURRENT.md here")
    # A separate, opt-in mode: prove each absence claim BITES by applying its mutation to a scratch
    # copy and requiring its observable to go red. Opt-in because it spawns a pytest subprocess per
    # provable claim; kept out of the default verify path, which stays purely static.
    ap.add_argument(
        "--prove-absences",
        action="store_true",
        help="execute-prove absence claims (apply mutation to a scratch tree, require observable red)",
    )
    # A QUERY, not a gate: a ref-stamped read of the scorecard, no corpus, no engine tree, no network,
    # nothing cached to disk. It exists because the dominant token cost of ASVS work is not reading
    # the record, it is reconciling two readings of it that were taken at different refs and printed
    # identically. There is deliberately NO --fetch: see `_git` on why a query must not mutate.
    ap.add_argument(
        "--status",
        action="store_true",
        help="print the provenance line and the scorecard's own counts, then exit (no corpus needed)",
    )
    # NO --anchor-sha injected by CI. The anchor is the commit the EVIDENCE was read on — a property
    # of the assessment, recorded in [scorecard].anchor_commit. Passing ${{ github.sha }} made the
    # rendered file differ on every run, so the drift check could never pass: a gate that cannot go
    # green is as useless as one that cannot go red, and this one shipped that way.
    args = ap.parse_args(argv)

    # `--status` is the one-second answer to "what does the record say" and needs NO engine tree, so
    # it keeps the cwd default. Making it required here would put an engine checkout between a person
    # and the only fast, correct read of the record -- which is the other half of the problem.
    if args.status:
        return _run_status(args.scorecard, args.root or Path.cwd())

    if args.prove_absences:
        return _run_prove_absences(args.scorecard, args.root or Path.cwd())

    # VERIFY MODE ONLY from here. The anchors are claims about a specific tree, so a verify pass that
    # did not name one is not a measurement of anything in particular.
    if args.root is None:
        print(
            "error: --root is required to verify -- the anchors are claims about a specific tree, "
            "and an unnamed tree makes the result unattributable. Pass the engine checkout "
            "explicitly. (--status and --prove-absences still default to the working directory.)",
            file=sys.stderr,
        )
        return 2  # could not measure — never 0, never confused with "clean"

    # The containment refusal is NOT here: it moved into `verify`, which every caller reaches. The
    # `except ScorecardError` below already maps it to exit 2, so the CLI behaviour is unchanged.
    if args.corpus is None:
        print(
            "error: --corpus is required to verify the scorecard (only --prove-absences may omit it)",
            file=sys.stderr,
        )
        return 2

    try:
        findings = verify(args.scorecard, args.corpus, args.root)
    except ScorecardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2  # could not measure — never 0, never confused with "clean"

    cells = load_scorecard(args.scorecard)
    # EVERY verdict state, derived from the type and reconciled against the cell count before it is
    # printed (BACKLOG #1012). This line used to enumerate five states and state a sixth-state total --
    # 344 components against a stated 345 -- because the enumeration was retyped here by hand and
    # `needs-review` was never added to it. It is the line people quote, so it was quoted wrong all day.
    try:
        parts, total = verdict_breakdown(cells)
    except ScorecardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2  # could not measure — never 0, never confused with "clean"
    breakdown = " / ".join(f"{c} {v}" for v, c in parts)
    # THE HEADLINE CARRIES ITS COORDINATES TOO, on the same stream as the numbers it describes.
    #
    # Fixing only the stale-anchor sentence would have left the line people actually quote — the
    # verdict breakdown — bare, and on a CLEAN record (no advisories) the whole run printed no ref
    # anywhere at all. That is the same defect one line up from where it was fixed.
    #
    # Stamps are taken ONCE here and reused by the stale-anchor sentence below, so this costs no
    # extra git work; it moved the existing cost earlier and made it unconditional.
    sc_stamp = repo_stamp(args.scorecard)
    en_stamp = repo_stamp(args.root)
    for line in provenance_from(sc_stamp, en_stamp, label="asvs-verify"):
        print(line)
    print(
        f"scanned {total} cells "
        f"({breakdown}); "
        # "verified" OVERCLAIMED, on the line that IS the record's rendered face. An anchor check
        # proves the token is present and unique in the file. It does not prove the statement still
        # executes under the control flow the cell reasoned about, and it cannot prove the cell's
        # conclusion follows from it -- `expect` is matched as a substring, so a statement that moved
        # inside a `try`, into another function, or under a different condition still resolves.
        # Measured instance: 15.3.1 sat at `pass` with every anchor resolving while the control it
        # named had a hole, found only by EXECUTING the code. A summary that says "verified" invites
        # exactly the inference the tool cannot support.
        f"resolved {findings.checked_anchors} evidence anchors "
        f"(token present and unique -- NOT proof the control operates) "
        f"and checked {findings.checked_absences} absence claims"
    )
    # Beside the resolved count, and deliberately not folded into it: WHAT those anchors resolve into.
    # "Resolved 1,980" reads as 1,980 pieces of code evidence; roughly a quarter of them are prose or a
    # non-Python file that no structural or executable check will ever reach. See `form_summary`.
    for line in form_summary(findings):
        print(line)
    for a in findings.advisories:
        print(f"  DRIFT {a}", file=sys.stderr)
    if findings.advisories:
        # DENOMINATOR: anchors that LOCATED, not anchors that were CHECKED. Only a located anchor can
        # produce a line-drift advisory — a GONE or AMBIGUOUS one raises a problem and returns before
        # the line is ever compared — so `checked_anchors` counted a population part of which cannot
        # contribute to the numerator. The two agree only while GONE and AMBIGUOUS are both zero,
        # which is to say the error is invisible on a clean record and appears on a dirty one.
        located = findings.located_anchors
        # NUMERATOR: the one producer this sentence describes. See `Findings.advisory_kinds`.
        stale = findings.advisory_kinds["line"]
        # THE REFS GO INSIDE THE SENTENCE, not in a header above it, for two independent reasons.
        # `form_summary` prints to stdout and this prints to stderr, so a header would attach the
        # coordinates to a different stream and interleave unpredictably. And a number leaves a log
        # by being copied as a sentence, never as a neighbourhood — every transcription defect on
        # record kept the figure and dropped the surrounding qualification.
        sc_ref, en_ref = sc_stamp.ref(), en_stamp.ref()
        pct = 100.0 * stale / located if located else 0.0
        print(
            f"  {stale} of {located} LOCATED anchors ({pct:.1f}%) carry a stale line number, "
            f"measured at scorecard={sc_ref} engine={en_ref}: the evidence is present and unique, "
            "only the recorded position is wrong. NOT fatal, and re-anchoring is bookkeeping rather "
            "than assessment — but the percentage is the thing to watch, because it only ever grows "
            "between re-anchor passes. THOSE TWO REFS ARE PART OF THE NUMBER: re-derived at any "
            "other pair this is a DIFFERENT MEASUREMENT, not a correction of this one.",
            file=sys.stderr,
        )
        # Every other producer, named and counted apart. Folding these in is what let one injected
        # `sym` mismatch print as a 184th anchor "carrying a stale line number" while 183 did.
        # No `and n` filter: `advisory_kinds` is only ever written by `advise`, and `Counter` returns
        # 0 for a missing key WITHOUT inserting one, so a zero-valued kind is unreachable. Guarding
        # against it would tell a reader the opposite.
        others = [(k, n) for k, n in sorted(findings.advisory_kinds.items()) if k != "line"]
        if others:
            named = ", ".join(f"{n} {k}" for k, n in others)
            print(
                f"  plus {sum(n for _, n in others)} advisory(ies) that are NOT line drift "
                f"({named}), counted apart: one anchor can raise three, and a scratch-tree advisory "
                "is not about an anchor at all.",
                file=sys.stderr,
            )
    for p in findings.problems:
        print(f"  FAIL {p}", file=sys.stderr)

    # RENDER IS NOT GATED ON `findings.ok`, and un-gating it is the point.
    #
    # It used to be `if args.render and findings.ok`, which coupled two unrelated things: the render is
    # derived from CELLS (verdicts, levels, dates), while `problems` is overwhelmingly about ANCHORS --
    # a token that moved, went ambiguous, or vanished. An anchor problem does not change a single
    # number in the rendered table, yet it made the only sanctioned command refuse to write it.
    #
    # So ANCHOR RED BECAME RENDER RED, and then render red became a stale committed entry point, which
    # is what reddened the scheduled arm for eight consecutive days through 2026-08-18. The fix for a
    # drifted render was to run the render -- and the drift itself was blocking that.
    #
    # The exit code is UNCHANGED and still `findings.ok`: this makes the artifact current, it does not
    # make a failing run look clean. `load_scorecard` has already succeeded by here (a malformed record
    # raises and returns 2 far above), so `cells` is valid whatever the anchors are doing.
    if args.render:
        anchor = load_meta(args.scorecard).get("anchor_commit", "unrecorded")
        # The spread is computed HERE rather than inside `render_current`, because measuring how far
        # each base is from the checked tree needs the engine checkout and `render_current` is a pure
        # function of the cells. Keeping it pure is what lets the renderer be unit-tested against a
        # fixture with no repository at all.
        spread = base_spread(cells, anchor)
        # The PURE spread goes into the file. `base_spread` reads only the record, so this line moves
        # when the record moves and at no other time -- which is the property a committed artifact
        # needs. See `_base_line` for what happens when a moving number gets committed.
        args.render.write_text(
            render_current(cells, anchor_sha=anchor, spread=spread),
            encoding="utf-8",
        )
        print(f"rendered {args.render}")

    # The distance to the checked tree, on STDERR and committed by nobody. It is real information --
    # it is how you see that the widest cohort was verified 500 commits ago -- it simply cannot live
    # in a file, because it changes on every engine commit rather than on every record change.
    if args.root is not None and (refs := {c.verified_at for c in cells if c.verified_at}):
        behind = ref_distances(args.root, refs)
        if behind:
            lo, hi = min(behind.values()), max(behind.values())
            # ONE number when they coincide: "spanning 6 to 6" reads as a measurement error.
            span = f"{lo}" if lo == hi else f"{lo} to {hi}"
            print(
                f"  {len(behind)} of {len(refs)} verdict base(s) resolve in the checked tree, "
                f"spanning {span} commit(s) behind its HEAD. NOT rendered into the entry point: this "
                "number moves on every engine commit, so committing it would red the drift gate on "
                "merges that changed nothing about the record.",
                file=sys.stderr,
            )
        else:
            # Absent is not zero. Say which, for the same reason every other count here names its base.
            print(
                f"  0 of {len(refs)} verdict base(s) resolve in the checked tree, so no distance "
                "could be measured. That is NOT a distance of zero -- the refs may predate this "
                "checkout's history, or the tree may be shallow.",
                file=sys.stderr,
            )

    return 0 if findings.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
