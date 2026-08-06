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
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

Verdict = Literal["pass", "partial", "fail", "na", "needs-review", "unverified"]

#: The scoring buckets. ``unverified`` is deliberately first-class (ADR 0156 §5): a cell inherited from
#: an earlier assessment and never re-read against the requirement text is NOT a Pass, and conflating
#: the two is what let ~219 unchecked verdicts hide inside a headline.
VERDICTS: Final[frozenset[str]] = frozenset(
    {"pass", "partial", "fail", "na", "needs-review", "unverified"}
)

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

#: How far from the recorded line the expected token may drift before the anchor is considered broken.
#: Anchors name a TOKEN rather than a bare line number precisely so that ordinary edits above a cell's
#: evidence do not thrash every anchor in the file; the window keeps the line number meaningful without
#: making it load-bearing.
ANCHOR_WINDOW: Final[int] = 40


class ScorecardError(Exception):
    """A defect in the scorecard itself — malformed, incomplete, or contradicting the corpus."""


@dataclass(frozen=True)
class Anchor:
    """A claim that some token exists in the tree, at roughly a known place."""

    path: str
    line: int
    expect: str


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
    checked_anchors: int = 0
    checked_absences: int = 0
    skipped_anchors: int = 0
    #: Populated only by :func:`prove_absences`. ``proved_absences`` counts claims whose observable
    #: went red under the applied mutation (a live proof); ``static_screened`` counts claims that took
    #: the static backstop (a screen, not a proof); ``skipped_absences`` counts claims carrying no
    #: ``mutation_path`` (nothing to apply). UNPROVEN and PROVE-ERROR outcomes go into ``problems``.
    proved_absences: int = 0
    static_screened: int = 0
    skipped_absences: int = 0

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
        cells.append(
            Cell(
                id=str(raw["id"]),
                level=int(raw["level"]),
                verdict=verdict,  # type: ignore[arg-type]
                residual=str(raw.get("residual", "")),
                posture=str(raw.get("posture", "single")),
                decision_closed=raw.get("decision_closed") is True,
                decision_closed_on=str(raw.get("decision_closed_on", "")),
                decision_closed_by=str(raw.get("decision_closed_by", "")),
                last_verified=str(raw.get("last_verified", "")),
                verified_at=str(raw.get("verified_at", "")),
                reviewed_by=str(raw.get("reviewed_by", "")),
                evidence=tuple(
                    Anchor(path=str(e["path"]), line=int(e["line"]), expect=str(e["expect"]))
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


def check_anchors(cells: list[Cell], root: Path, findings: Findings) -> None:
    """Open every evidence anchor and assert its token still resolves, and resolves UNAMBIGUOUSLY.

    When the code moves, this reds a test — instead of the sentence rotting in place and the next
    session funding work that is already done.

    **Uniqueness is not pedantry; it is what makes the resolution mean anything.** An ``expect`` that
    occurs many times in its file resolves from almost anywhere: with ``await conn.rollback()``
    appearing 101 times in one module, *any* line number in that file lands within ±40 of some
    occurrence, so the anchor cannot fail and certifies nothing. Two such anchors sat in this scorecard
    as evidence for weeks.

    It also closes a defect in the REPAIR path rather than the detection path. When code moves, the
    check correctly reports it — but a re-anchor to the nearest occurrence can silently install a
    *stale-but-resolving* anchor that passes forever. That happened live: after ADR 0154 landed,
    ``UPDATE sessions SET revoked_at=`` had two occurrences 19 lines apart — one the keep-N revoke, one
    a different method entirely — each inside the other's window, so the check would have accepted the
    wrong one. A repair is exactly where suspicion lapses, because the tool has just proved it works.
    """
    for c in cells:
        for a in c.evidence:
            target = root / a.path
            if not target.is_file():
                findings.problems.append(f"{c.id}: evidence path {a.path} does not exist")
                continue
            text = target.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            lo = max(0, a.line - 1 - ANCHOR_WINDOW)
            hi = min(len(lines), a.line + ANCHOR_WINDOW)
            findings.checked_anchors += 1
            occurrences = text.count(a.expect)
            if occurrences > 1:
                findings.problems.append(
                    f"{c.id}: {a.path}:{a.line} anchor is AMBIGUOUS — {a.expect!r} occurs "
                    f"{occurrences} times in the file, so the line number is not load-bearing and a "
                    "re-anchor cannot be checked. Cite a longer token that appears exactly once"
                )
                continue
            if a.expect in "\n".join(lines[lo:hi]):
                continue
            where = " (found elsewhere in the file)" if a.expect in "\n".join(lines) else ""
            findings.problems.append(
                f"{c.id}: {a.path}:{a.line} no longer contains {a.expect!r} within "
                f"±{ANCHOR_WINDOW} lines{where} — the evidence moved or the claim is now false"
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


def _prove_one(
    a: Absence,
    cell_id: str,
    root: Path,
    scratch_dir: Path,
    findings: Findings,
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

    if a.observable:
        scratch = _copy_scratch(root, scratch_dir)
        baseline = _run_node(scratch, a.observable, python, timeout)
        if baseline != 0:
            # An already-red or uncollectable observable cannot attribute its red to the mutation.
            findings.problems.append(
                f"{cell_id}: absence claim PROVE-ERROR — observable {a.observable!r} is not green on "
                f"the pristine tree (pytest exit {baseline}); a red or uncollectable baseline cannot "
                "be attributed to the mutation"
            )
            return
        _apply_mutation(scratch, a.mutation_path, a.mutation)
        mutated = _run_node(scratch, a.observable, python, timeout)
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
    with tempfile.TemporaryDirectory(prefix="asvs_prove_") as td_base:
        base = Path(td_base)
        i = 0
        for c in cells:
            for a in c.absence:
                i += 1
                _prove_one(
                    a,
                    c.id,
                    resolved_root,
                    base / f"scratch_{i}",
                    findings,
                    python=python,
                    timeout=timeout,
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
    findings = Findings()
    cells = load_scorecard(scorecard)
    findings.problems.extend(check_pinning(scorecard, corpus))
    findings.problems.extend(check_completeness(cells, load_corpus(corpus)))
    check_anchors(cells, root, findings)
    check_absences(cells, root, findings)
    return findings


def render_current(cells: list[Cell], *, anchor_sha: str) -> str:
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
    n = count(cells)
    total = sum(n.values())
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
        f"**Anchor commit:** `{anchor_sha}` · **Method:** `docs/ASVS-ASSESSMENT-METHOD.md`",
        "",
        "## Survey progress",
        "",
        f"**{len(examined)} of {total} requirements have been verified against the pinned ASVS "
        f"requirement text ({pct:.1f}%).** {unexamined} carry a verdict that has not been re-verified "
        "against it.",
        "",
        "> **There is deliberately no headline score here.** A count that folds in cells not yet",
        "> re-verified is an average over verdicts reached from a paraphrase, not a measurement. Those",
        "> cells were graded by the earlier lineage — against the requirement verb as restated in our",
        "> own scorecards, because the ASVS 5.0.0 text was not held until 2026-07-31. That is",
        "> re-verification debt, not unassessed surface.",
        "> Until the baseline sweep completes, the honest number is the one above:",
        "> how much of the survey is done. Verdict counts below cover **examined cells only** unless",
        "> stated otherwise.",
        "",
        "| State | Count | Meaning |",
        "|---|---:|---|",
        f"| Pass | {n['pass']} | verb satisfied by a shipped default or a refusing gate |",
        f"| Partial | {n['partial']} | control exists but ships off, warns, or covers part of the surface |",
        f"| Fail | {n['fail']} | no implementing control in any configuration |",
        f"| N/A | {n['na']} | does not apply on the declared scope, with a written rationale |",
        f"| Needs review | {n['needs-review']} | examined; verdict contested or blocked on a decision |",
        f"| **Unverified** | **{n['unverified']}** | **not re-verified against the requirement text "
        "— not a Pass** |",
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


def _run_prove_absences(scorecard: Path, root: Path) -> int:
    """The ``--prove-absences`` entry point: execute-prove every absence claim (see
    :func:`prove_absences`). Needs no corpus — it applies mutations, it does not grep for patterns."""
    try:
        cells = load_scorecard(scorecard)
    except ScorecardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2  # could not measure — never 0, never confused with "clean"
    findings = prove_absences(cells, root)
    print(
        f"prove-absences: proved {findings.proved_absences} by mutation; "
        f"{findings.static_screened} static-screened; {findings.skipped_absences} skipped; "
        f"{len(findings.problems)} problem(s)"
    )
    for p in findings.problems:
        print(f"  FAIL {p}", file=sys.stderr)
    return 0 if findings.ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify or render the ASVS scorecard (ADR 0156).")
    ap.add_argument("--scorecard", type=Path, required=True)
    # Not required: --prove-absences applies mutations and never greps for patterns, so it needs no
    # corpus. Verify mode still does; that is enforced after parsing, not by argparse.
    ap.add_argument("--corpus", type=Path, required=False)
    ap.add_argument(
        "--root", type=Path, default=Path.cwd(), help="tree the evidence anchors point into"
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
    # NO --anchor-sha injected by CI. The anchor is the commit the EVIDENCE was read on — a property
    # of the assessment, recorded in [scorecard].anchor_commit. Passing ${{ github.sha }} made the
    # rendered file differ on every run, so the drift check could never pass: a gate that cannot go
    # green is as useless as one that cannot go red, and this one shipped that way.
    args = ap.parse_args(argv)

    if args.prove_absences:
        return _run_prove_absences(args.scorecard, args.root)

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
    n = count(cells)
    print(
        f"scanned {len(cells)} cells "
        f"({n['pass']} pass / {n['partial']} partial / {n['fail']} fail / {n['na']} na / "
        f"{n['unverified']} unverified); "
        f"verified {findings.checked_anchors} evidence anchors and {findings.checked_absences} absence claims"
    )
    for p in findings.problems:
        print(f"  FAIL {p}", file=sys.stderr)

    if args.render and findings.ok:
        anchor = load_meta(args.scorecard).get("anchor_commit", "unrecorded")
        args.render.write_text(render_current(cells, anchor_sha=anchor), encoding="utf-8")
        print(f"rendered {args.render}")

    return 0 if findings.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
