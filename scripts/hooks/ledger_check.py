#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Ledger gate — stop two concurrent sessions from silently colliding on an ADR number.

THE DEFECT THIS EXISTS FOR. Two sessions each grep for "the next free number", both pick N, and create
DIFFERENTLY-NAMED files: docs/adr/0084-alpha.md and docs/adr/0084-beta.md. Git merges both **cleanly**
— there is no textual conflict — and the ledger is quietly corrupt. It has happened three times here
(d1d0a5a #574, 5b7d046 #598, 9f3483d), and it is the one measured collision class that a worktree, a
file lock, and `git merge-tree` are all blind to.

THE BACKLOG HALF IS GONE. Two of those three collisions were backlog items, not ADRs, and that arm
was retired with the ledger itself (BACKLOG #1250) — see the note above `git()` for what went and
why. The remaining risk is real and unchanged: ADRs still live in this repository.

WHY A GIT PRE-COMMIT HOOK. Installed by scripts/coord/install-git-hooks.ps1 into the SHARED .git/hooks,
one copy governs EVERY worktree at once — no branch, no merge, no propagation lag — and it sees every
write route (the Edit tool, a shell redirect, VS Code, a subagent), because it inspects the TREE at commit
time rather than a tool call. The `--ci` mode re-runs the same rules against a freshly fetched origin/main,
which is what catches the STALE-BASE collision: each branch is internally consistent, and the duplicate
only exists once both have merged.

Reads the STAGED tree (`git show :path`), never the working tree — otherwise an untracked work-in-progress
ADR sitting in your checkout would block every unrelated commit.

Stdlib only, no `messagefoundry` import: most worktrees have no .venv, and a gate that silently skips is
worse than no gate. `git commit --no-verify` is the escape hatch; the --ci run is the backstop for it.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

ADR_FILE = re.compile(r"^docs/adr/(\d{4})-[^/]+\.md$")
#: THE ONE DEFINITION OF AN INDEX ROW (BACKLOG #2003). index_rows is the one enumeration built on
#: it, and every check reads rows from there, so a row is seen by every check or by none. index_row
#: used to need the exact prefix `| [NNNN]` while the row count allowed `|[NNNN]`, so such a row
#: passed the has-a-row test and was invisible to the companion check and to adr_index_coverage.
#: `[^\S\r\n]*` is whitespace other than a line ending: `\s*` under re.M crossed one, so a bare `|`
#: line made the NEXT line a row.
INDEX_ROW = re.compile(r"^\|[^\S\r\n]*\[(\d{4})\]", re.M)
#: THE ONE LINK FORM THAT NAMES AN ADR FILE (BACKLOG #2001): `[text](NNNN-name.md)` or
#: `[text](./NNNN-name.md)`, with an optional `#fragment`. Group 1 is the basename. Narrow on
#: purpose. Every row in the index uses the sibling form, and each extra form (angle brackets, a
#: title, percent-encoding, a `docs/adr/` prefix) is a place where this regex and the renderer can
#: disagree. A `docs/adr/` prefix is also a dead link from docs/adr/README.md. So an ADR file whose
#: name holds a space or a `(` cannot be linked, and the gate refuses it rather than guess.
ADR_LINK = re.compile(r"(?<!\\)\[[^\[\]\n]*\]\((?:\./)?(\d{4}-[^\s()<>#/\\]+\.md)(?:#[^\s()]*)?\)")
#: Inline code and HTML comments. The renderer shows no link inside either, so neither names a file.
NOT_RENDERED = re.compile(r"`[^`\n]*`|<!--.*?-->")

#: How far back the restore carve-out (BACKLOG #1468) will look for a blob one ADR path once carried.
#: Bounded because this runs inside a pre-commit hook; see Ledger._history_of_this_number, which
#: REPORTS hitting this cap rather than reporting "not found".
RESTORE_HISTORY_DEPTH = 200

# THE BACKLOG HALF OF THIS GATE IS RETIRED (BACKLOG #1250, BACKLOG #1754).
#
# The numbered-item ledger no longer lives in this repository. It moved to the maintainer-internal
# one, and docs/BACKLOG.md is now a stub saying so. With no `## N.` items anywhere in this tree
# there is no namespace for a collision rule to police, so check_backlog(), the item-destruction
# reverse arm, and every helper only they used were removed rather than left to pass vacuously over
# an empty corpus. A gate that cannot fail is worse than no gate: it licenses the behaviour while
# withdrawing the caution its absence would have preserved.
#
# PUBLIC_BACKLOG_FLOOR WENT WITH THEM, AND ITS READER WENT FIRST. `scripts/coord/alloc.ps1` used to
# regex-match the literal out of this file so the floor was defined exactly once; that allocator no
# longer accepts `-Kind backlog`, so the constant had no reader and no subject. Do not reintroduce
# it to "preserve the contract" -- a floor guarding a number space this repository does not carry
# is a compensating control resting on a false premise.
#
# THIS GATE STILL POLICES ADR NUMBERS, which is now the whole of its job. ADRs live in docs/adr/
# here, they are public, and two sessions can still allocate one number and merge clean. Allocate
# with `pwsh -NoProfile -File scripts/coord/alloc.ps1 -Kind adr -Title "<title>"`.


def git(*args: str) -> str:
    # encoding= is REQUIRED, not cosmetic: `text=True` alone decodes with the LOCALE default, which is
    # cp1252 on a stock Windows box. docs/BACKLOG.md and docs/adr/README.md are UTF-8 (em-dashes,
    # U+2705, U+26A0), so the decode raised inside subprocess's reader thread, `proc.stdout` came back
    # **None**, and the caller died on `findall(None)` — blocking every commit that touched either
    # ledger file. The gate's own failure mode was the one it exists to prevent: silent, and worst on
    # the files it guards.
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", *args], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    # A git failure (bad ref, missing path) must not read as "the file is empty" — an empty ledger parses
    # as "no numbers taken", which is exactly the false-clean this gate must never emit.
    if proc.returncode != 0:
        raise OSError(
            f"git {' '.join(args)} failed ({proc.returncode}): {(proc.stderr or '').strip()}"
        )
    return proc.stdout or ""


def _paths(out: str) -> list[str]:
    """Split the output of a `-z` git path listing into whole paths (BACKLOG #1871).

    NOT `.split()`: that splits on ANY whitespace, so `docs/adr/0190-with space.md` arrived as two
    halves, neither half matched ADR_FILE, and the file was invisible to every rule in this gate.
    NOT `.splitlines()` either: under git's default `core.quotePath`, line-oriented output C-quotes a
    non-ASCII path (`"docs/adr/0192-caf\\303\\251.md"`), which ADR_FILE cannot match. With `-z`, git
    writes each path unquoted and ends it with NUL, the one separator a path cannot hold. What reaches
    here has still passed through git()'s text decoding, so a path holding a CR or invalid UTF-8 is
    altered and its later `:path` lookup misses. That fails closed (a refusal), never open.

    Every caller must pass `-z`. Without it the output holds no NUL and would come back as ONE bogus
    path, hiding every file, so non-empty output with no NUL raises rather than reading as clean.
    """
    if out and "\0" not in out:
        raise ValueError(f"expected NUL-terminated git output (-z); got {out[:80]!r}")
    return [p for p in out.split("\0") if p]


def _obj_exists(spec: str) -> bool:
    """Does the `<ref>:<path>` object exist? Probed EXPLICITLY rather than inferred from an error.

    :func:`git` raises on any non-zero exit deliberately — a swallowed failure would read as "empty
    ledger", i.e. "no numbers taken", the false-clean this gate exists to prevent. "The path is simply
    not on that ref" is the one case that is NOT a failure, so it gets its own probe instead of a
    broad ``except``.
    """
    probe = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", "cat-file", "-e", spec], capture_output=True
    )
    return probe.returncode == 0


def _blob_id(spec: str) -> str | None:
    """The object id a ``<rev>:<path>`` (or staged ``:<path>``) spec names, or None if it names nothing.

    Separate from :func:`git` for the same reason :func:`_obj_exists` is: a spec that names nothing is
    an ANSWER here, not a failure, and :func:`git` raises on every non-zero exit deliberately. The
    caller (BACKLOG #1468) compares two of these for equality, so returning None on a miss is what
    keeps a miss from ever comparing equal to another miss.
    """
    probe = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", "rev-parse", "--verify", "--quiet", spec],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if probe.returncode != 0:
        return None
    return (probe.stdout or "").strip() or None


def index_rows(readme: str) -> list[tuple[str, str]]:
    """Every docs/adr/README.md row, in file order, as (number, row text).

    THE ONE ENUMERATION OF ROWS (BACKLOG #2003). The row count, the duplicate check, index_row and
    adr_index_coverage all read it. A row ends at the next newline, the same line break INDEX_ROW's
    `^` starts at. A second scan with str.splitlines() would split on more characters (U+2028, form
    feed and others), and could return a row the count never saw.
    """
    rows: list[tuple[str, str]] = []
    for m in INDEX_ROW.finditer(readme):
        end = readme.find("\n", m.start())
        rows.append((m.group(1), readme[m.start() : end if end >= 0 else None].rstrip("\r")))
    return rows


def _first_rows(rows: list[tuple[str, str]]) -> dict[str, str]:
    """Each number's FIRST row. A duplicate row is check_adrs's own refusal; this does not hide it."""
    first: dict[str, str] = {}
    for number, row in rows:
        first.setdefault(number, row)
    return first


def index_row(readme: str, number: str) -> str:
    """The docs/adr/README.md row for one ADR number, or "" when the index has none."""
    return _first_rows(index_rows(readme)).get(number, "")


def _row_links_as_own(row: str, basename: str) -> bool:
    """True when the row's number cell links this file, i.e. it is the row's own ADR, not a companion.

    Anchored with INDEX_ROW (BACKLOG #2003) and read with ADR_LINK, the parser row_names_file uses,
    so `[0190](./0190-x.md)` is the row's own file here exactly as it is named there.
    """
    m = INDEX_ROW.match(row)
    if m is None:
        return False
    link = ADR_LINK.match(row, m.start(1) - 1)  # the `[` that opens `[NNNN]`
    return link is not None and link.group(1) == basename


def row_names_file(row: str, basename: str) -> bool:
    """True when an index row names this ADR file, as its own link or as a DECLARED COMPANION.

    THE ONE DEFINITION OF COMPANION LEGALITY (BACKLOG #1516). check_adrs uses it at commit time to
    tell a declared companion from an undeclared reuse of a number. adr_index_coverage uses it to ask
    whether every existing file is represented. Two copies of this test would drift apart silently,
    so there is one.

    EXACT LINK TARGETS, NOT A SUBSTRING (BACKLOG #2001). The test used to be
    `basename.removesuffix(".md") in row`, so a stray `0001-fir.md` passed under a row naming
    `0001-first.md`. Now the file must be the target of an ADR_LINK in the row. A name in plain text,
    inline code or an HTML comment is not a rendered link, so it does not index the file.
    """
    return basename in ADR_LINK.findall(NOT_RENDERED.sub(" ", row))


class AdrCoverage(NamedTuple):
    """What adr_index_coverage found. Every list holds basenames, sorted."""

    #: Every `NNNN-*.md` file in the directory, one entry per FILE, never one per number.
    files: list[str]
    #: Files named inside their number's row that are not the row's own link (ADR 0013's second file).
    companions: list[str]
    #: Files their number's row does not name at all, or whose number has no row.
    unrepresented: list[str]


def adr_index_coverage(adr_dir: Path) -> AdrCoverage:
    """Check that every ADR file in adr_dir is reachable from adr_dir/README.md (BACKLOG #1516).

    check_adrs looks only at files a commit ADDS, which is the right scope for a commit-time gate.
    This covers the whole corpus, and tests/test_adr_index_coverage.py asserts it. It enumerates
    FILES, not numbers: keying on the number is how two audits of every ADR each dropped ADR 0013's
    companion without an error. ADR_FILE decides what an ADR file is, here as in the gate.
    """
    readme = (adr_dir / "README.md").read_text(encoding="utf-8")
    files = sorted(p.name for p in adr_dir.iterdir() if ADR_FILE.match(f"docs/adr/{p.name}"))
    first_rows = _first_rows(index_rows(readme))
    companions: list[str] = []
    unrepresented: list[str] = []
    for name in files:
        row = first_rows.get(name[:4], "")
        if not row_names_file(row, name):
            unrepresented.append(name)
        elif not _row_links_as_own(row, name):
            companions.append(name)
    return AdrCoverage(files, companions, unrepresented)


class _RestoreEvidence(NamedTuple):
    """What one bounded history walk established about an ADR number (BACKLOG #1468).

    Three states, not two, because "the base never held this number" and "I could not see far enough
    to tell" are different answers that the same empty result set produces.
    """

    #: The staged bytes match a blob this exact path already carried. The pass condition.
    restores_lost_bytes: bool
    #: Some file existed at this number within the walk. Words the refusal; never grants one.
    number_is_historical: bool
    #: The walk hit a shallow graft or its own cap, so a negative above is NOT evidence of absence.
    truncated: bool


def _clone_is_shallow() -> bool:
    """Is this clone grafted? A negative history result means something different when it is.

    Measured on a managed worktree of this repository: `--is-shallow-repository` returns true and only
    900 commits are reachable from origin/main, so an ADR deleted before the graft is invisible to any
    walk. Probed rather than assumed, and any failure reads as "shallow" -- the direction that makes
    the caller word its refusal more cautiously rather than less.
    """
    probe = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", "rev-parse", "--is-shallow-repository"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return probe.returncode != 0 or (probe.stdout or "").strip() != "false"


def _safe_for_message(value: object, limit: int = 400) -> str:
    """Fold a value about to be INTERPOLATED INTO PROSE AN AGENT IS TOLD TO ACT ON (BACKLOG #1040).

    This gate's deny text is read by a model that then does what it says, so a value carrying a line
    break can forge a SECOND remedy block -- and a forged block placed FIRST is the one a reader going
    top-down obeys. Proven on ``worktree_gate.ps1``, where a ``Write`` whose ``file_path`` held embedded
    line breaks produced a reason with two ``Do this instead:`` blocks, the injected one first. It needed
    nothing on disk -- only the JSON field -- so no other gate saw it.

    A LOCAL COPY RATHER THAN AN IMPORT, and the reason is mechanical rather than stylistic:
    ``install-git-hooks.ps1`` COPIES this file into the git hooks directory and runs it from there, so an
    import of anything under ``scripts/hooks/`` resolves at development time and fails at the moment the
    gate actually runs. ``claim_check.py`` carries the same helper for the same reason.

    Folds line breaks to spaces, collapses whitespace runs, strips control characters and truncates --
    the value stays READABLE and can no longer add a line.
    """
    text = "" if value is None else str(value)
    # EVERY control character, not only the line breaks: a lone ESC can rewrite a terminal line and a
    # backspace can erase what precedes it, so a value that "contains no newline" is not therefore inert.
    text = "".join(" " if ch < " " or ch == chr(127) else ch for ch in text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


class Ledger:
    def __init__(self, *, ci: bool, base: str = "origin/main") -> None:
        self.ci = ci
        self.base = base
        self.repo = Path(git("rev-parse", "--path-format=absolute", "--show-toplevel").strip())
        common = git("rev-parse", "--path-format=absolute", "--git-common-dir").strip()
        # The registry lives beside the SHARED object store, so every worktree of this repo sees the same
        # allocations — and a different clone gets its own, automatically.
        self.alloc = Path(common) / "mefor-coord" / "alloc"
        self.failures: list[str] = []
        # Per-run memos. Every entry is derived from a REF, and refs do not move inside one run of a
        # pre-commit hook -- so a repeat lookup is pure waste, and each one costs git subprocesses.
        # Measured 2026-09-10 on this box: a `git` spawn is 53-315 ms whatever it does, and the
        # retired per-ref item sweep was five spawns plus two full parses of a 30k-line file per ref.
        self._parents: list[str] | None = None

    # -- tree access ---------------------------------------------------------------------------------
    #
    # CI uses a TWO-dot diff (`base HEAD`), deliberately, not three-dot (`base...HEAD`).
    #
    # On a `pull_request`, actions/checkout checks out the MERGE commit — HEAD already CONTAINS base. So
    # three-dot bought nothing here, and it cost everything: it resolves a MERGE BASE, the checkout is
    # shallow (depth 1), and two truncated histories routinely fail to reach their common ancestor —
    # `fatal: no merge base`. Deepening to fix that is a race (`fatal: shallow file has changed since we
    # read it`) and needs a full history to be reliable.
    #
    # A two-dot diff compares two TREES. No ancestry, no depth, nothing to race. Against the merge commit
    # it yields exactly "what this PR adds on top of base", which is the question the gate asks.
    #
    # This mattered more than it looks: the three-dot failure was SILENT. git() used to swallow a nonzero
    # exit and return "", so added_files() was [] and the gate reported PASS on every run where it could
    # not see. A false clean, on the one check whose whole purpose is never to emit one.
    def added_files(self) -> list[str]:
        """Files ADDED by this change. In CI, HEAD is the PR merged into base, so this is the PR's set."""
        if self.ci:
            return _paths(git("diff", "-z", "--name-only", "--diff-filter=A", self.base, "HEAD"))
        return _paths(git("diff", "-z", "--cached", "--name-only", "--diff-filter=A"))

    def head_text(self, path: str) -> str:
        """The file as it will exist after this commit — the INDEX, not the working tree."""
        return git("show", f"HEAD:{path}") if self.ci else git("show", f":{path}")

    def base_text(self, path: str) -> str:
        return git("show", f"{self.base}:{path}")

    def base_adr_numbers(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for f in _paths(git("ls-tree", "-z", "--name-only", self.base, "docs/adr/")):
            m = ADR_FILE.match(f)
            if m:
                out.setdefault(m.group(1), f.rsplit("/", 1)[-1])
        return out

    # -- merge parents -------------------------------------------------------------------------------
    #
    # A MERGE COMMIT ALLOCATES NOTHING. It carries forward numbers another branch already committed, and
    # the ownership rule below is keyed on the worktree that ran the allocator -- so without this, a
    # merge resolved by anyone other than the item's author is refused for carrying that author's number.
    #
    # MEASURED 2026-09-05. The Lander resolved a docs/BACKLOG.md tail conflict on PR 850 -- the routine
    # kind, two branches appending different items -- verified it (zero deleted or changed lines against
    # main, 158 added, byte-identical to the branch's own section) and could not commit it: `#1441 was
    # not allocated to this worktree`. The gate then named the owning worktree and said to commit from
    # there, which the WORKTREE gate refuses, because operating in another session's tree is what that
    # one exists to stop. Two correct controls, and between them a duty the Lander playbook assigns
    # ("docs/BACKLOG.md row conflicts -- Lander, locally") that could not be discharged from any seat.
    #
    # THIS OPENS NO HOLE, and the reason is that the grandfathered numbers are not asserted, they are
    # READ OFF A COMMIT. To launder a number this way you would need a commit that already contains it,
    # and producing one means passing this same gate on the worktree that allocated it. Editing the BODY
    # of an item that already exists was never policed here either way -- the rule compares NUMBER SETS,
    # `head - base`, so a merge cannot smuggle a subject past a check that never read subjects.
    def _merge_parents(self) -> list[str]:
        """EVERY parent of the merge commit being built, HEAD included; empty outside a merge.

        ***HEAD IS A PARENT, AND LEAVING IT OUT MISSED THE CASE THIS WAS WRITTEN FOR.*** The first
        version of this read only ``MERGE_HEAD``, which covers *their branch merged into mine* and
        not *main merged into theirs* -- and the second is the shape a Lander actually resolves,
        because the number then sits on HEAD rather than on MERGE_HEAD. Measured 2026-09-05, after
        the first fix had already landed: a faithful reproduction of the PR 850 case was still
        refused with ``#1441 was not allocated to this worktree``.

        **The test that shipped with that version merged the sibling INTO main -- the easy direction
        -- so it passed, and two mutations proved its arms disjoint from each other while both
        exercised the wrong direction.** Disjointness is not coverage.

        ``MERGE_HEAD`` is read as LINES, not via ``git rev-parse MERGE_HEAD``: an octopus merge
        writes one sha per line and rev-parse would answer only the first, silently policing the
        rest. CI never has a merge in progress -- there HEAD is already the merge commit -- so this
        is empty there and the CI path is unchanged.

        Memoized per run. ``MERGE_HEAD`` cannot change while the hook runs, and this is called once
        per rule plus once per added ADR file -- each call spawning a `git rev-parse`.
        """
        if self._parents is None:
            self._parents = self._read_merge_parents()
        return self._parents

    def _read_merge_parents(self) -> list[str]:
        if self.ci:
            return []
        path = Path(git("rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD").strip())
        if not path.is_file():
            return []
        parents = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not parents:
            return []
        # HEAD only counts once a merge is confirmed in progress. Outside one it is the commit being
        # built on, and folding it in unconditionally would stop policing an ordinary second commit
        # that adds a number to a branch -- a real narrowing, and not this fix's business.
        return [*parents, "HEAD"]

    def _carried_by_a_merge_parent(self, path: str) -> bool:
        """Does ``path`` already exist on a commit this merge is bringing in?"""
        return any(_obj_exists(f"{parent}:{path}") for parent in self._merge_parents())

    # -- restoring a number the base LOST ------------------------------------------------------------
    #
    # THE GATE HAD TWO VERBS AND A THIRD CASE FITS NEITHER (BACKLOG #1468). Allocate mints a fresh
    # number; recover hands an existing claim back to the tree entitled to it. A RESTORE is neither:
    # the number was SPENT on this exact document and the base has since lost the file.
    #
    # ***THE REASONING LIVES IN docs/LEDGER-GATE.md, "Restoring a number the base lost", AND IS NOT
    # REPEATED HERE.*** Why the predicate reads history rather than trusting the committer, which two
    # shapes were rejected for doing the opposite, and why this opens no hole are stated there once.
    # An earlier draft of this block restated all of it, and the two copies had already contradicted
    # each other on the shallow-clone question by the time anyone read them -- which is the failure
    # CLAUDE.md section 11 (SDS-3.5) names, arriving as a defect rather than as a principle.
    #
    # WHAT BELONGS HERE IS WHAT A READER OF THIS CODE CANNOT SEE FROM THE DOC:
    #
    #   it fails closed        every uncertain answer is False, and False is the status quo refusal.
    #   it never runs in CI    its only caller sits inside the `not self.ci` ownership arm.
    #   it costs nothing on    the caller is the last conjunct of a chain that has already decided to
    #     a passing commit     refuse, and ONE walk answers both questions the refusal needs.
    #   a negative is not      a shallow clone and a saturated cap both report no commits and exit 0,
    #     always an absence    so the walk returns WHY it found nothing. See _RestoreEvidence.
    def _history_of_this_number(self, path: str, number: str) -> _RestoreEvidence:
        """What the base's history says about this ADR number, in one bounded walk.

        Bounded on purpose: an ADR file is touched a handful of times, and an unbounded walk would put
        a per-commit cost inside a pre-commit hook. The bound is REPORTED rather than assumed away --
        see :class:`_RestoreEvidence`, whose ``exhausted`` flag is what stops the refusal text claiming
        the base never held bytes it simply did not walk far enough to see.
        """
        try:
            commits = git(
                "rev-list",
                f"--max-count={RESTORE_HISTORY_DEPTH}",
                self.base,
                "--",
                f"docs/adr/{number}-*.md",
            ).split()
        except OSError:  # pragma: no cover - defensive; an unreadable base is never a restore
            return _RestoreEvidence(False, False, False)
        staged = _blob_id(f":{path}")
        restores = staged is not None and any(
            _blob_id(f"{commit}:{path}") == staged for commit in commits
        )
        # "I found nothing" and "I could not look" must not share an answer. A shallow clone is the
        # measured case; a walk that hit its own cap is the other.
        truncated = (not commits and _clone_is_shallow()) or len(commits) >= RESTORE_HISTORY_DEPTH
        return _RestoreEvidence(restores, bool(commits), truncated)

    # -- ownership -----------------------------------------------------------------------------------
    def owns(self, kind: str, number: str) -> bool:
        """Was this number allocated to THIS worktree by scripts/coord/alloc.ps1?

        Keying ownership on the worktree only works because the worktree gate now forces each session into
        its own worktree; before that, every session shared the primary checkout and this key collapsed.

        ***THE PATH IS MORTAL AND THE BRANCH IS NOT, SO THE BRANCH IS A SECOND KEY (BACKLOG #1282).***
        A worktree can be removed by `rm -rf`, by `git worktree remove`, or by any cleanup that never
        consults `scripts/worktree/remove.ps1` -- whose guard is real but sits on ONE door. When that
        happens the recorded path stops matching for EVERY session, the number is uncommittable by
        anyone, and nothing reports it. Measured 2026-08-30: 43 numbers were already in that state.

        ***THE FALLBACK PRESERVES THE EXCLUSIVITY THE PATH WAS PROVIDING, AND THAT IS THE ONLY REASON
        IT IS SAFE: GIT REFUSES AN ORDINARY SECOND CHECKOUT OF ONE BRANCH IN TWO WORKTREES.*** So "the
        session on this branch" is as single-valued as "the session in this worktree" ever was -- the
        gate exists to stop two sessions filing one number, and two sessions do not hold one branch.
        What changes is that the key now survives its worktree.

        ***THAT REFUSAL IS A DEFAULT, NOT A GUARANTEE, AND THIS SENTENCE USED TO SAY "GIT REFUSES"
        FLAT (BACKLOG #1039).*** Measured: `git worktree add --force` (and `-f`) check the same branch
        out again and succeed, and `git checkout --ignore-other-worktrees` switches -- the same two
        bypasses `worktree_gate.ps1` already spells out in its own rule-3b deny text. A claim about
        this repository's CONFIGURATION was being written as a claim about git.

        **So there is a real residual, stated rather than repaired here, because repairing it is a
        change to the ownership model and not to a docstring.** Force a second checkout of the
        recorded branch and BOTH trees satisfy the fallback, so entitlement to the number leaks to a
        tree that never allocated it. It is narrow: the fallback is unreachable while the recorded
        path still matches (see the early return below), so the leak needs the recorded worktree to be
        gone AND a deliberate `--force`. It stops the ACCIDENT, not a determined bypass -- which is
        the same bound `worktree_gate.ps1` reaches about its own guard, and it is the honest strength
        of the argument above rather than a hole this change opens.

        WHY THIS AND NOT A TRANSFER VERB: a transfer verb would let a seat take a number another
        session is actively holding, which is the collision the gate exists to prevent. The branch
        fallback only becomes reachable once the original worktree is GONE -- and a branch that is
        free to check out is one nobody is working in.

        ***THE LIMIT, STATED RATHER THAN DISCOVERED: A DELETED BRANCH STRANDS THE NUMBER AGAIN.***
        That is a smaller hole (a branch is cheap to recreate at any commit, and a branch deleted
        with its work unlanded has lost more than a number) and it is not closed here. The
        owner-ruled recovery in docs/LEDGER-GATE.md -- recreate a worktree at the recorded path --
        remains valid and is now the second resort rather than the only one.
        """
        try:
            claim = json.loads((self.alloc / kind / f"{number}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        mine = str(self.repo).replace("\\", "/").casefold()
        theirs = str(claim.get("worktree", "")).replace("\\", "/").casefold()
        if mine == theirs.rstrip("/"):
            return True
        # Branch fallback. Deliberately NOT reached when the path matches, so the ordinary case is
        # unchanged and this cannot mask a path comparison that is merely wrong.
        recorded_branch = str(claim.get("branch", "")).strip()
        if not recorded_branch:
            return False
        try:
            current = git("rev-parse", "--abbrev-ref", "HEAD").strip()
        except (
            Exception
        ):  # pragma: no cover - defensive; a detached or broken HEAD is not ownership
            return False
        # A detached HEAD reports "HEAD" and names no branch, so it can never match a recorded one.
        return current != "HEAD" and current.casefold() == recorded_branch.casefold()

    def fail(self, what: str, why: str, fix: str) -> None:
        self.failures.append(f"  BLOCKED: {what}\n  {why}\n\n  Do this:\n      {fix}\n")

    def ownership_remedy(self, kind: str, number: str) -> str:
        """What to actually DO about an ownership refusal -- RECOVER the number, or allocate a new one.

        ***THE OLD TEXT NAMED ONLY THE ALLOCATOR, AND THAT IS WHAT BURNS NUMBERS.*** A refusal here is
        usually the gate working correctly: the number belongs to a live session in another worktree,
        or to this session's own other tree. Both are recoverable -- commit from the recorded worktree,
        or check out the recorded branch -- and neither was ever mentioned. So a seat that hit a correct
        refusal was steered into `alloc.ps1`, which issues a FRESH number, and the first one became a
        permanent hole ("holes are free, collisions are not" makes that irreversible).

        The cost is measurable rather than theoretical. `scripts/coord/alloc_strand_sweep.py --titles`
        reports 19 titles on this clone holding more than one number, including BACKLOG #1297/#1298,
        #1422/#1423 and #1425/#1426 -- each a number spent twice on one piece of work.

        The gate already READ the claim to decide the refusal, so naming the owner costs nothing. The
        recorded values are FOLDED through :func:`_safe_for_message` because they come out of a JSON
        field and land in prose an agent then acts on -- the BACKLOG #1040 injection route, and a
        remedy block is precisely what that defect forged.
        """
        allocate = f'pwsh -NoProfile -File scripts\\coord\\alloc.ps1 -Kind {kind} -Title "<title>"'
        try:
            claim = json.loads((self.alloc / kind / f"{number}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # No record at all: nobody holds it, so allocating is the only move and the ONLY case
            # where it is the right one.
            return allocate
        worktree = _safe_for_message(claim.get("worktree", ""))
        branch = _safe_for_message(claim.get("branch", ""))
        lines = ["this number is already allocated -- RECOVER it, do not allocate another:", ""]
        if worktree:
            lines.append(f"    1. commit from the worktree that holds it:  {worktree}")
        if branch:
            lines.append(f"    2. or check that branch out and commit there: {branch}")
        lines += [
            "       (git refuses an ORDINARY second checkout of a branch another worktree holds. Do",
            "        not force past that -- two trees on one branch is what makes the branch key above",
            "        stop being exclusive. From the worktree in 1 you can still reach it with:",
            "        git checkout -b <alias> <branch>, then push <alias>:<branch>)",
            "    3. ONLY if neither tree nor branch still exists, allocate a new number:",
            f"       {allocate}",
            "",
            "    See docs/LEDGER-GATE.md, 'Recovering a number the gate has refused'.",
        ]
        return "\n      ".join(lines)

    def _ownership_refusal(self, number: str, seen: _RestoreEvidence) -> tuple[str, str, str]:
        """Word an ownership refusal against what history actually showed (BACKLOG #1468).

        ***THE REMEDY NEVER BUILDS A SHELL COMMAND OUT OF A REPO-CONTROLLED VALUE, AND AN EARLIER
        DRAFT OF THIS DID.*** It printed ``git checkout $(git rev-list -1 <base> -- <path>)^ -- <path>``
        with the staged path interpolated. ``ADR_FILE`` admits ``[^/]+`` before ``.md``, so a file named
        ``0002-x$(id).md`` put a live command substitution inside a block this gate tells an agent to
        run -- and :func:`_safe_for_message` does not defend against that. It folds control characters
        so a value cannot forge a SECOND remedy block (BACKLOG #1040); it does not quote, so ``$( )``,
        backticks and ``;`` pass straight through. Folding is not escaping, and a command is not prose.
        The exact commands live in docs/LEDGER-GATE.md, where nothing is interpolated at all.

        ***IT ALWAYS APPENDS :meth:`ownership_remedy`, INCLUDING ON THE RESTORE WORDING.*** A claim
        record can outlive the commit that landed the number and still name a LIVE worktree, so
        "nobody can be holding a number the base already spent" is true of the ALLOCATOR and false of
        the registry. Dropping the recover-first advice on this branch would have re-introduced the
        BACKLOG #1414 number-burn through the door opened to close it.
        """
        where = self.alloc / "adr" / (number + ".json")
        remedy = self.ownership_remedy("adr", number)
        if seen.truncated:
            return (
                f"ADR {number} cannot be checked against {self.base} -- the history is TRUNCATED",
                f"This clone cannot see far enough back to tell whether {self.base} ever carried this "
                "number, so a genuine restore and an invented number look identical here. Refusing, "
                "because guessing in the other direction hands out a number that is already spent.",
                "deepen the clone, then retry:\n"
                "          git fetch --deepen=1000 origin\n"
                "      If this is NOT a restore, the number simply needs allocating:\n"
                f"      {remedy}",
            )
        if seen.number_is_historical:
            return (
                f"ADR {number} is a RESTORE, but not of the bytes {self.base} lost",
                f"{self.base} once carried an ADR at this number and no longer does. The staged file "
                "matches no blob its own path held, and the gate cannot tell a restore from a reuse by "
                "the number alone.",
                "restore the file EXACTLY first -- same path, same bytes -- with its index row, then\n"
                "      amend it in a SECOND commit; an amended file is no longer an ADD, so this rule\n"
                "      does not look at it again. The commands are in docs/LEDGER-GATE.md,\n"
                "      'Restoring a number the base lost'.\n"
                f"      If a claim record still names a live tree, prefer that route:\n      {remedy}",
            )
        return (
            f"ADR {number} was not allocated to this worktree",
            f"Nothing in {where} names {self.repo}. A sibling session may be holding this number "
            "right now.",
            remedy,
        )

    # -- rules ---------------------------------------------------------------------------------------
    def check_adrs(self) -> None:
        """ADR rules -- now the only rules this gate has. See the retirement note at the top.

        THERE IS NO ADR REVERSE ARM, AND THAT WAS DELIBERATE BEFORE THE BACKLOG HALF LEFT. The two
        ledgers hid a deletion differently. A backlog item was a HEADING inside a 30k-line file:
        absorb it into the line above and the diffstat reads 5 insertions, 1 deletion, with the
        item's whole body still present and re-attributed (BACKLOG #1470). An ADR is a FILE --
        delete it and git prints `D docs/adr/0084-x.md` in the diffstat and in the PR's file list.
        Building the same machinery against a threat git already reports is not depth, it is noise.
        So the reverse arm went with the half that needed it, and nothing is owed here.

        WHAT IS GENUINELY UNCOVERED HERE, stated rather than implied: nothing checks the ROW -> FILE
        direction, so an index row in docs/adr/README.md can outlive the file it names and the number
        reads as live to every citation checker while naming nothing. That is an index-only question --
        no parents, no base, no shallow reasoning -- and it belongs to its own row. The FILE -> ROW
        direction over the existing corpus is covered, by adr_index_coverage (BACKLOG #1516).
        """
        base_adrs = self.base_adr_numbers()
        try:
            head_readme = self.head_text("docs/adr/README.md") or self.base_text(
                "docs/adr/README.md"
            )
        except OSError:  # pragma: no cover - defensive
            head_readme = ""
        indexed = index_rows(head_readme)
        rows = [number for number, _ in indexed]
        first_rows = _first_rows(indexed)

        for path in self.added_files():
            m = ADR_FILE.match(path)
            if not m:
                continue
            number, basename = m.group(1), path.rsplit("/", 1)[-1]

            if number in base_adrs:
                # A DECLARED COMPANION is legal: one number, one index row, two files — the row itself
                # names the companion. ADR 0013 is exactly this and is CORRECT. Only an UNdeclared reuse
                # is a collision.
                if not row_names_file(first_rows.get(number, ""), basename):
                    self.fail(
                        f"ADR {number} already exists on {self.base} as "
                        f"{_safe_for_message(base_adrs[number])}",
                        "Two sessions picking the same number create DIFFERENT filenames, merge CLEAN, and "
                        "silently corrupt the ledger. This has happened 3x (d1d0a5a, 5b7d046, 9f3483d).",
                        'pwsh -NoProfile -File scripts\\coord\\alloc.ps1 -Kind adr -Title "<title>"'
                        "   # then rename your file to the number it prints",
                    )
            elif (
                not self.ci
                and not self.owns("adr", number)
                and not self._carried_by_a_merge_parent(path)
            ):
                # LAST, AND THE ORDER IS THE COST CONTROL. Everything above is cheap or memoized; the
                # history walk is not. Reaching it means the commit was already headed for a refusal,
                # so the walk is never paid on a passing commit (BACKLOG #1468).
                #
                # ***IT MUST NOT `continue`, AND WRITING IT THAT WAY ONCE IS WHY THIS SAYS SO.*** The
                # index-row rule below is the second half of THIS iteration, and a restore needs its
                # row back exactly as much as a new ADR does -- that row is how 0077, 0079 and 0080
                # went missing. Skipping the loop body on a granted restore would have shipped the
                # dropped-row defect through the restore door.
                seen = self._history_of_this_number(path, number)
                if not seen.restores_lost_bytes:
                    self.fail(*self._ownership_refusal(number, seen))

            # Only ADDED files are checked here, the right scope for a commit-time gate. The whole
            # corpus is adr_index_coverage's, and it needs no legacy exemption: 0077/0079/0080 have rows.
            if number not in rows:
                self.fail(
                    f"ADR {number} ({_safe_for_message(basename)}) has no row in docs/adr/README.md",
                    "An ADR that is not in the index is invisible — the tail-append hazard shows up as a "
                    "DROPPED ROW, not as a conflict. Three ADRs were already lost this way.",
                    "add its row to docs/adr/README.md in THIS commit",
                )
            elif number not in base_adrs and not row_names_file(
                first_rows.get(number, ""), basename
            ):
                # BACKLOG #2002. A row for the number is not enough: a row naming a DIFFERENT file
                # leaves this one unindexed. A base number already got this test above, as the
                # companion question, so asking it again there would only repeat that refusal.
                # The text names the number, not the staged basename: a filename is attacker-
                # influenceable and _safe_for_message folds but does not quote (see
                # test_the_refusal_never_builds_a_SHELL_COMMAND_from_the_staged_path).
                self.fail(
                    f"ADR {number}'s row in docs/adr/README.md does not link the {number} file "
                    "this commit adds",
                    "A row for the number exists, but it does not link this file, so this ADR is "
                    "invisible in the index while the number reads as indexed.",
                    "make the row link this file (a second file under one number is linked inside "
                    "the row, as a declared companion)",
                )

        duplicated = sorted({n for n in rows if rows.count(n) > 1})
        if duplicated:
            self.fail(
                f"duplicate index row(s) in docs/adr/README.md: {duplicated}",
                "One number must have exactly one row (a companion file is named INSIDE its number's row, "
                "it does not get a second row).",
                "remove the duplicate row",
            )

    def run(self) -> int:
        self.check_adrs()
        if not self.failures:
            return 0
        print("\nMessageFoundry ledger gate\n", file=sys.stderr)
        for f in self.failures:
            print(f, file=sys.stderr)
        print(
            "  Do NOT work around this by renaming the file, editing a copy, or using --no-verify: all of\n"
            "  those leave a ledger that merges CLEAN and is invisible to git. If you cannot proceed, STOP\n"
            '  and tell the user: "The ledger gate blocked this commit and I need guidance."\n',
            file=sys.stderr,
        )
        return 1


def main(argv: list[str]) -> int:
    return Ledger(ci="--ci" in argv).run()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
