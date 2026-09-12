#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Ledger gate — stop two concurrent sessions from silently colliding on an ADR / BACKLOG number.

THE DEFECT THIS EXISTS FOR. Two sessions each grep for "the next free number", both pick N, and create
DIFFERENTLY-NAMED files (docs/adr/0084-alpha.md and docs/adr/0084-beta.md, or two `## 227.` headings
1,600 lines apart in BACKLOG.md). Git merges both **cleanly** — there is no textual conflict — and the
ledger is quietly corrupt. It has happened three times here (d1d0a5a #574, 5b7d046 #598, 9f3483d), and it
is the one measured collision class that a worktree, a file lock, and `git merge-tree` are all blind to.

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

import functools
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ADR_FILE = re.compile(r"^docs/adr/(\d{4})-[^/]+\.md$")
INDEX_ROW = re.compile(r"^\|\s*\[(\d{4})\]", re.M)

# THE ITEM NUMBER SPACE SPANS MORE THAN ONE FILE.
#
# docs/BACKLOG.md carries the OPEN items; retired ones are moved verbatim into docs/archive/backlog/.
# A number is taken if it appears in EITHER, so every rule below reads their union. Keying on the one
# published path was safe only while it was the only path, and would leave the archive an unpoliced
# region: a commit touching only the archive would early-return having checked nothing, and two
# sessions could file the same number there and merge clean -- the exact collision this gate exists
# to stop, reintroduced through the back door of a file it does not look at.
#
# Reading the union on BOTH sides also disposes of a false positive that a base-only view would
# create: the move commit RELOCATES 185 items, so head-union == base-union and `head - base` is
# empty. A per-file view would instead see 185 numbers vanish from BACKLOG.md and, on any worktree
# whose base straddles the move, report them -- with a remedy that would renumber cited items.
BACKLOG_PATH = "docs/BACKLOG.md"
BACKLOG_ARCHIVE_DIR = "docs/archive/backlog"

# THE PUBLIC BACKLOG NUMBER SPACE IS PARTITIONED AT #1000.
#
# docs/BACKLOG.md is a published baseline of a larger maintainer-internal ledger. The two sequences
# diverged around #231 and have been allocated INDEPENDENTLY since, so one number can name two
# unrelated items: public #248 and internal #248 are different work. That overlap is recorded, not
# repaired -- renumbering would rewrite ratified ADRs and an operator-facing refusal string that ships
# inside the wheel, and it would not stop the NEXT one. It would only make stale citations resolve
# uniquely and WRONGLY, which is worse than resolving ambiguously.
#
# The partition stops the next one. New items here are allocated at #1000+, the internal sequence stays
# below (high-water 314 when this landed), so the overlapping set is CLOSED at the numbers already
# issued and a cited #N >= 1000 is unambiguously an item in THIS file.
#
# Why a constant and not a manifest of reserved numbers: a manifest cannot fire. `## 316.` is already
# on origin/main and alloc.ps1's floor is max(...)+1 over a sweep that includes it, so every clone
# issues >= 317 while a manifest of internal numbers tops out at 314 -- the reject set and the emit set
# never intersect. A manifest would also be born stale (its source refs belong to a remote this clone
# no longer lists), be regenerable on exactly one machine, and be the very instrument the erratum
# convicts: "the published baseline is not a safe place to check a number against; only the allocator
# is." A constant has no source data, so it cannot rot.
#
# This is the ONE backlog rule that also runs in --ci. The ownership rule cannot: it reads a per-clone
# registry under .git and compares a worktree path, and a runner has neither -- which left the CI half
# of check_backlog() computing a set and discarding it, i.e. unable to fail at all. A floor needs no
# registry, no worktree, and no sight of the internal ledger (CI checks out origin only).
#
# KNOWN RESIDUAL, and it is NOT detected anywhere: this binds only the public side, and nothing in this
# repository can stop -- or observe -- the maintainer-internal ledger allocating past #1000.
#
# This comment used to claim alloc.ps1 "warns at allocation time if the all-refs maximum ever reaches
# this boundary". That was the wrong instrument twice over, and it was the defect written down:
#   - The all-refs maximum has NO PROVENANCE. A public item legitimately allocated at the boundary and
#     an internal breach are the same observation. That guard fired on BACKLOG #1000 -- correct input --
#     and bricked every backlog allocation in the repo until 2026-08-03.
#   - It claimed a liveness the ref store does not have. The vault-ish remote-tracking refs it would
#     read are a FOSSIL: no configured refspec advances them, the newest is older than the partition
#     itself, and a fresh clone has none at all.
# alloc.ps1 now warns only on the highest number BELOW the boundary (which over-states the internal
# high-water, so it warns early), and refuses only on a lowered boundary, which is locally observable.
#
# Raising this number is a one-line reviewable source change, deliberately not an allowlist file that
# would rot out of sight. LOWERING it is the dangerous direction and is the one thing neither this gate
# nor CI can catch -- both read only the current value and have no memory of the previous one -- so
# alloc.ps1 keeps a `.boundary-highwater` ratchet beside its registry and refuses when the constant
# drops beneath a value that clone has already allocated against.
#
# THIS LINE IS PARSED, not imported: scripts/coord/alloc.ps1 regex-matches it so the floor is defined
# exactly once and the allocator can never emit a number this gate refuses. Keep the name and the
# literal on ONE line. A type annotation is tolerated; splitting, computing, or renaming it is not, and
# would make every backlog allocation refuse. tests/test_ledger_check.py pins the contract, so that
# break lands in CI on whoever edits this line rather than on an unrelated session days later.
PUBLIC_BACKLOG_FLOOR = 1000

# WHAT COUNTS AS AN ITEM IS THE PARSER'S TO SAY, AND THIS GATE ASKS IT (BACKLOG #1470).
#
# This file used to carry `BACKLOG_HEADING = re.compile(r"^#{2,3} (\d+)\.", re.M)` and scan with it.
# That was a SECOND definition of item identity sitting beside `backlog_status_check.parse_items`,
# which is the one CLAUDE.md section 11 names as the single source -- and the two do not agree:
# the local regex counted a `### N.` SUB-heading inside an item's body as an item of its own, and
# `parse_items` does not. Measured 2026-09-10 over both ledger files: the two readings return the
# SAME 746 ids, so nothing changes today -- they agree on this corpus by luck, which is exactly the
# hazard section 11 records, and the fix is to stop having two readings rather than to keep checking
# that they still match. Positive control for that measurement: against a planted
# `### 99999. a sub-heading`, the old regex reports 99999 and `parse_items` does not, so the
# comparison can report a difference and the agreement above is a result rather than a broken probe.
#
# NOT REPO-WIDE, and claiming otherwise would be the thing this comment is about.
# `scripts/coord/alloc_strand_sweep.py` still carries the identical regex, in a function that models
# THIS gate's arithmetic; the divergence is recorded at that site rather than repaired from here.
STATUS_CHECK = Path(__file__).resolve().parents[1] / "docs" / "backlog_status_check.py"

# THE REMEDY DEPENDS ON WHICH TREE THE MARKER IS IN, so it is chosen at the read and not at the catch.
# "Re-stage the file" is right for the index and UNPERFORMABLE for `origin/main` or a parent commit --
# the marker is in committed history and there is nothing of yours to stage. That matters more here
# than it looks: this gate's deny text is read by an agent that then does what it says (BACKLOG
# #1040), and an instruction it cannot carry out leaves `--no-verify` as the only move, which run()'s
# own footer forbids by name. A gate must not be unexitable by its own instructions.
FIX_STAGED = "resolve the conflict, re-stage docs/BACKLOG.md, and commit again"
FIX_COMMITTED_CONFLICT = (
    "this marker is in COMMITTED history, not in your index -- there is nothing to re-stage. Find the "
    "commit that carries it (git log -S '<<<<<<<' -- docs/BACKLOG.md) and repair the ledger there"
)


class ConflictedLedger(Exception):
    """A ledger source that `parse_items` refuses to read -- it still carries a conflict marker.

    Carries its own remedy because only the READ site knows which tree the marker is in.
    """

    def __init__(self, detail: str, remedy: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.remedy = remedy


@functools.cache
def _load_status_check() -> Any:
    """Import `backlog_status_check` by PATH -- `scripts/` is not an importable package.

    This is the same by-path load `dangling_citation_check.py`, `banner_sha_check.py` and
    `subject_exists_screen.py` use, and it keeps this file's stdlib-only promise: that module imports
    only argparse/re/sys/pathlib, so a worktree with no .venv still runs the gate.

    ***AN IMPORT IS SAFE HERE AND WOULD NOT BE IN EVERY HOOK, so do not copy this into a sibling
    without re-checking.*** `_safe_for_message` below is a LOCAL COPY precisely because
    `install-git-hooks.ps1` Copy-Items its file into the git hooks directory, where a relative import
    resolves at development time and fails when the gate runs. That stopped being true of THIS file:
    the installer now `Remove-Item`s a previously-installed `.git/hooks/ledger_check.py` and the gate
    runs from the tree as a `local` pre-commit hook (`entry: python scripts/hooks/ledger_check.py`).
    `claim_check.py` and `push_guard.py` are still copied, so the local-copy reasoning still binds
    there.

    Fails LOUDLY when the module is missing. A gate that silently skips is worse than no gate, and an
    unreadable item set would read as "no numbers taken" -- the false clean this file exists to
    prevent.
    """
    spec = importlib.util.spec_from_file_location("_backlog_status_check", STATUS_CHECK)
    if spec is None or spec.loader is None:  # pragma: no cover - a broken checkout, not a state
        raise RuntimeError(f"cannot load {STATUS_CHECK}")
    module = importlib.util.module_from_spec(spec)
    # Registered BEFORE execution, for the reason subject_exists_screen.py records: dataclass
    # processing resolves sys.modules[cls.__module__] mid-class-body, and an unregistered module
    # turns that into an AttributeError naming neither file.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def item_numbers(text: str, where: str, remedy: str) -> set[str]:
    """Every `## N.` item id in ``text``, read through the parser that DEFINES what an item is.

    Ids come back as STRINGS to match the rest of this file, which sorts with ``key=int`` and
    compares against the floor with ``int(number)``.

    `parse_items` REFUSES a source still carrying a conflict marker rather than miscounting it, and
    that refusal is converted into a gate failure here instead of a traceback: this gate's own worst
    recorded failure mode was crashing on the files it guards, and a traceback reads as "the hook is
    broken" rather than "your ledger is conflicted".

    ``where`` is a REF SPEC and is folded through :func:`_safe_for_message` at the RAISE, not at the
    catch, so the invariant holds for every future catcher. It reaches deny prose an agent acts on,
    and it is built from `git ls-tree` / `git ls-files` output -- the BACKLOG #1040 route.
    """
    try:
        return {str(item.num) for item in _load_status_check().parse_items(text)}
    except ValueError as exc:
        raise ConflictedLedger(
            f"{_safe_for_message(where, 120)}: {_safe_for_message(exc)}", remedy
        ) from exc


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
        # Measured 2026-09-10 on this box: a `git` spawn is 53-315 ms whatever it does, and
        # `_backlog_numbers_at` is five spawns plus two full parses of a 30k-line file per ref.
        self._parents: list[str] | None = None
        self._numbers_at: dict[str, set[str]] = {}

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
            return git("diff", "--name-only", "--diff-filter=A", self.base, "HEAD").split()
        return git("diff", "--cached", "--name-only", "--diff-filter=A").split()

    def changed_files(self) -> list[str]:
        if self.ci:
            return git("diff", "--name-only", self.base, "HEAD").split()
        return git("diff", "--cached", "--name-only").split()

    def head_text(self, path: str) -> str:
        """The file as it will exist after this commit — the INDEX, not the working tree."""
        return git("show", f"HEAD:{path}") if self.ci else git("show", f":{path}")

    def base_text(self, path: str) -> str:
        return git("show", f"{self.base}:{path}")

    def base_has(self, path: str) -> bool:
        """Does the base ref contain ``path`` at all?

        A ledger file being ADDED legitimately has no base version, and `git show base:path` exits 128
        for that — indistinguishable, to :func:`git`, from a real failure, which it must keep raising on
        (an error swallowed as "empty ledger" reads as "no numbers taken", the false-clean this gate
        exists to prevent). So absence is probed EXPLICITLY here, and only after the base ref itself is
        verified — otherwise a bad/unfetched base would quietly answer "absent" and disable the check.
        """
        git("rev-parse", "--verify", f"{self.base}^{{commit}}")
        return _obj_exists(f"{self.base}:{path}")

    def head_has(self, path: str) -> bool:
        """Does the commit under test contain ``path``? Mirrors :meth:`head_text`'s ref.

        The symmetric case to :meth:`base_has`, and it bites the moment a ledger file is FIRST
        published. In CI the change set is `diff base HEAD`, so once ``origin/main`` gains a file that
        a branch predates, that branch's diff lists it — as a DELETION relative to base — even though
        the branch never touched it. The rule then reads HEAD for a copy that was never there and
        `git show HEAD:path` exits 128. That is not a ledger violation; it is a stale branch, and it
        broke every open branch the hour docs/BACKLOG.md landed.
        """
        return _obj_exists(f"HEAD:{path}" if self.ci else f":{path}")

    def base_adr_numbers(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for f in git("ls-tree", "--name-only", self.base, "docs/adr/").split():
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

    def _backlog_numbers_at(self, ref: str) -> set[str]:
        """Every ``## N.`` number carried by ``ref``, across the live file and the archive.

        Mirrors :meth:`backlog_paths` for an arbitrary commit rather than for base/head, and probes each
        path's existence for the same reason that method does: a listed-but-absent path makes `git show`
        exit 128, which :func:`git` correctly raises on and which would read here as a crash rather than
        as "this ref has no archive".

        ***THE CALLER MUST ASK :meth:`_ref_is_readable` FIRST.*** An unreadable ref answers ``set()``
        here, and empty means two opposite things -- "there is nothing prior" for an unborn HEAD,
        which is truthful, and "this object was never fetched" on a shallow clone, which means the
        rule did not run. This file raises rather than answer empty everywhere else for exactly that
        reason, so the discrimination is the caller's and is not optional.

        Memoized per ref: refs do not move inside one run, and each miss costs three `git` spawns plus
        a full parse per ledger path.
        """
        cached = self._numbers_at.get(ref)
        if cached is not None:
            return cached
        out: set[str] = set()
        if self._ref_is_readable(ref):
            paths = [BACKLOG_PATH] if _obj_exists(f"{ref}:{BACKLOG_PATH}") else []
            listing = git("ls-tree", "-r", "--name-only", ref, f"{BACKLOG_ARCHIVE_DIR}/")
            paths += [p for p in listing.split() if p.endswith(".md")]
            for p in paths:
                out |= item_numbers(git("show", f"{ref}:{p}"), f"{ref}:{p}", FIX_COMMITTED_CONFLICT)
        self._numbers_at[ref] = out
        return out

    @staticmethod
    def _ref_is_readable(ref: str) -> bool:
        """Is ``ref``'s commit object actually in this clone?

        False for an unborn HEAD (the first commit in a repository, which the test rig reaches) and
        for a commit a shallow checkout never fetched. Those are different states and the caller must
        keep them apart -- see :meth:`_backlog_numbers_at`.
        """
        return _obj_exists(f"{ref}^{{commit}}")

    def _carried_by_a_merge_parent(self, path: str) -> bool:
        """Does ``path`` already exist on a commit this merge is bringing in?"""
        return any(_obj_exists(f"{parent}:{path}") for parent in self._merge_parents())

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

    # -- rules ---------------------------------------------------------------------------------------
    def check_adrs(self) -> None:
        """ADR rules. NOTE THE ASYMMETRY WITH check_backlog, WHICH IS DELIBERATE AND NOT AN OVERSIGHT.

        There is no ADR equivalent of the backlog REVERSE arm, because the two ledgers hide a deletion
        differently. A backlog item is a HEADING inside a 30k-line file: absorb it into the line above
        and the diffstat reads 5 insertions, 1 deletion, with the item's whole body still present and
        re-attributed (BACKLOG #1470). An ADR is a FILE -- delete it and git prints
        `D docs/adr/0084-x.md` in the diffstat and in the PR's file list. Building the same machinery
        against a threat git already reports is not depth, it is noise.

        WHAT IS GENUINELY UNCOVERED HERE, stated rather than implied: nothing checks the ROW -> FILE
        direction, so an index row in docs/adr/README.md can outlive the file it names and the number
        reads as live to every citation checker while naming nothing. That is an index-only question --
        no parents, no base, no shallow reasoning -- and it belongs to its own row.
        """
        base_adrs = self.base_adr_numbers()
        try:
            head_readme = self.head_text("docs/adr/README.md") or self.base_text(
                "docs/adr/README.md"
            )
        except OSError:  # pragma: no cover - defensive
            head_readme = ""
        rows = INDEX_ROW.findall(head_readme)

        for path in self.added_files():
            m = ADR_FILE.match(path)
            if not m:
                continue
            number, basename = m.group(1), path.rsplit("/", 1)[-1]

            if number in base_adrs:
                # A DECLARED COMPANION is legal: one number, one index row, two files — the row itself
                # names the companion. ADR 0013 is exactly this and is CORRECT. Only an UNdeclared reuse
                # is a collision.
                row = next(
                    (ln for ln in head_readme.splitlines() if ln.startswith(f"| [{number}]")), ""
                )
                if basename.removesuffix(".md") not in row:
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
                self.fail(
                    f"ADR {number} was not allocated to this worktree",
                    f"Nothing in {self.alloc / 'adr' / (number + '.json')} names {self.repo}. A sibling "
                    "session may be holding this number right now.",
                    self.ownership_remedy("adr", number),
                )

            # Only ADDED files are checked for an index row: three legacy ADRs (0077/0079/0080) shipped
            # without one, and failing every unrelated commit over old debt is how a gate gets uninstalled.
            if number not in rows:
                self.fail(
                    f"ADR {number} ({_safe_for_message(basename)}) has no row in docs/adr/README.md",
                    "An ADR that is not in the index is invisible — the tail-append hazard shows up as a "
                    "DROPPED ROW, not as a conflict. Three ADRs were already lost this way.",
                    "add its row to docs/adr/README.md in THIS commit",
                )

        duplicated = sorted({n for n in rows if rows.count(n) > 1})
        if duplicated:
            self.fail(
                f"duplicate index row(s) in docs/adr/README.md: {duplicated}",
                "One number must have exactly one row (a companion file is named INSIDE its number's row, "
                "it does not get a second row).",
                "remove the duplicate row",
            )

    def backlog_paths(self, side: str) -> list[str]:
        """Every file carrying numbered items on ``side`` ('head' or 'base').

        Enumerated per side rather than assumed, because the archive does not exist on a base that
        predates it, and a path listed but absent makes `git show` exit 128 — indistinguishable from
        a real failure, which is the false-clean this gate must never produce.
        """
        if side == "base":
            listing = git("ls-tree", "-r", "--name-only", self.base, f"{BACKLOG_ARCHIVE_DIR}/")
            have_main = self.base_has(BACKLOG_PATH)
        elif self.ci:
            listing = git("ls-tree", "-r", "--name-only", "HEAD", f"{BACKLOG_ARCHIVE_DIR}/")
            have_main = self.head_has(BACKLOG_PATH)
        else:
            # The INDEX, matching head_text() — a staged archive edit must be policed before it lands.
            listing = git("ls-files", "--", f"{BACKLOG_ARCHIVE_DIR}/")
            have_main = self.head_has(BACKLOG_PATH)
        paths = [BACKLOG_PATH] if have_main else []
        paths += [p for p in listing.split() if p.endswith(".md")]
        return paths

    def check_backlog(self) -> None:
        changed = self.changed_files()
        if not any(f == BACKLOG_PATH or f.startswith(f"{BACKLOG_ARCHIVE_DIR}/") for f in changed):
            return
        base_paths = self.backlog_paths("base")
        if not base_paths:
            # The base has no backlog at all — the file is being ADDED (it was gitignored until the
            # cutover published it). Numbers that do not exist on base cannot be collided with, so
            # there is nothing to police; without this, importing the ledger wholesale would report
            # every one of its ~229 items as "not allocated to this worktree".
            return
        head_paths = self.backlog_paths("head")
        if not head_paths:
            # Present on base, absent here: a branch that PREDATES the file's publication. CI diffs
            # against origin/main, so the file shows up as "changed" (a deletion relative to base)
            # although the branch never touched it — and reading HEAD for a copy that was never there
            # exits 128. A stale branch is not a ledger violation.
            return
        try:
            head, base, prior = self._item_sets(head_paths, base_paths)
        except ConflictedLedger as exc:
            self.fail(
                "the ledger under test does not parse",
                f"{exc.detail} A conflicted ledger parses WITHOUT error into a census that counts "
                "items from BOTH sides, so the number looks right -- which is why the reader refuses "
                "instead. The item sets below could not be computed, so NOTHING was checked on this "
                "run.",
                exc.remedy,
            )
            return
        # Only `head - base` is examined, so everything already on origin/main -- including the
        # pre-partition overlap -- is grandfathered by construction. No allowlist, nothing to maintain.
        for number in sorted(head - base, key=int):
            # Floor first: a below-floor number gets the reason that is actionable, rather than
            # "not allocated to this worktree", which would send you to re-run the allocator and file
            # at whatever it prints -- correct by luck rather than because you were told why.
            if int(number) < PUBLIC_BACKLOG_FLOOR:
                self.fail(
                    f"BACKLOG item #{number} is below the public floor (#{PUBLIC_BACKLOG_FLOOR})",
                    "Numbers under the floor belong to the maintainer-internal ledger this file is a "
                    "published baseline of, or to the pre-partition overlap. Filing one means every "
                    "citation of it resolves to two unrelated items -- and it looks like success. This "
                    "also catches a branch cut before the partition whose number has since been "
                    "re-allocated. See the Ledger erratum at the top of docs/BACKLOG.md.",
                    'pwsh -NoProfile -File scripts\\coord\\alloc.ps1 -Kind backlog -Title "<title>"'
                    "   # issues >=1000 now; move your heading to the number it prints",
                )
            elif not self.ci and not self.owns("backlog", number):
                self.fail(
                    f"BACKLOG item #{number} was not allocated to this worktree",
                    "BACKLOG numbers are '## N.' headings inside ONE 6.7k-line file. Two sessions adding "
                    "#N land ~1,600 lines apart, merge CLEAN, and both ship (cf. 5b7d046 / #598).",
                    self.ownership_remedy("backlog", number),
                )
        # THE REVERSE ARM. Everything above asks which numbers APPEARED; nothing asked which
        # DISAPPEARED, and an item can be destroyed without any number appearing (BACKLOG #1470).
        for number in sorted(prior - head, key=int):
            self.fail(
                f"BACKLOG item #{number} is on this change's parent and on {self.base}, and this "
                "change DELETES it",
                "An item is destroyed by losing its '## N.' heading, not by having its body deleted: "
                "the banner, the fields and the whole body stay in the file, silently re-attributed to "
                "the item ABOVE it. Measured on 642225f78, where an appended paragraph absorbed the "
                "'## 1147.' heading -- the diffstat read 5 insertions and 1 deletion, the commit "
                "message never named the item, and every wired gate stayed green while main carried "
                "442 items where it should carry 443. Items are RETIRED by moving them verbatim into "
                f"{BACKLOG_ARCHIVE_DIR}/, which keeps the number in this set, so a move is not this.",
                f"restore the '## {number}.' heading line -- it goes ABOVE the blockquote carrying the "
                "status banner, which is not always the earliest blockquote in the block",
            )

    def _parents_under_test(self) -> list[str]:
        """The commits the change under test is built ON -- its parents, on either path.

        In ``--ci`` the commit DOES exist -- HEAD is the PR merged into base -- so its parents are read
        straight off it.

        ***OFF THE RAW COMMIT OBJECT, NOT `git rev-list --parents`, AND THE DIFFERENCE IS WHETHER THIS
        ARM RUNS IN CI AT ALL.*** `actions/checkout` takes `refs/pull/N/merge` at its default depth of
        1, so HEAD is a SHALLOW GRAFT and rev-list honours the graft by reporting NO parents. An empty
        parent list yields an empty prior set, which is indistinguishable from a clean answer -- the
        arm would be dead in CI and every test would still pass. `git cat-file commit` prints the
        object's own header, which lists every parent whether or not the graft hides them and whether
        or not the objects are present.

        **Measured 2026-09-10, and the FIRST measurement was wrong in the reassuring direction, which
        is why both are recorded.** A rig where HEAD sat on `main` showed rev-list recovering the
        parent after the deepen, i.e. "no problem". Re-run on the shape CI actually has -- a merge ref
        cloned at depth 1, then `git fetch --no-tags --depth=200 origin main` exactly as the ledger
        step runs it -- rev-list reported **1 token (no parents) both before and after the deepen**,
        while cat-file reported **2 parents** in both states. After the deepen the FIRST parent's
        object was PRESENT and the second's ABSENT, so the base tip -- where this arm's whole CI
        coverage lives -- is readable and the PR head is the documented residual.

        Parsing stops at the first blank line: that ends the commit header, and a message line may
        legitimately begin with "parent ".

        Pre-commit the commit does not exist yet, so its parents are ``HEAD`` plus, mid-merge,
        whatever :meth:`_merge_parents` reads out of ``MERGE_HEAD`` (that method already appends HEAD
        itself once a merge is confirmed, and returns empty outside one).
        """
        if not self.ci:
            return self._merge_parents() or ["HEAD"]
        parents: list[str] = []
        for line in git("cat-file", "commit", "HEAD").splitlines():
            if not line:
                break
            if line.startswith("parent "):
                parents.append(line[len("parent ") :].strip())
        return parents

    def _prior_item_numbers(self) -> set[str]:
        """The item ids the change under test is BUILT ON -- the left-hand side of the reverse arm.

        ***THE PRIOR SIDE IS THE COMMIT'S OWN PARENTS, NOT ``origin/main``, AND THAT IS THE WHOLE
        DESIGN.*** The forward arm can compare against ``origin/main`` because a number that is there
        and not here is simply one you did not add. The reverse arm cannot, because a two-way
        comparison cannot see WHICH SIDE MOVED. Both directions of that would have been live defects:

        - Pre-commit, ``origin/main`` legitimately carries items a branch cut an hour ago has never
          seen, so the arm would refuse a commit on every stale branch in the repository.
        - In CI it is worse, because the leg is REQUIRED. HEAD is the merge ref computed when the
          event fired; ``origin/main`` is fetched when the job starts. Anything that merges in
          between is in ``base`` and not in ``head``, and a rule reading ``base - head`` would report
          somebody else's landed item as destroyed by this PR. Under a merge queue that window is
          minutes wide.

        Asking the parents instead makes the rule local and one-sided: *a commit must not drop an id
        one of its own parents had*. Main advancing afterwards changes nothing.

        The caller intersects this with ``base``, which is the false-positive guard -- see
        :meth:`_item_sets`.

        ***ONE STATED RESIDUAL.*** In CI a parent whose commit object the shallow checkout never
        fetched contributes nothing. In practice that is the PR head, whose ids are additions the
        forward arm owns; the base tip -- where this arm's whole CI coverage lives -- arrives with the
        workflow's ``git fetch --depth=200 origin main``. A run where NO parent is readable is not
        narrowed silently: it is refused below, because "nothing prior" and "the rule did not run"
        must not look alike.
        """
        refs = self._parents_under_test()
        prior: set[str] = set()
        for ref in refs:
            prior |= self._backlog_numbers_at(ref)
        if refs and not any(self._ref_is_readable(ref) for ref in refs):
            # ***THIS IS THE ONE PLACE THE REVERSE ARM CAN GO BLIND, SO IT SAYS SO.*** In --ci the
            # parents arrive only because ci.yml deepens origin/main; trim that fetch to --depth=1 as
            # a plausible speedup and every parent goes unreadable, `prior` goes empty, the arm stops
            # firing and every test still passes. An empty answer here would be indistinguishable
            # from a clean one, which is the false clean this whole file is written against.
            self.fail(
                "the reverse arm could not read ANY parent of the commit under test",
                f"Refs asked for: {_safe_for_message(' '.join(refs))}. None of their commit objects "
                "is in this clone, so 'no item was deleted' could not be established -- it was merely "
                "not observable. In CI this means the checkout is too shallow to reach the base tip.",
                "deepen the checkout (ci.yml fetches origin main at --depth=200 for exactly this)",
            )
        return prior

    def _item_sets(
        self, head_paths: list[str], base_paths: list[str]
    ) -> tuple[set[str], set[str], set[str]]:
        """``(head, base, prior)`` -- the three id sets both arms of the backlog rule compare.

        Raises :class:`ConflictedLedger` when any source still carries a conflict marker.
        """
        # The head side is the INDEX pre-commit and the HEAD COMMIT in --ci, matching head_text(), and
        # only the first of those is something you can re-stage.
        head_ref, head_fix = ("HEAD", FIX_COMMITTED_CONFLICT) if self.ci else ("", FIX_STAGED)
        head: set[str] = set()
        for p in head_paths:
            head |= item_numbers(self.head_text(p), f"{head_ref}:{p}", head_fix)
        base: set[str] = set()
        for p in base_paths:
            base |= item_numbers(self.base_text(p), f"{self.base}:{p}", FIX_COMMITTED_CONFLICT)
        # A merge allocates nothing: numbers the other parent already carries are not new here. See
        # the MERGE PARENTS block above for why this is safe and what it cost when it was missing.
        for parent in self._merge_parents():
            base |= self._backlog_numbers_at(parent)
        # ***TWO SEPARATE THINGS ON ONE LINE, AND THE `& base` IS THE LOAD-BEARING ONE. DO NOT DELETE
        # IT AS REDUNDANT WITH THE SHORT-CIRCUIT.***
        #
        # `& base` is BEHAVIOUR. It confines the reverse arm to numbers that reached shared history,
        # which is what stops `git commit --amend` withdrawing an item you filed one commit ago from
        # reading as destruction -- the parent has it, the index does not, and that is byte-for-byte
        # the shape the arm refuses. Without it the gate falsely refuses a pre-commit on any branch
        # that withdrew a number it invented. `_prior_item_numbers`' docstring states the rule; this
        # is where it is applied. Pinned by
        # test_a_number_this_branch_INVENTED_and_then_withdrew_is_not_a_deletion, and pinned ONLY
        # because that test's rig keeps `base - head` non-empty: an earlier rig left it empty, so the
        # short-circuit below fired first and the whole intersection could be deleted with every test
        # green. Measured 2026-09-11 -- deleting `& base` reddens that one test and nothing else.
        #
        # `if base - head` is PERFORMANCE ONLY and changes no verdict. `prior - head` expands to
        # `P & (base - head)`, so an empty difference makes the arm unable to report anything -- the
        # shape of every ordinary commit, which adds items and deletes none. Measured 2026-09-10, the
        # skip saves six git subprocesses (582 ms) and two full parses of a 30k-line file. A branch
        # behind origin/main has a non-empty difference and pays.
        prior = self._prior_item_numbers() & base if base - head else set()
        return head, base, prior

    def run(self) -> int:
        self.check_adrs()
        self.check_backlog()
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
