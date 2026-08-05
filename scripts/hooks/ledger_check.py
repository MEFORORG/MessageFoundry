#!/usr/bin/env python3
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

import json
import re
import subprocess
import sys
from pathlib import Path

ADR_FILE = re.compile(r"^docs/adr/(\d{4})-[^/]+\.md$")
INDEX_ROW = re.compile(r"^\|\s*\[(\d{4})\]", re.M)
BACKLOG_HEADING = re.compile(r"^#{2,3} (\d+)\.", re.M)

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

    # -- ownership -----------------------------------------------------------------------------------
    def owns(self, kind: str, number: str) -> bool:
        """Was this number allocated to THIS worktree by scripts/coord/alloc.ps1?

        Keying ownership on the worktree only works because the worktree gate now forces each session into
        its own worktree; before that, every session shared the primary checkout and this key collapsed.
        """
        try:
            claim = json.loads((self.alloc / kind / f"{number}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        mine = str(self.repo).replace("\\", "/").casefold()
        theirs = str(claim.get("worktree", "")).replace("\\", "/").casefold()
        return mine == theirs.rstrip("/")

    def fail(self, what: str, why: str, fix: str) -> None:
        self.failures.append(f"  BLOCKED: {what}\n  {why}\n\n  Do this:\n      {fix}\n")

    # -- rules ---------------------------------------------------------------------------------------
    def check_adrs(self) -> None:
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
                        f"ADR {number} already exists on {self.base} as {base_adrs[number]}",
                        "Two sessions picking the same number create DIFFERENT filenames, merge CLEAN, and "
                        "silently corrupt the ledger. This has happened 3x (d1d0a5a, 5b7d046, 9f3483d).",
                        'pwsh -NoProfile -File scripts\\coord\\alloc.ps1 -Kind adr -Title "<title>"'
                        "   # then rename your file to the number it prints",
                    )
            elif not self.ci and not self.owns("adr", number):
                self.fail(
                    f"ADR {number} was not allocated to this worktree",
                    f"Nothing in {self.alloc / 'adr' / (number + '.json')} names {self.repo}. A sibling "
                    "session may be holding this number right now.",
                    'pwsh -NoProfile -File scripts\\coord\\alloc.ps1 -Kind adr -Title "<title>"',
                )

            # Only ADDED files are checked for an index row: three legacy ADRs (0077/0079/0080) shipped
            # without one, and failing every unrelated commit over old debt is how a gate gets uninstalled.
            if number not in rows:
                self.fail(
                    f"ADR {number} ({basename}) has no row in docs/adr/README.md",
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
        head: set[str] = set()
        for p in head_paths:
            head |= set(BACKLOG_HEADING.findall(self.head_text(p)))
        base: set[str] = set()
        for p in base_paths:
            base |= set(BACKLOG_HEADING.findall(self.base_text(p)))
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
                    'pwsh -NoProfile -File scripts\\coord\\alloc.ps1 -Kind backlog -Title "<title>"',
                )

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
