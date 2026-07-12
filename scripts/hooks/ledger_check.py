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


def git(*args: str) -> str:
    # encoding= is REQUIRED, not cosmetic: `text=True` alone decodes with the LOCALE default, which is
    # cp1252 on a stock Windows box. docs/BACKLOG.md and docs/adr/README.md are UTF-8 (em-dashes, ✅, ⚠️),
    # so the decode raised inside subprocess's reader thread, `proc.stdout` came back **None**, and the
    # caller died on `findall(None)` — blocking every commit that touched either ledger file. The gate's
    # own failure mode was the one it exists to prevent: silent, and worst on the files it guards.
    proc = subprocess.run(
        ["git", *args], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    # A git failure (bad ref, missing path) must not read as "the file is empty" — an empty ledger parses
    # as "no numbers taken", which is exactly the false-clean this gate must never emit.
    if proc.returncode != 0:
        raise OSError(
            f"git {' '.join(args)} failed ({proc.returncode}): {(proc.stderr or '').strip()}"
        )
    return proc.stdout or ""


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

    def check_backlog(self) -> None:
        if "docs/BACKLOG.md" not in self.changed_files():
            return
        head = set(BACKLOG_HEADING.findall(self.head_text("docs/BACKLOG.md")))
        base = set(BACKLOG_HEADING.findall(self.base_text("docs/BACKLOG.md")))
        for number in sorted(head - base, key=int):
            if not self.ci and not self.owns("backlog", number):
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
