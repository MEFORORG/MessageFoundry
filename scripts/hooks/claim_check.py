#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Claim gate -- stop two sessions building the same backlog item in parallel (BACKLOG #309).

`ledger_check.py` stops two sessions taking the same ADR/BACKLOG *number*. This stops them doing the same
*work*. On 2026-07-24 three sessions independently fixed one npm advisory: two PRs were closed as
duplicates, and the one that merged had not tested the failure mode the others found, so it shipped a
latent break that `npm audit` reported as clean.

The rule, deliberately narrow so it never fights you:

    A commit whose SUBJECT declares it implements `BACKLOG #N`, and whose staged diff touches CODE,
    must hold a claim on N for THIS worktree.

Three scoping decisions, each load-bearing:

* **Subject line only.** A body may reference other items freely -- this very repo's commits routinely
  cite the item they supersede or were found by. Enforcing on the body would fire on every one of those.
  The subject is where a commit *declares* what it implements.
* **Code-touching diffs only.** Banner flips, doc corrections and ledger reconciles legitimately cite an
  item without building it, and they are exactly the commits a coordination gate must not block.
* **Numbered items only.** Free-text claims (`claim.ps1 -Take npm-audit-brace-expansion`) are advisory --
  surfaced at session start, not enforced here, because there is no reliable way to map an arbitrary diff
  to a topic. Visibility is the win there; enforcement would be guesswork.

Run as a git `commit-msg` hook (argv[1] = the message file). It CANNOT be a pre-commit hook: pre-commit
never receives the commit message, so the check would look installed and silently never fire.

Stdlib only, no `messagefoundry` import: most worktrees have no .venv, and a gate that silently skips is
worse than no gate.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# `(BACKLOG #71, #72)` is the house form, so once BACKLOG appears in the subject every `#N` after it in
# that line counts -- otherwise the second item of a paired commit would slip through unclaimed.
_BACKLOG_TOKEN = re.compile(r"\bBACKLOG\b", re.IGNORECASE)
_ITEM = re.compile(r"#(\d{1,5})\b")

# A commit touching ONLY these is documentation/ledger work: it may cite an item without implementing it.
_DOC_PREFIXES = ("docs/", ".github/")
_DOC_SUFFIXES = (".md",)


def _git(*args: str) -> str:
    return subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", *args], capture_output=True, text=True, encoding="utf-8", errors="replace"
    ).stdout


def _staged_paths() -> list[str]:
    out = _git("diff", "--cached", "--name-only")
    return [p.strip().replace("\\", "/") for p in out.splitlines() if p.strip()]


def _touches_code(paths: list[str]) -> bool:
    """True if any staged path is not documentation. An empty diff counts as no code (e.g. --amend of a
    message), so a message-only fixup is never blocked."""
    for p in paths:
        if p.startswith(_DOC_PREFIXES):
            continue
        if p.endswith(_DOC_SUFFIXES):
            continue
        return True
    return False


def _claims_dir() -> Path:
    common = _git("rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return Path(common) / "mefor-coord" / "claims"


def _repo() -> str:
    return _git("rev-parse", "--path-format=absolute", "--show-toplevel").strip()


def _norm(p: str) -> str:
    return p.replace("\\", "/").rstrip("/").casefold()


def _holder(item: str) -> dict[str, object] | None:
    """The claim record for `item`, or None if unclaimed/unreadable. A malformed claim reads as UNCLAIMED
    on purpose: the gate then asks for a claim rather than silently passing on a corrupt one. A non-object
    payload (a bare list/string) is treated the same way -- it cannot name a holder, so it grants nothing."""
    f = _claims_dir() / f"{item}.json"
    try:
        loaded = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def main() -> int:
    if len(sys.argv) < 2:
        return 0  # not wired as a commit-msg hook; do nothing rather than guess
    try:
        message = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0

    subject = next((ln for ln in message.splitlines() if ln.strip() and not ln.startswith("#")), "")
    m = _BACKLOG_TOKEN.search(subject)
    if not m:
        return 0
    items = _ITEM.findall(subject[m.start() :])
    if not items:
        return 0

    paths = _staged_paths()
    if not _touches_code(paths):
        return 0  # docs/ledger-only: cites the item, does not build it

    me = _norm(_repo())
    problems: list[str] = []
    for item in dict.fromkeys(items):  # de-dupe, keep order
        claim = _holder(item)
        if claim is None:
            problems.append(
                f"  BACKLOG #{item} is NOT CLAIMED.\n"
                f"      Another session may already be building it -- that is the duplicate work this\n"
                f"      gate exists to stop. Claim it, then commit again:\n"
                f'          pwsh -NoProfile -File scripts\\coord\\claim.ps1 -Take {item} -Note "<what>"'
            )
            continue
        if _norm(str(claim.get("worktree", ""))) != me:
            problems.append(
                f"  BACKLOG #{item} is claimed by ANOTHER worktree:\n"
                f"      held by: {claim.get('worktree')} [{claim.get('branch')}]\n"
                f"      since  : {claim.get('claimed')}\n"
                f"      note   : {claim.get('note')}\n"
                f"      Do not build it in parallel. Coordinate with that session, or if it is dead:\n"
                f"          pwsh -NoProfile -File scripts\\coord\\claim.ps1 -Release {item} -Force"
            )

    if not problems:
        return 0

    sys.stderr.write("\nMessageFoundry claim gate\n\n")
    sys.stderr.write("\n\n".join(problems))
    sys.stderr.write(
        "\n\n  See who is building what:  pwsh -NoProfile -File scripts\\coord\\claim.ps1 -List\n"
        "  This fires only on a code-touching commit whose SUBJECT says 'BACKLOG #N'.\n"
        "  A docs-only commit (banner flip, ledger reconcile) is never blocked.\n\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
