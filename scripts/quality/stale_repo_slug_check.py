#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A renamed repository's OLD slug still resolves, so a stale reference answers instead of failing.

The private vault repository was renamed on 2026-09-05, from the same name the public engine
repository carries to ``wshallwshall/MessageFoundry-vault``. It had shared both a NAME and a
DESCRIPTION with the engine, so two rows in ``gh repo list`` read as one project.

**WHY A RENAME NEEDS A GUARD AT ALL, WHICH IS THE ONLY INTERESTING PART.** GitHub keeps a
PERMANENT redirect from the old path, and their documentation names exactly one way to drop it:
create a new repository claiming the old name. Doing that would put a second repository with the
engine's name back in the account listing -- the collision the rename just cleared. So the
redirect stays, and the cost of keeping it is that a stale reference does not fail. It quietly
answers, correctly, about the vault. Nothing anywhere reports that the name it used is dead.

That is the shape this file exists for: a reference that is wrong and green. The engine tree was
swept clean when the rename landed, and this guard is what keeps it swept -- a sweep fixes today's
instances, a guard catches the next one.

**IT NEVER WRITES THE PRE-RENAME SLUG AS A LITERAL.** The needle is assembled from parts below.
Written whole, this file and its test would each be a violation of the rule they enforce, and the
usual answer -- exempting the guard from itself -- makes the guard the one place a real stale
reference can hide. The cost is real and is accepted: someone grepping the tree for the old slug
will not find this file. That is what the docstring is for.

**THE ONE EXEMPTION IS PINNED TO A COUNT, NOT TO A PATH.** ``docs/LEDGER-GATE.md`` quotes the URL
a REFLOG literally recorded, and rewriting it would make the document disagree with the artifact
it is reading. A path-level exemption would blind the guard to every FUTURE stale reference in
that same file. So the exemption says how MANY occurrences that path may hold, and drift in
either direction is a failure: one more is a new stale reference, one fewer means the quoted
passage moved and the pin now protects nothing.

Scope is ``git grep`` over TRACKED files, which is the same population a reader greps and skips
binaries, ``.venv`` and untracked scratch without needing a list of them here.

Usage:
  stale_repo_slug_check.py            # scan the repository this file lives in
  stale_repo_slug_check.py --root DIR # scan DIR instead (used by the tests)

Exit: 0 clean, 1 on a violation, 2 on a usage or git error.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

#: Assembled, never written whole. See the docstring: a literal here would make this file the
#: violation it reports, and exempting it would make it the one place a real one can hide.
_OWNER = "wshallwshall"
_OLD_NAME = "MessageFoundry"
_SUFFIX = "-vault"

OLD_SLUG = f"{_OWNER}/{_OLD_NAME}"
NEW_SLUG = f"{OLD_SLUG}{_SUFFIX}"

#: The old slug NOT followed by the suffix. Matching per occurrence rather than per line matters:
#: a single line may legitimately carry the new slug and still hide a bare old one beside it.
_BARE = re.compile(re.escape(OLD_SLUG) + f"(?!{re.escape(_SUFFIX)})")

#: Paths permitted to carry the pre-rename slug, and EXACTLY how many times.
#:
#: docs/LEDGER-GATE.md quotes a URL recorded in a reflog, as evidence, with the current name
#: named beside it. The section is reading that artifact; changing the quotation would make the
#: document disagree with what it cites.
ALLOWED: dict[str, int] = {
    "docs/LEDGER-GATE.md": 1,
}


class GitError(RuntimeError):
    """``git grep`` could not run, which is a usage error and never a clean tree."""


def _grep(root: Path) -> list[tuple[str, int, str]]:
    """Return ``(path, line number, line)`` for every tracked line containing the old slug.

    Exit code 1 from ``git grep`` means "no matches", which is a legitimate clean result. Any
    other non-zero is an error -- reporting it as a clean tree is precisely the silent green this
    guard exists to prevent.
    """
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only git grep
            ["git", "grep", "-n", "-I", "-F", "-e", OLD_SLUG],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        # A missing root, or no git on PATH. Both arrive here as an exception rather than an exit
        # code, and an unhandled one is a traceback that reads like a bug in the guard.
        raise GitError(f"could not run git grep in {root}: {exc}") from exc

    if proc.returncode == 1 and not proc.stdout:
        return []
    if proc.returncode not in (0, 1):
        raise GitError(f"git grep exited {proc.returncode}: {proc.stderr.strip()}")

    hits: list[tuple[str, int, str]] = []
    for raw in proc.stdout.splitlines():
        path, _, rest = raw.partition(":")
        number, _, text = rest.partition(":")
        if not path or not number.isdigit():
            continue
        hits.append((path, int(number), text))
    return hits


def check(root: Path) -> list[str]:
    """Return one problem line per violation. Empty means clean."""
    counts: dict[str, int] = {}
    sites: dict[str, list[str]] = {}
    problems: list[str] = []

    for path, number, text in _grep(root):
        found = len(_BARE.findall(text))
        if not found:
            continue
        counts[path] = counts.get(path, 0) + found
        sites.setdefault(path, []).append(f"{path}:{number}: {text.strip()}")
        if path not in ALLOWED:
            problems.extend(sites[path][-1:])

    for path, pinned in ALLOWED.items():
        seen = counts.get(path, 0)
        if seen == pinned:
            continue
        problems.append(
            f"{path}: pinned at {pinned} pre-rename slug(s), found {seen}. "
            "One more is a new stale reference; one fewer means the quoted passage moved and the "
            "pin protects nothing. Either way, update ALLOWED deliberately."
        )
        # Show them, because a bare count looks identical whether the guard caught the new site
        # or lost the old one.
        problems.extend(f"  {site}" for site in sites.get(path, []))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--root", type=Path, default=_ROOT, help="repository to scan (default: this one)"
    )
    args = parser.parse_args(argv)

    try:
        problems = check(args.root)
    except GitError as exc:
        print(f"stale-repo-slug: {exc}", file=sys.stderr)
        return 2

    if not problems:
        return 0

    print(
        f"stale-repo-slug: {len(problems)} problem(s) naming the repository by its pre-rename slug.",
        file=sys.stderr,
    )
    print(f"  It was renamed to {NEW_SLUG} on 2026-09-05.", file=sys.stderr)
    print(
        "  The old path still RESOLVES through a permanent GitHub redirect, so nothing else",
        file=sys.stderr,
    )
    print(
        "  reports this: the reference answers about the vault under a name that is gone.",
        file=sys.stderr,
    )
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
