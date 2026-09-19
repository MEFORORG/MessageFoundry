#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A retired repository path still resolves, so a stale reference answers instead of failing.

The private vault repository has moved TWICE, and both moves leave the same wreckage. It was
RENAMED on 2026-09-05, off the name the public engine repository carries, because the two shared
both a NAME and a DESCRIPTION and read as one project in ``gh repo list``. It was then
TRANSFERRED on 2026-09-19 out of the maintainer's personal account into the ``MEFORORG``
organization, so that it would sit under the MessageFoundry Foundation enterprise alongside the
engine. Its live path is ``CURRENT_SLUG`` below.

The **role playbooks** repository was transferred the same day and for the same reason; its live
path is ``CURRENT_METHOD_SLUG``. It is worth guarding for a sharper reason than the vault: every
seat is told to read its playbook at ``origin/main``, on every session start, so a stale path
there is exercised constantly and answers constantly.

**WHY A MOVE NEEDS A GUARD AT ALL, WHICH IS THE ONLY INTERESTING PART.** GitHub keeps a PERMANENT
redirect from every path a repository has ever had, and their documentation names exactly one way
to drop one: create a new repository claiming the old path. Doing that would put a second
repository with the engine's name back in the account listing -- the collision the rename just
cleared. So the redirects stay, and the cost of keeping them is that a stale reference does not
fail. It quietly answers, correctly, about the vault. Nothing anywhere reports that the path it
used is dead.

That is the shape this file exists for: a reference that is wrong and green. The tree was swept
when the rename landed and swept again when the transfer landed, and this guard is what keeps it
swept -- a sweep fixes today's instances, a guard catches the next one.

**IT REJECTS THE WHOLE RETIRED FAMILY, NOT ONE SPELLING.** The needle is the retired OWNER plus
the shared NAME, so it matches the pre-rename path and the pre-transfer path alike, with or
without a suffix. The earlier version excluded the suffixed form with a negative lookahead,
because that form was then CURRENT. The transfer retired it, and the lookahead would have kept
the guard silent on eleven live references across eight files. A move that only changes the OWNER
is the case an exclusion written around the NAME cannot see.

**IT NEVER WRITES A RETIRED PATH AS A LITERAL.** The needle is assembled from parts below.
Written whole, this file and its test would each be a violation of the rule they enforce, and the
usual answer -- exempting the guard from itself -- makes the guard the one place a real stale
reference can hide. The cost is real and is accepted: someone grepping the tree for a retired
path will not find this file. That is what this docstring is for. The CURRENT path carries no
such restriction and is written plainly.

**THE ONE EXEMPTION IS PINNED TO A COUNT, NOT TO A PATH.** ``docs/LEDGER-GATE.md`` narrates the
move itself -- it quotes the URL a REFLOG literally recorded, and names what the repository was
called between the rename and the transfer. Rewriting either would make the document disagree
with the artifact it is reading, or assert a name that was not in use on the date it gives. A
path-level exemption would blind the guard to every FUTURE stale reference in that same file. So
the exemption says how MANY occurrences that path may hold, and drift in either direction is a
failure: one more is a new stale reference, one fewer means a quoted passage moved and the pin
now protects nothing.

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
_RETIRED_OWNER = "wshallwshall"
_SHARED_NAME = "MessageFoundry"
_METHOD_NAME = "korus"

#: The retired OWNER plus the shared NAME. Deliberately a PREFIX and not a whole path: it matches
#: the pre-rename form and the pre-transfer ``-vault`` form in one pattern, and it will match any
#: further suffix somebody writes under that dead owner.
RETIRED_PREFIX = f"{_RETIRED_OWNER}/{_SHARED_NAME}"

#: The role playbooks, transferred the same day and for the same reason. Every seat reads them at
#: ``origin/main``, so a stale path here sends a seat to a redirect on every session start.
RETIRED_METHOD = f"{_RETIRED_OWNER}/{_METHOD_NAME}"

#: Both retired repository paths. A LIST and not the bare owner, which was measured and rejected:
#: the retired account still holds ``claude-multisession``, a live repository this tree names
#: legitimately, and a captured GitHub API payload in tests/fixtures carries owner-qualified API
#: URLs that are not repository references at all. Rejecting the owner outright would fail both.
RETIRED_PREFIXES = (RETIRED_PREFIX, RETIRED_METHOD)

#: Where the two actually live. Not retired, so they are written plainly -- and a line may carry
#: one and still hide a retired path beside it, which is why matching is per OCCURRENCE below.
CURRENT_SLUG = "MEFORORG/MessageFoundry-vault"
CURRENT_METHOD_SLUG = "MEFORORG/korus"

_RETIRED = re.compile("|".join(re.escape(prefix) for prefix in RETIRED_PREFIXES))

#: ``git grep`` takes one ``-e`` per needle. Built from the same tuple the regex is, so the search
#: and the count can never disagree about what they are looking for.
_GREP_NEEDLES = tuple(arg for prefix in RETIRED_PREFIXES for arg in ("-e", prefix))

#: Paths permitted to carry a retired path, and EXACTLY how many times.
#:
#: docs/LEDGER-GATE.md narrates the two moves: it quotes a URL recorded in a reflog, as evidence,
#: and it names what the repository was called between the rename and the transfer. The section is
#: reading those artifacts; changing either would make the document disagree with what it cites.
ALLOWED: dict[str, int] = {
    "docs/LEDGER-GATE.md": 2,
}


class GitError(RuntimeError):
    """``git grep`` could not run, which is a usage error and never a clean tree."""


def _grep(root: Path) -> list[tuple[str, int, str]]:
    """Return ``(path, line number, line)`` for every tracked line naming a retired path.

    Exit code 1 from ``git grep`` means "no matches", which is a legitimate clean result. Any
    other non-zero is an error -- reporting it as a clean tree is precisely the silent green this
    guard exists to prevent.
    """
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only git grep
            ["git", "grep", "-n", "-I", "-F", *_GREP_NEEDLES],
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
        found = len(_RETIRED.findall(text))
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
            f"{path}: pinned at {pinned} retired path(s), found {seen}. "
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
        f"stale-repo-slug: {len(problems)} problem(s) naming the repository by a retired path.",
        file=sys.stderr,
    )
    print(
        f"  The vault was renamed on 2026-09-05 and transferred on 2026-09-19; it now lives at "
        f"{CURRENT_SLUG}. The role playbooks moved the same day, to {CURRENT_METHOD_SLUG}.",
        file=sys.stderr,
    )
    print(
        "  Every old path still RESOLVES through a permanent GitHub redirect, so nothing else",
        file=sys.stderr,
    )
    print(
        "  reports this: the reference answers about the vault under a path that is gone.",
        file=sys.stderr,
    )
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
