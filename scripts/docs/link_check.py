#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Resolve relative markdown links, so a moved file cannot silently orphan the docs that cite it.

**Why this exists.** Closing a backlog item moves its text *verbatim* from ``docs/BACKLOG.md`` into
``docs/archive/backlog/BACKLOG-CLOSED.md`` -- two directories deeper -- and nothing rewrites its
relative links. A link written as ``adr/0083-x.md`` was correct while the item lived in ``docs/`` and
resolves to ``docs/archive/backlog/adr/0083-x.md`` the moment it lands. Measured 2026-08-07: **267 of
the archive's 270 broken links resolved cleanly when read from** ``docs/``, which is what identifies
the archival move rather than authoring error as the cause. The remaining three were *ADR slug rot* --
the ADR merged under a different title than the one cited.

None of this was catchable. The repo runs **no link checker of any kind**, so 635 broken relative
links accumulated across 19 files before anyone counted them.

**What this does NOT check**, deliberately, because a checker that overreaches gets deleted:

* **Absolute URLs** (``http``/``https``/``mailto``) -- reachability is a network question, not a
  repository invariant.
* **Fragments.** ``#some-anchor`` is not validated here; only the path is. Heading slugs churn on
  every retitle and would make this noisy.
* **Withheld directories.** ``docs/security/``, ``docs/reviews/`` and ``docs/marketing/`` are
  gitignored post-cutover. The master test plan states a missing path there is a deliberate
  publishing boundary, not a defect, so flagging them would train readers to ignore the gate.
* **Fenced code.** A path inside ``` is sample output being shown, not a link to follow.
* **``file.py:27`` citation targets.** The repo's ``file_path:line_number`` convention appears inside
  some hrefs. Those cannot resolve as paths whatever prefix is used; repairing them is a convention
  decision, not a repair, so they are reported under ``--include-line-cites`` and otherwise skipped.

Usage::

    python scripts/docs/link_check.py                          # whole repo
    python scripts/docs/link_check.py docs/archive/backlog      # one subtree

Exit 1 if any link fails to resolve.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

# Gitignored post-cutover; a missing target here is a publishing boundary, not a broken link.
WITHHELD = ("docs/security/", "docs/reviews/", "docs/marketing/")

_LINK = re.compile(r"\]\((?P<href>[^)\s]+?)(?P<frag>#[^)\s]*)?\)")
_LINE_CITE = re.compile(r":\d+$")
_FENCE = re.compile(r"^\s*```")


def repo_root() -> Path:
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout.strip()
    return Path(out)


def tracked_markdown(root: Path, subtree: str | None) -> list[str]:
    args = ["git", "-C", str(root), "ls-files", "*.md"]
    if subtree:
        args = [
            "git",
            "-C",
            str(root),
            "ls-files",
            f"{subtree.rstrip('/')}/**/*.md",
            f"{subtree.rstrip('/')}/*.md",
        ]
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        args, capture_output=True, text=True, encoding="utf-8", check=True
    ).stdout
    return sorted(set(out.split()))


def _normalise(base: PurePosixPath, href: str) -> str:
    """Resolve ``href`` against ``base`` without touching the filesystem (no symlink surprises)."""
    parts: list[str] = []
    for part in (base / href).parts:
        if part == "..":
            if parts:
                parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts)


def check(root: Path, subtree: str | None, include_line_cites: bool) -> tuple[list[str], int, int]:
    """Return ``(failures, links_checked, files_scanned)``."""
    tracked = set(
        subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
            ["git", "-C", str(root), "ls-files"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout.splitlines()
    )
    failures: list[str] = []
    checked = 0
    files = tracked_markdown(root, subtree)

    for rel in files:
        path = root / rel
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:  # unreadable is a finding, not a crash
            failures.append(f"{rel}: cannot read ({exc})")
            continue
        here = PurePosixPath(rel).parent
        in_fence = False

        for lineno, text in enumerate(lines, 1):
            if _FENCE.match(text):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for m in _LINK.finditer(text):
                href = m.group("href")
                if href.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                if _LINE_CITE.search(href) and not include_line_cites:
                    continue
                target = _normalise(here, href)
                if not target:
                    continue
                # Test the RESOLVED target, not the raw href. A relative link into a withheld
                # directory ("../../security/X.md") shares no prefix with the repo-root form
                # ("docs/security/"), so matching on the href exempts nothing -- caught by
                # test_withheld_directories_are_not_flagged.
                if any(target.startswith(w) for w in WITHHELD):
                    continue
                checked += 1
                if target not in tracked and not (root / target).exists():
                    failures.append(f"{rel}:{lineno}: ({href}) -> {target} does not exist")

    return failures, checked, len(files)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "subtree", nargs="?", default=None, help="limit to a subtree, e.g. docs/archive/backlog"
    )
    ap.add_argument(
        "--include-line-cites",
        action="store_true",
        help="also check hrefs ending in ':<line>' (normally skipped)",
    )
    args = ap.parse_args(argv)

    root = repo_root()
    failures, checked, files = check(root, args.subtree, args.include_line_cites)

    # Always print the SCOPE alongside the verdict: a green run over three files looks identical to
    # a green run over the repo, and "it passed" is not a useful claim without knowing what it read.
    scope = args.subtree or "<whole repo>"
    print(f"link_check: {checked} relative links in {files} markdown files under {scope}")
    if failures:
        print(f"FAIL: {len(failures)} unresolved")
        for f in failures:
            print(f"  {f}")
        return 1
    print("OK: every relative link resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
