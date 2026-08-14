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
* **Withheld directories.** ``docs/security/``, ``docs/reviews/``, ``docs/marketing/`` and
  ``docs/releases/`` are gitignored. The master test plan states a missing path there is a
  deliberate publishing boundary, not a defect, so flagging them would train readers to ignore the
  gate. ``.claude/`` was a fifth entry until ``.claude/settings.json`` became tracked; every link
  the exemption covered pointed at that one file, so they are now checked like any other.
* **Fenced code.** A path inside ``` is sample output being shown, not a link to follow.
* **Inline code.** A link inside backticks is being *displayed*, not offered -- the same argument as
  fenced code, at smaller scale. Four real sites turn on it: a regex whose character class contains
  ``](``, two VS Code ``command:`` URIs (one quoted as an attack payload), and ADR 0160 quoting the
  very link it records as having been removed. Repointing any of them would corrupt the text.
  Measured 2026-08-07, the cost is **10** links no longer checked out of 5,344, five of which were
  passing. The discriminator is POSITION, not shape: the dominant repo idiom ``[`x.md`](../x.md)``
  closes its span before the ``]``, so it is still checked.
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

# Gitignored; a missing target here is a publishing boundary, not a broken link.
#
# docs/releases/ joined when ADR 0160 Phase 1 untracked it (.gitignore carries "/docs/releases/") --
# an archived throughput doc still cites the v0.1 plan that moved out with it.
#
# .claude/ WAS a fifth entry, exempt because 7 links pointed at .claude/settings.json and no clone
# had it. It is gone because the premise is: settings.json is tracked now, so those 7 resolve
# through tracked_paths() like every other link and are counted rather than skipped.
#
# Measured before removing it: all 7 markdown links whose href names a .claude/ path name
# settings.json and nothing else, so nothing else loses its exemption. That mattered, because the
# exemption `continue`s BEFORE `checked += 1` -- a withheld href is not merely resolved, it is never
# counted, which #327 demonstrated by planting a missing path under .claude/ and watching the total
# stay at 5359 and the run stay green. An exemption that hides its own coverage gap is the
# compensating-control-on-a-false-premise shape (CLAUDE.md section 11, SDS-3.7). Keep this tuple to
# genuinely unpublished trees; a path that ships belongs in the gate.
WITHHELD = (
    "docs/security/",
    "docs/reviews/",
    "docs/marketing/",
    "docs/releases/",
)

_LINK = re.compile(r"\]\((?P<href>[^)\s]+?)(?P<frag>#[^)\s]*)?\)")
_LINE_CITE = re.compile(r":\d+$")
_FENCE = re.compile(r"^\s*```")
_CODE = re.compile(r"`[^`]*`")


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


def tracked_paths(root: Path) -> set[str]:
    """Every tracked FILE, plus every directory that contains one.

    Resolution is against this set ALONE -- never against the filesystem. That is what makes a run
    in a long-lived local checkout and a run on CI's clean clone give the same answer, which for a
    repo-wide invariant is the difference between a control and a coin flip. A filesystem fallback
    passes any path that merely happens to be present, and gitignored-but-present paths are exactly
    the ones a developer has and CI does not: `.claude/` is the measured case, 7 links that passed
    locally and would have failed on the runner.

    ``git ls-files`` lists files and never directories, so the ancestor prefixes have to be derived
    or every link to a directory breaks -- 122 of them here (``docs/adr``, ``environments``,
    ``.github/workflows``). Those are legitimate: a directory link resolves for anyone who clones.
    """
    files = set(
        subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
            ["git", "-C", str(root), "ls-files"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout.splitlines()
    )
    dirs: set[str] = set()
    for f in files:
        part = f
        while "/" in part:
            part = part.rsplit("/", 1)[0]
            dirs.add(part)
    return files | dirs


def check(root: Path, subtree: str | None, include_line_cites: bool) -> tuple[list[str], int, int]:
    """Return ``(failures, links_checked, files_scanned)``."""
    tracked = tracked_paths(root)
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
            code_spans = [c.span() for c in _CODE.finditer(text)]
            for m in _LINK.finditer(text):
                # A link inside backticks is DISPLAYED, not offered. Tested by POSITION rather than
                # shape, so that the dominant idiom -- [`x.md`](../x.md), whose span closes before
                # the "]" -- keeps being checked. test_links_inside_inline_code_are_not_followed
                # asserts both halves, because a shape-based rule would silently stop checking most
                # of the docs while still looking green.
                if any(s <= m.start() < e for s, e in code_spans):
                    continue
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
                # Tracked set only -- deliberately NO filesystem fallback. See tracked_paths().
                if target not in tracked:
                    failures.append(f"{rel}:{lineno}: ({href}) -> {target} is not tracked")

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
