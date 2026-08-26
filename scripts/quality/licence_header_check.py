#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Licence-header gate: assert every first-party source declares the project's SPDX identifier.

Two callers share this one module so their enforcement can never drift:
  * ``.pre-commit-config.yaml`` runs it over staged files before every commit.
  * ``.github/workflows/ci.yml`` runs it over the whole tracked tree in CI.

AGPL-3.0-or-later is asserted twice at the project level -- in ``LICENSE`` and in ``pyproject.toml``
-- and then per-file provenance was left to habit. Habit held at over 93 percent and then decayed
silently across a whole package: ``messagefoundry/tray/`` landed (ADR 0113) with no header on any of
its seventeen files, all of which are wheel content, and nothing noticed. This is the control that
makes the convention checkable instead of remembered.

THE GATE ASSERTS THE VALUE, NOT THE PRESENCE OF THE STRING, and that distinction is the whole point.
A presence-only check -- ``grep -l SPDX-License-Identifier`` -- passes a file that affirmatively
declares the WRONG licence, and five files in this repo did exactly that (``Apache-2.0`` in an AGPL
project). An affirmative misstatement of licence is worse than an omission, so a wrong identifier is
reported as its own violation class and is never quietly folded into "missing".

SCOPE IS STATED POSITIVELY AND WAS MEASURED, NOT ASSUMED. Every tracked file carrying one of the
extensions in ``COMMENT_PREFIXES`` is in scope. There is still no TREE exemption -- every directory
this project owns is checked against ``EXPECTED_IDENTIFIER`` with no exceptions. ``tee/`` (vendored
from this project's own ``messagefoundry/anon/``) is already fully compliant, as are ``harness/``,
``samples/``, ``packaging/``, ``docker/``, ``messagefoundry_webconsole/`` and the archived
``docs/benchmarks/results/``.

``VENDORED_LICENCES`` is the one narrow exception, and it is a FILE list, not a tree exemption: each
entry still asserts an exact expected value, just not this project's own. It exists because BACKLOG
#1364 vendored genuinely third-party, differently-licensed code (an Apache-2.0 GitHub Action,
authored by SAP, pinned to a specific upstream commit) into ``.github/actions/``. Stamping this
project's AGPL identifier on someone else's Apache-2.0 file would be exactly the affirmative
misstatement this gate exists to catch, and worse than the omission it would paper over. Add an
entry here only for a file that is genuinely someone else's code under its own real licence -- never
to wave through a first-party file that is merely inconvenient to header.

``tests/`` IS IN SCOPE, on evidence rather than assumption: the tree sits at roughly 94 percent
compliance on its own, which is not what a deliberately-exempt tree looks like, and no config, hook
or workflow excludes it from anything header-related. The gap is drift, not policy.

The header must appear within the first ``HEAD_LINES`` lines and must be a COMMENT -- the line, once
stripped, has to begin with the language's comment prefix. Requiring the comment form keeps a header
string embedded in code from counting: ``messagefoundry/corepoint_import.py`` contains the literal
``"# SPDX-License-Identifier: AGPL-3.0-or-later",`` because it GENERATES headers for imported
configuration, and a substring check would read a header-emitting file as a headered one.

Usage:
  licence_header_check.py [FILE ...]   # check the given files (how pre-commit invokes it)
  licence_header_check.py              # check every in-scope git-tracked file (how CI invokes it)
  licence_header_check.py --list       # print the in-scope file list and exit 0 (scope, auditable)

Exit: 0 clean, 1 violations found, 2 usage error.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# The SPDX identifier every first-party source must declare. Stated once, here.
EXPECTED_IDENTIFIER = "AGPL-3.0-or-later"

# One specific vendored file -> the licence IT actually carries upstream. See the module docstring's
# VENDORED_LICENCES paragraph for why this exists and what does and does not belong here. Keyed by
# the exact git-tracked path (forward slashes, as `git ls-files` emits), never a prefix or glob.
VENDORED_LICENCES: dict[str, str] = {
    ".github/actions/cla-assistant-lite/dist/index.js": "Apache-2.0",
}

# The tag whose VALUE is asserted. Kept separate from the identifier so a file carrying the tag with
# the wrong value is distinguishable from a file carrying no tag at all -- see WRONG vs MISSING.
SPDX_TAG = "SPDX-License-Identifier:"

# Extension -> line-comment prefix. Membership of this map IS the extension scope: adding a language
# is adding a row here, and nothing else needs to change.
COMMENT_PREFIXES = {
    ".py": "#",
    ".ps1": "#",
    ".sh": "#",
    ".ts": "//",
    ".js": "//",
    ".go": "//",
}

# How far into a file the header may sit. Generous enough for a shebang, an encoding line, a
# ``#Requires -Version 7`` directive or a short leading banner; bounded so the check cannot be
# satisfied by an identifier buried hundreds of lines down.
HEAD_LINES = 20

# Violation classes. Reported separately because they are different defects with different fixes.
MISSING = "MISSING"
WRONG = "WRONG"


def in_scope(path: str) -> bool:
    """True when *path* carries an in-scope extension."""
    return Path(path).suffix in COMMENT_PREFIXES


def tracked_files() -> list[str]:
    """Every in-scope file git tracks, relative to the repo root.

    ``-z`` and an explicit utf-8 decode rather than text mode: on a stock Windows console text mode
    decodes as cp1252, which mangles any non-ASCII path and would silently drop it from the scan.
    """
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8", errors="replace")
    return sorted(p for p in out.split("\0") if p and in_scope(p))


def check_file(path: Path) -> tuple[str, str] | None:
    """Classify one file. Returns ``(class, detail)`` for a violation, or None when compliant."""
    prefix = COMMENT_PREFIXES[path.suffix]
    # .as_posix(), not str(path): on Windows str() renders backslashes, and VENDORED_LICENCES is
    # keyed the way git ls-files emits paths (forward slashes) on every platform.
    expected = VENDORED_LICENCES.get(path.as_posix(), EXPECTED_IDENTIFIER)
    try:
        head = path.read_bytes().decode("utf-8", errors="replace").splitlines()[:HEAD_LINES]
    except OSError as exc:  # unreadable is a violation we must not swallow
        return (MISSING, f"could not read: {exc}")

    for line in head:
        stripped = line.strip()
        # The header must be a comment, not a string literal that happens to contain the tag.
        if not stripped.startswith(prefix):
            continue
        if SPDX_TAG not in stripped:
            continue
        value = stripped.split(SPDX_TAG, 1)[1].strip()
        if value == expected:
            return None
        return (WRONG, f"declares {value!r}, expected {expected!r}")

    return (MISSING, f"no {SPDX_TAG} comment in the first {HEAD_LINES} lines")


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}

    unknown = flags - {"--list"}
    if unknown:
        print(f"licence-header: unknown option(s): {' '.join(sorted(unknown))}", file=sys.stderr)
        return 2

    # pre-commit passes staged paths; CI passes none and gets the whole tracked tree.
    candidates = [p for p in args if in_scope(p)] if args else tracked_files()

    if "--list" in flags:
        for entry in candidates:
            print(entry)
        return 0

    violations: list[tuple[str, str, str]] = []
    for name in candidates:
        path = Path(name)
        if not path.is_file():  # staged deletion, or a path that no longer exists
            continue
        result = check_file(path)
        if result is not None:
            violations.append((result[0], name, result[1]))

    if not violations:
        vendored_note = (
            f" ({len(VENDORED_LICENCES)} vendored under its own upstream licence)"
            if VENDORED_LICENCES
            else ""
        )
        print(
            f"licence-header: OK -- {len(candidates)} file(s) checked, all declare their expected "
            f"licence{vendored_note}"
        )
        return 0

    wrong = [v for v in violations if v[0] == WRONG]
    missing = [v for v in violations if v[0] == MISSING]

    # WRONG is printed first and named separately: an affirmative misstatement of licence is a worse
    # defect than an omission, and folding the two together is what a presence-only check does.
    if wrong:
        print(
            f"licence-header: {len(wrong)} file(s) declare the WRONG licence "
            f"(expected {EXPECTED_IDENTIFIER}):",
            file=sys.stderr,
        )
        for _, name, detail in wrong:
            print(f"  {name}: {detail}", file=sys.stderr)
    if missing:
        print(f"licence-header: {len(missing)} file(s) carry NO licence header:", file=sys.stderr)
        for _, name, detail in missing:
            print(f"  {name}: {detail}", file=sys.stderr)

    print(
        f"licence-header: {len(violations)} violation(s) across {len(candidates)} file(s) checked. "
        f"Add '<comment> {SPDX_TAG} {EXPECTED_IDENTIFIER}' within the first {HEAD_LINES} lines.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
