#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

THE COPYRIGHT HOLDER IS PINNED TOO (BACKLOG #1552), in the same window under the same comment rule.
The licence and the holder are separate assertions because they fail separately: a file can declare
the right licence and name a superseded legal entity, which is what happened when the entity renamed
and nothing checked it. The holder is asserted POSITIONALLY -- "does this file's header name the
right holder" -- never by excluding paths allowed to contain the old string. A path exclusion answers
the wrong question and rots silently the moment someone legitimately quotes the old name in an ADR, a
NOTICE or a migration note. ``docs/BACKLOG.md`` quotes the superseded entity deliberately, to record
what was replaced; that is prose, not a header, so it never trips this and needs no exemption.

AND THE COMMENT RULE LEAVES A BLIND SPOT THIS GATE NOW COVERS. A header inside a string literal is
skipped by design -- but some of those literals are TEMPLATES that stamp headers onto GENERATED
files, so the lines deciding the copyright holder of future files are exactly the lines the comment
rule can never see. A naive scan for "SPDX tag in a string literal" finds seven sites and only two
are templates; the other five are this module's own docstring, its ``SPDX_TAG`` constant, and test
fixtures -- prose QUOTING the tag while explaining this very trap. ``_is_template_site`` discriminates
by ADJACENCY rather than by a path list: a template carries the SPDX line and a copyright line
together inside the same literal, and the prose mentions quote the tag alone and continue into
sentences. Adjacency was chosen because a path list is the same enumeration mistake one level down --
it would need an edit every time a template is added, and nothing would report that it needed one.

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

# This file is ``<repo>/scripts/quality/licence_header_check.py``, so the root is two levels up.
# Derived statically rather than shelled out of ``git rev-parse``: the lookup below runs once per
# file, and a subprocess per file would be the whole cost of the scan. Correct inside a git worktree
# too, where ``.git`` is a FILE rather than a directory -- nothing here reads it either way.
_REPO_ROOT = Path(__file__).resolve().parents[2]

# The SPDX identifier every first-party source must declare. Stated once, here.
EXPECTED_IDENTIFIER = "AGPL-3.0-or-later"

# The copyright holder every first-party header must name. Stated once, here, for the same reason
# EXPECTED_IDENTIFIER is: BACKLOG #1552. The entity renamed (PR 1020) and nothing pinned it, so the
# rename was left incomplete three times -- twice by its own author's later work, once by an
# unrelated merge -- and CI could not see any of it.
#
# The HOLDER only. Not the year and not the trailing "and contributors": pinning those would red on
# an ordinary new-year edit, which is how a gate teaches people to ignore it.
EXPECTED_HOLDER = "MessageFoundry Foundation, LLC"

# How a copyright line is recognised, kept separate from the holder for the same WRONG-vs-MISSING
# reason SPDX_TAG is kept separate from EXPECTED_IDENTIFIER.
COPYRIGHT_MARKER = "Copyright"

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
HOLDER_MISSING = "HOLDER_MISSING"
HOLDER_WRONG = "HOLDER_WRONG"
TEMPLATE_HOLDER_WRONG = "TEMPLATE_HOLDER_WRONG"


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


def registry_key(path: Path) -> str:
    """The VENDORED_LICENCES key for *path*, so one file gets one answer however it is addressed.

    Two traps, and only the first was handled when the registry was written:

    * SEPARATORS. ``.as_posix()``, not ``str(path)``: on Windows ``str()`` renders backslashes, and
      the registry is keyed the way ``git ls-files`` emits paths (forward slashes) on every platform.
    * POSITION. The registry is keyed REPO-RELATIVE, but nothing stops a caller passing an absolute
      path, and an absolute ``as_posix()`` can never equal a relative key. Such a caller would lose
      the exemption SILENTLY: the ``.get()`` default takes over and the gate would demand this
      project's AGPL identifier on genuinely third-party code, which is the exact affirmative
      misstatement VENDORED_LICENCES exists to prevent. Unlike the separator trap it is
      platform-independent, so it would fail everywhere at once rather than on one OS.

    A path OUTSIDE the repo has no repo-relative form, so it keeps its own spelling. That is not a
    fallback that weakens anything: an unregistered path still falls through to EXPECTED_IDENTIFIER.
    """
    try:
        return path.resolve().relative_to(_REPO_ROOT).as_posix()
    except ValueError:  # not under the repo root
        return path.as_posix()


def _read_lines(path: Path) -> list[str] | None:
    """Every line of *path*, or None when it cannot be read.

    The read deliberately uses *path* as given, so a relative invocation still resolves against the
    caller's cwd exactly as it always has. Only LOOKUP keys are normalised (see ``registry_key``).
    """
    try:
        return path.read_bytes().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return None


def header_lines(path: Path) -> list[str] | None:
    """The window a header may sit in. ONE definition of "where the header is", shared by both checks.

    The licence check and the holder check must never disagree about which lines are the header, so
    neither of them slices the file itself.
    """
    lines = _read_lines(path)
    return None if lines is None else lines[:HEAD_LINES]


def check_file(path: Path) -> tuple[str, str] | None:
    """Classify one file's LICENCE declaration. ``(class, detail)`` for a violation, else None."""
    prefix = COMMENT_PREFIXES[path.suffix]
    expected = VENDORED_LICENCES.get(registry_key(path), EXPECTED_IDENTIFIER)
    head = header_lines(path)
    if head is None:  # unreadable is a violation we must not swallow
        return (MISSING, "could not read")

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


def check_holder(path: Path) -> tuple[str, str] | None:
    """Classify one file's COPYRIGHT HOLDER. ``(class, detail)`` for a violation, else None.

    A file registered in VENDORED_LICENCES is someone else's code under its own licence, so it is
    exempt: stamping this project's holder on third-party work is the same affirmative misstatement
    the licence half of this gate exists to prevent. The exemption is the registry's, not a second
    list -- a file is exempt here exactly when it is exempt there.
    """
    if registry_key(path) in VENDORED_LICENCES:
        return None

    prefix = COMMENT_PREFIXES[path.suffix]
    head = header_lines(path)
    if head is None:
        return (HOLDER_MISSING, "could not read")

    for line in head:
        stripped = line.strip()
        if not stripped.startswith(prefix):
            continue
        if COPYRIGHT_MARKER not in stripped:
            continue
        if EXPECTED_HOLDER in stripped:
            return None
        return (HOLDER_WRONG, f"names {stripped.removeprefix(prefix).strip()!r}")

    return (
        HOLDER_MISSING,
        f"no {COPYRIGHT_MARKER} comment in the first {HEAD_LINES} lines",
    )


def _is_template_site(lines: list[str], index: int) -> str | None:
    """The ADJACENCY DISCRIMINATOR. Returns the adjacent copyright line, or None if this is prose.

    *index* is a line carrying the SPDX tag in non-comment form -- that is, inside a string literal.
    Two kinds of thing look like that, and only one of them decides a future file's header:

      * a TEMPLATE, which carries the SPDX line and a copyright line together in the same literal;
      * PROSE, which quotes the tag alone and continues into sentences.

    So the next NON-EMPTY line decides it. Blank lines are skipped rather than ending the search
    because a template may space its header block, and a blank line is not evidence either way.
    """
    for follow in lines[index + 1 :]:
        stripped = follow.strip()
        if not stripped:
            continue
        return stripped if COPYRIGHT_MARKER in stripped else None
    return None


def template_sites(path: Path) -> list[tuple[int, str]]:
    """Every header-stamping TEMPLATE in *path*, as ``(line number, the copyright line it stamps)``.

    Enumerates sites REGARDLESS of whether their holder is correct, which is what makes the scan
    auditable: while every template happens to be right, a violations-only view returns nothing and
    cannot tell "found both templates, both fine" apart from "found no templates at all". Those two
    render identically and only one of them means the scan works.

    Scans the whole file, not the head window: a template sits wherever the generating code sits.
    """
    if registry_key(path) in VENDORED_LICENCES:
        return []

    lines = _read_lines(path)
    if lines is None:
        return []

    prefix = COMMENT_PREFIXES[path.suffix]
    sites: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if SPDX_TAG not in stripped:
            continue
        if stripped.startswith(prefix):
            continue  # a real header, already covered by check_file/check_holder
        adjacent = _is_template_site(lines, i)
        if adjacent is None:
            continue  # prose quoting the tag, not a template
        sites.append((i + 1, adjacent))
    return sites


def check_templates(path: Path) -> list[tuple[str, str]]:
    """Every template site in *path* whose stamped copyright line names the wrong holder."""
    return [
        (TEMPLATE_HOLDER_WRONG, f"line {number}: template stamps {stamped!r}")
        for number, stamped in template_sites(path)
        if EXPECTED_HOLDER not in stamped
    ]


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
        holder = check_holder(path)
        if holder is not None:
            violations.append((holder[0], name, holder[1]))
        for cls, detail in check_templates(path):
            violations.append((cls, name, detail))

    if not violations:
        vendored_note = (
            f" ({len(VENDORED_LICENCES)} vendored under its own upstream licence)"
            if VENDORED_LICENCES
            else ""
        )
        print(
            f"licence-header: OK -- {len(candidates)} file(s) checked, all declare their expected "
            f"licence and name {EXPECTED_HOLDER}{vendored_note}"
        )
        return 0

    wrong = [v for v in violations if v[0] == WRONG]
    missing = [v for v in violations if v[0] == MISSING]
    holder_wrong = [v for v in violations if v[0] == HOLDER_WRONG]
    holder_missing = [v for v in violations if v[0] == HOLDER_MISSING]
    template_wrong = [v for v in violations if v[0] == TEMPLATE_HOLDER_WRONG]

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

    # A TEMPLATE is printed before the ordinary holder classes and named as its own defect, for the
    # same reason WRONG precedes MISSING: a template decides the header of every file it generates,
    # so one wrong template line is a wrong holder on files that do not exist yet.
    if template_wrong:
        print(
            f"licence-header: {len(template_wrong)} header-stamping TEMPLATE(s) name the wrong "
            f"holder (expected {EXPECTED_HOLDER}):",
            file=sys.stderr,
        )
        for _, name, detail in template_wrong:
            print(f"  {name}: {detail}", file=sys.stderr)
    if holder_wrong:
        print(
            f"licence-header: {len(holder_wrong)} file(s) name the WRONG copyright holder "
            f"(expected {EXPECTED_HOLDER}):",
            file=sys.stderr,
        )
        for _, name, detail in holder_wrong:
            print(f"  {name}: {detail}", file=sys.stderr)
    if holder_missing:
        print(
            f"licence-header: {len(holder_missing)} file(s) carry NO copyright line:",
            file=sys.stderr,
        )
        for _, name, detail in holder_missing:
            print(f"  {name}: {detail}", file=sys.stderr)

    print(
        f"licence-header: {len(violations)} violation(s) across {len(candidates)} file(s) checked. "
        f"Add '<comment> {SPDX_TAG} {EXPECTED_IDENTIFIER}' and "
        f"'<comment> Copyright (C) <year> {EXPECTED_HOLDER} and contributors' "
        f"within the first {HEAD_LINES} lines.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
