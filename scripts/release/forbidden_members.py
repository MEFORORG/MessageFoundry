#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
r"""Refuse to publish a built distribution that carries a maintainer-internal file.

WHY THIS EXISTS (BACKLOG #1832, follow-up to #1702). The engine sdist already has a six-step leak
gate in ``.github/workflows/release.yml``, and that gate asked one question: **where does this member
sit?** Its allowlist is a path regex (``^(messagefoundry/|licenses/|README\.md$|...)``). A location
test cannot see what KIND of file something is, so ``messagefoundry/CLAUDE.md`` -- this project's
instructions to its own coding agents -- matched the ``messagefoundry/`` branch and shipped to PyPI on
every release from 0.1.0 to 0.2.15. #1702 fixed the BUILD config so hatchling stops packing it. This
script is the release-time backstop for the same class, and it asks the other question.

TWO PROPERTIES MAKE THIS A DIFFERENT CHECK, NOT A SECOND COPY OF THE ALLOWLIST.

1. It is a DENYLIST over the basename and the path components, so it is immune to the prefix-laundering
   the allowlist had to be hardened against. That gate derives one archive root and strips it, because
   ``docs/messagefoundry/security/PRIVATE.md`` inside a ``messagefoundry-0.3.0/`` root laundered itself
   into an allowlisted path. A basename is the same string wherever the member sits, so there is no
   prefix to launder and nothing to strip.

2. It covers the distributions the allowlist never reached. The allowlist runs on ``dist/*.tar.gz``
   alone. The engine WHEEL, the console wheel and the harness wheel had no member gate at all -- and
   the harness is the one distribution whose force-included tree hatchling's ``exclude`` cannot filter,
   so the artifact needing the strongest backstop had none.

SCOPE, STATED SO NOBODY OVER-READS IT. This is a name rule, not a content classifier: it matches
basenames and path components, and it does not read a single byte of any member. A maintainer-internal
file under a name not listed here passes, and that is a known limit rather than an oversight -- adding
a name is a one-line edit, and a content sniffer that guessed would be worse than a rule that states
its reach. The archive-INTEGRITY questions (a truncated tar listing partial members and exiting 0) stay
with the sdist leak gate, which owns them; a zip's central directory makes the wheel case structural,
and the zero-member control below is what keeps a failed listing from reading as a clean one.
"""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
import zlib
from collections.abc import Iterable, Sequence
from pathlib import Path

#: Basenames no published distribution may carry, matched CASEFOLDED on the final path
#: component. Case folding is the safe direction for a denylist: Windows and macOS filesystems fold
#: case, so ``claude.md`` and ``CLAUDE.md`` are one file to the person who committed it, and a rule
#: that only caught one spelling would be satisfied by a rename that changed nothing.
#:
#: The class is "a file that instructs a coding agent, or records maintainer-internal context" --
#: deliberately NOT an enumeration that claims to be complete. Measured at the time of writing: the
#: repository tracks three ``CLAUDE.md`` (root, ``harness/``, ``messagefoundry/``) and none of the
#: other names, so every entry but the first guards against the next file of the same class rather
#: than describing one that exists.
FORBIDDEN_BASENAMES: frozenset[str] = frozenset(
    {
        "claude.md",
        "claude.local.md",
        "agents.md",
        "gemini.md",
        ".cursorrules",
    }
)

#: Directory names no published distribution may carry at ANY depth, matched case-insensitively on
#: every path component. These hold agent and CI configuration that is about building the project, not
#: about running it, so a member inside one is internal wherever it sits.
FORBIDDEN_PATH_COMPONENTS: frozenset[str] = frozenset({".claude", ".github"})


class InspectionError(RuntimeError):
    """An archive could not be inspected, so nothing about it has been proved."""


def _members(archive: Path) -> list[str]:
    """Every member name in ``archive``, or raise :class:`InspectionError`.

    RAISING RATHER THAN RETURNING EMPTY IS THE POINT. "No forbidden member" and "the listing failed"
    are the same empty set, and a gate that cannot tell them apart reports a clean archive when it read
    nothing at all. Both readers below fail loudly instead: ``tarfile`` and ``zipfile`` raise on a
    stream they cannot parse, and :func:`inspect` turns a zero-length listing into a failure too.
    """
    suffixes = [s.lower() for s in archive.suffixes]
    try:
        if archive.suffix.lower() in {".whl", ".zip"}:
            with zipfile.ZipFile(archive) as zf:
                return zf.namelist()
        if suffixes[-2:] == [".tar", ".gz"] or archive.suffix.lower() == ".tgz":
            # `r:gz` and not `r:*`: the mode must be the one the filename promised, so a `.tar.gz`
            # that is secretly an uncompressed tar fails here rather than being read anyway.
            with tarfile.open(archive, "r:gz") as tf:
                return tf.getnames()
    # `EOFError` IS NOT AN `OSError`, and a truncated archive is exactly what raises it: a `.tar.gz`
    # cut mid-stream gives "Compressed file ended before the end-of-stream marker was reached" from
    # gzip, which an `OSError` clause walks straight past. Measured against a 40-byte truncation of a
    # real fixture. `zlib.error` is the same shape one layer down. Neither would have leaked a file --
    # an uncaught exception still exits non-zero -- but the release log would carry a Python traceback
    # instead of the one line saying which archive could not be read, and the reader of a red release
    # is the person who most needs that sentence.
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, zlib.error) as exc:
        raise InspectionError(f"could not list {archive}: {exc}") from exc
    raise InspectionError(
        f"{archive} has no extension this gate can read (.whl, .zip, .tar.gz, .tgz), "
        f"so it would be published uninspected"
    )


def _normalise(part: str) -> str:
    """One path component, reduced to the form the denylist is written in (BACKLOG #1838).

    TRAILING DOTS AND SPACES ARE STRIPPED because Windows strips them when it opens the file, so
    ``CLAUDE.md `` and ``CLAUDE.md.`` install as ``CLAUDE.md`` -- exactly the file this gate exists
    to stop. Measured: all four of ``CLAUDE.md ``, ``CLAUDE.md.``, ``.claude./x`` and ``.claude /x``
    passed the first version of this rule.

    CASEFOLD, NOT ``lower()``. The two differ, and ``lower()`` is the weaker: a filename spelling
    ``agents.md`` with U+017F (LATIN SMALL LETTER LONG S) in place of the ``s`` casefolds to exactly
    ``agents.md`` and lowercases to itself,
    so it passed while the module docstring and this project's own test name both said "case-folded".
    That mismatch between prose and code is the defect; the prose was right.

    BOTH CHARACTERS ABOVE ARE NAMED BY CODE POINT RATHER THAN WRITTEN, and that is a rule here
    rather than a preference: tests/test_cp1252_console_safety.py refuses any non-cp1252 character
    in a file under ``scripts/`` that does not reconfigure ``sys.stdout``, because printing one
    aborts a stock Windows console with UnicodeEncodeError. This docstring cost that gate a red
    when the characters were written literally. Do not helpfully restore them.

    This is NOT a claim to normalise away every equivalent spelling. A homoglyph (Cyrillic
    U+0430 for the Latin ``a``) still passes, and no case-insensitive matcher catches one -- the scope
    paragraph in the module docstring says so, and it stays true.
    """
    return part.rstrip(". ").casefold()


def forbidden(member: str) -> str | None:
    """Why ``member`` is forbidden, or ``None``.

    SPLITS ON BOTH ``/`` AND ``\\``. An earlier version split on ``/`` alone, reasoning that it is
    "what both container formats use". That is true of what a spec-conformant writer STORES and
    false of what the readers hand back: ``tarfile.getnames()`` and ``zipfile.namelist()`` return
    stored names verbatim, so a member written as ``pkg\\CLAUDE.md`` arrives with its backslash
    intact, split into ONE component, and matched nothing (BACKLOG #1838). Hatchling on the Linux
    release runner emits ``/``, so that was a hole in the rule rather than a live bypass -- but a
    gate should not depend on the writer being well-behaved, which is the whole premise of a
    denylist over built artifacts.

    Empty components (a trailing slash on a directory entry, a leading ``/``, a doubled separator)
    drop out.
    """
    parts = [p for p in member.replace("\\", "/").split("/") if p]
    if not parts:
        return None
    for part in parts[:-1]:
        if _normalise(part) in FORBIDDEN_PATH_COMPONENTS:
            return f"path component {part!r} is maintainer-internal"
    leaf = parts[-1]
    if _normalise(leaf) in FORBIDDEN_BASENAMES:
        return f"basename {leaf!r} is maintainer-internal"
    # A directory entry named for a forbidden component arrives with no child to catch it.
    if _normalise(leaf) in FORBIDDEN_PATH_COMPONENTS:
        return f"path component {leaf!r} is maintainer-internal"
    return None


def inspect(archives: Iterable[Path]) -> tuple[int, list[str]]:
    """Inspect every archive; return (members inspected, error lines). Never raises."""
    errors: list[str] = []
    total = 0
    for archive in archives:
        try:
            names = _members(archive)
        except InspectionError as exc:
            errors.append(f"::error::member gate {exc}, so nothing was inspected")
            continue
        # A ZERO-MEMBER LISTING IS NOT A CLEAN ARCHIVE, it is no evidence at all -- the same control
        # the sdist leak gate applies to its own `tar` output, for the same reason.
        if not names:
            errors.append(
                f"::error::member gate listed {archive} and got ZERO members, so nothing was inspected"
            )
            continue
        hits = [(name, why) for name in names if (why := forbidden(name)) is not None]
        errors.extend(f"::error::{archive.name} ships {name} -- {why}" for name, why in hits)
        total += len(names)
        verdict = f"{len(hits)} forbidden" if hits else "none forbidden"
        print(f"member gate: inspected {len(names)} members in {archive.name}, {verdict}")
    return total, errors


def _resolve(patterns: Sequence[str]) -> tuple[list[Path], list[str]]:
    """Expand each pattern, requiring EVERY ONE to match at least one file.

    A pattern that matches nothing is the failure this whole gate exists to prevent, one layer up: a
    misspelled ``harness-dist/*.whl`` inspects zero archives, finds zero forbidden members and prints a
    green line. So an unmatched pattern is an error, not an empty list. Globbing happens HERE rather
    than in the shell for the same reason -- an unmatched shell glob either expands to its own literal
    text or (under ``nullglob``) to nothing, and both are silent.
    """
    found: list[Path] = []
    errors: list[str] = []
    for pattern in patterns:
        p = Path(pattern)
        if p.is_file():
            found.append(p)
            continue
        matches = (
            sorted(m for m in Path(p.parent or ".").glob(p.name) if m.is_file()) if p.name else []
        )
        if not matches:
            errors.append(
                f"::error::member gate found no file matching {pattern!r} -- "
                f"refusing to report a clean result for an archive it never opened"
            )
            continue
        found.extend(matches)
    return found, errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail if a built distribution carries a maintainer-internal file.",
    )
    parser.add_argument(
        "archives",
        nargs="+",
        metavar="ARCHIVE",
        help="paths or globs, e.g. 'dist/*.tar.gz' 'dist/*.whl' (quote them: this script globs)",
    )
    args = parser.parse_args(argv)

    archives, errors = _resolve(args.archives)
    total, inspect_errors = inspect(archives)
    errors.extend(inspect_errors)

    if errors:
        for line in errors:
            print(line, file=sys.stderr)
        print(
            f"member gate FAILED after inspecting {total} members across {len(archives)} archive(s)",
            file=sys.stderr,
        )
        return 1
    # Print the COUNT, not just a word: a green log line has to show the gate inspected something.
    print(
        f"member gate passed: inspected {total} members across {len(archives)} archive(s), "
        f"none matching {len(FORBIDDEN_BASENAMES)} forbidden basenames or "
        f"{len(FORBIDDEN_PATH_COMPONENTS)} forbidden path components"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
