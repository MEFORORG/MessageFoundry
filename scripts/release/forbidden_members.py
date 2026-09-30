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

A SECOND RULE, FOR TEST AND DEVELOPMENT CONTENT (BACKLOG #1938). The first rule asks whether a
member is maintainer-internal. It never asked whether a member is a test, a fixture or a sample, so
a ``tests/`` tree or a ``conftest.py`` that a build config started packing would have shipped with
this gate green. :func:`development_content` is that second question, read the same way: path
components and basenames, casefolded, never file bytes. It applies to every archive EXCEPT one built for a
distribution in :data:`TEST_TOOLING_DISTRIBUTIONS`, and the reason for that one exemption is
written beside the constant.

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
import re
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

#: Directory names that mark test, sample or development content, matched casefolded on every path
#: component (BACKLOG #1938). Measured when this was written: the engine wheel, its sdist and the
#: console wheel carry none of them, so each entry guards against the next build-config change
#: rather than describing a member that ships today. Shipping example content on purpose one day
#: is a one-line edit here, made in the same change that adds it, which is the point of saying so.
TEST_CONTENT_PATH_COMPONENTS: frozenset[str] = frozenset({"tests", "test", "fixtures", "samples"})

#: Exact basenames that mark test content, matched casefolded. The ``test_*.py`` and ``*_test.py``
#: module shapes are matched by :func:`development_content` itself, because they are patterns.
TEST_CONTENT_BASENAMES: frozenset[str] = frozenset({"conftest.py"})

#: Distributions the test-content rule does NOT apply to, as PEP 503 normalised names.
#:
#: THE HARNESS IS TEST TOOLING BY DESIGN, AND THAT IS THE WHOLE REASON FOR THIS SET. It is the send
#: and receive test harness: acceptance runs, load profiles, reconcile tools and the config graphs
#: they drive. A test module or fixture added to it is the product, not a leak, so refusing one on a
#: tag would be a false alarm. Measured when this was written, no harness member trips the rule, so
#: the exemption changes no verdict today; it states the class, not a current exception.
#:
#: The exemption covers ONLY this rule. The maintainer-internal rule above still applies to the
#: harness in full, and the harness is the distribution that needs it most.
#:
#: Keyed on the distribution name in the ARCHIVE FILENAME, which the wheel and sdist specs both put
#: first. That fails safe: a renamed or unrecognised file is not exempt, so the rule gets stricter,
#: never looser. The engine and the web console are deliberately absent.
TEST_TOOLING_DISTRIBUTIONS: frozenset[str] = frozenset({"messagefoundry-harness"})

#: A THIRD RULE, FOR THE ENGINE AND TOOLKIT SPLIT (ADR 0201 section 4, BACKLOG #1192, ASVS 15.2.3).
#: The toolkit distribution carries the authoring and development code that the engine wheel must not.
#: This rule is keyed on the distribution name in the archive filename, like the test-content rule,
#: and matches path COMPONENTS, never a prefix string: an sdist member is
#: ``messagefoundry-0.4.0/messagefoundry/...``, and a prefix match would never fire on it.
ENGINE_DISTRIBUTION = "messagefoundry"
TOOLKIT_DISTRIBUTION = "messagefoundry-toolkit"
TOOLKIT_PACKAGE = "messagefoundry_toolkit"

#: Engine paths ADR 0201 has moved into the toolkit, each as its run of path components. An engine
#: archive carrying one as a CONSECUTIVE run is refused, wheel or sdist. A retired path stays
#: retired, so this list only grows, one entry in the slice that retires each path.
RETIRED_ENGINE_PATHS: tuple[tuple[str, ...], ...] = (
    # Slice 2: the advisory ADR coverage report, now messagefoundry_toolkit/adr_analyze.py.
    ("messagefoundry", "adr_analyze.py"),
)


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


def _parts(member: str) -> list[str]:
    """``member``'s path components, split on BOTH ``/`` and ``\\``, empty ones dropped.

    ONE copy for every rule below, so an evasion closed in the split is closed for all of them.
    :func:`forbidden` says why both separators count and why empty components drop out."""
    return [p for p in member.replace("\\", "/").split("/") if p]


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
    parts = _parts(member)
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


def development_content(member: str) -> str | None:
    """Why ``member`` is test or development content, or ``None`` (BACKLOG #1938).

    Split and normalised exactly as :func:`forbidden` is, so every evasion that function closes
    (backslash separators, trailing dots and spaces, case) is closed here by the same code.
    """
    parts = _parts(member)
    if not parts:
        return None
    for part in parts:
        # Every component, the leaf included, so a bare directory entry is caught too.
        if _normalise(part) in TEST_CONTENT_PATH_COMPONENTS:
            return f"path component {part!r} is test or development content"
    leaf = parts[-1]
    name = _normalise(leaf)
    if (
        name in TEST_CONTENT_BASENAMES
        or (name.startswith("test_") and name.endswith(".py"))
        or name.endswith("_test.py")
    ):
        return f"basename {leaf!r} is test or development content"
    return None


def split_violation(member: str, dist: str) -> str | None:
    """Why ``member`` breaks the engine and toolkit split for distribution ``dist``, or ``None``.

    An engine archive may carry no ``messagefoundry_toolkit`` component and no retired engine path.
    A toolkit archive may carry nothing whose first component is ``messagefoundry``: a toolkit that
    writes into the engine's package directory is the split-package shape ADR 0201 rejects. Every
    other distribution passes. Split and normalised exactly as :func:`forbidden` is.
    """
    parts = [_normalise(p) for p in _parts(member)]
    if not parts:
        return None
    if dist == ENGINE_DISTRIBUTION:
        if TOOLKIT_PACKAGE in parts:
            return f"path component {TOOLKIT_PACKAGE!r} belongs to the toolkit distribution"
        for retired in RETIRED_ENGINE_PATHS:
            width = len(retired)
            if any(tuple(parts[i : i + width]) == retired for i in range(len(parts) - width + 1)):
                return f"{'/'.join(retired)} moved to the toolkit distribution (ADR 0201)"
    elif dist == TOOLKIT_DISTRIBUTION and _install_root_parts(parts)[:1] == [ENGINE_DISTRIBUTION]:
        return "the toolkit may not write into the engine's package directory (ADR 0201)"
    return None


#: The wheel ``.data`` subdirectories pip installs into site-packages itself (PEP 427).
_SITE_PACKAGES_DATA_DIRS = frozenset({"purelib", "platlib"})


def _install_root_parts(parts: list[str]) -> list[str]:
    """``parts`` as they land under site-packages. A wheel member at the archive root lands there as
    written, and so does one under ``<name>.data/purelib/`` or ``<name>.data/platlib/``: PEP 427
    moves those into site-packages at install, so either spelling can write into another package."""
    if len(parts) > 2 and parts[0].endswith(".data") and parts[1] in _SITE_PACKAGES_DATA_DIRS:
        return parts[2:]
    return parts


def distribution(archive: Path) -> str:
    """The PEP 503 normalised distribution name an archive's filename declares.

    Both a wheel (``name-version-...whl``) and an sdist (``name-version.tar.gz``) put the name first
    and end it at the first hyphen, since the name itself is written with underscores. A filename
    that follows neither shape yields whatever precedes its first hyphen, which matches no exempt
    distribution, so the result is the strict path.
    """
    name = archive.name
    lowered = name.lower()
    for suffix in (".tar.gz", ".tgz", ".whl", ".zip"):
        if lowered.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return re.sub(r"[-_.]+", "-", name.split("-", 1)[0]).casefold()


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
        dist = distribution(archive)
        tooling = dist in TEST_TOOLING_DISTRIBUTIONS
        hits = [
            (name, why)
            for name in names
            if (
                why := forbidden(name)
                or (None if tooling else development_content(name))
                or split_violation(name, dist)
            )
            is not None
        ]
        errors.extend(f"::error::{archive.name} ships {name} -- {why}" for name, why in hits)
        total += len(names)
        verdict = f"{len(hits)} forbidden" if hits else "none forbidden"
        print(f"member gate: inspected {len(names)} members in {archive.name}, {verdict}")
        if tooling:
            # Said in the log every time, so the exemption is visible where the verdict is read.
            print(
                f"member gate: test-content rule not applied to {archive.name}: {dist} is test "
                f"tooling by design"
            )
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
        description=(
            "Fail if a built distribution carries a maintainer-internal file, test or "
            "development content outside the test-tooling harness, or a file on the wrong side "
            "of the engine and toolkit split."
        ),
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
        f"{len(FORBIDDEN_PATH_COMPONENTS)} forbidden path components, and none carrying test or "
        f"development content outside {len(TEST_TOOLING_DISTRIBUTIONS)} test-tooling distribution, "
        f"and none on the wrong side of the engine and toolkit split"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
