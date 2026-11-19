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

1. Its first two rules are DENYLISTS over the basename and every path component, so they are immune
   to the prefix-laundering the allowlist had to be hardened against. That gate derives one archive
   root and strips it, because ``docs/messagefoundry/security/PRIVATE.md`` inside a
   ``messagefoundry-0.3.0/`` root laundered itself into an allowlisted path. A basename is the same
   string wherever the member sits, so those two rules have no prefix to launder and nothing to
   strip. The third rule, the engine and toolkit split, is the exception: its half for every
   distribution but the engine reads a member's FIRST component, so it does derive the archive's
   root from the listing, as the leak gate does, refuses any archive but a wheel that lacks exactly
   one, and tests each member both with and without that root (:func:`_archive_root`, :func:`_split_candidates`).

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
import stat
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

#: Every distribution this repository publishes, as PEP 503 normalised names. An archive whose
#: filename names a distribution outside this set is refused, and so is one whose filename has no
#: ``<name>-<version>`` shape at all (:func:`filename_problem`): the split rule is keyed on the
#: filename, so a name it cannot place would otherwise get no split rule, where reading up to the
#: first hyphen used to give ``messagefoundry-dev.whl`` the engine's (BACKLOG #5470). Every archive
#: this gate is pointed at is one of these four, so any other name is as unplaceable as no name.
KNOWN_DISTRIBUTIONS: frozenset[str] = frozenset(
    {
        ENGINE_DISTRIBUTION,
        TOOLKIT_DISTRIBUTION,
        "messagefoundry-harness",
        "messagefoundry-webconsole",
    }
)

#: What may follow ``messagefoundry.`` in a top-level FILE of any non-engine archive: documentation and
#: configuration, which Python never imports. Every other suffix, and none, is refused, so a module,
#: extension module or a suffix nobody listed stays refused; only this list is let through. A
#: top-level ``.pth`` is refused whatever its name, by its own check in :func:`_split_rule`.
_INERT_SUFFIXES: frozenset[str] = frozenset(
    {"md", "rst", "txt", "toml", "json", "yaml", "yml", "cfg", "ini"}
)

#: Modules ``site`` imports at every interpreter start when they sit on a site directory.
_STARTUP_MODULES: frozenset[str] = frozenset({"sitecustomize", "usercustomize"})

#: Engine paths ADR 0201 has moved into the toolkit, each as its run of path components. An engine
#: archive carrying one as a CONSECUTIVE run is refused, wheel or sdist. A retired path stays
#: retired, so this list only grows, one entry in the slice that retires each path.
RETIRED_ENGINE_PATHS: tuple[tuple[str, ...], ...] = (
    # Slice 2: the advisory ADR coverage report, now messagefoundry_toolkit/adr_analyze.py.
    ("messagefoundry", "adr_analyze.py"),
    # Slice 4: the scaffold, the Steps view and the Corepoint importer, each now under
    # messagefoundry_toolkit/ with the same file name.
    ("messagefoundry", "scaffold.py"),
    ("messagefoundry", "lens.py"),
    ("messagefoundry", "lens_schema.py"),
    ("messagefoundry", "corepoint_import.py"),
    # Slice 6: the de-identification package (ADR 0030), now messagefoundry_toolkit/anon/. The run
    # names the directory, so it refuses every member under it, whatever the file, and the last
    # component matches by stem, so a one-file module (anon.py, anon.pyc, an extension module)
    # that would restore the import name messagefoundry.anon is refused too.
    ("messagefoundry", "anon"),
    # Slice 7: the synthetic HL7 generators and the two schema emitters, now
    # messagefoundry_toolkit/generators/, hl7schema.py and hl7structures.py. The generators run
    # names the directory, so it refuses every member under it, as the anon run does.
    ("messagefoundry", "generators"),
    ("messagefoundry", "hl7schema.py"),
    ("messagefoundry", "hl7structures.py"),
)


_ASCII_DIGITS = frozenset("0123456789")

#: The shape of a Windows 8.3 short name, matched on a normalised component: at most six
#: characters, ``~``, digits, and an optional extension of at most three characters
#: (``messag~1``, ``messag~1.py``). A ``~<digit>`` elsewhere in a longer name (``b~1c.txt``) is
#: not one, because Windows does not open a file under it.
_SHORT_NAME = re.compile(r"[^.]{1,6}~\d+(\.[^.]{0,3})?")

_SPECIAL = "a link or special file; a published distribution carries regular files only"


#: The Unix file types a zip entry may carry: none recorded, a regular file, or a directory.
_ZIP_PLAIN_TYPES: frozenset[int] = frozenset({0, stat.S_IFREG, stat.S_IFDIR})


class InspectionError(RuntimeError):
    """An archive could not be inspected, so nothing about it has been proved."""


def _members(archive: Path) -> list[tuple[str, bool]]:
    """Every member of ``archive`` as ``(name, special)``, or raise :class:`InspectionError`.

    ``special`` marks a member that is not a regular file or directory: a tar symbolic or hard
    link, device or fifo, or a zip entry whose Unix mode names any file type but a regular file or
    a directory (a zip written with no Unix mode carries type 0 and reads as regular). :func:`inspect`
    refuses every one (BACKLOG #5470). Reading names alone never saw a link's target, so an
    innocently named link, or a chain of them, could make extraction write into the engine
    package or outside the archive. Modelling targets by text cannot follow a chain; a published
    distribution has no reason to carry a link, so refusing the class closes it whole.

    RAISING RATHER THAN RETURNING EMPTY IS THE POINT. "No forbidden member" and "the listing failed"
    are the same empty set, and a gate that cannot tell them apart reports a clean archive when it read
    nothing at all. Both readers below fail loudly instead: ``tarfile`` and ``zipfile`` raise on a
    stream they cannot parse, and :func:`inspect` turns a zero-length listing into a failure too.
    """
    suffixes = [s.lower() for s in archive.suffixes]
    try:
        if archive.suffix.lower() in {".whl", ".zip"}:
            with zipfile.ZipFile(archive) as zf:
                return [
                    (i.filename, stat.S_IFMT(i.external_attr >> 16) not in _ZIP_PLAIN_TYPES)
                    for i in zf.infolist()
                ]
        if suffixes[-2:] == [".tar", ".gz"] or archive.suffix.lower() == ".tgz":
            # `r:gz` and not `r:*`: the mode must be the one the filename promised, so a `.tar.gz`
            # that is secretly an uncompressed tar fails here rather than being read anyway.
            with tarfile.open(archive, "r:gz") as tf:
                return [(i.name, not (i.isfile() or i.isdir())) for i in tf.getmembers()]
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


def _archive_root(names: Sequence[str]) -> tuple[str | None, str | None]:
    """``(root, None)`` for the one top-level directory every member sits under, normalised, or
    ``(None, why)`` when the listing has no such single directory.

    An sdist puts everything under one ``<name>-<version>/`` root whatever the version looks like,
    and the toolkit test reads the FIRST component, so the split rule tests each member without it
    too (BACKLOG #5470). Derived from the listing, as the sdist leak gate does, not guessed from a
    version shape. Each member is read as an extractor writes it: ``..`` applied, ``.`` and empty
    components (GNU tar's ``./`` entry) dropped, and the first component normalised, so a case or
    trailing-dot spelling of the root is the same root. A listing with two top-level entries, or
    with no directory at all, has no root to strip, and :func:`inspect` refuses it rather than
    silently testing every member unstripped."""
    resolved = [r for n in names if (r := _resolve_dots(_parts(n))[0])]
    firsts = sorted({_normalise(r[0]) for r in resolved})
    if len(firsts) == 1 and any(len(r) > 1 for r in resolved):
        return firsts[0], None
    if len(firsts) > 1:
        shown = ", ".join(repr(f) for f in firsts[:5])
        return None, f"it has {len(firsts)} top-level entries ({shown})"
    return None, "it has no top-level directory"


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
    """``member``'s path components, split on BOTH ``/`` and ``\\``, empty and ``.`` ones dropped.

    ONE copy for every rule below, so an evasion closed in the split is closed for all of them.
    :func:`forbidden` says why both separators count and why empty components drop out. A ``.``
    component names the directory it sits in, so ``./messagefoundry/x.py`` is ``messagefoundry/x.py``
    to an extractor, and keeping it hid that from a rule that reads the first component or a
    consecutive run (BACKLOG #5470). Dropping one never removes a component a rule could match.
    ``. `` counts as ``.``, as :func:`_normalise` reads a trailing space. So does every other
    component that :func:`_normalise` reduces to nothing (``...``, ``   ``, ``. .``): Windows strips
    trailing dots and spaces and then drops the empty component, so ``   /messagefoundry/x.py``
    writes ``messagefoundry/x.py`` there. ``..`` is the one such component kept, because it climbs."""
    return [
        p for p in member.replace("\\", "/").split("/") if p.rstrip(" ") == ".." or _normalise(p)
    ]


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


def _stem(part: str) -> str:
    """A path component up to its first dot: ``anon.cpython-314.pyc`` is ``anon``."""
    return part.split(".", 1)[0]


def _has_retired_run(parts: list[str], retired: tuple[str, ...]) -> bool:
    """Whether ``parts`` holds ``retired`` as a consecutive run, its last component matched by
    stem. A retired module comes back as a sourceless ``.pyc`` or an extension module just as
    well as a ``.py``, and a retired package as a one-file module, so the last component is
    compared by what Python imports it as, not by its whole name."""
    *parents, last = retired
    width = len(retired)
    for i in range(len(parts) - width + 1):
        window = parts[i : i + width]
        if window[:-1] == parents and _stem(window[-1]) == _stem(last):
            return True
    return False


def _name_version(stem: str) -> str | None:
    """The name half of a ``<name>-<version>`` string, or ``None`` if it has no such shape.

    The version is the first hyphen-separated segment, after the first, that starts with a digit,
    which is where the wheel and sdist rules end a name. Splitting at the first hyphen instead
    read ``messagefoundry-toolkit-0.4.0.tar.gz`` as the engine (BACKLOG #5470). The digit must be
    ASCII: ``str.isdigit`` also accepts other scripts' digits, which no version scheme writes, so a
    segment starting with one is part of the name and the name is then refused as unknown."""
    segments = stem.split("-")
    for i in range(1, len(segments)):
        if segments[i][:1] in _ASCII_DIGITS:
            return "-".join(segments[:i])
    return None


def _resolve_dots(parts: list[str]) -> tuple[list[str], bool]:
    """``parts`` with each ``..`` applied to the component before it, as an extractor would, and
    whether a ``..`` climbed above the first component. ``.. `` counts as ``..``."""
    resolved: list[str] = []
    climbed = False
    for part in parts:
        if part.rstrip(" ") == "..":
            if resolved:
                resolved.pop()
            else:
                climbed = True
        else:
            resolved.append(part)
    return resolved, climbed


def escapes_root(member: str) -> str | None:
    """Why ``member`` points outside the archive, or ``None``.

    An absolute path, a drive letter, or a ``..`` that climbs above the archive's top level names a
    file the archive does not hold, such as an installed engine package, so no rule here can read
    it. A published distribution has no reason to carry one, so it is refused (BACKLOG #5470)."""
    unified = member.replace("\\", "/")
    # A drive letter in ANY component, not only the first: ``./C:/x.py`` is ``C:/x.py`` once the
    # ``.`` component drops out, as every other rule here reads it.
    if unified.startswith("/") or any(re.match(r"[A-Za-z]:", p) for p in _parts(member)):
        return "the path is absolute, outside the archive"
    if _resolve_dots(_parts(member))[1]:
        return "the path climbs above the archive's top level"
    # Two Windows spellings of a path no rule here can read, each opening a file under another
    # name: a colon names an alternate data stream (``messagefoundry::$INDEX_ALLOCATION`` is the
    # directory ``messagefoundry``), and ``~<digit>`` an 8.3 short name (``MESSAG~1``). No build
    # backend writes either into a published distribution.
    for part in _parts(member):
        if ":" in part:
            return f"component {part!r} names a drive or an alternate data stream"
        if _SHORT_NAME.fullmatch(_normalise(part)):
            return f"component {part!r} has the shape of a Windows 8.3 short name"
    return None


def _split_candidates(member: str, root: str | None) -> list[list[str]]:
    """Every reading of ``member`` the split rule tests, normalised: as written and with ``..``
    applied, each also without the archive's common ``root`` when it starts with it (BACKLOG
    #5470). The root is stripped from the ``..``-resolved reading too, so
    ``<root>/../<root>/messagefoundry/x.py`` is read as the ``messagefoundry/x.py`` an extractor
    writes. Every reading is tested, so stripping a root cannot hide a ``<name>.data/`` tree.
    ``root`` may be given raw; it is normalised here."""
    # Resolved and stripped on the components as written: normalising first would turn ``..`` into
    # an empty string that no longer climbs.
    raw = _parts(member)
    readings = [raw, _resolve_dots(raw)[0]]
    if root is not None:
        key = _normalise(root)
        readings += [parts[1:] for parts in readings if parts and _normalise(parts[0]) == key]
    unique = dict.fromkeys(tuple(_normalise(p) for p in parts) for parts in readings if parts)
    return [list(parts) for parts in unique]


def _canonical(name: str) -> str:
    """``name`` with every run of ``-``, ``_`` and ``.`` read as one ``-``, the PEP 503 form."""
    return re.sub(r"[-_.]+", "-", name)


def _versioned_as(part: str, dist: str) -> bool:
    """Whether one normalised component is a ``<name>-<version>`` entry for ``dist``: its
    ``.dist-info``, ``.data`` or ``.egg-info`` directory, or its sdist root.

    A ``.dist-info`` or ``.egg-info`` directory is also read as ``importlib.metadata`` reads it:
    the suffix dropped and the name ended at the first hyphen, with no version required, so
    ``messagefoundry-dev.dist-info`` declares the engine just as ``messagefoundry-0.4.0`` does."""
    name = _name_version(part)
    if name is not None and _canonical(name) == dist:
        return True
    stem, dot, suffix = part.rpartition(".")
    return (
        bool(dot)
        and suffix in {"dist-info", "egg-info"}
        and (_canonical(stem.partition("-")[0]) == dist)
    )


def _names_dist(part: str, dist: str) -> bool:
    """Whether one normalised component names ``dist``: its import name by stem, in any PEP 503
    spelling, or any ``<name>-<version>`` entry for it."""
    return _canonical(_stem(part)) == dist or _versioned_as(part, dist)


def _split_rule(parts: list[str], dist: str) -> str | None:
    """Why one normalised reading breaks the split for ``dist``, or ``None``."""
    if dist == ENGINE_DISTRIBUTION:
        if any(_names_dist(part, TOOLKIT_DISTRIBUTION) for part in parts):
            return f"a path named for {TOOLKIT_PACKAGE!r} belongs to the toolkit distribution"
        for retired in RETIRED_ENGINE_PATHS:
            if _has_retired_run(parts, retired):
                return f"{'/'.join(retired)} moved to the toolkit distribution (ADR 0201)"
    else:
        # EVERY other distribution installs beside the engine, so none may install over it: the
        # harness and web console are as able to write a messagefoundry/ tree or a .pth as the
        # toolkit is (BACKLOG #5470).
        first = parts[0]
        if _versioned_as(first, ENGINE_DISTRIBUTION):
            return f"{dist} may not carry an engine <name>-<version> entry (ADR 0201)"
        # A directory named for the engine, or a top-level file Python could import as it. A
        # documentation or configuration file of that name is neither (_INERT_SUFFIXES).
        if _stem(first) == ENGINE_DISTRIBUTION and (
            len(parts) > 1 or first.partition(".")[2] not in _INERT_SUFFIXES
        ):
            return f"{dist} may not write into the engine's package directory (ADR 0201)"
        # A top-level .pth of ANY name runs its import lines at every interpreter start, where it
        # can rebind engine modules: the split-package override ADR 0201 rejects. So does a
        # top-level sitecustomize or usercustomize module or package, which `site` imports.
        if len(parts) == 1 and first.endswith(".pth"):
            return f"{dist} ships no top-level .pth, which runs code at interpreter start"
        if _stem(first) in _STARTUP_MODULES:
            return f"{dist} ships no top-level {_stem(first)}, which runs at interpreter start"
        if first.endswith(".data"):
            return f"{dist} ships no wheel .data tree, which installs outside its package"
    return None


def split_violation(member: str, dist: str, root: str | None = None) -> str | None:
    """Why ``member`` breaks the engine and toolkit split for distribution ``dist``, or ``None``.

    An engine archive may carry nothing named for the toolkit, as a directory, a module or a
    ``.pth`` (any component whose stem is ``messagefoundry_toolkit`` in any PEP 503 spelling), or a
    toolkit ``<name>-<version>`` entry, and no retired engine path. Every other archive, the
    toolkit, harness and web console alike, may carry no first component that installs as the
    engine: a ``messagefoundry`` directory, a top-level ``messagefoundry`` file other than
    documentation or configuration (:data:`_INERT_SUFFIXES`), an engine ``<name>-<version>`` entry,
    or a top-level ``.pth``, ``sitecustomize`` or ``usercustomize``. Nor may it carry a
    ``<name>.data/`` tree at all: PEP 427 installs ``purelib``, ``platlib``, ``scripts`` and
    ``data`` outside the package, where each can overwrite the engine's package or its console
    script. None of them has a reason to ship one, so refusing the whole class is simpler than
    modelling each scheme. That is the split-package shape ADR 0201 rejects. Split and normalised
    exactly as :func:`forbidden` is, and tested in every
    reading :func:`_split_candidates` names.
    """
    for parts in _split_candidates(member, root):
        why = _split_rule(parts, dist)
        if why is not None:
            return why
    return None


def distribution(archive: Path) -> str:
    """The PEP 503 normalised distribution name an archive's filename declares.

    Both a wheel (``name-version-...whl``) and an sdist (``name-version.tar.gz``) put the name first
    and end it where the version begins: the first hyphen-separated segment that starts with a
    digit. A conforming name is written with underscores, but a hyphenated one
    (``messagefoundry-toolkit-0.4.0.tar.gz``) must not read as its first word, which named the
    engine and skipped the toolkit rule (BACKLOG #5470). A filename with no version segment yields
    its whole stem, and :func:`filename_problem` refuses that archive, so such a name is only ever
    used to report it.
    """
    return _canonical(_declared_name(archive)).casefold()


def _filename_stem(archive: Path) -> str:
    """``archive``'s filename without the archive suffix this gate reads."""
    name = archive.name
    lowered = name.lower()
    for suffix in (".tar.gz", ".tgz", ".whl", ".zip"):
        if lowered.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _declared_name(archive: Path) -> str:
    """The name part of ``archive``'s filename as written, before normalisation."""
    stem = _filename_stem(archive)
    return _name_version(stem) or stem


def filename_problem(archive: Path) -> str | None:
    """Why ``archive``'s filename cannot be placed, or ``None`` (BACKLOG #5470).

    The split rule is keyed on the distribution the filename names, so a filename that names none
    would get no split rule at all. Two shapes are refused, fail closed: a filename with no
    ``<name>-<version>`` shape, which no wheel or sdist build writes (``messagefoundry-dev.whl``,
    ``messagefoundry-v0.4.0.tar.gz``), and any name outside :data:`KNOWN_DISTRIBUTIONS`, where a
    ``messagefoundry`` one once got the engine's rule by reading up to the first hyphen and a
    renamed toolkit (``mftoolkit-0.4.0``) would get none.
    :func:`inspect` still inspects such an archive, under both split rules."""
    # Falsy, not `is None`: an empty name (``-1.0-py3-none-any.whl``) places nothing either.
    if not _name_version(_filename_stem(archive)):
        return (
            "its filename has no <name>-<version> shape, so the distribution, and the engine and "
            "toolkit split rule that applies to it, cannot be read"
        )
    # A wheel filename writes its name with underscores (the wheel spec escapes every run of
    # ``-``, ``_`` and ``.`` to ``_``), so a hyphen in it is no wheel any build writes. Placing it
    # by its canonical name gave ``messagefoundry-webconsole-0.4.0-...whl`` the console's (empty)
    # split rule where the engine rule used to run on it.
    if archive.suffix.lower() == ".whl" and "-" in _declared_name(archive):
        return (
            "it is a wheel whose distribution name contains a hyphen, which no wheel build writes, "
            "so the engine and toolkit split rule that applies to it cannot be read"
        )
    dist = distribution(archive)
    if dist not in KNOWN_DISTRIBUTIONS:
        return f"its filename names {dist!r}, which is no distribution this repository publishes"
    return None


def inspect(archives: Iterable[Path]) -> tuple[int, list[str]]:
    """Inspect every archive; return (members inspected, error lines). Never raises."""
    errors: list[str] = []
    total = 0
    for archive in archives:
        try:
            entries = _members(archive)
        except InspectionError as exc:
            errors.append(f"::error::member gate {exc}, so nothing was inspected")
            continue
        # A ZERO-MEMBER LISTING IS NOT A CLEAN ARCHIVE, it is no evidence at all -- the same control
        # the sdist leak gate applies to its own `tar` output, for the same reason.
        if not entries:
            errors.append(
                f"::error::member gate listed {archive} and got ZERO members, so nothing was inspected"
            )
            continue
        dist = distribution(archive)
        problem = filename_problem(archive)
        if problem is not None:
            errors.append(f"::error::member gate refuses {archive.name}: {problem}")
        # An unplaceable filename gets BOTH split rules, the strictest reading there is.
        split_dists = (ENGINE_DISTRIBUTION, TOOLKIT_DISTRIBUTION) if problem else (dist,)
        # The exemption is keyed on the exact name the build writes, all lowercase with underscores
        # (``messagefoundry_harness``): any other spelling of the same distribution, a hyphen, a dot
        # or a capital, is not exempt, so a rename only tightens.
        tooling = (
            problem is None
            and dist in TEST_TOOLING_DISTRIBUTIONS
            and _declared_name(archive) == dist.replace("-", "_")
        )
        names = [name for name, _special in entries]
        root: str | None = None
        refused = problem is not None
        if archive.suffix.lower() != ".whl":
            # A wheel installs at the top level and has no root. Every other archive is an sdist,
            # zip or tar, whose one root the split rule must know to read a first component.
            root, root_problem = _archive_root(names)
            if root_problem is not None:
                refused = True
                errors.append(
                    f"::error::member gate refuses {archive.name}: {root_problem}, not the one "
                    f"<name>-<version>/ root an sdist has, so no first component can be read"
                )
        hits = [
            (name, why)
            for name, special in entries
            if (
                why := (_SPECIAL if special else None)
                or forbidden(name)
                or escapes_root(name)
                or (None if tooling else development_content(name))
                or next(filter(None, (split_violation(name, d, root) for d in split_dists)), None)
            )
            is not None
        ]
        errors.extend(f"::error::{archive.name} ships {name} -- {why}" for name, why in hits)
        total += len(entries)
        verdict = f"{len(hits)} forbidden" if hits else "none forbidden"
        if refused:
            # A member count of zero must not read as a clean archive when the archive itself was
            # refused, by its filename or its root.
            verdict = f"ARCHIVE REFUSED, {len(hits)} members forbidden"
        print(f"member gate: inspected {len(entries)} members in {archive.name}, {verdict}")
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
        f"member gate passed: inspected {total} members across {len(archives)} archive(s) and "
        f"refused none, under every rule in scripts/release/forbidden_members.py, at least "
        f"{len(FORBIDDEN_BASENAMES)} forbidden basenames, {len(FORBIDDEN_PATH_COMPONENTS)} "
        f"forbidden path components, test or development content outside "
        f"{len(TEST_TOOLING_DISTRIBUTIONS)} test-tooling distribution, links and special members, "
        f"paths leaving the archive, unplaceable filenames, rootless sdists, and the engine and "
        f"toolkit split"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
