# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No tracked file that reaches a distribution may be one the release gate would refuse (#1840).

WHY THIS IS NOT ALREADY COVERED. ``tests/test_packaging.py`` guards ONE basename -- its
``_INSTRUCTIONS_FILE`` is ``CLAUDE.md`` and deliberately nothing else. The release gate,
``scripts/release/forbidden_members.py``, refuses a CLASS: ``CLAUDE.md``, ``CLAUDE.local.md``,
``AGENTS.md``, ``GEMINI.md``, ``.cursorrules``, and the ``.claude`` and ``.github`` path components.
Everything in that class but the first is invisible to every check that runs on a pull request, and
the gate that does see it fires only on a TAG -- the one moment nobody is watching and the one
outcome that cannot be undone, because a PyPI version number is never re-usable.

WHY A SEPARATE FILE. This belongs beside the packaging guards and is not written there on purpose:
two live branches held committed changes to ``test_packaging.py`` when this was written, one of them
refactoring the very table reader this would have sat next to. A new file conflicted with neither.
That refactor has since landed (BACKLOG #1836), so the build table below is READ THROUGH
``tests/_force_include`` rather than walked here. The separate file stays; a second reader does not.

IMPORTING THE GATE IS LOAD-BEARING, NOT A CONVENIENCE. A second copy of the denylist here would be a
second rule, free to drift from the one that actually refuses a publish -- and the drift would
surface as a green pull request followed by a red release, which is the worst place to learn it.
One rule, read at two moments.

THE TWO DISTRIBUTION SHAPES FAIL DIFFERENTLY, so they are checked differently:

- The engine's package tree is WALKED, so ``exclude`` reaches it. A forbidden file there is fine
  exactly as long as a pattern covers it.
- A ``force-include`` map is NOT filtered by ``exclude`` at all -- hatchling's
  ``recurse_forced_files`` never calls ``include_path`` -- so a mapped file ships, full stop, and the
  only fix is to stop mapping it.

WHAT THIS STILL CANNOT SEE, stated so nobody reads it as complete. It models hatchling from config
and the git index; it does not build. A file that is untracked but present on the build machine
still reaches a wheel through a whole-directory mapping, and no tracked-tree scan can see that. The
build job in ``ci.yml`` is the half that measures instead of modelling; this half is the one that is
free enough to run on every pull request.
"""

from __future__ import annotations

import functools
import importlib.util
import subprocess
from collections.abc import Callable
from pathlib import Path

from tests._force_include import hatch_build, wheel_force_include

_REPO = Path(__file__).resolve().parents[1]
_GATE = _REPO / "scripts" / "release" / "forbidden_members.py"


@functools.cache
def _forbidden() -> Callable[[str], str | None]:
    """``forbidden()`` from the release gate, loaded by PATH rather than imported by name.

    ``scripts/`` is not a package and has no ``__init__.py``, so there is no import path to it.
    Loading the file directly also keeps this module from mutating ``sys.path``, which
    ``tests/test_release_member_gate.py`` does -- two test modules disagreeing about ``sys.path`` is
    how an import-order flake starts.

    Fails LOUDLY if the gate moves. A ``try/except`` returning a no-op would turn a relocated gate
    into a green scan over an unguarded tree, which is the exact failure shape this item exists for.
    """
    assert _GATE.is_file(), (
        f"{_GATE} is missing -- the release member gate moved and this scan is blind"
    )
    spec = importlib.util.spec_from_file_location("_mefor_release_gate", _GATE)
    assert spec is not None and spec.loader is not None, f"cannot load {_GATE}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    loaded: Callable[[str], str | None] = module.forbidden
    return loaded


@functools.cache
def _tracked(*prefixes: str) -> frozenset[str]:
    """Repo-relative POSIX paths git tracks under any of ``prefixes``."""
    out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, repo-local paths
        ["git", "-C", str(_REPO), "ls-files", "-z", "--", *prefixes],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return frozenset(p for p in out.split("\0") if p)


def _force_include_map(pyproject: Path) -> dict[str, str]:
    """Repo-relative source -> the path inside the wheel that a ``force-include`` entry lands it at.

    The map comes from ``tests._force_include``, which resolves the wheel target against the global
    table the way ``BuilderConfig.force_include`` does -- on PRESENCE of the key, not on the map
    being non-empty. This walked the TOML itself until BACKLOG #1836, and the hand walk it replaced
    branched on truthiness: a wheel declaring an EMPTY map would have been credited with the global
    one, and this scan would have reported files that wheel never ships.

    Turning the SOURCES into repo-relative paths stays here, because the shared reader returns them
    as written -- relative to the PROJECT directory, which is where the build reads them from. The
    TARGETS are already wheel-relative and are carried through untouched.
    """
    out: dict[str, str] = {}
    for source, target in wheel_force_include(pyproject).items():
        resolved = (pyproject.parent / source).resolve()
        try:
            out[resolved.relative_to(_REPO).as_posix()] = target
        except ValueError:
            raise AssertionError(
                f"{pyproject.relative_to(_REPO).as_posix()} force-includes {source!r}, resolving to "
                f"{resolved}, outside the repository -- this scan cannot model what that wheel ships"
            ) from None
    return out


def _shipped_members(mapping: dict[str, str], tracked: frozenset[str]) -> dict[str, str]:
    """Tracked repo path -> the member name the wheel carries it under.

    What a ``force-include`` map ships: a named FILE outright, a named DIRECTORY walked whole.

    THE MEMBER NAME IS WHAT THE GATE SEES, and it is not always the repo path. ``forbidden()``
    matches a BASENAME and PATH COMPONENTS on the name inside the archive, so an entry whose target
    renames its source makes the two disagree -- ``"../../tools/agentdocs" = "harness/.github"``
    carries no forbidden component on the left and one on the right. Reading the source there is a
    false negative in the dangerous direction: a clean scan and a tag that cannot be re-cut.

    Nothing under ``packaging/`` renames today, and ``test_packaging.py`` pins that for the harness
    map alone, so the case is planted in ``test_the_member_model_follows_a_renaming_map`` rather than
    read off the tree. The source path is still what gets REPORTED, because it is what a maintainer
    has to edit.
    """
    out: dict[str, str] = {}
    for path in tracked:
        for source, target in mapping.items():
            if path == source:
                out[path] = target
            elif path.startswith(f"{source}/"):
                out[path] = f"{target}/{path[len(source) + 1 :]}"
    return out


def _refused(dist: str, shipped: dict[str, str]) -> list[str]:
    """Which of ``shipped`` the release gate would refuse -- TESTED member-side, REPORTED source-side.

    One predicate, called by the scan and by its planted control, so the control covers the reading
    the scan actually does. Two spellings of it could not: a control that exercised only
    ``_shipped_members`` would stay green while the scan went back to reading the repo path.
    """
    forbidden = _forbidden()
    return [
        f"{dist}: {path} -> {member} ({why})"
        for path, member in sorted(shipped.items())
        if (why := forbidden(member)) is not None
    ]


def _packaging_pyprojects() -> list[Path]:
    """Every ``packaging/<dist>/`` project, discovered rather than listed, so a new one is covered."""
    return sorted(_REPO.glob("packaging/*/pyproject.toml"))


# --------------------------------------------------------------------------------------------------
# The control comes FIRST, because every scan below is vacuous if the gate did not load.
# --------------------------------------------------------------------------------------------------


def test_the_gate_import_reaches_a_real_denylist() -> None:
    """A loader returning a function that matched nothing would make every scan below pass forever."""
    forbidden = _forbidden()
    assert forbidden("messagefoundry/CLAUDE.md") is not None, (
        "the gate refuses nothing -- import broke"
    )
    assert forbidden("messagefoundry/AGENTS.md") is not None, (
        "the gate is narrower than this scan assumes -- it should refuse the whole class, not one name"
    )
    assert forbidden("messagefoundry/.claude/settings.json") is not None, (
        "path components unguarded"
    )
    assert forbidden("messagefoundry/__init__.py") is None, "the gate refuses ordinary source"


def test_the_tracked_scan_sees_a_real_tree() -> None:
    """The other half of the control: a scan over an empty file set is silent, not clean."""
    assert len(_tracked("messagefoundry")) > 100, (
        "git ls-files returned almost nothing -- scan broke"
    )
    assert _packaging_pyprojects(), "no packaging/*/pyproject.toml found -- the discovery broke"


# --------------------------------------------------------------------------------------------------
# The scans.
# --------------------------------------------------------------------------------------------------


def test_no_force_included_tree_ships_a_denylisted_file() -> None:
    """A mapped file ships regardless of ``exclude``, so the map is the only place to fix it."""
    problems: list[str] = []
    seen = 0
    mapped = 0
    for pyproject in _packaging_pyprojects():
        mapping = _force_include_map(pyproject)
        if not mapping:
            # A distribution whose package sits inside its own project directory needs no map, and
            # demanding one would red it for the wrong reason. It is covered by `exclude` instead.
            continue
        mapped += 1
        shipped = _shipped_members(mapping, _tracked(*{src.split("/")[0] for src in mapping}))
        assert shipped, f"{pyproject.relative_to(_REPO).as_posix()} maps sources but ships no file"
        seen += len(shipped)
        problems.extend(_refused(pyproject.parent.name, shipped))
    assert mapped >= 1, "no distribution force-includes anything -- the parse broke"
    assert seen >= 100, f"the force-include scan saw only {seen} shipped files -- it broke"
    assert not problems, (
        f"these force-included files would be REFUSED by the release gate on a tag: {problems}. "
        f"`exclude` does not reach a force-included file in hatchling -- remove the entry from the "
        f"wheel's force-include map, enumerating siblings if the map names a whole directory."
    )


def test_the_member_model_follows_a_renaming_map() -> None:
    """The control for the arm above: it must read the WHEEL's member name, not the repo's path.

    PLANTED, because the tree cannot supply this case. Both maps under ``packaging/`` land every
    source at its own path, and ``test_packaging.py`` pins that for the harness map -- so against the
    real tree a scan reading the source and a scan reading the member agree on every file, and the
    arm above would stay green with either one. That is the shape of a check whose subject never
    varies: it proves nothing until the varying case is written down.

    Both halves matter. The sources here are CLEAN and the members are FORBIDDEN, so a scan reading
    the source sees nothing at all -- which is why the last assertion is not decoration.

    Goes through ``_refused``, the same predicate the scan calls, so this covers the READING and not
    just the model. Mutation: pass ``path`` to ``forbidden()`` there. Red: no refusal here.
    """
    shipped = _shipped_members(
        {"tools/agentdocs": "harness/.github", "tools/notes.md": "harness/AGENTS.md"},
        frozenset({"tools/agentdocs/setup.md", "tools/notes.md", "tools/unmapped.md"}),
    )
    assert shipped == {
        "tools/agentdocs/setup.md": "harness/.github/setup.md",
        "tools/notes.md": "harness/AGENTS.md",
    }, (
        "a directory entry rewrites the prefix, a file entry replaces the whole name, and a tracked "
        "file no entry names is not shipped at all"
    )
    refused = _refused("planted", shipped)
    assert len(refused) == 2, (
        f"the gate must refuse both planted members -- one carries a forbidden path component, the "
        f"other a forbidden basename, and both arrive only through the TARGET side of the map. "
        f"Refused: {refused}"
    )
    forbidden = _forbidden()
    assert all(forbidden(path) is None for path in shipped), (
        "the control is vacuous unless every SOURCE path is clean: if the gate refused those too, "
        "the scan would red whichever string it read and this would establish nothing"
    )


def test_no_walked_engine_file_ships_a_denylisted_file() -> None:
    """The engine's tree IS filtered by ``exclude``, so a forbidden file is fine if a pattern covers it.

    Matched on the BASENAME against the exclude list, which is how the patterns in this repo are
    written and why ``pyproject.toml`` records that they must stay slashless: hatchling reads
    ``exclude`` with gitignore semantics, so a bare ``CLAUDE.md`` matches at any depth while
    ``/CLAUDE.md`` is anchored at the project root and would leave the nested copy shipping.
    """
    forbidden = _forbidden()
    excluded = set(hatch_build(_REPO / "pyproject.toml").get("exclude", []))
    problems = [
        f"{path} ({why})"
        for path in sorted(_tracked("messagefoundry"))
        if (why := forbidden(path)) is not None and Path(path).name not in excluded
    ]
    assert not problems, (
        f"these tracked engine files would be REFUSED by the release gate on a tag: {problems}. "
        f"Add each basename to [tool.hatch.build].exclude in the root pyproject.toml, keeping the "
        f"pattern slashless so it matches at any depth."
    )


def test_the_engine_exclusion_still_guards_something() -> None:
    """Liveness for the arm above: an exclude list that covers nothing has stopped doing work.

    Without this, deleting every forbidden file from the tree would leave a dead pattern that reads
    as protection. Asserted at any depth, so a move WITHIN the package does not red it.
    """
    forbidden = _forbidden()
    excluded = set(hatch_build(_REPO / "pyproject.toml").get("exclude", []))
    guarded = sorted(
        path
        for path in _tracked("messagefoundry")
        if forbidden(path) is not None and Path(path).name in excluded
    )
    assert guarded, (
        "no tracked file under messagefoundry/ is both denylisted and excluded, so "
        "[tool.hatch.build].exclude now guards nothing against this class -- drop it or repoint it"
    )
