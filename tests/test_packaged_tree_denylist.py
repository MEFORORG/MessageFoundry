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
two live branches held committed changes to ``test_packaging.py`` when this landed, one of them
refactoring the very table reader this would have sat next to. A new file conflicts with neither.

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
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

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


def _build_table(pyproject: Path) -> dict[str, Any]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    table: dict[str, Any] = data.get("tool", {}).get("hatch", {}).get("build", {})
    return table


def _force_include_sources(pyproject: Path) -> frozenset[str]:
    """Repo-relative sources a wheel's ``force-include`` pulls from.

    Reads the TARGET table and falls back to the global one, the way ``BuilderConfig.force_include``
    resolves it -- reading only the target would skip a distribution using the global spelling, and
    skipping is silent.
    """
    build = _build_table(pyproject)
    mapping: dict[str, str] = build.get("targets", {}).get("wheel", {}).get(
        "force-include", {}
    ) or build.get("force-include", {})
    out: set[str] = set()
    for source in mapping:
        resolved = (pyproject.parent / source).resolve()
        try:
            out.add(resolved.relative_to(_REPO).as_posix())
        except ValueError:
            raise AssertionError(
                f"{pyproject.relative_to(_REPO).as_posix()} force-includes {source!r}, resolving to "
                f"{resolved}, outside the repository -- this scan cannot model what that wheel ships"
            ) from None
    return frozenset(out)


def _shipped_by(sources: frozenset[str], tracked: frozenset[str]) -> frozenset[str]:
    """What a ``force-include`` map ships: a named FILE outright, a named DIRECTORY walked whole."""
    return frozenset(
        path
        for path in tracked
        if path in sources or any(path.startswith(f"{src}/") for src in sources)
    )


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
    forbidden = _forbidden()
    problems: list[str] = []
    seen = 0
    mapped = 0
    for pyproject in _packaging_pyprojects():
        sources = _force_include_sources(pyproject)
        if not sources:
            # A distribution whose package sits inside its own project directory needs no map, and
            # demanding one would red it for the wrong reason. It is covered by `exclude` instead.
            continue
        mapped += 1
        shipped = _shipped_by(sources, _tracked(*{src.split("/")[0] for src in sources}))
        assert shipped, f"{pyproject.relative_to(_REPO).as_posix()} maps sources but ships no file"
        seen += len(shipped)
        problems.extend(
            f"{pyproject.parent.name}: {path} ({why})"
            for path in sorted(shipped)
            if (why := forbidden(path)) is not None
        )
    assert mapped >= 1, "no distribution force-includes anything -- the parse broke"
    assert seen >= 100, f"the force-include scan saw only {seen} shipped files -- it broke"
    assert not problems, (
        f"these force-included files would be REFUSED by the release gate on a tag: {problems}. "
        f"`exclude` does not reach a force-included file in hatchling -- remove the entry from the "
        f"wheel's force-include map, enumerating siblings if the map names a whole directory."
    )


def test_no_walked_engine_file_ships_a_denylisted_file() -> None:
    """The engine's tree IS filtered by ``exclude``, so a forbidden file is fine if a pattern covers it.

    Matched on the BASENAME against the exclude list, which is how the patterns in this repo are
    written and why ``pyproject.toml`` records that they must stay slashless: hatchling reads
    ``exclude`` with gitignore semantics, so a bare ``CLAUDE.md`` matches at any depth while
    ``/CLAUDE.md`` is anchored at the project root and would leave the nested copy shipping.
    """
    forbidden = _forbidden()
    excluded = set(_build_table(_REPO / "pyproject.toml").get("exclude", []))
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
    excluded = set(_build_table(_REPO / "pyproject.toml").get("exclude", []))
    guarded = sorted(
        path
        for path in _tracked("messagefoundry")
        if forbidden(path) is not None and Path(path).name in excluded
    )
    assert guarded, (
        "no tracked file under messagefoundry/ is both denylisted and excluded, so "
        "[tool.hatch.build].exclude now guards nothing against this class -- drop it or repoint it"
    )
