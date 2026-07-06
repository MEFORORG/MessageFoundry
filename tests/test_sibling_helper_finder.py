# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SEC-019 (CWE-427): the sibling-helper import finder must serve ONLY the documented ``_``-prefixed
helper convention, so a config-dir file named after a real stdlib/installed module can't shadow it."""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.wiring import _SiblingHelperFinder, load_config


def _make_safe_dir(tmp_path: Path) -> Path:
    # On POSIX, load_config refuses a foreign-owned/world-writable dir; tmp_path is owner-owned and
    # not group/world-writable by default, so it loads cleanly. (No special handling needed.)
    return tmp_path


def test_underscore_sibling_still_imports(tmp_path: Path) -> None:
    """The ``import _helpers`` feature is intact: a ``_``-prefixed sibling resolves and is usable."""
    d = _make_safe_dir(tmp_path)
    (d / "_shared.py").write_text("ARCHIVE = 'arch_out'\n", encoding="utf-8")
    (d / "cfg.py").write_text(
        textwrap.dedent(
            """
            import _shared
            from messagefoundry import outbound, File

            outbound(_shared.ARCHIVE, File(directory="./out"))
            """
        ),
        encoding="utf-8",
    )
    registry = load_config(d)
    # The outbound's name came from the _shared sibling helper — proves the import resolved.
    assert "arch_out" in registry.outbound


def test_nonunderscore_sibling_does_not_shadow_stdlib(tmp_path: Path) -> None:
    """A hostile ``json.py`` in the config dir must NOT shadow the real stdlib ``json`` during load."""
    d = _make_safe_dir(tmp_path)
    # A file named after a stdlib module that, if imported, would set a sentinel + lack json.dumps.
    (d / "json.py").write_text("SHADOWED = True\n", encoding="utf-8")
    (d / "cfg.py").write_text(
        textwrap.dedent(
            """
            import json
            from messagefoundry import outbound, File

            # The REAL stdlib json must win: it has dumps and no SHADOWED attribute.
            assert hasattr(json, "dumps"), "config-dir json.py shadowed the stdlib json"
            assert getattr(json, "SHADOWED", False) is False, "config-dir json.py shadowed stdlib"
            outbound("o", File(directory="./out"))
            """
        ),
        encoding="utf-8",
    )
    # load_config raising would mean the assert tripped (i.e. shadowing happened) -> a WiringError.
    registry = load_config(d)
    assert "o" in registry.outbound
    # Sanity: the real json in THIS process is also untouched after the load.
    assert not getattr(json, "SHADOWED", False)


def test_finder_returns_none_for_bare_module_name(tmp_path: Path) -> None:
    """Unit-test the finder directly: it resolves ``_h`` but returns None for a bare ``os``."""
    d = _make_safe_dir(tmp_path)
    (d / "os.py").write_text("SHADOWED = True\n", encoding="utf-8")
    (d / "_h.py").write_text("VALUE = 1\n", encoding="utf-8")
    created: set[str] = set()
    finder = _SiblingHelperFinder(d, created)
    # A real-module name (not '_'-prefixed) is declined even though os.py exists in the dir.
    assert finder.find_spec("os", None) is None
    assert "os" not in created
    # The documented '_'-prefixed helper still resolves to a spec.
    spec = finder.find_spec("_h", None)
    assert spec is not None
    assert "_h" in created
    # Dotted / submodule imports are never served (only top-level absolute).
    assert finder.find_spec("_h.sub", None) is None


@pytest.mark.skipif(os.name != "posix", reason="cleanup uses POSIX-friendly tmp dirs")
def test_nonunderscore_was_previously_resolvable(tmp_path: Path) -> None:
    """Regression guard: the finder no longer resolves a NON-underscore sibling at all.

    Before the SEC-019 fix, ``import shared`` would have resolved ``shared.py`` in the config dir.
    Now the finder declines it (the import would fall through to the normal finders and fail to
    find a top-level ``shared`` module), proving the shadow path is closed."""
    d = _make_safe_dir(tmp_path)
    (d / "shared.py").write_text("VALUE = 1\n", encoding="utf-8")
    finder = _SiblingHelperFinder(d, set())
    assert finder.find_spec("shared", None) is None
