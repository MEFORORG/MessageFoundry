# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Packaging guards.

A consumer's config repo (its mypy/IDE) type-checks against the engine's public surface ONLY if the
engine ships a PEP 561 ``py.typed`` marker. The marker must live in the *installed* package; hatchling
ships every file under ``messagefoundry/`` (see the comment in pyproject.toml), so the empty
``messagefoundry/py.typed`` rides along with no build-config change. Asserting its presence via
``importlib.resources`` — the same guard the password corpus uses — means a build-config change that
dropped it fails the suite, not just a release dry-run.
"""

from __future__ import annotations

from importlib.resources import files


def test_py_typed_marker_ships_in_the_package() -> None:
    marker = files("messagefoundry").joinpath("py.typed")
    assert marker.is_file(), (
        "messagefoundry/py.typed is missing from the installed package — external mypy won't see the "
        "engine as typed (PEP 561). It must sit next to messagefoundry/__init__.py and ship in the wheel."
    )
