# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The package version is single-sourced and SemVer.

hatchling's dynamic version (`[tool.hatch.version] path = "messagefoundry/__init__.py"`) reads
``__version__`` straight from the module, so there is exactly one place the version literal lives — no
``pyproject.toml``-vs-``__init__.py`` drift. These tests guard that invariant.
"""

from __future__ import annotations

import importlib.metadata
import re

import messagefoundry
from packaging.version import Version

_SEMVER = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?")


def test_version_is_semver() -> None:
    assert _SEMVER.fullmatch(messagefoundry.__version__), messagefoundry.__version__


def test_installed_metadata_matches_dunder_version() -> None:
    # The installed package metadata must equal the module's __version__ (the single source). Compare as
    # PARSED versions, not raw strings: installed metadata is PEP 440-normalized (a pre-release __version__
    # like "0.1.0-rc1" becomes "0.1.0rc1" in metadata), so a raw-string compare spuriously fails for any
    # non-canonical version. If this fails locally right after bumping __version__, refresh the editable
    # metadata: pip install -e . --no-deps
    assert Version(importlib.metadata.version("messagefoundry")) == Version(
        messagefoundry.__version__
    )
