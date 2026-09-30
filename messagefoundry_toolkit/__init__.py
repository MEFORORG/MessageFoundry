# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""MessageFoundry toolkit: the authoring and development commands, kept out of the engine wheel.

ADR 0201 (BACKLOG #1192, ASVS 15.2.3) moves every command ``messagefoundry.cli_surface.CLI_TIERS``
marks ``toolkit`` out of the engine's ``messagefoundry`` command and into this package, whose own
command is ``messagefoundry-toolkit``. A production install carries the engine alone, so it neither
includes this code nor exposes these commands.

The toolkit may import the engine. The engine must never import the toolkit, and
``tests/test_dependency_boundaries.py`` holds that direction with a text search over
``messagefoundry/``.

The distribution is ``messagefoundry-toolkit``, built from ``packaging/messagefoundry-toolkit/`` in
lockstep with the engine: same version, same tag. Dev and CI environments do not install it. The
engine's editable install already puts the repository root on the import path, so
``python -m messagefoundry_toolkit`` runs this checkout's copy. ADR 0201 section 1 says why an
editable install of this distribution would be a frozen copy instead.
"""

from __future__ import annotations
