# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Conformant **synthetic** HL7 v2.5.1 message generators (no real PHI).

The reference-driven machinery lives in :mod:`messagefoundry.generators._core`; each message-type
module (``adt``, ``oru``, …) registers a spec on import, and :mod:`messagefoundry.generators.all_types`
imports them all. The ``messagefoundry generate`` CLI is the user-facing entry point.

Import ``all_types`` before reading the registry so every built-in type is registered::

    from messagefoundry.generators import _core, all_types  # noqa: F401
    _core.message_codes()  # -> ["ADT", "ORM", ...]
"""

from __future__ import annotations
