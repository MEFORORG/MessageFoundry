#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Run ``pip-audit`` over a hashed lock so it audits every pin, whatever the pin's marker.

A thin wrapper. The implementation, the 2026-10-17 measurement and the reasoning live in
``messagefoundry/security/audit_all_platforms.py``, which ships in the wheel so the ``audit-pin`` job
``messagefoundry init`` generates for an adopter runs the same code as this repository's gate. This
path stays the entry point ``security.yml`` calls, because those jobs install only the scanner lock,
not the engine: the module is stdlib only, and the checkout is put on ``sys.path`` to import it.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

if str(_REPO_ROOT) not in sys.path:  # runnable as a bare script, like its siblings
    sys.path.insert(0, str(_REPO_ROOT))

from messagefoundry.security.audit_all_platforms import (  # noqa: E402
    is_requirement_line,
    main,
    strip_markers,
)

__all__ = ["is_requirement_line", "main", "strip_markers"]

if __name__ == "__main__":
    sys.exit(main())
