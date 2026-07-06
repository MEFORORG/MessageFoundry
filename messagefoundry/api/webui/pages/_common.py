# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared cell/format helpers for the /ui page builders (ADR 0065).

Small, escape-neutral formatters imported by the per-area page modules (``connections``,
``messages``, …) so the rendering conventions live in one place, never copy-pasted per module.
"""

from __future__ import annotations


def _num(value: object) -> str:
    """Render a count/None as text ('—' for None)."""
    return "—" if value is None else str(value)


def _secs(value: float | None) -> str:
    """Render an age in seconds as a compact string ('—' for None)."""
    if value is None:
        return "—"
    return f"{value:.0f}s"
