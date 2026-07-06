# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Build a short, human-readable message summary from a :class:`Peek`.

Computed once at ingest and stored in its own column (outside the serialized body) so the
search/list view never reparses HL7. PHI-bearing (MRN, patient name) — see the store's audit
note. Tolerant: any missing field is simply omitted.
"""

from __future__ import annotations

from messagefoundry.parsing.peek import Peek

__all__ = ["summarize"]

_ORDER_TYPES = {"ORM", "ORU"}


def _patient_name(peek: Peek) -> str | None:
    family = peek.field("PID-5.1")
    given = peek.field("PID-5.2")
    if family and given:
        return f"{family}, {given}"
    return family


def summarize(peek: Peek) -> str:
    """e.g. ``MRN 100001 · DOE, JANE`` (+ ``· Order 12345 · Acc 67890`` for ORM/ORU)."""
    parts: list[str] = []

    mrn = peek.field("PID-3.1")
    if mrn:
        parts.append(f"MRN {mrn}")
    name = _patient_name(peek)
    if name:
        parts.append(name)

    if (peek.message_code or "") in _ORDER_TYPES:
        order = peek.field("ORC-2.1") or peek.field("OBR-2.1")  # placer order number
        accession = peek.field("OBR-3.1") or peek.field("ORC-3.1")  # filler / accession
        if order:
            parts.append(f"Order {order}")
        if accession:
            parts.append(f"Acc {accession}")

    return " · ".join(parts)
