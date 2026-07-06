# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Embedded-document strip result + per-connection cutoff resolution (#47, ADR 0042).

The in-place embedded-document strip (a sibling to ``purge_message_bodies``, ADR 0042 D2) is a
**select → codec-transform → write-back** path, not pure SQL: the bulky base64 in each stored ``raw``
is replaced by a small self-describing tombstone via the :mod:`messagefoundry.parsing.binary` codec
(the generic ``mfb64:v1:`` carriage marker AND HL7 OBX-5 ED embeds), while the surrounding message
stays byte-stable and parseable (CLAUDE.md §8 — never string-slice raw HL7). Each store backend
implements ``strip_embedded_documents`` (SQLite / Postgres / SQL Server) on this shared contract.

This module is intentionally tiny and dependency-light (no backend imports) so it can be shared by all
three store backends and the retention runner without a cycle.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

__all__ = ["StripResult", "cutoff_for"]


@dataclass(frozen=True)
class StripResult:
    """What one ``strip_embedded_documents`` pass did (ADR 0042 D3): how many messages had at least one
    embedded document stripped, the total documents stripped across them, and the on-disk base64 bytes
    reclaimed. Returned for the runner's single audit row + the tests — **metadata only**, never any
    message content (no PHI)."""

    messages_stripped: int = 0
    documents_stripped: int = 0
    bytes_reclaimed: int = 0


def cutoff_for(
    channel_id: str,
    global_cutoff: float,
    connection_cutoffs: Mapping[str, float] | None,
) -> float:
    """The strip cutoff for a message received by ``channel_id``: its per-connection override when the
    connection is in ``connection_cutoffs`` (``float('-inf')`` = keep forever → never stripped),
    otherwise the ``global_cutoff`` (the ELSE branch). The Python analog of the SQL ``CASE`` the purge
    path uses — applied here because the strip selects-then-transforms in Python, so the cutoff is
    re-checked on the materialized row rather than baked into a pure-SQL UPDATE. Empty/None ⇒ always the
    global cutoff (byte-identical to a single global window)."""
    if connection_cutoffs:
        override = connection_cutoffs.get(channel_id)
        if override is not None:
            return override
    return global_cutoff
