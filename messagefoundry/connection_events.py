# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connection-event vocabulary, written once (BACKLOG #1624).

A connection event is one metadata-only row in the ``connection_event`` log (#46): a listener's
accept, refusal or close, a poll source's reject of an item it could not read, and the runner's
outbound lane transitions. Its ``kind`` names which. This module holds the closed set of kinds.

The connectors emit these kinds, and :mod:`messagefoundry.transports.base` re-exports the set beside
the connector contract. Two places read it at run time: the store, which refuses an undeclared kind
on write (:func:`check_connection_event_kind`, called by every backend's connection-event writer),
and the web console's event-log filter, which offers :data:`CONNECTION_EVENT_KIND_ORDER` as its
choices. Before this module the console kept its own copy and the store accepted any string.

WHY A TOP-LEVEL MODULE AND NOT ``transports/base.py``. The web console is a client, and a client may
not import ``messagefoundry.transports`` (CLAUDE.md section 4, enforced by
``tests/test_dependency_boundaries.py``). A module that imports nothing from the engine is the one
place the connectors, the store and the console can all reach, the same arrangement as
:mod:`messagefoundry.connection_names`.

KEEPING IT TRUE. ``tests/test_phi_logging_inventory.py`` derives the kinds from the literal emit
sites in ``transports/`` and the runner and asserts this set equals them, so a new emit site fails
CI until its kind is added here. A kind forwarded through a variable is invisible to that walk, which
is why the store also checks every write at run time. ``docs/PHI.md`` section 7 row 7 says what each
kind means and must name every one, which CI also asserts.
"""

from __future__ import annotations

from typing import Final

__all__ = ["CONNECTION_EVENT_KINDS", "CONNECTION_EVENT_KIND_ORDER", "check_connection_event_kind"]

#: Every ``kind`` a ``connection_event`` row may carry, in the order an operator reads them: a
#: listener's lifecycle, its refusals and faults, the poll sources' rejects, the intake-auth
#: refusals, then the outbound lane transitions. ``docs/PHI.md`` section 7 row 7 describes each.
CONNECTION_EVENT_KIND_ORDER: Final[tuple[str, ...]] = (
    "established",
    "closed",
    "idle_timeout",
    "peer_not_allowlisted",
    "at_capacity",
    "frame_oversize",
    "peer_reset",
    "framing_error",
    "handler_error",  # BACKLOG #1619
    "tls_handshake_failed",  # vault BACKLOG #2613, #3302
    "row_undecodable",  # BACKLOG #1662
    "file_oversize",  # BACKLOG #1621, and the three below
    "file_decompress_failed",
    "file_content_mismatch",
    "file_scan_rejected",
    "intake_auth_failed",  # ADR 0154 D6, and the two below
    "auth_subject_denied",
    "auth_rate_limited",
    "connection_lost",
    "connection_restored",
)

#: :data:`CONNECTION_EVENT_KIND_ORDER` as a set, for membership.
CONNECTION_EVENT_KINDS: Final[frozenset[str]] = frozenset(CONNECTION_EVENT_KIND_ORDER)


def check_connection_event_kind(kind: str) -> None:
    """Raise :class:`ValueError` for a ``kind`` outside :data:`CONNECTION_EVENT_KINDS`.

    A row with an undeclared kind would be stored, but the console's kind filter could not select
    it and ``docs/PHI.md`` would not say what it means, so the store refuses it rather than write it.

    What the refusal costs is the caller's affair. The runner's connection-event drainer re-writes a
    refused burst row by row, so a lone undeclared row costs that row alone. Its salvage gives up
    after a few failures in a row, though, so a run of undeclared rows also loses the declared rows
    queued behind them in the same burst."""
    if kind not in CONNECTION_EVENT_KINDS:
        raise ValueError(
            f"unknown connection_event kind {kind!r}: add it to "
            "messagefoundry.connection_events.CONNECTION_EVENT_KIND_ORDER and to the docs/PHI.md "
            "section 7 connection_event row"
        )
