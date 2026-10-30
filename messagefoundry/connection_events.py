# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connection-event vocabulary, written once (BACKLOG #1624).

A connection event is one metadata-only row in the ``connection_event`` log (#46): a listener's
accept, refusal or close, a poll source's quarantine of an item it could not read, and the runner's
outbound lane transitions. Its ``kind`` names which. This module holds the closed set of kinds.

Three places read it, and before this module each kept its own copy:

* the connectors, which emit the kinds (:mod:`messagefoundry.transports.base` re-exports the set,
  so it sits beside the connector contract it belongs to);
* the store, which refuses an undeclared kind on write (:func:`check_connection_event_kind`, called
  by every backend's connection-event writer);
* the web console's event-log filter, which offers the kinds as choices.

WHY A TOP-LEVEL MODULE AND NOT ``transports/base.py``. The web console is a client, and a client may
not import ``messagefoundry.transports`` (CLAUDE.md section 4, enforced by
``tests/test_dependency_boundaries.py``). A module that imports nothing from the engine is the one
place the connectors, the store and the console can all reach, the same arrangement as
:mod:`messagefoundry.connection_names`.

KEEPING IT TRUE. ``tests/test_phi_logging_inventory.py`` derives the kinds from the literal emit
sites in ``transports/`` and the runner and asserts this set equals them, so a new emit site fails
CI until its kind is added here. A kind forwarded through a variable is invisible to that walk, which
is why the store also checks every write at run time. Each kind must also be named in the
``docs/PHI.md`` section 7 ``connection_event`` row, which CI asserts.
"""

from __future__ import annotations

from typing import Final

__all__ = ["CONNECTION_EVENT_KINDS", "check_connection_event_kind"]

#: Every ``kind`` a ``connection_event`` row may carry.
CONNECTION_EVENT_KINDS: Final[frozenset[str]] = frozenset(
    {
        # A listener's connection lifecycle.
        "established",
        "closed",
        "idle_timeout",
        # Pre-ingress refusals and faults on a listener.
        "peer_not_allowlisted",
        "at_capacity",
        "frame_oversize",
        "peer_reset",
        "framing_error",
        # BACKLOG #1619 -- the MLLP listener's inbound handler faulted on a frame it read cleanly (a
        # store outage at the ingress commit is the reachable case). Not a framing fault.
        "handler_error",
        # vault BACKLOG #2613 and #3302 -- a TLS handshake on an MLLP or HTTP listener failed.
        # Throttled to one per minute per listener; the reason carries the count since the last one.
        "tls_handshake_failed",
        # BACKLOG #1662 -- the DATABASE poll source, on a row it cannot turn into a body. A poll
        # source has no peer, so its rows carry a NULL peer_host.
        "row_undecodable",
        # BACKLOG #1621 -- the FILE source's four quarantine arms, each moving a drop to `.error`.
        "file_oversize",
        "file_decompress_failed",
        "file_content_mismatch",
        "file_scan_rejected",
        # ADR 0154 D6 -- inbound HTTP intake-auth refusals. Each also writes an audit_log row, which
        # is the copy that survives diagnostics being off.
        "intake_auth_failed",
        "auth_subject_denied",
        "auth_rate_limited",
        # The runner's outbound lane transitions (#46).
        "connection_lost",
        "connection_restored",
    }
)


def check_connection_event_kind(kind: str) -> None:
    """Raise :class:`ValueError` for a ``kind`` outside :data:`CONNECTION_EVENT_KINDS`.

    A row with an undeclared kind would be stored but unreachable from the console's filter and
    undocumented in ``docs/PHI.md``, so the store refuses it rather than write it. The runner's
    connection-event drainer re-writes a refused burst row by row and logs the failure, so one bad
    kind costs that row, not its neighbours."""
    if kind not in CONNECTION_EVENT_KINDS:
        raise ValueError(
            f"unknown connection_event kind {kind!r}: add it to "
            "messagefoundry.connection_events.CONNECTION_EVENT_KINDS and to the docs/PHI.md "
            "section 7 connection_event row"
        )
