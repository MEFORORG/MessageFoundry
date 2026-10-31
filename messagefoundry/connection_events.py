# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connection-event vocabulary, written once (BACKLOG #1624).

A connection event is one metadata-only row in the ``connection_event`` log (#46): a listener's
accept, refusal or close, a poll source's reject of an item it could not read, and the runner's
outbound lane transitions. Its ``kind`` names which. This module holds the closed set of kinds.

The connectors emit these kinds, and :mod:`messagefoundry.transports.base` re-exports the set beside
the connector contract. Three places read it at run time:

* the runner, which refuses an undeclared kind before the event is queued
  (``RegistryRunner._enqueue_connection_event``), counts it and logs it, so it never joins a burst;
* the store, as the backstop for any other writer: every backend's connection-event writer calls
  :func:`check_connection_event_kind` and raises on an undeclared kind;
* the web console's event-log filter, which offers :data:`CONNECTION_EVENT_KIND_ORDER` as its
  choices.

Before this module the console kept its own copy and nothing refused an undeclared kind.

WHY A TOP-LEVEL MODULE AND NOT ``transports/base.py``. The web console is a client, and a client may
not import ``messagefoundry.transports`` (CLAUDE.md section 4, enforced by
``tests/test_dependency_boundaries.py``). A module that imports nothing from the engine is the one
place the connectors, the store and the console can all reach, the same arrangement as
:mod:`messagefoundry.connection_names`.

KEEPING IT TRUE. ``tests/test_phi_logging_inventory.py`` asserts this set equals the kinds it finds
by an AST walk. The walk reads only the modules directly under ``transports/`` (not subpackages) and
``pipeline/wiring_runner.py``, and only a string literal in one of these shapes: the first argument
of an ``_emit_event`` call, or a ``kind=`` keyword on an ``_emit_event``,
``_enqueue_connection_event``, ``HttpRequestError`` or ``Refusal`` call. A new emit site in that
shape fails CI until its kind is added here. Any other emit site is invisible to it, such as a kind
forwarded through a variable, a direct ``on_connection_event`` call, or a module elsewhere; the
run-time refusals above are what catch those. ``docs/PHI.md`` section 7 row 7 says what each kind
means and must name every one, which CI also asserts.
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
    A burst holding one undeclared row is refused whole. The runner refuses undeclared kinds before
    they are queued, so its bursts never meet this check; it is the backstop for other writers."""
    if kind not in CONNECTION_EVENT_KINDS:
        raise ValueError(
            f"unknown connection_event kind {kind!r}: add it to "
            "messagefoundry.connection_events.CONNECTION_EVENT_KIND_ORDER and to the docs/PHI.md "
            "section 7 connection_event row"
        )
