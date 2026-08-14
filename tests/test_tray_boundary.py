# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The not-a-console boundary, frozen (ADR 0113 §2).

The tray must render only status + link affordances — never workload data (message bodies, queue
depths, connection rows, counts, rates). This is the tray analogue of the IDE's frozen
``ENGINE_LINK_FIELDS`` allowlist: the render model is asserted to carry no such field, so a future
"just show the backlog count" drive-by fails the build instead of silently becoming a second
operator console. Widening it requires a new ADR.
"""

from __future__ import annotations

import dataclasses

from messagefoundry.tray.state import StatusSnapshot

# Substrings that would signal workload data leaking into the render model.
_FORBIDDEN_FIELD_SUBSTRINGS = (
    "message",
    "msg",
    "queue",
    "backlog",
    "outbox",
    "inbox",
    "connection",
    "count",
    "rate",
    "throughput",
    "kpi",
    "depth",
    "pending",
    "errored",
    "dead_letter",
    "deadletter",
    "volume",
    "token",
    "bearer",
    "session",
)

# The exact allowlist of fields the snapshot may carry. Changing this set is an ADR-level decision.
_ALLOWED_SNAPSHOT_FIELDS = frozenset(
    {"state", "service_name", "engine_url", "console_enabled", "monitor_only"}
)


def test_status_snapshot_fields_are_exactly_the_allowlist() -> None:
    actual = {f.name for f in dataclasses.fields(StatusSnapshot)}
    assert actual == _ALLOWED_SNAPSHOT_FIELDS, (
        "StatusSnapshot fields drifted from the ADR 0113 §2 allowlist; adding a render field "
        "requires a new ADR (see tests/test_tray_boundary.py)."
    )


def test_status_snapshot_carries_no_workload_field() -> None:
    for field in dataclasses.fields(StatusSnapshot):
        lowered = field.name.lower()
        offending = [s for s in _FORBIDDEN_FIELD_SUBSTRINGS if s in lowered]
        assert not offending, (
            f"StatusSnapshot.{field.name} looks like workload data ({offending}); the tray is not "
            "an operator console (ADR 0113 §2)."
        )
