# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The vault_transit bound attestation on the SERVER store backends (BACKLOG #2337).

The structural checks run anywhere. :func:`attestation_roundtrip` runs from
``tests/test_sqlserver_store.py`` and ``tests/test_postgres_store.py``, on the CI legs that set their
live-database gates: a record writes the row and its audit row, a second record replaces it, and a
withdraw removes it with its own audit row. Non-secret throughout: key names, a reason and an actor.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from messagefoundry.store.store import AuditAppend
from messagefoundry.store.transit_attestation import (
    TRANSIT_BOUND_ATTESTED_ACTION,
    TRANSIT_BOUND_WITHDRAWN_ACTION,
    TransitBoundAttestationStore,
)

_SERVER_BACKENDS: list[tuple[str, str]] = [
    ("messagefoundry.store.sqlserver", "SqlServerStore"),
    ("messagefoundry.store.postgres", "PostgresStore"),
]


@pytest.mark.parametrize(("module", "name"), _SERVER_BACKENDS)
def test_server_backend_satisfies_the_attestation_protocol(module: str, name: str) -> None:
    """Without it the engine's ``isinstance`` gate reads every server store as unattested, which
    refuses every vault_transit start under enforce."""
    cls = getattr(importlib.import_module(module), name)
    assert isinstance(object.__new__(cls), TransitBoundAttestationStore)


@pytest.mark.parametrize(
    "module", ["messagefoundry.store.sqlserver", "messagefoundry.store.postgres"]
)
def test_the_table_is_in_the_schema_batch(module: str) -> None:
    """The table must join the schema batch, so the schema hash moves and the DDL runs."""
    batch = "\n".join(str(stmt) for stmt in importlib.import_module(module)._SCHEMA)
    assert "transit_bound_attestation" in batch


async def attestation_roundtrip(store: Any) -> None:
    """Shared by the live SQL Server and Postgres suites, which own the clean-slate fixture."""

    def withdrawn_row(_w: object) -> AuditAppend:
        return AuditAppend(TRANSIT_BOUND_WITHDRAWN_ACTION, actor="cli:ci")

    await store.withdraw_transit_bound_attestation(audit=withdrawn_row)  # a clean slate
    assert await store.get_transit_bound_attestation() is None
    assert await store.withdraw_transit_bound_attestation(audit=withdrawn_row) is None

    await store.record_transit_bound_attestation(
        key_name="first",
        reason="r1",
        audit=AuditAppend(TRANSIT_BOUND_ATTESTED_ACTION, actor="cli:ci", detail='{"n":1}'),
    )
    recorded = await store.record_transit_bound_attestation(
        key_name="mefor-store",
        reason="rotates every 30 days",
        audit=AuditAppend(TRANSIT_BOUND_ATTESTED_ACTION, actor="cli:ci", detail='{"n":2}'),
    )
    got = await store.get_transit_bound_attestation()
    assert got == recorded and got.key_name == "mefor-store" and got.actor == "cli:ci"
    [newest] = await store.recent_audit_of([TRANSIT_BOUND_ATTESTED_ACTION], limit=1)
    assert newest["actor"] == "cli:ci" and newest["detail"] == '{"n":2}'
    assert abs(float(newest["ts"]) - recorded.attested_at) < 1e-3

    withdrawn = await store.withdraw_transit_bound_attestation(audit=withdrawn_row)
    assert withdrawn is not None and withdrawn.key_name == "mefor-store"
    assert await store.get_transit_bound_attestation() is None
    [row] = await store.recent_audit_of([TRANSIT_BOUND_WITHDRAWN_ACTION], limit=1)
    assert row["actor"] == "cli:ci"
