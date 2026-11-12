# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5722: the claim procedures live, are gated, and are called in the store's schema.

A store provisioned under a login whose default schema is not ``dbo`` creates its tables there
(the batch's DDL is unqualified). The claim procedures used to be deployed as ``dbo.<name>``,
gated on ``ALTER`` over ``dbo`` and called as ``dbo.<name>``, so they sat apart from the table
their unqualified ``queue`` reference has to reach. The deploy head is now unqualified (the proc
lands where the tables do), the guard probes ``ALTER`` on that default schema, and the gate and the
CALL address the schema of the ``queue`` table the engine resolves. The stub-driven gate rig is the
one in ``tests/test_adr0114_claim_proc.py``; the live leg is ``test_open_deploys_procs_and_gate_passes``
in ``tests/test_adr0114_claim_proc_live.py``.
"""

from __future__ import annotations

import pytest

from messagefoundry.store import sqlserver as ss
from tests.test_adr0114_claim_proc import _drive_proc, _gate, _gate_rows


async def test_the_gate_finds_and_records_procs_in_a_non_dbo_store_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await _gate(_gate_rows(schema="mefor_app"), monkeypatch)
    assert store.claim_proc_effective is True, store.claim_proc_degraded_reason
    assert store._claim_proc_schema == "[mefor_app]"


@pytest.mark.parametrize(
    ("stage", "proc_name"),
    [("ingress", ss._CLAIM_PROC_CID), ("outbound", ss._CLAIM_PROC_DST)],
)
async def test_the_call_names_the_schema_the_gate_verified(
    stage: str, proc_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await _gate(_gate_rows(schema="mefor_app"), monkeypatch)
    ops, _, _ = await _drive_proc(stage, ["lane-0"], store=store)
    kind, sql, _ = ops[0]
    assert kind == "execute-batch"
    assert sql == f"{{CALL [mefor_app].{proc_name} (?,?,?,?,?,?,?,?,?)}}"


async def test_a_schema_name_is_bracket_quoted(monkeypatch: pytest.MonkeyPatch) -> None:
    # The name comes from the server, but it is still an identifier spliced into SQL text.
    store = await _gate(_gate_rows(schema="odd]name"), monkeypatch)
    assert store.claim_proc_effective is True, store.claim_proc_degraded_reason
    assert store._claim_proc_schema == "[odd]]name]"


async def test_an_unresolvable_queue_table_degrades_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    store = await _gate(_gate_rows(schema=None), monkeypatch)
    assert store.claim_proc_effective is False
    assert store._claim_proc_schema is None
    assert "queue table does not resolve" in (store.claim_proc_degraded_reason or "")
    ops, _, _ = await _drive_proc("ingress", ["lane-0"], store=store)
    assert ops[0][1].startswith("SET NOCOUNT ON;"), "a degraded gate runs the shipped batch"


async def test_a_missing_proc_reason_names_the_schema_it_looked_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await _gate(_gate_rows(schema="mefor_app", cid_body=None), monkeypatch)
    assert store.claim_proc_effective is False
    assert f"[mefor_app].{ss._CLAIM_PROC_CID} is missing" in (
        store.claim_proc_degraded_reason or ""
    )


def test_called_procs_deploy_unqualified_and_probe_alter_on_the_default_schema() -> None:
    for name, col in ((ss._CLAIM_PROC_CID, "channel_id"), (ss._CLAIM_PROC_DST, "destination_name")):
        ddl = ss._claim_proc_ddl(name, col)
        assert f" EXEC(N'CREATE OR ALTER PROCEDURE {name} @now FLOAT," in ddl
        assert "HAS_PERMS_BY_NAME(QUOTENAME(SCHEMA_NAME()), 'SCHEMA', 'ALTER') = 1" in ddl
        assert "dbo" not in ddl


def test_retained_v1_procs_keep_their_dbo_head_and_its_matching_guard() -> None:
    """The ``_v1`` bodies are frozen with their dbo head, so their guard must keep probing ALTER on
    dbo: a guard that probed another schema could pass and then fail the must-succeed schema
    transaction creating the proc in dbo."""
    for name, col in ss._RETAINED_CLAIM_PROCS:
        ddl = ss._claim_proc_ddl(name, col)
        assert f" EXEC(N'CREATE OR ALTER PROCEDURE dbo.{name} @now FLOAT," in ddl
        assert "HAS_PERMS_BY_NAME('dbo', 'SCHEMA', 'ALTER') = 1" in ddl
