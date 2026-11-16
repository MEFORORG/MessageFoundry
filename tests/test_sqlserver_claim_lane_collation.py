# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5721: the SQL Server pooled claim compares lane names BINARY on every dispatch path.

A connection name is case-sensitive everywhere else in the engine (the registry is a dict, and
SQLite and Postgres compare it exactly), so ``IB_A`` and ``ib_a`` are two lanes. The queue's lane
columns carry no COLLATE, so under a case-insensitive database collation the claim used to compare
them case-insensitively: the ad-hoc batch inserted one queue row into ``@heads`` under both lanes
and failed on its primary key, while the proc's DISTINCT lane decode merged the two names. The
batch, the stored procedure and the prepared text all render from ``_fifo_heads_steps``, so these
pins hold each rendering to the binary semantics. The live parity leg is in
``tests/test_adr0114_claim_proc_live.py``.
"""

from __future__ import annotations

import re

import pytest

from messagefoundry.store import sqlserver as ss
from tests.test_adr0114_claim_fold import _NOW, _bare_store, _FakeConn, _FakeCursor, _Ops, _wire

_BIN = "COLLATE Latin1_General_100_BIN2"


def _renderings() -> list[tuple[str, str, str]]:
    """(label, lane column, claim text) for every text the store can send or deploy and CALL."""
    batch = [
        (
            f"batch-{col}",
            col,
            ss._fifo_heads_steps(lane_col=col, lane_source="(VALUES (?),(?))", epoch_guard=""),
        )
        for col in ("channel_id", "destination_name")
    ]
    procs = [
        (name, col, ss._claim_proc_body(name, col))
        for name, col in (
            (ss._CLAIM_PROC_CID, "channel_id"),
            (ss._CLAIM_PROC_DST, "destination_name"),
        )
    ]
    return [*batch, *procs, ("prepared", "channel_id", ss._PREPARED_CLAIM_SQL)]


@pytest.mark.parametrize(("label", "lane_col", "text"), _renderings(), ids=lambda v: str(v)[:24])
def test_every_lane_comparison_is_binary(label: str, lane_col: str, text: str) -> None:
    # The @heads lane is binary, so its own lane = lane comparisons (STEPs 2 and 4) and GROUP BY are.
    assert f"DECLARE @heads TABLE (lane NVARCHAR(256) {_BIN} NOT NULL," in text, label
    # The per-lane window numbers each lane on its own: a case-insensitive partition would number
    # two case-variant lanes as one, and the head-skip marker keys on rn = 1.
    assert f"PARTITION BY l.lane {_BIN} ORDER BY h.seq" in text, label
    # Discovery and probe: a seekable equality in the column's collation, plus the binary residual.
    assert f"{lane_col} = l.lane COLLATE DATABASE_DEFAULT AND {lane_col} {_BIN} = l.lane" in text, (
        label
    )
    assert (
        f"qq.{lane_col} = L.lane COLLATE DATABASE_DEFAULT AND qq.{lane_col} {_BIN} = L.lane" in text
    ), label
    # No lane equality may be left to the database collation alone.
    bare = re.findall(rf"(?:qq\.)?{lane_col} = [lL]\.lane(?! COLLATE)", text)
    assert bare == [], f"{label}: unpinned lane comparison(s) {bare}"


@pytest.mark.parametrize(
    "text",
    [ss._claim_proc_body(ss._CLAIM_PROC_CID, "channel_id"), ss._PREPARED_CLAIM_SQL],
    ids=["proc", "prepared"],
)
def test_the_json_lane_decode_dedupes_binary(text: str) -> None:
    """The caller dedupes case-sensitively, so the server-side DISTINCT must too, or it merges
    ``IB_A`` and ``ib_a`` and claims only one of them."""
    assert f"SELECT DISTINCT CAST(j.[value] AS NVARCHAR(256)) {_BIN} FROM OPENJSON(@lanes)" in text


def test_the_marker_arm_relabels_the_binary_lane_for_union_all() -> None:
    """``@heads.lane`` is binary and the claimed rows' lane column is not, so an unlabelled UNION ALL
    would fail on a collation conflict. The explicit label resolves it."""
    for col in ("channel_id", "destination_name"):
        text = ss._fifo_heads_steps(lane_col=col, lane_source="(X)", epoch_guard="")
        arm = text[text.index(" UNION ALL SELECT NULL") :]
        assert "h.lane COLLATE DATABASE_DEFAULT" in arm
        assert re.search(r"h\.lane(?! COLLATE)", arm.split(" FROM @heads h")[0]) is None


def test_retained_v1_bodies_keep_the_unpinned_bytes_they_shipped_with() -> None:
    """The ``_v1`` procs are frozen (their byte-identity pin is in test_adr0114_claim_proc.py); the
    binary pins are this build's called bodies only."""
    for name, col in ss._RETAINED_CLAIM_PROCS:
        assert _BIN not in ss._claim_proc_body(name, col), name


async def test_case_variant_lanes_reach_the_batch_as_two_lanes() -> None:
    """The client-side dedupe stays case-sensitive: two names that differ only in case are two lane
    parameters, never folded into one before the server sees them."""
    ops: _Ops = []
    store = _bare_store(fold=False, epoch=False)
    _wire(store, _FakeCursor(ops), _FakeConn(ops))
    await store.claim_fifo_heads("ingress", ["IB_CASE", "ib_case", "IB_CASE"], now=_NOW)
    kind, sql, params = ops[0]
    assert kind == "execute-batch"
    assert "(VALUES (?),(?))" in sql
    assert params[5:7] == ("IB_CASE", "ib_case")


@pytest.mark.parametrize(
    ("stage", "lane_col"), [("ingress", "channel_id"), ("outbound", "destination_name")]
)
async def test_lane_discovery_tells_case_variants_apart(
    stage: str, lane_col: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sweep's lane discovery must surface every lane the binary claim treats as its own: a
    folding DISTINCT would list one of two case variants, and the sweep would never ready the other.
    The DISTINCT, the after cursor and the ORDER BY are binary; the head read keeps the seekable
    database-collation equality beside the binary one."""
    seen: list[str] = []

    async def fake_fetchall(sql: str, params: tuple[object, ...] = ()) -> list[dict[str, object]]:
        seen.append(sql)
        return []

    store = _bare_store(fold=False, epoch=False)
    monkeypatch.setattr(store, "_fetchall", fake_fetchall)
    await store.list_fifo_lanes(stage)
    (sql,) = seen
    assert f"SELECT DISTINCT {lane_col} {_BIN} AS lane FROM queue" in sql
    assert f"(@after IS NULL OR {lane_col} {_BIN} > @after)" in sql
    assert f"{lane_col} = d.lane COLLATE DATABASE_DEFAULT AND {lane_col} {_BIN} = d.lane AND" in sql
    assert sql.endswith(" ORDER BY d.lane;"), "d.lane is binary, so the page order is too"
    assert re.findall(rf"{lane_col} = d\.lane(?! COLLATE)", sql) == []
