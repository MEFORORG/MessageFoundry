# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-connection retention / pruning windows (#34, ADR 0027).

The global ``[retention]`` window can be overridden per connection: an inbound's ``messages_days``
keys the body purge by ``messages.channel_id``, an outbound's ``dead_letter_days`` keys the dead-letter
purge by ``queue.destination_name``. ``None`` = inherit the global window, ``0`` = keep forever, ``>0`` =
days. The override is AND-ed with the unchanged never-purge-an-in-flight-body guard, a global-only
deployment is byte-identical to before, and the RetentionRunner still writes exactly one audit row per
pass recording the per-connection cutoffs (metadata only, no PHI). Time is injected for determinism.

These cover the ADR 0027 EARS criteria (AC-1..AC-6, AC-8); AC-7 (the connections.toml round-trip) lives
in ``tests/test_connections_file.py::test_retention_override_roundtrips_toml``.

The store-level cases run on **all three backends** for purge-SQL parity (AC-8): SQLite always; Postgres
and SQL Server are skipif-gated on ``MEFOR_TEST_POSTGRES`` / ``MEFOR_TEST_SQLSERVER`` (+ ``MEFOR_STORE_*``
connection env), exactly like ``tests/test_postgres_store.py`` / ``tests/test_sqlserver_store.py``."""

from __future__ import annotations

import json
import os
from typing import AsyncIterator

import pytest

from messagefoundry.config.settings import RetentionSettings
from messagefoundry.config.wiring import (
    MLLP,
    File,
    Registry,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.retention import RetentionRunner
from messagefoundry.store import MessageStore

DAY = 86_400.0
RAW = "MSH|^~\\&|raw-body"

# --- backend fixtures (SQLite always; PG/SQLServer skipif-gated) ---------------

_PG = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres parity case",
)
_MSSQL = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the SQL Server parity case",
)


async def _open_sqlite(tmp_path) -> MessageStore:
    return await MessageStore.open(tmp_path / "per_conn_retention.db")


async def _open_postgres(_tmp_path):  # pragma: no cover - only runs when gated on
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    async with s._pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE message_events, audit_log, queue, response, delivered_keys, messages "
            "RESTART IDENTITY CASCADE"
        )
    return s


async def _open_sqlserver(_tmp_path):  # pragma: no cover - only runs when gated on
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    async with s._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in (
            "message_events",
            "audit_log",
            "queue",
            "response",
            "delivered_keys",
            "messages",
        ):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    return s


@pytest.fixture(
    params=[
        pytest.param(_open_sqlite, id="sqlite"),
        pytest.param(_open_postgres, id="postgres", marks=_PG),
        pytest.param(_open_sqlserver, id="sqlserver", marks=_MSSQL),
    ]
)
async def store(request, tmp_path) -> AsyncIterator[MessageStore]:
    s = await request.param(tmp_path)
    yield s
    await s.close()


# --- helpers: drive a message on a NAMED connection to a terminal state --------


async def _delivered(
    store: MessageStore, *, channel_id: str, dest: str, now: float, control: str
) -> tuple[str, str]:
    """Enqueue → claim → mark_done on the given inbound (channel_id) → outbound (dest), leaving the
    message fully terminal (one DONE outbound row)."""
    mid = await store.enqueue_message(
        channel_id=channel_id,
        raw=RAW,
        deliveries=[(dest, "OUT|delivered")],
        control_id=control,
        now=now,
    )
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=now)
    await store.mark_done(row["id"], now=now)
    return mid, row["id"]


async def _dead(
    store: MessageStore, *, channel_id: str, dest: str, now: float, control: str
) -> str:
    """Enqueue → claim → dead_letter_now on the given inbound → outbound, leaving one DEAD outbound row.
    Returns the message id (its single outbound row's payload is read via :func:`_payload`)."""
    mid = await store.enqueue_message(
        channel_id=channel_id,
        raw=RAW,
        deliveries=[(dest, "OUT|dead")],
        control_id=control,
        now=now,
    )
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=now)
    await store.dead_letter_now(row["id"], "permanent reject", now=now)
    return mid


async def _raw(store: MessageStore, mid: str) -> str:
    return (await store.get_message(mid))["raw"]


async def _payload(store: MessageStore, mid: str) -> str | None:
    """The payload of the message's single outbound row (portable across all three backends)."""
    [row] = await store.outbox_for(mid)
    return row["payload"]


# --- AC-1: inbound messages_days override keys off channel_id ------------------


async def test_override_applies_per_inbound(store: MessageStore) -> None:
    """AC-1: a connection with ``messages_days`` is purged at its own cutoff; every connection without
    an override uses the global window — keyed on ``messages.channel_id`` (the receiving inbound)."""
    # Both received at t=0. IB_FAST overrides to a 1-day window; IB_SLOW inherits the global 30-day one.
    fast, _ = await _delivered(store, channel_id="IB_FAST", dest="OB", now=0.0, control="C-FAST")
    slow, _ = await _delivered(store, channel_id="IB_SLOW", dest="OB", now=0.0, control="C-SLOW")

    # now = 5 days. Global = 30 days (cutoff = -25d → nothing global-only is old enough). IB_FAST's
    # 1-day override (cutoff = +4d) makes its 0-day-old body eligible.
    now = 5 * DAY
    purged = await store.purge_message_bodies(
        older_than=now - 30 * DAY,
        now=now,
        connection_cutoffs={"IB_FAST": now - 1 * DAY},
    )

    assert purged == 1
    assert await _raw(store, fast) == ""  # the overriding connection's body was nulled
    assert await _raw(store, slow) == RAW  # the inheriting connection still under the global window


# --- AC-2: outbound dead_letter_days override keys off destination_name --------


async def test_dead_letter_override_keys_off_outbound(store: MessageStore) -> None:
    """AC-2: the dead-letter override keys off the OUTBOUND that dead-lettered the row
    (``queue.destination_name``), not the inbound."""
    fast = await _dead(store, channel_id="IB", dest="OB_FAST", now=0.0, control="D-FAST")
    slow = await _dead(store, channel_id="IB", dest="OB_SLOW", now=0.0, control="D-SLOW")

    now = 5 * DAY
    purged = await store.purge_dead_letters(
        older_than=now - 30 * DAY,
        now=now,
        connection_cutoffs={"OB_FAST": now - 1 * DAY},
    )

    assert purged == 1
    assert await _payload(store, fast) == ""  # OB_FAST's dead body purged on its own window
    assert await _payload(store, slow) == "OUT|dead"  # OB_SLOW still under the global window


# --- AC-3: global-only is byte-identical --------------------------------------


async def test_global_only_unchanged(store: MessageStore) -> None:
    """AC-3: with NO per-connection override (empty/omitted map), the purge is exactly the store-wide
    policy — a single global cutoff, byte-identical to before this feature."""
    a, _ = await _delivered(store, channel_id="IB1", dest="OB", now=0.0, control="C1")
    b, _ = await _delivered(store, channel_id="IB2", dest="OB", now=0.0, control="C2")

    # No connection_cutoffs at all (the default) and the empty-map form must behave identically.
    assert await store.purge_message_bodies(older_than=10 * DAY) == 2
    assert await _raw(store, a) == "" and await _raw(store, b) == ""

    # And a recent message (cutoff before its received_at) is still kept — the global predicate is intact.
    c, _ = await _delivered(store, channel_id="IB1", dest="OB", now=20 * DAY, control="C3")
    assert await store.purge_message_bodies(older_than=15 * DAY, connection_cutoffs={}) == 0
    assert await _raw(store, c) == RAW


# --- AC-4: an in-flight body is never purged regardless of its window ----------


async def test_in_flight_body_never_purged(store: MessageStore) -> None:
    """AC-4: a body still pending/inflight is NOT purged even when its per-connection cutoff has elapsed
    — the per-connection cutoff AND-s with the in-flight guard (at-least-once is preserved)."""
    mid = await store.enqueue_message(
        channel_id="IB_FAST", raw=RAW, deliveries=[("OB", "p")], control_id="C-INFLIGHT", now=0.0
    )  # left PENDING (never claimed/delivered)

    now = 100 * DAY
    purged = await store.purge_message_bodies(
        older_than=now - 1 * DAY,
        now=now,
        connection_cutoffs={"IB_FAST": now - 1 * DAY},  # aggressive 1-day window, long elapsed
    )

    assert purged == 0  # never purge a body still in the pipeline
    assert await _raw(store, mid) == RAW


# --- AC-5: per-connection 0 keeps forever -------------------------------------


async def test_per_connection_zero_keeps_forever(store: MessageStore) -> None:
    """AC-5: a connection whose override is ``0`` keeps its bodies forever even while the global window
    prunes others (per-feed opt-out). The runner maps ``0 → -inf`` so ``received_at < -inf`` is false."""
    keep, _ = await _delivered(store, channel_id="IB_KEEP", dest="OB", now=0.0, control="C-KEEP")
    prune, _ = await _delivered(store, channel_id="IB_PRUNE", dest="OB", now=0.0, control="C-PRUNE")

    now = 100 * DAY
    purged = await store.purge_message_bodies(
        older_than=now - 1 * DAY,  # global 1-day window — IB_PRUNE is far past it
        now=now,
        connection_cutoffs={"IB_KEEP": float("-inf")},  # 0 days resolves to keep-forever
    )

    assert purged == 1
    assert await _raw(store, keep) == RAW  # opted out — kept forever
    assert await _raw(store, prune) == ""  # global window pruned it


# --- AC-8: three-backend parity (the store cases above run on each backend) ----


async def test_three_backend_parity(store: MessageStore) -> None:
    """AC-8: the per-connection cutoff applies identically across SQLite / Postgres / SQL Server. This
    runs the combined message + dead-letter override scenario; the ``store`` fixture is parametrized over
    all three backends (PG/SQL Server skipif-gated), so a divergence in any backend's purge SQL fails."""
    # An inbound override AND an outbound override in the same pass, with sibling connections inheriting.
    fast, _ = await _delivered(store, channel_id="IB_FAST", dest="OB", now=0.0, control="P-FAST")
    slow, _ = await _delivered(store, channel_id="IB_SLOW", dest="OB", now=0.0, control="P-SLOW")
    df = await _dead(store, channel_id="IB", dest="OB_FAST", now=0.0, control="P-DFAST")
    ds = await _dead(store, channel_id="IB", dest="OB_SLOW", now=0.0, control="P-DSLOW")

    now = 5 * DAY
    mp = await store.purge_message_bodies(
        older_than=now - 30 * DAY, now=now, connection_cutoffs={"IB_FAST": now - 1 * DAY}
    )
    dp = await store.purge_dead_letters(
        older_than=now - 30 * DAY, now=now, connection_cutoffs={"OB_FAST": now - 1 * DAY}
    )

    assert (mp, dp) == (1, 1)
    assert await _raw(store, fast) == "" and await _raw(store, slow) == RAW
    assert await _payload(store, df) == "" and await _payload(store, ds) == "OUT|dead"


# --- AC-6: one audit row per pass recording per-connection cutoffs -------------


def _registry() -> Registry:
    """A registry with one overriding inbound (90 days), one keep-forever inbound (0), one inheriting
    inbound (None), and one overriding outbound (7 days) — resolved each pass by the runner."""
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection("IB_FAST", MLLP(port=2600), router="r", messages_days=1)
    )
    reg.add_inbound(
        build_inbound_connection("IB_KEEP", MLLP(port=2601), router="r", messages_days=0)
    )
    reg.add_inbound(build_inbound_connection("IB_SLOW", MLLP(port=2602), router="r"))  # inherit
    reg.add_outbound(
        build_outbound_connection("OB_FAST", File(directory="./out"), dead_letter_days=1)
    )
    reg.add_outbound(build_outbound_connection("OB_SLOW", File(directory="./out2")))  # inherit
    return reg


async def test_audit_records_per_connection_cutoffs(store: MessageStore) -> None:
    """AC-6: a pass that purges across connections writes EXACTLY ONE ``retention_purge`` audit row
    recording the per-connection cutoffs (+ the aggregate counts) and NO message content (no PHI)."""
    await _delivered(store, channel_id="IB_FAST", dest="OB", now=0.0, control="A-FAST")
    await _delivered(store, channel_id="IB_SLOW", dest="OB", now=0.0, control="A-SLOW")
    await _dead(store, channel_id="IB", dest="OB_FAST", now=0.0, control="A-DFAST")

    reg = _registry()
    runner = RetentionRunner(
        store,
        RetentionSettings(messages_days=30, dead_letter_days=30),
        clock=lambda: 5 * DAY,
        registry_source=lambda: reg,
    )

    result = await runner.run_once()

    # IB_FAST purged on its 1-day window; IB_SLOW still under the global 30-day window. OB_FAST's dead
    # row purged on its 1-day window.
    assert result.messages_purged == 1 and result.dead_purged == 1

    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1  # exactly one row per pass
    detail = json.loads(audit[0]["detail"])
    # The per-connection cutoffs are recorded (connection name -> days; 0 = keep forever).
    assert detail["messages_overrides"] == {"IB_FAST": 1, "IB_KEEP": 0}
    assert detail["dead_letter_overrides"] == {"OB_FAST": 1}
    # The aggregate counts + global windows are still recorded alongside.
    assert detail["messages_purged"] == 1 and detail["dead_purged"] == 1
    # No message content / PHI in the audit detail.
    assert "raw" not in audit[0]["detail"] and RAW not in audit[0]["detail"]


async def test_keep_forever_override_survives_a_global_purge_via_runner(
    store: MessageStore,
) -> None:
    """The runner end-to-end: an inbound with messages_days=0 keeps its bodies even as the global window
    prunes an inheriting sibling — proving the runner threads 0 → keep-forever into the purge."""
    keep, _ = await _delivered(store, channel_id="IB_KEEP", dest="OB", now=0.0, control="K-KEEP")
    prune, _ = await _delivered(store, channel_id="IB_SLOW", dest="OB", now=0.0, control="K-PRUNE")

    reg = _registry()
    runner = RetentionRunner(
        store,
        RetentionSettings(messages_days=1),  # global 1-day window
        clock=lambda: 100 * DAY,
        registry_source=lambda: reg,
    )

    await runner.run_once()

    assert await _raw(store, keep) == RAW  # IB_KEEP (messages_days=0) opted out — kept
    assert await _raw(store, prune) == ""  # IB_SLOW inherits the global window — pruned


async def test_runner_without_registry_is_global_only(store: MessageStore) -> None:
    """No registry_source wired → no overrides → a single global cutoff (byte-identical to the global
    runner), and the audit records empty override maps."""
    a, _ = await _delivered(store, channel_id="IB1", dest="OB", now=0.0, control="G1")
    runner = RetentionRunner(store, RetentionSettings(messages_days=1), clock=lambda: 10 * DAY)

    result = await runner.run_once()

    assert result.messages_purged == 1 and await _raw(store, a) == ""
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    detail = json.loads(audit[0]["detail"])
    assert detail["messages_overrides"] == {} and detail["dead_letter_overrides"] == {}
