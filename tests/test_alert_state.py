# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Operator alert-state — the resolvable ``alert_instance`` store layer + the ``NotifierAlertSink``
side-observer that upserts/auto-resolves it (ADR 0044, #56).

Covers the load-bearing invariants: the open->ack->resolve lifecycle, de-dup on ADR 0014's
``(event_type, connection)`` throttle key, recording even when a rule suppresses the notification,
auto-resolution on the inverse lifecycle signal, the side-observer guarantee (no queue row / no
finalizer touched / never raises into ``_emit``), and three-backend schema/method parity.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

from messagefoundry.config.settings import AlertRule, AlertSeverity
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.store.crypto import PREFIX, generate_key, make_cipher
from messagefoundry.store.store import MessageStore


# --- store lifecycle ---------------------------------------------------------


async def test_first_fire_opens_instance(tmp_path: Path) -> None:
    # AC-1: first fire opens one `open` instance with count=1 and first_seen == last_seen.
    store = await MessageStore.open(tmp_path / "a.db")
    try:
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_X", severity="critical", now=100.0
        )
        rows = await store.list_active_alert_instances()
        assert len(rows) == 1
        a = rows[0]
        assert a.event_type == "connection_error" and a.connection == "OB_X"
        assert a.status == "open" and a.count == 1
        assert a.first_seen == 100.0 and a.last_seen == 100.0
        assert a.severity == "critical"
    finally:
        await store.close()


async def test_refire_dedupes_on_throttle_key(tmp_path: Path) -> None:
    # AC-2: a re-fire folds into the existing open instance (count++ / last_seen advances), no 2nd row.
    store = await MessageStore.open(tmp_path / "a.db")
    try:
        await store.upsert_alert_instance(
            event_type="queue_buildup", connection="OB_X", severity="warning", now=100.0
        )
        await store.upsert_alert_instance(
            event_type="queue_buildup", connection="OB_X", severity="critical", now=150.0
        )
        rows = await store.list_active_alert_instances()
        assert len(rows) == 1
        a = rows[0]
        assert a.count == 2
        assert a.first_seen == 100.0 and a.last_seen == 150.0
        assert a.severity == "critical"  # last write wins
        # A DIFFERENT key opens a distinct instance (de-dup is per (type, connection)).
        await store.upsert_alert_instance(
            event_type="queue_buildup", connection="OB_Y", severity="warning", now=160.0
        )
        assert len(await store.list_active_alert_instances()) == 2
    finally:
        await store.close()


async def test_ack_transitions_and_excludes_from_open_count(tmp_path: Path) -> None:
    # AC-4 (store half): ack sets acknowledged + acked_by/acked_at and drops out of the open count.
    store = await MessageStore.open(tmp_path / "a.db")
    try:
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_X", severity="critical", now=100.0
        )
        (a,) = await store.list_active_alert_instances()
        assert await store.ack_alert_instance(a.id, actor="scott", now=200.0) is True
        got = await store.get_alert_instance(a.id)
        assert got is not None
        assert got.status == "acknowledged" and got.acked_by == "scott" and got.acked_at == 200.0
        # acknowledged stays VISIBLE on the active list but is EXCLUDED from alerts_active (open count).
        assert {r.id for r in await store.list_active_alert_instances()} == {a.id}
        assert await store.count_open_alerts_by_connection() == {}
        # an unknown / already-resolved id returns False
        assert await store.ack_alert_instance(99999, actor="scott") is False
    finally:
        await store.close()


async def test_acknowledged_refire_stays_acknowledged(tmp_path: Path) -> None:
    # An acknowledged instance that re-fires folds in (count++) but does NOT pop back to open.
    store = await MessageStore.open(tmp_path / "a.db")
    try:
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_X", severity="critical", now=100.0
        )
        (a,) = await store.list_active_alert_instances()
        await store.ack_alert_instance(a.id, actor="scott", now=120.0)
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_X", severity="critical", now=130.0
        )
        got = await store.get_alert_instance(a.id)
        assert got is not None
        assert got.status == "acknowledged" and got.count == 2 and got.last_seen == 130.0
        assert await store.count_open_alerts_by_connection() == {}  # still not "open"
    finally:
        await store.close()


async def test_resolve_and_reopen(tmp_path: Path) -> None:
    # Resolve closes the instance; the SAME key may then open a FRESH instance (the partial index frees it).
    store = await MessageStore.open(tmp_path / "a.db")
    try:
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_X", severity="critical", now=100.0
        )
        (a,) = await store.list_active_alert_instances()
        assert await store.resolve_alert_instance(a.id, now=200.0) is True
        assert await store.list_active_alert_instances() == []
        assert await store.resolve_alert_instance(a.id) is False  # already resolved
        # the key is now free — a new fire opens a brand-new (distinct id) open instance
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_X", severity="warning", now=300.0
        )
        (b,) = await store.list_active_alert_instances()
        assert b.id != a.id and b.status == "open" and b.count == 1
    finally:
        await store.close()


async def test_auto_resolves_on_inverse_signal(tmp_path: Path) -> None:
    # AC-5 (store half): the inverse-event resolver closes the matching live instance(s) for the key.
    store = await MessageStore.open(tmp_path / "a.db")
    try:
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_X", severity="critical", now=100.0
        )
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_Y", severity="critical", now=110.0
        )
        n = await store.resolve_alert_instances_for(
            event_type="connection_error", connection="OB_X", now=200.0
        )
        assert n == 1
        assert {r.connection for r in await store.list_active_alert_instances()} == {"OB_Y"}
        # a no-match resolve is a no-op (0)
        assert (
            await store.resolve_alert_instances_for(event_type="connection_error", connection="ZZ")
            == 0
        )
    finally:
        await store.close()


async def test_count_open_by_connection(tmp_path: Path) -> None:
    # AC-6 (store half): count_open_alerts_by_connection counts ONLY open instances, per connection.
    store = await MessageStore.open(tmp_path / "a.db")
    try:
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_X", severity="critical", now=100.0
        )
        await store.upsert_alert_instance(
            event_type="queue_buildup", connection="OB_X", severity="warning", now=101.0
        )
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_Y", severity="critical", now=102.0
        )
        (acked,) = [r for r in await store.list_active_alert_instances() if r.connection == "OB_Y"]
        await store.ack_alert_instance(acked.id, actor="scott")  # ack drops OB_Y to 0 open
        assert await store.count_open_alerts_by_connection() == {"OB_X": 2}
    finally:
        await store.close()


async def test_reason_encrypted_at_rest(tmp_path: Path) -> None:
    # Metadata-only + the scrubbed reason is encrypted at rest (parity with connection_event.reason).
    key = generate_key()
    cipher = make_cipher(key)
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=cipher)
    try:
        await store.upsert_alert_instance(
            event_type="connection_error",
            connection="OB_X",
            severity="critical",
            reason="connect refused to 10.0.0.9",
            now=100.0,
        )
        (a,) = await store.list_active_alert_instances()
        assert a.reason == "connect refused to 10.0.0.9"  # decrypted at the boundary
    finally:
        await store.close()
    con = sqlite3.connect(db)
    try:
        raw = con.execute("SELECT reason FROM alert_instance").fetchone()[0]
        assert isinstance(raw, str) and raw.startswith(PREFIX)  # ciphertext on disk
        assert "refused" not in raw
    finally:
        con.close()


async def test_purge_resolved_only(tmp_path: Path) -> None:
    # AC-8 (retention half): only RESOLVED instances older than the cutoff are pruned; open/ack survive.
    store = await MessageStore.open(tmp_path / "a.db")
    try:
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_OPEN", severity="critical", now=100.0
        )
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_RESOLVED", severity="critical", now=100.0
        )
        (r,) = [
            x for x in await store.list_active_alert_instances() if x.connection == "OB_RESOLVED"
        ]
        await store.resolve_alert_instance(r.id, now=100.0)
        purged = await store.purge_alert_instances(older_than=200.0)
        assert purged == 1  # the resolved one
        assert {x.connection for x in await store.list_active_alert_instances()} == {"OB_OPEN"}
        # a too-recent resolved row is NOT purged
        await store.upsert_alert_instance(
            event_type="queue_buildup", connection="OB_RECENT", severity="warning", now=500.0
        )
        (rec,) = [
            x for x in await store.list_active_alert_instances() if x.connection == "OB_RECENT"
        ]
        await store.resolve_alert_instance(rec.id, now=500.0)
        assert await store.purge_alert_instances(older_than=200.0) == 0
    finally:
        await store.close()


async def test_instance_write_is_side_observer(tmp_path: Path) -> None:
    # AC-9 (store half): an alert-instance write touches NO queue row and does not change message counts
    # or disposition — it is invisible to the finalizer (which scans `FROM queue` only).
    store = await MessageStore.open(tmp_path / "a.db")
    try:
        before = await store.stats()
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_X", severity="critical", now=100.0
        )
        after = await store.stats()
        assert after == before  # no message/queue rows created
    finally:
        await store.close()


# --- the NotifierAlertSink side observer -------------------------------------


class _RecordingStore:
    """A minimal in-memory stand-in for the alert-state slice the sink uses, so the sink wiring can be
    exercised without a real store. Records the upsert/auto-resolve calls the sink makes."""

    def __init__(self) -> None:
        self.upserts: list[dict[str, object]] = []
        self.resolves: list[dict[str, object]] = []
        self.raise_on_upsert = False

    async def upsert_alert_instance(
        self,
        *,
        event_type: str,
        connection: str,
        severity: str,
        reason: str | None = None,
        now: float | None = None,
    ) -> None:
        if self.raise_on_upsert:
            raise RuntimeError("boom")  # the sink must swallow this (AC-9)
        self.upserts.append(
            {
                "event_type": event_type,
                "connection": connection,
                "severity": severity,
                "reason": reason,
            }
        )

    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = None
    ) -> int:
        self.resolves.append({"event_type": event_type, "connection": connection})
        return 1


async def _drain(sink: NotifierAlertSink) -> None:
    # Let the fire-and-forget state tasks the sink scheduled run to completion.
    for _ in range(10):
        if not sink._state_tasks:
            break
        await asyncio.gather(*list(sink._state_tasks), return_exceptions=True)
        await asyncio.sleep(0)


async def test_emit_upserts_instance_on_throttle_key() -> None:
    store = _RecordingStore()
    sink = NotifierAlertSink([], store=store)
    sink.connection_error("OB_X", kind="connection_lost", detail="refused")
    await _drain(sink)
    assert store.upserts == [
        {
            "event_type": "connection_error",
            "connection": "OB_X",
            "severity": AlertSeverity.WARNING.value,
            "reason": "refused",
        }
    ]


async def test_suppressed_notification_still_recorded() -> None:
    # AC-3: a rule that suppresses the NOTIFICATION (transports=[]) still records the instance — the
    # dashboard shows the open condition the operator chose not to be paged about.
    store = _RecordingStore()
    rule = AlertRule(event_type="connection_error", connection="*", transports=[])
    sink = NotifierAlertSink([], rules=[rule], store=store)
    sink.connection_error("OB_X", kind="connection_lost", detail="refused")
    await _drain(sink)
    assert len(store.upserts) == 1  # recorded despite suppression
    assert store.upserts[0]["connection"] == "OB_X"


async def test_connection_restored_auto_resolves() -> None:
    # AC-5 (sink half): the inverse signal resolves the matching connection_error instance, with NO
    # notification path involved.
    store = _RecordingStore()
    sink = NotifierAlertSink([], store=store)
    sink.connection_restored("OB_X")
    await _drain(sink)
    assert store.upserts == []  # a recovery records no new instance
    assert store.resolves == [{"event_type": "connection_error", "connection": "OB_X"}]


async def test_state_write_failure_never_raises() -> None:
    # AC-9 (sink half): a store error in the side observer is swallowed — it never propagates into the
    # synchronous _emit caller (a delivery worker) and the notification path is unaffected.
    store = _RecordingStore()
    store.raise_on_upsert = True
    sink = NotifierAlertSink([], store=store)
    sink.connection_error("OB_X", kind="connection_lost", detail="refused")  # must not raise
    await _drain(sink)  # the background task swallows the RuntimeError


async def test_no_store_is_noop() -> None:
    # With no store wired (state tracking off) the sink behaves byte-identically to pre-#56: emit works,
    # no state tasks are scheduled.
    sink = NotifierAlertSink([])  # store=None
    sink.connection_error("OB_X", kind="connection_lost", detail="refused")
    sink.connection_restored("OB_X")
    assert sink._state_tasks == set()


# --- three-backend parity (AC-8) ---------------------------------------------


_ALERT_API = frozenset(
    {
        "upsert_alert_instance",
        "list_active_alert_instances",
        "ack_alert_instance",
        "resolve_alert_instance",
        "resolve_alert_instances_for",
        "get_alert_instance",
        "count_open_alerts_by_connection",
        "purge_alert_instances",
    }
)


def test_three_backend_parity_methods() -> None:
    # AC-8 (parity half): all three backends + the QueueStore Protocol the engine depends on define the
    # SAME public alert-instance method set.
    from messagefoundry.store.base import QueueStore
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    for cls in (MessageStore, PostgresStore, SqlServerStore, QueueStore):
        assert _ALERT_API <= set(dir(cls)), cls.__name__


def _create_body(stmt: str, table: str) -> str:
    """The balanced-paren body of the ``CREATE TABLE ... <table> (...)`` in a single DDL ``stmt``."""
    marker = "alert_instance ("
    assert table == "alert_instance"
    i = stmt.find(marker)
    assert i != -1, f"statement does not create {table}: {stmt[:60]}"
    start = stmt.index("(", i)
    depth = 0
    for j in range(start, len(stmt)):
        if stmt[j] == "(":
            depth += 1
        elif stmt[j] == ")":
            depth -= 1
            if depth == 0:
                return stmt[start + 1 : j]
    raise AssertionError("unbalanced parentheses in CREATE TABLE body")


def _columns_from_body(body: str) -> set[str]:
    # strip SQL line comments first (the SQLite DDL annotates each column inline) so a comment word is
    # never mistaken for a column, then split on TOP-LEVEL commas only (so IDENTITY(1,1) stays intact).
    clean = "\n".join(line.split("--", 1)[0] for line in body.splitlines())
    parts: list[str] = []
    depth = 0
    cur = ""
    for ch in clean:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    cols: set[str] = set()
    for line in parts:
        line = line.strip()
        if not line or line.upper().startswith(("CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN")):
            continue
        token = line.split()[0].strip("[]").strip('"')
        cols.add(token.lower())
    return cols


def _alert_table_columns_sqlite() -> set[str]:
    from messagefoundry.store import store as sqlite_mod

    return _columns_from_body(_create_body(sqlite_mod._SCHEMA, "alert_instance"))


def _alert_table_columns(schema_stmts: list[str]) -> set[str]:
    stmt = next(s for s in schema_stmts if "alert_instance (" in s)
    return _columns_from_body(_create_body(stmt, "alert_instance"))


def test_three_backend_parity_columns() -> None:
    # AC-8 (parity half): the alert_instance columns match across SQLite / Postgres / SQL Server DDL.
    from messagefoundry.store import postgres as pg
    from messagefoundry.store import sqlserver as ms

    expected = {
        "id",
        "event_type",
        "connection",
        "severity",
        "status",
        "first_seen",
        "last_seen",
        "count",
        "reason",
        "acked_by",
        "acked_at",
        "resolved_at",
    }
    assert _alert_table_columns_sqlite() == expected
    assert _alert_table_columns(pg._SCHEMA) == expected
    assert _alert_table_columns(ms._SCHEMA) == expected
