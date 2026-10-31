# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A restored store records the restore at its first engine start (BACKLOG #2614).

``restore`` brings back the archive's accounts, password hashes, roles, factors and sessions, and
nothing recorded that it had. Now the restore writes a one-row marker into the store it places,
and the first start consumes it: every session is revoked, one ``store_restored`` audit row names
the archive's hash and age, and a ``store_restored`` alert is raised. Each step has a control: a
store no restore placed records nothing, and a second start records nothing again.
"""

from __future__ import annotations

import ast
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api.app import _record_a_restore
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import _ALERT_EVENT_TYPES, BackupSettings, StoreSettings
from messagefoundry.pipeline.alerts import STORE_RESTORED_SUBJECT, LoggingAlertSink
from messagefoundry.pipeline.dr_backup import BackupRunner, run_restore
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import (
    STORE_RESTORED_ACTION,
    MessageStore,
    write_restore_marker,
)

_ROOT = Path(__file__).resolve().parents[1]


async def _seed(store: MessageStore, user_id: str = "u1") -> str:
    await store.create_user(
        user_id=user_id,
        username=user_id,
        auth_provider="local",
        display_name=None,
        email=None,
        password_hash="h",
        now=time.time(),
        password_generated=False,
    )
    token = mint_token()
    await store.create_session(
        token_hash=hash_token(token),
        user_id=user_id,
        expires_at=time.time() + 3600,
        client="192.0.2.10",
        auth_mechanism="password",
    )
    return token


async def _revoked(store: MessageStore, token: str) -> bool:
    row = await store.get_session(hash_token(token))
    return row is not None and row.revoked_at is not None


class _Sink(LoggingAlertSink):
    def __init__(self) -> None:
        self.raised: list[tuple[str, str, str]] = []

    def store_restored(self, name: str, *, detail: str, last_audit_at: str) -> None:
        self.raised.append((name, detail, last_audit_at))


async def test_the_first_start_after_a_marker_records_the_restore(tmp_path: Path) -> None:
    db = tmp_path / "restored.db"
    key = generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(key))
    token = await _seed(store)
    await store.close()
    ended = write_restore_marker(
        db,
        archive_sha256="ab" * 32,
        archive_created_at=1_000_000.0,
        last_audit_at=999_000.0,
        restored_at=1_000_000.0 + 3 * 86400,
    )

    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        # The restore itself ends the sessions in the file, which needs no key...
        assert ended == 1 and await _revoked(store, token)
        # ...and the start ends any made since, such as one from a command run on the file first.
        late = await _seed(store, "u3")
        assert not await _revoked(store, late)  # control
        sink = _Sink()
        await _record_a_restore(store, sink)
        assert await _revoked(store, late)
        rows = await store.list_audit(action=STORE_RESTORED_ACTION, limit=5)
        assert len(rows) == 1
        detail = json.loads(rows[0]["detail"])
        assert detail["archive_sha256"] == "ab" * 32
        assert detail["archive_age_seconds"] == 3 * 86400
        assert detail["last_audit_at"] == 999_000.0
        assert detail["sessions_revoked"] == 2
        assert rows[0]["actor"] == "system"
        assert [(n, a) for n, _d, a in sink.raised] == [
            (STORE_RESTORED_SUBJECT, "1970-01-12T13:30:00Z")
        ]
        assert "3.0 days old" in sink.raised[0][1] and "2 session(s)" in sink.raised[0][1]
        assert "Re-apply every disable, delete, role change and reset" in sink.raised[0][1]

        # Once only: the marker is gone, so a second start writes and raises nothing.
        fresh = await _seed(store, "u2")
        await _record_a_restore(store, sink)
        assert len(sink.raised) == 1
        assert not await _revoked(store, fresh)
        assert len(await store.list_audit(action=STORE_RESTORED_ACTION, limit=5)) == 1
    finally:
        await store.close()


async def test_a_store_no_restore_placed_records_nothing(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "plain.db")
    try:
        token = await _seed(store)
        sink = _Sink()
        await _record_a_restore(store, sink)
        assert sink.raised == []
        assert not await _revoked(store, token)
        assert await store.list_audit(action=STORE_RESTORED_ACTION, limit=5) == []
    finally:
        await store.close()


async def test_a_failing_alert_does_not_undo_the_record(tmp_path: Path) -> None:
    db = tmp_path / "restored.db"
    store = await MessageStore.open(db)
    token = await _seed(store)
    await store.close()
    write_restore_marker(
        db, archive_sha256="cd" * 32, archive_created_at=None, last_audit_at=None, restored_at=5.0
    )

    class _Broken(LoggingAlertSink):
        def store_restored(self, name: str, *, detail: str, last_audit_at: str) -> None:
            raise RuntimeError("transport down")

    store = await MessageStore.open(db)
    try:
        await _record_a_restore(store, _Broken())
        assert await _revoked(store, token)
        rows = await store.list_audit(action=STORE_RESTORED_ACTION, limit=5)
        assert json.loads(rows[0]["detail"])["archive_age_seconds"] is None
    finally:
        await store.close()


async def test_the_audit_rows_age_is_clamped_at_zero_as_the_alerts_is(tmp_path: Path) -> None:
    """An archive dated a little after the restore (a backup host whose clock led, inside the age
    check's skew allowance) has no negative age: the audit row says 0, as the alert says 0.0."""
    db = tmp_path / "restored.db"
    store = await MessageStore.open(db)
    await store.close()
    write_restore_marker(
        db,
        archive_sha256="aa" * 32,
        archive_created_at=1_000_600.0,
        last_audit_at=None,
        restored_at=1_000_000.0,
    )
    store = await MessageStore.open(db)
    try:
        sink = _Sink()
        await _record_a_restore(store, sink)
        rows = await store.list_audit(action=STORE_RESTORED_ACTION, limit=5)
        assert json.loads(rows[0]["detail"])["archive_age_seconds"] == 0
        assert "0.0 days old" in sink.raised[0][1]
    finally:
        await store.close()


async def test_the_restore_writes_the_marker_with_the_archive_hash(tmp_path: Path) -> None:
    """End to end through ``run_restore``: the placed store carries the marker, naming the hash of
    the archive bytes and the time of the newest audit row the archive held."""
    import hashlib

    key = generate_key()
    primary = await MessageStore.open(tmp_path / "msg.db", cipher=make_cipher(key))
    token = await _seed(primary)
    await primary.record_audit("synthetic_probe", actor="t", detail="{}")
    newest = max(float(r["ts"]) for r in await primary.list_audit(limit=50))
    ss = StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=key)
    runner = BackupRunner(
        primary,
        BackupSettings(enabled=True, destination=str(tmp_path / "b")),
        store_settings=ss,
        config_dir=None,
    )
    backup = await runner.run_once(now=time.time())
    assert backup is not None
    await primary.close()

    dest = tmp_path / "dr" / "msg.db"
    result = await run_restore(
        backup.archive_path,
        dest_store_path=dest,
        store_settings=StoreSettings(path=str(dest), encryption_key=key),
    )
    expected = hashlib.sha256(Path(backup.archive_path).read_bytes()).hexdigest()
    assert result.archive_sha256 == expected
    assert result.last_audit_at == newest
    assert result.archive_created_at is not None
    assert abs(result.archive_created_at - time.time()) < 300

    with sqlite3.connect(dest) as conn:
        marker = conn.execute(
            "SELECT archive_sha256, last_audit_at FROM restore_marker WHERE id = 1"
        ).fetchone()
    assert marker == (expected, newest)

    restored = await MessageStore.open(dest, cipher=make_cipher(key))
    try:
        assert await _revoked(restored, token)  # the restore ended the archive's session
        record = await restored.consume_restore_record()
        assert record is not None and record.archive_sha256 == expected
        assert record.sessions_revoked == 1  # counted by the restore, carried to the record
    finally:
        await restored.close()


def test_store_restored_is_a_routable_alert_type() -> None:
    assert "store_restored" in _ALERT_EVENT_TYPES


def test_the_lifespan_records_a_restore_before_it_builds_the_auth_service() -> None:
    """The record must run before any request can present a restored session. The lifespan builds
    the auth service, and only then serves; so the call must come first in its body."""
    tree = ast.parse((_ROOT / "messagefoundry" / "api" / "app.py").read_text("utf-8"))
    lifespan = next(
        n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "lifespan"
    )
    lines: dict[str, list[int]] = {"_record_a_restore": [], "AuthService": []}
    for node in ast.walk(lifespan):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in lines:
            lines[node.func.id].append(node.lineno)
    assert len(lines["_record_a_restore"]) == 1, lines
    assert lines["AuthService"], "the instrument found no AuthService construction"
    assert lines["_record_a_restore"][0] < min(lines["AuthService"])


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
def test_the_server_backends_hold_no_marker(backend: str) -> None:
    """Restore places only a SQLite store, so the server backends answer ``None`` without a
    query. Read from source, since their live suites are gated and their drivers are extras."""
    tree = ast.parse((_ROOT / "messagefoundry" / "store" / f"{backend}.py").read_text("utf-8"))
    found = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "consume_restore_record"
    ]
    assert len(found) == 1
    returns = [n for n in ast.walk(found[0]) if isinstance(n, ast.Return)]
    assert len(returns) == 1
    value: Any = returns[0].value
    assert isinstance(value, ast.Constant) and value.value is None


def test_the_schema_carries_the_marker_table_verbatim() -> None:
    """The restore writes ``_RESTORE_MARKER_DDL`` into an archive's store and the open runs
    ``_SCHEMA``; the two must create the same table, or the open's schema check refuses a restored
    store."""
    from messagefoundry.store.store import _RESTORE_MARKER_DDL, _SCHEMA

    assert "CREATE TABLE IF NOT EXISTS restore_marker" in _RESTORE_MARKER_DDL
    assert _RESTORE_MARKER_DDL.strip() in _SCHEMA


@pytest.mark.parametrize("sealed", [True, False], ids=["seal-column", "pre-seal-column"])
def test_the_restore_ends_every_open_session_whatever_the_sessions_schema(
    tmp_path: Path, sealed: bool
) -> None:
    """An archive from before the session seal (BACKLOG #2592) has a sessions table with no
    ``seal`` column, which the first open's migration adds. The marker write must not refuse it,
    since restoring an earlier build's archive is the ordinary case, and it must still end every
    open session in it, as it does for a current one: the CLI notice reports this count. A
    revoked row stays as it was."""
    db = tmp_path / "old.db"
    seal = ", seal TEXT NOT NULL DEFAULT ''" if sealed else ""
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id TEXT, revoked_at REAL"
            f"{seal})"
        )
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, revoked_at) VALUES ('a', 'u', NULL)"
        )
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, revoked_at) VALUES ('b', 'u', NULL)"
        )
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, revoked_at) VALUES ('c', 'u', 1.0)"
        )
    conn.close()
    ended = write_restore_marker(
        db, archive_sha256="ef" * 32, archive_created_at=None, last_audit_at=None, restored_at=9.0
    )
    assert ended == 2
    with sqlite3.connect(db) as check:
        assert check.execute("SELECT sessions_revoked FROM restore_marker").fetchone() == (2,)
        assert check.execute(
            "SELECT token_hash, revoked_at FROM sessions ORDER BY 1"
        ).fetchall() == [
            ("a", 9.0),
            ("b", 9.0),
            ("c", 1.0),
        ]
        # The seal column is there either way, as the first open's migration would add it, and
        # the rows the revoke ended carry the blank seal every revoked row carries.
        assert check.execute(
            "SELECT seal FROM sessions WHERE token_hash IN ('a', 'b')"
        ).fetchall() == [("",), ("",)]
    check.close()


def test_a_store_with_no_sessions_table_is_marked_with_none_ended(tmp_path: Path) -> None:
    db = tmp_path / "older.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY)")
    conn.close()
    ended = write_restore_marker(
        db, archive_sha256="ef" * 32, archive_created_at=None, last_audit_at=None, restored_at=9.0
    )
    assert ended == 0


async def test_a_restore_record_that_raises_still_stops_the_engine_and_closes_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The record is the first statement of the lifespan's startup span, so its raise reaches the
    span's teardown before anything else in the span ran. That teardown reads ``auth``; bound
    below the record, it raised UnboundLocalError and skipped ``engine.stop()``, which closes the
    store, so the process hung (BACKLOG #1257). The startup error must surface as itself, and the
    engine stop and store close must both have run."""
    import messagefoundry.api.app as appmod
    from messagefoundry.api import create_managed_app
    from messagefoundry.config.settings import AlertsSettings, AuthSettings, EgressSettings
    from messagefoundry.pipeline import Engine

    async def _boom(store: object, sink: object) -> None:
        raise RuntimeError("PROBE: the restore record failed")

    stops: list[str] = []
    closes: list[str] = []
    real_stop = Engine.stop
    real_close = MessageStore.close

    async def _stop(self: Engine, *args: Any, **kwargs: Any) -> None:
        stops.append("stop")
        await real_stop(self, *args, **kwargs)

    async def _close(self: MessageStore) -> None:
        closes.append("close")
        await real_close(self)

    monkeypatch.setattr(appmod, "_record_a_restore", _boom)
    monkeypatch.setattr(Engine, "stop", _stop)
    monkeypatch.setattr(MessageStore, "close", _close)
    app = create_managed_app(
        db_path=tmp_path / "probe.db",
        poll_interval=0.05,
        auth_settings=AuthSettings(),
        alerts_settings=AlertsSettings(security_notifications_required=False),
        egress_settings=EgressSettings(),
    )
    with pytest.raises(RuntimeError, match="PROBE: the restore record failed"):
        async with app.router.lifespan_context(app):
            pytest.fail("the lifespan served after its restore record raised")
    assert stops == ["stop"]
    assert closes, "the store was never closed"
