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
    write_restore_marker(
        db,
        archive_sha256="ab" * 32,
        archive_created_at=1_000_000.0,
        last_audit_at=999_000.0,
        restored_at=1_000_000.0 + 3 * 86400,
    )

    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        assert not await _revoked(store, token)  # control: the marker alone ends nothing
        sink = _Sink()
        await _record_a_restore(store, sink)
        assert await _revoked(store, token)
        rows = await store.list_audit(action=STORE_RESTORED_ACTION, limit=5)
        assert len(rows) == 1
        detail = json.loads(rows[0]["detail"])
        assert detail["archive_sha256"] == "ab" * 32
        assert detail["archive_age_seconds"] == 3 * 86400
        assert detail["last_audit_at"] == 999_000.0
        assert detail["sessions_revoked"] == 1
        assert rows[0]["actor"] == "system"
        assert [(n, a) for n, _d, a in sink.raised] == [
            (STORE_RESTORED_SUBJECT, "1970-01-12T13:30:00Z")
        ]
        assert "3.0 days" in sink.raised[0][1] and "1 session(s)" in sink.raised[0][1]
        assert "re-apply every disable, delete, role change and reset" in sink.raised[0][1]

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
        assert not await _revoked(restored, token)  # the archive's session came back live...
        record = await restored.consume_restore_record()
        assert record is not None and record.archive_sha256 == expected
        assert await _revoked(restored, token)  # ...until the first start ended it
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
