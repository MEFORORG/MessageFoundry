# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``open_store`` refuses to create an absent SQLite store unless its caller provisions (BACKLOG #1780).

SQLite's own connect creates an absent file, and ``open_store`` then ensures the schema and runs the
migrations. So before this change a caller that meant *report on this store* got *create this store*:
a support bundle collected against a mistyped path built a 372 KB store and reported it healthy.

Every test here asserts the store file does NOT exist after the call, on each entry point that must
not create one, plus the two positive controls that must: ``create=True`` itself, and ``serve``'s
first run. Each test reads the outcome off the filesystem first and the exception type second, so on
the unfixed seam it fails on the file it created rather than on a missing name.

The second half is the no-migrate mode the row's step 1 asked for: ``read_only=True``, for a caller that
means *inspect this store*. Those tests read the file back through a separate ``mode=ro`` connection,
so what they see is what is durable, not what the store's own handle believes.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from messagefoundry.__main__ import main
from messagefoundry.api.app import create_managed_app
from messagefoundry.config.settings import ServiceSettings, StoreSettings
from messagefoundry.store import base as store_base
from messagefoundry.store.base import open_store, sqlite_settings
from messagefoundry.store.crypto import generate_key
from messagefoundry.support.bundle import build_bundle, status_snapshot


async def _open_then_close(target: Path, **kwargs: object) -> BaseException | None:
    """Open ``target`` through the seam and close it; return what the open raised, if anything."""
    try:
        store = await open_store(sqlite_settings(target), **kwargs, keyless_chain_refusal=None)  # type: ignore[arg-type]
    except Exception as exc:  # the outcome under test, returned so the file check runs first
        return exc
    await store.close()
    return None


def _created(directory: Path) -> list[str]:
    """Every file under ``directory`` -- the store, and any ``-wal``/``-shm`` sibling it left."""
    return sorted(p.name for p in directory.iterdir())


# --- the seam ----------------------------------------------------------------------------------------


async def test_open_store_refuses_an_absent_sqlite_store_by_default(tmp_path: Path) -> None:
    target = tmp_path / "mistyped-store.db"

    raised = await _open_then_close(target)

    assert _created(tmp_path) == [], "open_store created the store it was only asked to open"
    assert isinstance(raised, store_base.StoreNotFoundError)
    assert raised.path == target
    # The operator reading this needs the path they configured, not a traceback into SQLite.
    assert str(target) in str(raised)


async def test_open_store_create_true_provisions_an_absent_store(tmp_path: Path) -> None:
    """Positive control: the refusal is the default, not a lost ability to create."""
    target = tmp_path / "first-run.db"

    raised = await _open_then_close(target, create=True)

    assert raised is None
    assert target.is_file()


async def test_open_store_default_still_opens_an_existing_store(tmp_path: Path) -> None:
    target = tmp_path / "existing.db"
    assert await _open_then_close(target, create=True) is None

    assert await _open_then_close(target) is None


async def test_open_store_memory_store_is_not_refused() -> None:
    """``:memory:`` puts nothing on disk, so there is no absent file for the default to protect."""
    store = await open_store(sqlite_settings(":memory:"), keyless_chain_refusal=None)
    await store.close()


# --- the support bundle ------------------------------------------------------------------------------


def test_status_snapshot_reports_an_absent_store_without_creating_it(tmp_path: Path) -> None:
    target = tmp_path / "mistyped-store.db"

    snap = status_snapshot(ServiceSettings(store=sqlite_settings(target)))

    assert _created(tmp_path) == [], "the support bundle created the store it was reporting on"
    assert snap["db"] is None
    # A fixed code plus the exception type, never the path or the message (BACKLOG #1571).
    assert snap["db_error"] == "MF-BUNDLE-DB-001 StoreNotFoundError"


def test_build_bundle_reports_an_absent_store_without_creating_it(tmp_path: Path) -> None:
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    out = tmp_path / "bundle.zip"

    build_bundle(out, settings=ServiceSettings(store=sqlite_settings(store_dir / "typo.db")))

    assert _created(store_dir) == []
    assert out.is_file()


# --- a CLI subcommand that had no guard of its own ---------------------------------------------------


def test_backup_cli_refuses_an_absent_store(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    target = store_dir / "mistyped-store.db"
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text("[store]\n", encoding="utf-8")

    rc = main(
        [
            "backup",
            "--service-config",
            str(toml),
            "--db",
            str(target),
            "--destination",
            str(tmp_path / "backups"),
            "--json",
        ]
    )

    assert _created(store_dir) == [], "backup created the store it was asked to back up"
    assert rc == 2  # could not start, not a failed backup
    assert "no SQLite store" in capsys.readouterr().out


# --- the caller that must create ---------------------------------------------------------------------


def test_serve_first_run_still_creates_the_store(tmp_path: Path) -> None:
    """``serve``'s lifespan is the ordinary first run, so it opens with ``create=True``."""
    target = tmp_path / "first-run.db"
    app = create_managed_app(db_path=target, poll_interval=0.05)

    with TestClient(app):
        assert target.is_file()


# --- the read-only mode: neither create nor migrate (the row's step 1) -------------------------------

# An index the schema script builds on every ordinary open, so its absence is exactly what a migrating
# open would repair and a read-only open must leave alone.
_DROPPED_INDEX = "ix_messages_received"


def _durable(path: Path, sql: str) -> list[tuple[object, ...]]:
    """Read ``path`` through a connection the store does not own: it sees only what is on disk."""
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def _index_present(path: Path, name: str) -> bool:
    return bool(_durable(path, f"SELECT 1 FROM sqlite_master WHERE name = '{name}'"))


async def _store_missing_an_index(target: Path, **settings: object) -> StoreSettings:
    """A real store, then one index dropped behind its back: the state an older build leaves."""
    store_settings = StoreSettings(path=str(target), **settings)  # type: ignore[arg-type]
    store = await open_store(store_settings, create=True, keyless_chain_refusal=None)
    await store.close()
    conn = sqlite3.connect(target)
    try:
        conn.execute(f"DROP INDEX {_DROPPED_INDEX}")
        conn.commit()
    finally:
        conn.close()
    return store_settings


async def test_read_only_open_does_not_migrate(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    target = tmp_path / "older.db"
    settings = await _store_missing_an_index(target)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        store = await open_store(settings, read_only=True, keyless_chain_refusal=None)
        try:
            # It reads: the store answers through the ordinary API.
            assert (await store.db_status()).messages == 0
        finally:
            await store.close()

    assert not _index_present(target, _DROPPED_INDEX), "the read-only open migrated the store"
    # Not refused, but not silent either: the difference is named in the log.
    assert any(_DROPPED_INDEX in r.getMessage() for r in caplog.records), caplog.text

    # Control: an ordinary open of the same file does migrate it, so the absence above is the mode.
    store = await open_store(settings, keyless_chain_refusal=None)
    await store.close()
    assert _index_present(target, _DROPPED_INDEX)


async def test_read_only_open_refuses_every_write(tmp_path: Path) -> None:
    """SQLite enforces it, not the store's discipline: the handle is ``mode=ro``."""
    target = tmp_path / "ro.db"
    assert await _open_then_close(target, create=True) is None
    store = await open_store(sqlite_settings(target), read_only=True, keyless_chain_refusal=None)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            await store.record_connection_event(
                connection="IB_TEST", transport="mllp", direction="inbound", kind="probe"
            )
    finally:
        await store.close()
    assert _durable(target, "SELECT COUNT(*) FROM connection_event") == [(0,)]


async def test_read_only_open_of_a_keyed_store_writes_nothing_at_open(tmp_path: Path) -> None:
    """A keyed open reserves an AES-GCM invocation block and settles it at close. A read-only open
    does neither, and it does not start an empty audit chain either: it writes no genesis row."""
    target = tmp_path / "keyed.db"
    settings = await _store_missing_an_index(target, encryption_key=generate_key())
    conn = sqlite3.connect(target)
    try:
        # An empty chain, which the next writable open starts. The keyed create above wrote a
        # genesis row, so it is removed to put the log back in the state under test.
        conn.execute("DELETE FROM audit_log")
        conn.commit()
    finally:
        conn.close()
    before = _durable(target, "SELECT key_id, invocations FROM cipher_meta ORDER BY key_id")
    assert before, "the keyed create reserved nothing, so an unchanged count would prove nothing"

    store = await open_store(settings, read_only=True, keyless_chain_refusal=None)
    await store.close()

    assert _durable(target, "SELECT key_id, invocations FROM cipher_meta ORDER BY key_id") == before
    assert _durable(target, "SELECT COUNT(*) FROM audit_log") == [(0,)]

    # Control: a writable open of the same file does write both.
    store = await open_store(settings, keyless_chain_refusal=None)
    await store.close()
    assert _durable(target, "SELECT seq, action FROM audit_log") == [(1, "audit.key_epoch")]


async def test_read_only_open_refuses_an_absent_store(tmp_path: Path) -> None:
    target = tmp_path / "mistyped-store.db"

    raised = await _open_then_close(target, read_only=True)

    assert _created(tmp_path) == []
    assert isinstance(raised, store_base.StoreNotFoundError)


async def test_read_only_and_create_exclude_each_other(tmp_path: Path) -> None:
    target = tmp_path / "either.db"

    raised = await _open_then_close(target, read_only=True, create=True)

    assert isinstance(raised, ValueError)
    assert _created(tmp_path) == []


def _mismatched_store(target: Path) -> None:
    """A store whose index has the right name and the wrong columns: an ordinary open refuses it."""
    assert asyncio.run(_open_then_close(target, create=True)) is None
    conn = sqlite3.connect(target)
    try:
        conn.executescript(
            "DROP INDEX ix_messages_control; CREATE INDEX ix_messages_control ON messages(control_id);"
        )
    finally:
        conn.close()


def test_status_snapshot_reports_a_store_this_build_would_refuse(tmp_path: Path) -> None:
    """A bundle is collected when something is already wrong, so it opens read-only and still reports
    a store an ordinary open refuses (#1720), rather than only the refusal."""
    target = tmp_path / "mismatched.db"
    _mismatched_store(target)

    snap = status_snapshot(ServiceSettings(store=sqlite_settings(target)))

    assert snap.get("db_error") is None, snap.get("db_error")
    assert snap["db"] is not None and snap["db"]["messages"] == 0
    # Control: the ordinary open refuses this store, so the report above is the read-only mode's.
    from messagefoundry.store.schema_verify import SchemaMismatchError

    with pytest.raises(SchemaMismatchError):
        asyncio.run(open_store(sqlite_settings(target), keyless_chain_refusal=None))
    # Nothing was repaired behind the report's back.
    assert _durable(target, "SELECT sql FROM sqlite_master WHERE name = 'ix_messages_control'") == [
        ("CREATE INDEX ix_messages_control ON messages(control_id)",)
    ]


async def test_read_only_open_names_an_older_store_it_cannot_read(tmp_path: Path) -> None:
    """A store whose ``audit_log`` is in an earlier layout lacks a column the read-only open's own
    audit load reads. It is refused as a schema mismatch that says why, not as a bare "no such
    column". No earlier audit layout is converted (vault BACKLOG #2594), so the ordinary open
    refuses it too, by name. The control is the same store before its table is swapped."""
    from messagefoundry.store.schema_verify import SchemaMismatchError

    target = tmp_path / "older.db"
    assert await _open_then_close(target, create=True) is None
    assert await _open_then_close(target, read_only=True) is None  # the control
    conn = sqlite3.connect(target)
    try:
        conn.execute("DROP TABLE audit_log")
        conn.execute(
            "CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
            " actor TEXT, action TEXT NOT NULL, channel_id TEXT, detail TEXT, client TEXT,"
            " row_hash TEXT NOT NULL)"
        )
        conn.commit()
    finally:
        conn.close()

    raised = await _open_then_close(target, read_only=True)

    assert isinstance(raised, SchemaMismatchError)
    assert "opened read-only and lacks what this build reads" in str(raised)
    assert "no such column: seq" in str(raised)
    refused = await _open_then_close(target)
    assert isinstance(refused, SchemaMismatchError)
    assert "missing column 'seq'" in str(refused)


async def test_read_only_open_of_a_keyed_store_does_not_decrypt_the_caches(tmp_path: Path) -> None:
    """A keyed store with a legacy plaintext `state` value: the writable open seals it first, and a
    load of the cache refuses it unsealed. The read-only open loads no cache, so it opens."""
    from messagefoundry.store.crypto import CipherError

    target = tmp_path / "legacy.db"
    settings = await _store_missing_an_index(target, encryption_key=generate_key())
    conn = sqlite3.connect(target)
    try:
        conn.execute(
            "INSERT INTO state (namespace, key, value, set_at) VALUES ('ns', 'k', '\"plain\"', 1.0)"
        )
        conn.commit()
    finally:
        conn.close()

    store = await open_store(settings, read_only=True, keyless_chain_refusal=None)
    await store.close()

    # Control: the cache load itself refuses that value, so the open above is the skipped load.
    store = await open_store(settings, read_only=True, keyless_chain_refusal=None)
    try:
        with pytest.raises(CipherError):
            await store._load_state_cache()  # type: ignore[attr-defined]
    finally:
        await store.close()
