# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``cipher-audit`` on a server store, BACKLOG #1719 items 22 and 35.

Item 22: a keyless run over a server store whose audit log is empty is refused by the #1916 guard
as one that would start a keyless audit chain. The guard stands; a read-only probe after it only
says why, KEY_MISMATCH (exit 4) when the store holds keyed cells, as SQLite says it, and could not
start (exit 2) on a fresh store.

Item 35: a PostgreSQL table whose row-level security may hide rows from the audit login is
NOT_COVERED, never a PASS. The rule's exemptions are pinned one by one, since a wrong exemption is
the one way the change could move a verdict toward PASS.

The plain leg reuses the SQLite-backed fake server source of ``tests/test_cipher_cells_readback.py``.
Every value is synthetic (CLAUDE.md section 9).
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, cast

import pytest

import messagefoundry.store.base as store_base
from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.base import build_store_cipher
from messagefoundry.store.cipher_cells import (
    POSTGRES_CIPHER_CELLS,
    CipherCellSource,
    audit_server_cipher_cells,
    connect_readonly,
)
from messagefoundry.store.crypto import Cipher
from messagefoundry.store.postgres import PostgresStore, row_security_hides_rows
from messagefoundry.store.sqlserver import SqlServerStore
from tests.test_cipher_cells_readback import (
    _copy,
    _FakeServerStore,
    _keyless_store,
    _run_server_cli,
    _SqliteSource,
    _template,  # noqa: F401 -- the module-scoped store fixture these tests copy
)

_BACKENDS = ["postgres", "sqlserver"]


# --- item 22: the probe behind the keyless-chain refusal ----------------------------------------


class _EmptyLogStore(_FakeServerStore):
    """A fake server handle whose audit log reads as empty, so the REAL #1916 guard refuses it."""

    path = "fake-server-store"

    async def audit_anchor(self) -> tuple[int, str | None]:
        return 0, None


def _serve_an_empty_log(
    monkeypatch: pytest.MonkeyPatch, db: Path, cipher: Cipher
) -> list[_EmptyLogStore]:
    """``open_store`` hands back a handle over ``db`` and then runs the real guard on it with the
    verdict the command passed, as the real ``open_store`` does for a keyless cipher."""
    opened: list[_EmptyLogStore] = []

    async def fake_open_store(settings: StoreSettings, **kw: Any) -> _EmptyLogStore:
        handle = _EmptyLogStore(connect_readonly(db, busy_timeout=5.0), cipher)
        opened.append(handle)
        refusal = kw["keyless_chain_refusal"]
        assert refusal is not None, "cipher-audit must pass the shared #1916 verdict"
        await store_base._refuse_to_start_a_keyless_chain(
            cast(store_base.Store, handle), refusal, key_named=False
        )
        return handle

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    return opened


class _ProbeRecord:
    def __init__(self) -> None:
        self.entered = 0
        self.closed = 0
        self.ciphers: list[Cipher] = []


def _probe_from(
    monkeypatch: pytest.MonkeyPatch, db: Path, *, error: Exception | None = None
) -> _ProbeRecord:
    """Make the probe a SQLite-backed source over ``db``, recording that it was entered and closed;
    ``error`` makes the probe's open raise it instead."""
    record = _ProbeRecord()

    @asynccontextmanager
    async def fake_probe(
        settings: StoreSettings, *, posture: Any
    ) -> AsyncIterator[CipherCellSource]:
        if error is not None:
            raise error
        conn = connect_readonly(db, busy_timeout=5.0)
        record.entered += 1
        try:
            yield cast(CipherCellSource, _SqliteSource(conn))
        finally:
            conn.close()
            record.closed += 1

    monkeypatch.setattr(store_base, "open_cipher_walk_probe", fake_probe)
    return record


@pytest.mark.parametrize("backend", _BACKENDS)
def test_a_keyless_run_over_a_keyed_store_with_an_empty_log_is_key_mismatch(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    backend: str,
) -> None:
    """Exit 4, KEY_MISMATCH, as SQLite reports the same mistake, where it was exit 2 before. The
    guard still refused the open and closed its handle; the probe was entered and closed."""
    db, settings = _copy(_template, tmp_path)
    opened = _serve_an_empty_log(monkeypatch, db, build_store_cipher(StoreSettings(path=str(db))))
    probe = _probe_from(monkeypatch, db)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, backend)
    assert rc == 4 and payload["status"] == "KEY_MISMATCH", out
    assert "keyless open of a keyed store" in payload["reason"], out
    assert payload["keyed"] is False
    [handle] = opened
    assert handle.closed, "the guard's refused handle was left open"
    assert probe.entered == 1 and probe.closed == 1


@pytest.mark.parametrize("backend", _BACKENDS)
def test_sealed_values_alone_are_enough_for_key_mismatch(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    backend: str,
) -> None:
    """With no ``keyed_surface`` row left, the first sealed value the probe meets still says the
    store is keyed: exit 4."""
    db, _settings = _copy(_template, tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM keyed_surface")
    _serve_an_empty_log(monkeypatch, db, build_store_cipher(StoreSettings(path=str(db))))
    _probe_from(monkeypatch, db)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, backend)
    assert rc == 4 and payload["status"] == "KEY_MISMATCH", out


@pytest.mark.parametrize("backend", _BACKENDS)
def test_a_keyless_run_over_a_fresh_store_stays_could_not_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    backend: str,
) -> None:
    """A store with no keyed cell keeps the guard's refusal and its exit 2; the probe still ran,
    and closed."""
    db = tmp_path / "fresh.db"
    _keyless_store(db)
    opened = _serve_an_empty_log(monkeypatch, db, build_store_cipher(StoreSettings(path=str(db))))
    probe = _probe_from(monkeypatch, db)
    rc, out = _run_server_cli_raw(tmp_path, monkeypatch, capsys, backend)
    assert rc == 2, out
    assert "would start a KEYLESS audit chain" in out, out
    assert opened[0].closed
    assert probe.entered == 1 and probe.closed == 1


@pytest.mark.parametrize("backend", _BACKENDS)
def test_a_probe_that_fails_leaves_the_refusal_as_it_is(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    backend: str,
) -> None:
    """A probe that cannot connect says nothing, so the guard's exit 2 stands, never a PASS."""
    db, _settings = _copy(_template, tmp_path)
    _serve_an_empty_log(monkeypatch, db, build_store_cipher(StoreSettings(path=str(db))))
    _probe_from(monkeypatch, db, error=ConnectionResetError("synthetic: lost"))
    rc, out = _run_server_cli_raw(tmp_path, monkeypatch, capsys, backend)
    assert rc == 2, out
    assert "would start a KEYLESS audit chain" in out, out


def test_the_probe_is_not_asked_when_the_guard_does_not_refuse(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A keyed run, which the guard never refuses, reads the store through its own open alone."""
    db, settings = _copy(_template, tmp_path)

    async def fake_open_store(_settings: StoreSettings, **kw: Any) -> _FakeServerStore:
        return _FakeServerStore(
            connect_readonly(db, busy_timeout=5.0), build_store_cipher(settings)
        )

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    probe = _probe_from(monkeypatch, db)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 0 and payload["status"] == "PASS", out
    assert probe.entered == 0


def _run_server_cli_raw(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    backend: str,
) -> tuple[int, str]:
    """``cipher-audit`` without ``--json``: a refusal is an error line, not a JSON payload."""
    from messagefoundry.__main__ import main
    from tests.test_cipher_cells_readback import _SERVER_TOML, _SYNTH

    cfg = tmp_path / "server.toml"
    cfg.write_text(_SERVER_TOML[backend], encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = main(["cipher-audit", "--service-config", str(cfg)])
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert _SYNTH not in text, f"cipher-audit printed a plaintext or a key: {text}"
    return rc, text


def test_the_probe_seam_names_each_backend_and_refuses_sqlite() -> None:
    """Each server backend's probe is its one-connection store; SQLite has none."""
    for backend, cls in (("postgres", PostgresStore), ("sqlserver", SqlServerStore)):
        assert "cipher_walk_probe" in vars(cls), backend
    with pytest.raises(ValueError, match="server backend only"):
        store_base.open_cipher_walk_probe(StoreSettings(path="x.db"), posture=None)


# --- item 35: row-level security is NOT_COVERED --------------------------------------------------


@pytest.mark.parametrize(
    ("enabled", "forced", "owned", "superuser", "bypass", "hides"),
    [
        # Row security off: every row is read, whoever reads.
        (False, False, False, False, False, False),
        (False, True, False, False, False, False),
        # On, and an ordinary role: rows may be hidden, owner or not when the table forces it.
        (True, False, False, False, False, True),
        (True, True, False, False, False, True),
        (True, True, True, False, False, True),
        # The owner is exempt only while the table does not force row security on it.
        (True, False, True, False, False, False),
        # A superuser and a BYPASSRLS role are exempt, FORCE or not.
        (True, True, False, True, False, False),
        (True, False, False, True, False, False),
        (True, True, False, False, True, False),
        (True, False, False, False, True, False),
    ],
)
def test_each_row_security_exemption(
    enabled: bool, forced: bool, owned: bool, superuser: bool, bypass: bool, hides: bool
) -> None:
    got = row_security_hides_rows(
        enabled=enabled, forced=forced, owned=owned, superuser=superuser, bypass=bypass
    )
    assert got is hides


@pytest.mark.parametrize(
    "field", ["enabled", "forced", "owned", "superuser", "bypass"], ids=lambda f: f"{f}-unknown"
)
@pytest.mark.parametrize("unknown", [None, 1, "t"], ids=["null", "int", "text"])
def test_a_flag_nobody_read_never_exempts(field: str, unknown: object) -> None:
    """Only a read True or False counts. A NULL, or anything else, in the one flag that would
    otherwise grant an exemption, names the table; each base case below is exempt on its own."""
    exempt_by = {
        # The flag under test is the one exemption the other flags leave.
        "enabled": {
            "enabled": False,
            "forced": True,
            "owned": False,
            "superuser": False,
            "bypass": False,
        },
        "forced": {
            "enabled": True,
            "forced": False,
            "owned": True,
            "superuser": False,
            "bypass": False,
        },
        "owned": {
            "enabled": True,
            "forced": False,
            "owned": True,
            "superuser": False,
            "bypass": False,
        },
        "superuser": {
            "enabled": True,
            "forced": True,
            "owned": False,
            "superuser": True,
            "bypass": False,
        },
        "bypass": {
            "enabled": True,
            "forced": True,
            "owned": False,
            "superuser": False,
            "bypass": True,
        },
    }[field]
    assert row_security_hides_rows(**exempt_by) is False, "the base case must be exempt"
    assert row_security_hides_rows(**{**exempt_by, field: unknown}) is True


def test_an_unread_role_flag_never_lets_the_owner_through() -> None:
    """The owner exemption needs both role flags read: a NULL superuser flag names the table."""
    assert (
        row_security_hides_rows(
            enabled=True, forced=False, owned=True, superuser=None, bypass=False
        )
        is True
    )
    assert (
        row_security_hides_rows(
            enabled=True, forced=False, owned=True, superuser=False, bypass=None
        )
        is True
    )


class _Refused(sqlite3.DatabaseError):
    """A server driver's refusal, with an access-rule SQLSTATE."""

    sqlstate = "42501"


class _Lost(sqlite3.DatabaseError):
    """A server driver's lost connection."""

    sqlstate = "08006"


def _pg_reading(rows: list[dict[str, Any]] | Exception) -> PostgresStore:
    """A ``PostgresStore`` whose one fetch answers ``rows``, or raises them."""
    store = PostgresStore.__new__(PostgresStore)

    async def fetchall(sql: str, *params: Any) -> list[dict[str, Any]]:
        assert "relrowsecurity" in sql and "relforcerowsecurity" in sql
        assert "rolbypassrls" in sql and "rolsuper" in sql
        if isinstance(rows, Exception):
            raise rows
        return rows

    store._fetchall = fetchall  # type: ignore[method-assign]
    return store


def _row(name: str, **flags: object) -> dict[str, Any]:
    base: dict[str, object] = {
        "relrowsecurity": False,
        "relforcerowsecurity": False,
        "owned": True,
        "rolsuper": False,
        "rolbypassrls": False,
    }
    base.update(flags)
    return {"table_name": name, **base}


def test_the_postgres_read_names_each_table_the_rule_names() -> None:
    store = _pg_reading(
        [
            _row("messages"),
            _row("state", relrowsecurity=True, relforcerowsecurity=True),
            _row("queue", relrowsecurity=True),  # owned, not forced: exempt
            _row("reference", relrowsecurity=True, owned=False),
            _row("users", relrowsecurity=None),
        ]
    )
    got = asyncio.run(
        store.cipher_walk_row_filtered(["messages", "state", "queue", "reference", "users"])
    )
    assert got == {"state", "reference", "users"}


def test_a_table_the_catalog_read_did_not_return_is_named() -> None:
    """A table with no row, or a name met twice, is a doubt, and a doubt names it."""
    store = _pg_reading([_row("messages"), _row("queue"), _row("queue")])
    got = asyncio.run(store.cipher_walk_row_filtered(["messages", "state", "queue"]))
    assert got == {"state", "queue"}


def test_a_refused_catalog_read_names_every_table() -> None:
    store = _pg_reading(_Refused("synthetic: permission denied"))
    assert asyncio.run(store.cipher_walk_row_filtered(["messages", "state"])) == {
        "messages",
        "state",
    }


def test_a_lost_connection_is_raised_for_the_walk_to_report() -> None:
    store = _pg_reading(_Lost("synthetic: lost"))
    with pytest.raises(_Lost):
        asyncio.run(store.cipher_walk_row_filtered(["messages"]))


def test_sql_server_names_no_table_yet() -> None:
    """Out of scope for item 35: SQL Server security policies are not read, so nothing changes."""
    store = SqlServerStore.__new__(SqlServerStore)
    assert asyncio.run(store.cipher_walk_row_filtered(["messages"])) == frozenset()


class _RlsSource(_SqliteSource):
    """The fake source with a fixed set of row-filtered tables, recording what it was asked."""

    def __init__(self, conn: sqlite3.Connection, filtered: set[str]) -> None:
        super().__init__(conn)
        self.row_filtered = frozenset(filtered)
        self.asked: list[list[str]] = []

    async def cipher_walk_row_filtered(self, tables: Sequence[str]) -> frozenset[str]:
        self.asked.append(list(tables))
        # Over-reports a table the catalog does not show, which the walk must not record.
        return frozenset({*self.row_filtered, "not_a_store_table"})


def test_the_walk_records_row_filtered_tables_and_still_reads_them(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
) -> None:
    db, settings = _copy(_template, tmp_path)
    conn = connect_readonly(db, busy_timeout=5.0)
    try:
        source = _RlsSource(conn, {"messages", "keyed_surface"})
        audit = asyncio.run(
            audit_server_cipher_cells(
                cast(CipherCellSource, source),
                build_store_cipher(settings),
                cells=POSTGRES_CIPHER_CELLS,
            )
        )
    finally:
        conn.close()
    assert audit.row_filtered == ["messages", "keyed_surface"]
    assert "not_a_store_table" not in source.asked[0]
    assert "keyed_surface" in source.asked[0]
    raw = next(t for t in audit.tallies if t.name == "messages.raw")
    assert raw.present and raw.opened > 0, "a row-filtered table is still read"


@pytest.mark.parametrize("filtered", [{"messages"}, {"keyed_surface"}])
def test_cipher_audit_is_not_covered_under_row_level_security(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    filtered: set[str],
) -> None:
    """Exit 3, NOT_COVERED, naming the table and its cause, where the same store reads PASS with
    no row filter. The counts read are still printed."""
    db, settings = _copy(_template, tmp_path)
    cipher = build_store_cipher(settings)

    class _Handle(_FakeServerStore):
        async def cipher_walk_row_filtered(self, tables: Sequence[str]) -> frozenset[str]:
            return frozenset(t for t in tables if t in filtered)

    async def fake_open_store(_settings: StoreSettings, **kw: Any) -> _FakeServerStore:
        return _Handle(connect_readonly(db, busy_timeout=5.0), cipher)

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 3 and payload["status"] == "NOT_COVERED", out
    assert "row-level security" in payload["reason"], out
    assert next(iter(filtered)) in payload["reason"], out
    assert payload["opened"] and payload["opened"] > 0


def test_a_key_mismatch_still_names_row_level_security(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """KEY_MISMATCH leads, and the row filter it read is named beside it, so fixing the key first
    does not hide the gap until a second run."""
    db, _settings = _copy(_template, tmp_path)

    class _Handle(_FakeServerStore):
        async def cipher_walk_row_filtered(self, tables: Sequence[str]) -> frozenset[str]:
            return frozenset({"messages"} & set(tables))

    async def fake_open_store(_settings: StoreSettings, **kw: Any) -> _FakeServerStore:
        return _Handle(
            connect_readonly(db, busy_timeout=5.0),
            build_store_cipher(StoreSettings(path=str(db))),
        )

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 4 and payload["status"] == "KEY_MISMATCH", out
    assert "row-level security" in payload["reason"], out
