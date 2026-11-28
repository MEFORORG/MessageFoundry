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
    server_row_filtered,
    server_walk_tables,
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


class _Syntax(sqlite3.DatabaseError):
    """A server driver's syntax error, class 42 but not a refused grant."""

    sqlstate = "42601"


_SYNTAX_ERROR = _Syntax("synthetic: syntax")


# --- item 22: the probe behind the keyless-chain refusal ----------------------------------------


class _EmptyLogStore(_FakeServerStore):
    """A fake server handle whose audit log reads as empty, so the REAL #1916 guard refuses it."""

    path = "fake-server-store"

    async def audit_anchor(self) -> tuple[int, str | None]:
        return 0, None


def _serve_an_empty_log(
    monkeypatch: pytest.MonkeyPatch, db: Path, cipher: Cipher, *, key_named: bool = False
) -> list[_EmptyLogStore]:
    """``open_store`` hands back a handle over ``db`` and then runs the real guard on it with the
    verdict the command passed, as the real ``open_store`` does for a keyless cipher;
    ``key_named`` is the guard's own reading of whether the settings name a key."""
    opened: list[_EmptyLogStore] = []

    async def fake_open_store(settings: StoreSettings, **kw: Any) -> _EmptyLogStore:
        handle = _EmptyLogStore(connect_readonly(db, busy_timeout=5.0), cipher)
        opened.append(handle)
        refusal = kw["keyless_chain_refusal"]
        assert refusal is not None, "cipher-audit must pass the shared #1916 verdict"
        await store_base._refuse_to_start_a_keyless_chain(
            cast(store_base.Store, handle), refusal, key_named=key_named
        )
        return handle

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    return opened


class _ProbeRecord:
    def __init__(self) -> None:
        self.entered = 0
        self.closed = 0


def _probe_from(
    monkeypatch: pytest.MonkeyPatch,
    db: Path,
    *,
    error: Exception | None = None,
    close_error: Exception | None = None,
    filtered: frozenset[str] = frozenset(),
) -> _ProbeRecord:
    """Make the probe a SQLite-backed source over ``db``, recording that it was entered and closed;
    ``error`` makes the probe's open raise it instead, ``close_error`` its close, and ``filtered``
    the tables it reports as row-filtered."""
    record = _ProbeRecord()

    @asynccontextmanager
    async def fake_probe(
        settings: StoreSettings, *, posture: Any
    ) -> AsyncIterator[CipherCellSource]:
        if error is not None:
            raise error
        conn = connect_readonly(db, busy_timeout=5.0)
        record.entered += 1
        source = _SqliteSource(conn)
        source.row_filtered = filtered
        try:
            yield cast(CipherCellSource, source)
        finally:
            conn.close()
            record.closed += 1
        if close_error is not None:
            raise close_error

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
    assert "audit log also reads as empty" in payload["reason"], out
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


def test_a_close_failure_after_the_probe_found_the_mismatch_keeps_it(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The walk finished and found the key mismatch, so a failed close does not turn exit 4 into
    the guard's exit 2."""
    db, _settings = _copy(_template, tmp_path)
    _serve_an_empty_log(monkeypatch, db, build_store_cipher(StoreSettings(path=str(db))))
    _probe_from(monkeypatch, db, close_error=ConnectionResetError("synthetic: close"))
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 4 and payload["status"] == "KEY_MISMATCH", out


def test_the_probe_s_key_mismatch_names_what_its_catalog_read_could_not_cover(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A row filter the probe read is named beside its KEY_MISMATCH, so fixing the key first
    does not hide it until a second run."""
    db, _settings = _copy(_template, tmp_path)
    _serve_an_empty_log(monkeypatch, db, build_store_cipher(StoreSettings(path=str(db))))
    _probe_from(monkeypatch, db, filtered=frozenset({"messages"}))
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 4 and payload["status"] == "KEY_MISMATCH", out
    assert "row-level security" in payload["reason"] and "messages" in payload["reason"], out


def test_a_key_the_provider_did_not_resolve_keeps_the_refusal_s_cause(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Where the guard read the settings as naming a key, KEY_MISMATCH leads with that cause, and
    where it did not, the sentence is absent."""
    db, _settings = _copy(_template, tmp_path)
    keyless = build_store_cipher(StoreSettings(path=str(db)))
    cause = "A store key is configured, but [store].key_provider resolved no key"
    for key_named in (True, False):
        _serve_an_empty_log(monkeypatch, db, keyless, key_named=key_named)
        _probe_from(monkeypatch, db)
        rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
        assert rc == 4 and payload["status"] == "KEY_MISMATCH", out
        assert payload["reason"].startswith(cause) is key_named, out


@pytest.mark.parametrize(
    "error",
    [ConnectionResetError("synthetic: lost"), _SYNTAX_ERROR],
    ids=["link", "syntax"],
)
def test_a_failed_row_security_read_is_not_covered(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
) -> None:
    """A row-filter read that fails is a doubt over every table, so a run that can still finish
    is NOT_COVERED, exit 3, naming each table the catalog showed, never a PASS and never stopped
    by that read alone."""
    db, settings = _copy(_template, tmp_path)

    class _Handle(_FakeServerStore):
        async def cipher_walk_row_filtered(self, tables: Sequence[str]) -> frozenset[str]:
            raise error

    async def fake_open_store(_settings: StoreSettings, **kw: Any) -> _FakeServerStore:
        return _Handle(connect_readonly(db, busy_timeout=5.0), build_store_cipher(settings))

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 3 and payload["status"] == "NOT_COVERED", out
    assert "messages" in payload["row_filtered"] and "keyed_surface" in payload["row_filtered"]


def test_a_failed_row_security_read_does_not_stop_the_probe_s_key_mismatch(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Inside the probe the row-filter read decides nothing, so its failure still lets the
    key-mismatch read run: exit 4, never the refusal's exit 2."""
    db, _settings = _copy(_template, tmp_path)
    _serve_an_empty_log(monkeypatch, db, build_store_cipher(StoreSettings(path=str(db))))

    async def failing(self: _SqliteSource, tables: Sequence[str]) -> frozenset[str]:
        raise ConnectionResetError("synthetic: lost")

    monkeypatch.setattr(_SqliteSource, "cipher_walk_row_filtered", failing)
    _probe_from(monkeypatch, db)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 4 and payload["status"] == "KEY_MISMATCH", out


def test_the_row_filter_is_not_read_when_no_cipher_table_is_visible(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A catalog that shows only ``keyed_surface`` has nothing to audit, so the command says so
    without the row-filter read."""
    db, settings = _copy(_template, tmp_path)
    asked: list[Sequence[str]] = []

    class _Handle(_FakeServerStore):
        async def cipher_walk_columns(self, tables: Sequence[str]) -> dict[str, frozenset[str]]:
            found = await super().cipher_walk_columns(tables)
            return {t: c for t, c in found.items() if t == "keyed_surface"}

        async def cipher_walk_row_filtered(self, tables: Sequence[str]) -> frozenset[str]:
            asked.append(tables)
            return frozenset()

    async def fake_open_store(_settings: StoreSettings, **kw: Any) -> _FakeServerStore:
        return _Handle(connect_readonly(db, busy_timeout=5.0), build_store_cipher(settings))

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    rc, out = _run_server_cli_raw(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 2 and "nothing here this command can audit" in out, out
    assert asked == []


@pytest.mark.parametrize(
    "error",
    [TypeError("synthetic: defect"), KeyError("synthetic"), ConnectionResetError("lost")],
    ids=["type", "key", "link"],
)
def test_any_probe_failure_leaves_exit_2(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
) -> None:
    """The probe only chooses between exit 4 and the refusal's exit 2, so whatever it raises, a
    defect included, the refusal stands: never the exit 1 a FAIL uses."""
    db, _settings = _copy(_template, tmp_path)
    _serve_an_empty_log(monkeypatch, db, build_store_cipher(StoreSettings(path=str(db))))
    _probe_from(monkeypatch, db, error=error)
    rc, out = _run_server_cli_raw(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 2, out
    assert "would start a KEYLESS audit chain" in out, out


def test_the_shared_cause_and_the_public_names() -> None:
    """The configured-key cause is one sentence, the refusal's and the probe's, and the new entry
    points are each module's public names."""
    refusal = store_base.KeylessAuditChainRefused("x", "y", key_named=True)
    assert store_base.KEY_NAMED_UNRESOLVED in str(refusal) and refusal.key_named
    assert "open_cipher_walk_probe" in store_base.__all__
    assert "KEY_NAMED_UNRESOLVED" in store_base.__all__
    assert "server_row_filtered" in cipher_cells_all()


def cipher_cells_all() -> list[str]:
    import messagefoundry.store.cipher_cells as module

    return list(module.__all__)


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
        "relkind": "r",
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
    """A table with no row is a doubt, and a doubt names it."""
    store = _pg_reading([_row("messages"), _row("queue")])
    got = asyncio.run(store.cipher_walk_row_filtered(["messages", "state", "queue"]))
    assert got == {"state"}


class _TimedOut(sqlite3.DatabaseError):
    """A server driver's statement timeout."""

    sqlstate = "57014"


@pytest.mark.parametrize(
    "error",
    [
        _Refused("synthetic: permission denied"),
        _SYNTAX_ERROR,
        _Lost("synthetic: lost"),
        _TimedOut("synthetic: timeout"),
    ],
    ids=["refused", "syntax", "lost", "timeout"],
)
def test_the_postgres_read_raises_every_failure_for_its_caller_to_judge(
    error: Exception,
) -> None:
    """The backend read answers no failure itself, a refused grant included, so the one judge is
    ``server_row_filtered``, which can say the read failed rather than that row security
    applies."""
    store = _pg_reading(error)
    with pytest.raises(type(error)):
        asyncio.run(store.cipher_walk_row_filtered(["messages"]))


@pytest.mark.parametrize("relkind", ["v", "m", "f", None])
def test_a_relation_that_is_not_an_ordinary_table_is_named(relkind: str | None) -> None:
    """A view, a materialized view or a foreign table under a cipher table's name can filter rows
    no row-security flag shows, and a missing relkind is a doubt: each is named, though its
    flags read as exempt. An ordinary or partitioned table is read by its flags."""
    store = _pg_reading(
        [
            _row("messages", relkind=relkind),
            _row("state", relkind="r"),
            _row("queue", relkind="p"),
        ]
    )
    got = asyncio.run(store.cipher_walk_row_filtered(["messages", "state", "queue"]))
    assert got == {"messages"}


def test_sql_server_reads_no_row_filter() -> None:
    """Out of scope for item 35: SQL Server security policies are not read, and it says so with
    None rather than an empty set a reader would take for "read, none"."""
    store = SqlServerStore.__new__(SqlServerStore)
    assert asyncio.run(store.cipher_walk_row_filtered(["messages"])) is None


class _RaisingSource(_SqliteSource):
    def __init__(self, conn: sqlite3.Connection, error: Exception) -> None:
        super().__init__(conn)
        self.error = error

    async def cipher_walk_row_filtered(self, tables: Sequence[str]) -> frozenset[str] | None:
        raise self.error


def _row_filter_of(
    db: Path, source_error: Exception | None = None, answer: frozenset[str] | None = frozenset()
) -> Any:
    conn = connect_readonly(db, busy_timeout=5.0)
    try:
        source: _SqliteSource
        if source_error is not None:
            source = _RaisingSource(conn, source_error)
        else:

            class _Answering(_SqliteSource):
                async def cipher_walk_row_filtered(
                    self, tables: Sequence[str]
                ) -> frozenset[str] | None:
                    return answer

            source = _Answering(conn)
        columns = asyncio.run(source.cipher_walk_columns(server_walk_tables(POSTGRES_CIPHER_CELLS)))
        return asyncio.run(
            server_row_filtered(cast(CipherCellSource, source), POSTGRES_CIPHER_CELLS, columns)
        )
    finally:
        conn.close()


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("synthetic: defect"),
        ValueError("synthetic: defect"),
        TypeError("synthetic: defect"),
        NotImplementedError("synthetic: defect"),
        RecursionError("synthetic: defect"),
    ],
    ids=["runtime", "value", "type", "not-implemented", "recursion"],
)
def test_a_defect_in_the_row_filter_read_is_raised(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    error: Exception,
) -> None:
    """A bug is raised, never read as a failed read that names every table."""
    db, _settings = _copy(_template, tmp_path)
    with pytest.raises(type(error)):
        _row_filter_of(db, source_error=error)


@pytest.mark.parametrize(
    "error",
    [
        _Refused("synthetic: permission denied"),
        _Lost("synthetic: lost"),
        ConnectionResetError("synthetic: reset"),
    ],
    ids=["refused", "lost", "reset"],
)
def test_a_store_failure_of_the_row_filter_read_names_every_table(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    error: Exception,
) -> None:
    db, _settings = _copy(_template, tmp_path)
    reading = _row_filter_of(db, source_error=error)
    assert reading.state == "failed"
    assert "messages" in reading.tables and "keyed_surface" in reading.tables


def test_the_row_filter_reading_says_how_it_was_learned(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
) -> None:
    db, _settings = _copy(_template, tmp_path)
    assert _row_filter_of(db, answer=None).state == "unread"
    empty = _row_filter_of(db, answer=frozenset())
    assert empty.state == "read" and empty.tables == ()
    named = _row_filter_of(db, answer=frozenset({"messages"}))
    assert named.state == "read" and named.tables == ("messages",)


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
    assert "a a " not in payload["reason"] and ": a role with BYPASSRLS" in payload["reason"], out
    assert payload["row_filtered"] == sorted(filtered) and payload["hidden"] == [], out
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


@pytest.mark.parametrize(
    ("answer", "expected"),
    [(None, None), (frozenset(), [])],
    ids=["not-read", "read-empty"],
)
def test_json_row_filtered_is_null_where_no_row_filter_was_read(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    answer: frozenset[str] | None,
    expected: list[str] | None,
) -> None:
    """``null`` where the backend reads no row filter, ``[]`` only where it read one and found
    none, so an empty list always means read."""
    db, settings = _copy(_template, tmp_path)

    class _Handle(_FakeServerStore):
        async def cipher_walk_row_filtered(self, tables: Sequence[str]) -> frozenset[str] | None:
            return answer

    async def fake_open_store(_settings: StoreSettings, **kw: Any) -> _FakeServerStore:
        return _Handle(connect_readonly(db, busy_timeout=5.0), build_store_cipher(settings))

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "sqlserver")
    assert rc == 0 and payload["status"] == "PASS", out
    assert payload["row_filtered"] == expected, out


def test_json_row_filtered_is_null_on_sqlite(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    capsys: pytest.CaptureFixture[str],
) -> None:
    import json

    from messagefoundry.__main__ import main

    db, settings = _copy(_template, tmp_path)
    cfg = tmp_path / "service.toml"
    key = settings.encryption_key
    assert key is not None
    cfg.write_text(
        f'[store]\npath = "{db.as_posix()}"\nencryption_key = "{key}"\n', encoding="utf-8"
    )
    rc = main(["cipher-audit", "--service-config", str(cfg), "--json"])
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rc == 0, payload
    assert payload["row_filtered"] is None


def test_a_failed_row_filter_read_names_the_read_not_bypassrls(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Tables named because the read failed point at the read, a grant on pg_class and
    pg_roles; BYPASSRLS, which cannot fix a refused catalog read, is not suggested."""
    db, settings = _copy(_template, tmp_path)

    class _Handle(_FakeServerStore):
        async def cipher_walk_row_filtered(self, tables: Sequence[str]) -> frozenset[str] | None:
            raise _Refused("synthetic: permission denied")

    async def fake_open_store(_settings: StoreSettings, **kw: Any) -> _FakeServerStore:
        return _Handle(connect_readonly(db, busy_timeout=5.0), build_store_cipher(settings))

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 3 and payload["status"] == "NOT_COVERED", out
    assert "catalog read" in payload["reason"] and "failed" in payload["reason"], out
    assert "pg_catalog.pg_class" in payload["reason"], out
    assert "BYPASSRLS" not in payload["reason"], out


def test_the_empty_log_note_stays_on_the_mismatch_line() -> None:
    """Where a failure line follows the mismatch, the empty-log note goes on the mismatch, before
    it, and the configured-key cause leads."""
    from messagefoundry.__main__ import _keyed_refusal_mismatch
    from messagefoundry.store.cipher_cells import with_first_failure

    line = with_first_failure("X is recorded as keyed", "messages.raw id=3 is a BLOB")
    got = _keyed_refusal_mismatch(line, key_named=True)
    head, _sep, tail = got.partition("; also found before it: ")
    assert head.startswith(store_base.KEY_NAMED_UNRESOLVED)
    assert "audit log also reads as empty" in head
    assert tail == "messages.raw id=3 is a BLOB"
    plain = _keyed_refusal_mismatch("X is recorded as keyed", key_named=False)
    assert plain.startswith("X is recorded as keyed. The store's audit log also reads as empty")


@pytest.mark.parametrize(
    ("rule", "unseen"),
    [({"state"}, set()), (set(), {"messages"}), ({"state"}, {"messages"})],
    ids=["rule-only", "unseen-only", "both"],
)
def test_the_remedy_matches_why_each_table_was_named(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    rule: set[str],
    unseen: set[str],
) -> None:
    """A table the rule named gets the BYPASSRLS remedy; a view, foreign table or missing
    relation gets "audit the underlying tables", with no role advice, since no role clears it;
    a run with both gets both."""
    from messagefoundry.store.cipher_cells import RowFilterAnswer

    db, settings = _copy(_template, tmp_path)

    class _Handle(_FakeServerStore):
        async def cipher_walk_row_filtered(self, tables: Sequence[str]) -> frozenset[str] | None:
            return RowFilterAnswer(rule | unseen, unseen)

    async def fake_open_store(_settings: StoreSettings, **kw: Any) -> _FakeServerStore:
        return _Handle(connect_readonly(db, busy_timeout=5.0), build_store_cipher(settings))

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 3 and payload["status"] == "NOT_COVERED", out
    reason = payload["reason"]
    assert ("BYPASSRLS" in reason) is bool(rule), out
    assert ("superuser" in reason) is bool(rule), out
    assert ("Audit the underlying tables" in reason) is bool(unseen), out
    assert sorted(payload["row_filtered"]) == sorted(rule | unseen), out


def test_the_postgres_read_says_which_tables_it_could_not_see_into() -> None:
    """A view and a name with no catalog row are unseen; a table the rule named is not."""
    store = _pg_reading(
        [
            _row("messages", relkind="v"),
            _row("state", relrowsecurity=True, owned=False),
            _row("queue"),
        ]
    )
    got = asyncio.run(store.cipher_walk_row_filtered(["messages", "state", "queue", "users"]))
    assert got == {"messages", "state", "users"}
    assert getattr(got, "unseen", None) == {"messages", "users"}
