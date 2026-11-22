# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Follow-ups to ``cipher-audit``'s server walk, filed on BACKLOG #1719 from engine PR 2878.

Each test names the item it holds. The server-walk tests reuse the plain-leg scaffolding in
``tests/test_cipher_cells_readback.py``: a SQLite store written by the real writers, read through a
fake server source. Every value is synthetic (CLAUDE.md section 9).
"""

from __future__ import annotations

import ast
import asyncio
import builtins
import inspect
import json
import sqlite3
import textwrap
from collections.abc import Iterator
from itertools import product
from pathlib import Path
from typing import Any, cast

import pytest

import messagefoundry.__main__ as cli
import messagefoundry.store.base as store_base
import messagefoundry.store.cipher_cells as cipher_cells_module
import messagefoundry.store.postgres as postgres
import messagefoundry.store.sqlserver as sqlserver
from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.base import build_store_cipher, check_walk_identifiers
from messagefoundry.store.cipher_cells import SQLITE_CIPHER_CELLS, CipherWalkInterrupted
from messagefoundry.store.crypto import Cipher, CipherUnavailableError
from tests.test_cipher_cells_readback import (
    _copy,
    _flip_one_aead_byte,
    _GrantDenied,
    _run_server_cli,
    _serve_from,
    _SqliteSource,
    _template,  # noqa: F401 -- the module-scoped store fixture these tests copy
)

# --- item 1: an error part way through the server walk keeps what it found ----------------------


def _deny_from(monkeypatch: pytest.MonkeyPatch, table: str, error: Exception) -> None:
    """Make every chunk read of ``table`` raise ``error``, after the cells before it were read."""
    real = _SqliteSource.cipher_walk_chunk

    async def denying(
        self: _SqliteSource, tbl: str, *args: Any, **kwargs: Any
    ) -> list[tuple[Any, ...]]:
        if tbl == table:
            raise error
        return await real(self, tbl, *args, **kwargs)

    monkeypatch.setattr(_SqliteSource, "cipher_walk_chunk", denying)


@pytest.mark.parametrize(
    "error",
    [_GrantDenied("synthetic: permission denied"), ConnectionResetError("synthetic: lost")],
    ids=["grant", "connection"],
)
def test_a_failure_found_before_a_mid_walk_error_is_still_reported(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
) -> None:
    """A damaged ``state.value`` the walk read before a later cell's read failed is exit 1, FAIL,
    naming that cell, never the could-not-start 2 a denied grant alone earns. Item 1."""
    db, settings = _copy(_template, tmp_path)
    state = next(c for c in SQLITE_CIPHER_CELLS if c.table == "state")
    _flip_one_aead_byte(db, state)
    opened = _serve_from(monkeypatch, db, build_store_cipher(settings))
    _deny_from(monkeypatch, "attachment_chunk", error)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 1 and payload["status"] == "FAIL", out
    assert "stopped part way" in payload["reason"], payload
    assert "state.value position=1 did not decrypt" in payload["reason"], payload
    assert payload["opened"] is None, payload  # a partial walk prints no counts
    assert all(handle.closed for _kw, handle in opened)


class _DownFrom:
    """The real store cipher, until it is asked to open a value of ``table``: from there the key
    service is unreachable, as Transit's outage reads. Not a batch cipher, so the walk opens value
    by value and stops at the first outage."""

    def __init__(self, cipher: Any, table: str) -> None:
        self._cipher, self._table = cipher, table.encode()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cipher, name)

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        if aad is not None and self._table in aad:
            raise CipherUnavailableError("synthetic: key service unreachable")
        return cast(str, self._cipher.decrypt(stored, aad=aad))


def _damaged_state(tmp_path: Path, template: tuple[Path, StoreSettings]) -> tuple[Path, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    db, settings = _copy(template, tmp_path)
    _flip_one_aead_byte(db, next(c for c in SQLITE_CIPHER_CELLS if c.table == "state"))
    return db, settings


def _assert_stop_names_the_failure(rc: int, payload: dict[str, Any], out: str) -> None:
    assert rc == 1 and payload["status"] == "FAIL", out
    assert "stopped part way" in payload["reason"], payload
    assert "already fail" in payload["reason"], payload
    assert "state.value" in payload["reason"] and "did not decrypt" in payload["reason"], payload


def test_a_key_service_stop_on_a_server_store_keeps_the_failure_found_before_it(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Item 1, the outage limb: Transit going down at ``attachment_chunk`` still names the damaged
    ``state.value`` the walk read before it. Control: the same outage over intact cells is a FAIL
    that names no value."""
    db, settings = _copy(_template, tmp_path)
    _serve_from(
        monkeypatch, db, cast(Cipher, _DownFrom(build_store_cipher(settings), "attachment"))
    )
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 1 and "did not decrypt" not in payload["reason"], out
    db, settings = _damaged_state(tmp_path / "damaged", _template)
    _serve_from(
        monkeypatch, db, cast(Cipher, _DownFrom(build_store_cipher(settings), "attachment"))
    )
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    _assert_stop_names_the_failure(rc, payload, out)
    assert "CipherUnavailableError" in payload["reason"], payload


def _sqlite_cli(
    db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, Any], str]:
    monkeypatch.chdir(db.parent)
    rc = cli.main(["cipher-audit", "--db", str(db), "--json"])
    out = capsys.readouterr().out
    return rc, json.loads(out.strip().splitlines()[-1]), out


def _stop_reading_at(monkeypatch: pytest.MonkeyPatch, table: str, error: Exception) -> None:
    """Make the SQLite walk raise ``error`` when it reaches ``table``, after the cells before it."""
    real = cipher_cells_module.read_cipher_cells

    def stopping(*args: Any, **kwargs: Any) -> Iterator[Any]:
        for reading in real(*args, **kwargs):
            if reading.cell.table == table:
                raise error
            yield reading

    monkeypatch.setattr(cipher_cells_module, "read_cipher_cells", stopping)


@pytest.mark.parametrize(
    "stop",
    [
        sqlite3.OperationalError("synthetic: database is locked"),
        CipherWalkInterrupted("synthetic: the store changed under the walk"),
        "key_service",
    ],
    ids=["sqlite-error", "interrupted", "key-service"],
)
def test_a_sqlite_stop_keeps_the_failure_found_before_it(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stop: Exception | str,
) -> None:
    """Item 1 on SQLite: a lock, a VACUUM or an outage reached at ``attachment_chunk`` still names
    the damaged ``state.value`` the walk read before it, and exits 1."""
    db, settings = _damaged_state(tmp_path, _template)
    assert settings.encryption_key is not None
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", settings.encryption_key)
    if isinstance(stop, Exception):
        _stop_reading_at(monkeypatch, "attachment_chunk", stop)
    else:
        real = store_base.build_store_cipher
        monkeypatch.setattr(
            store_base,
            "build_store_cipher",
            lambda store, **kw: _DownFrom(real(store, **kw), "attachment"),
        )
    rc, payload, out = _sqlite_cli(db, monkeypatch, capsys)
    _assert_stop_names_the_failure(rc, payload, out)
    # Only a walk the store changed under warns that its rowid may have moved; no subset count.
    assert ("renumbered" in payload["reason"]) is isinstance(stop, CipherWalkInterrupted), payload
    assert "sealed value(s) did not open" not in payload["reason"], payload


def test_a_mid_walk_grant_error_with_nothing_failing_still_could_not_start(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The control: the same late denial over intact cells is exit 2, as it was."""
    db, settings = _copy(_template, tmp_path)
    _serve_from(monkeypatch, db, build_store_cipher(settings))
    _deny_from(monkeypatch, "attachment_chunk", _GrantDenied("synthetic: permission denied"))
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 2 and "42501" in payload["error"], out


# --- items 5 and 38: one identifier check and one sealed rule for both stores -------------------


def test_both_server_stores_share_one_walk_check_and_sealed_rule() -> None:
    """Item 5: neither store keeps its own copy of the identifier check or the sealed rule."""
    assert postgres.PostgresStore.cipher_walk_surface_sealed is (
        sqlserver.SqlServerStore.cipher_walk_surface_sealed
    )
    for module in (postgres, sqlserver):
        assert not hasattr(module, "_check_walk_identifiers"), module.__name__
        assert module.check_walk_identifiers is check_walk_identifiers
    check_walk_identifiers("messages", "raw")
    for bad in ("raw; DROP", "râw", "1raw"):
        with pytest.raises(ValueError, match="not a plain identifier"):
            check_walk_identifiers(bad)


class _Surfaces(store_base.ServerCipherWalk):
    def __init__(self, keyed: bool, marked: bool) -> None:
        self.keyed, self.marked = keyed, marked
        self.likes: list[str] = []

    async def _surface_keyed(self, table: str, column: str) -> bool:
        return self.keyed

    async def _surface_holds_ciphertext(self, table: str, column: str, like: str) -> bool:
        self.likes.append(like)
        return self.marked


@pytest.mark.parametrize(
    ("keyed_table", "keyed", "marked", "sealed", "likes"),
    [
        (True, True, False, True, 0),
        (True, False, True, True, 1),
        (False, True, False, False, 1),
        (True, False, False, False, 1),
    ],
)
def test_the_shared_sealed_rule_reads_the_marker_row_then_a_marked_value(
    keyed_table: bool, keyed: bool, marked: bool, sealed: bool, likes: int
) -> None:
    surfaces = _Surfaces(keyed, marked)
    got = asyncio.run(surfaces.cipher_walk_surface_sealed("messages", "raw", keyed=keyed_table))
    assert got is sealed
    assert len(surfaces.likes) == likes
    assert all(like == "mfenc:%" for like in surfaces.likes)


# --- item 7: SQL Server's column inventory is one statement -------------------------------------


def test_sqlserver_column_inventory_is_one_statement() -> None:
    store = sqlserver.SqlServerStore.__new__(sqlserver.SqlServerStore)
    calls: list[tuple[str, tuple[Any, ...]]] = []

    async def fetchall(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        calls.append((sql, params))
        return [
            {"table_name": "messages", "column_name": "raw"},
            {"table_name": "messages", "column_name": "id"},
            {"table_name": "state", "column_name": "value"},
        ]

    store._fetchall = fetchall  # type: ignore[method-assign]
    found = asyncio.run(store.cipher_walk_columns(["messages", "state", "absent", "messages"]))
    assert found == {"messages": frozenset({"raw", "id"}), "state": frozenset({"value"})}
    [(sql, params)] = calls
    assert params == ("messages", "state", "absent")
    assert "VALUES (?), (?), (?)" in sql and "OBJECT_ID(t.name, 'U')" in sql
    calls.clear()
    assert asyncio.run(store.cipher_walk_columns([])) == {}
    assert calls == []
    with pytest.raises(ValueError, match="not a plain identifier"):
        asyncio.run(store.cipher_walk_columns(["messages; --"]))


# --- item 8: no except tuple in cipher-audit lists a subclass of another member -----------------


def _redundant_builtin_excepts(source: str) -> tuple[int, list[tuple[str, str]]]:
    """How many ``except`` tuples ``source`` holds, and each builtin class one lists beside its
    own base. Only builtin names are resolved."""
    tuples, redundant = 0, []
    for node in ast.walk(ast.parse(textwrap.dedent(source))):
        if isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Tuple):
            tuples += 1
            names = [e.id for e in node.type.elts if isinstance(e, ast.Name)]
            classes = {n: getattr(builtins, n, None) for n in names}
            known = {n: c for n, c in classes.items() if isinstance(c, type)}
            redundant += [
                (a, b)
                for a, b in product(known, known)
                if a != b and issubclass(known[a], known[b])
            ]
    return tuples, redundant


def test_cipher_audit_lists_no_builtin_exception_class_beside_its_base() -> None:
    planted = "try:\n    pass\nexcept (RuntimeError, NotImplementedError, ValueError):\n    pass\n"
    assert _redundant_builtin_excepts(planted) == (1, [("NotImplementedError", "RuntimeError")])
    tuples, redundant = _redundant_builtin_excepts(inspect.getsource(cli._cipher_audit))
    assert tuples >= 1, "the scan read none of cipher-audit's except tuples"
    assert redundant == []


# --- item 11: the SQLite branch passes the command posture --------------------------------------


@pytest.mark.parametrize(("dial", "enforcing"), [("warn", None), ("enforce", True)])
def test_the_sqlite_audit_builds_its_cipher_on_the_command_posture(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    dial: str,
    enforcing: bool | None,
) -> None:
    """At ``warn`` the posture is None, which the Vault hops read as enforcing, as the server
    branch passes it; the ``warn`` posture would relax them. At ``enforce`` it is enforcing."""
    db, settings = _copy(_template, tmp_path)
    assert settings.encryption_key is not None
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", settings.encryption_key)
    seen: list[Any] = []
    real = store_base.build_store_cipher

    def recording(store: StoreSettings, **kwargs: Any) -> Any:
        seen.append(kwargs.get("posture"))
        return real(store, **kwargs)

    monkeypatch.setattr(store_base, "build_store_cipher", recording)
    cfg = tmp_path / "svc.toml"
    cfg.write_text(
        f"[store]\npath = {str(db)!r}\n\n[security]\nenforcement = {dial!r}\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["cipher-audit", "--service-config", str(cfg), "--json"])
    out = capsys.readouterr().out
    assert rc == 0, out
    [posture] = seen
    if enforcing is None:
        assert posture is None
    else:
        assert posture is not None and posture.enforcing is True


# --- item 31: SQL Server's composite key bound leads with a seekable range ----------------------


def test_the_composite_key_bound_leads_with_a_seekable_range() -> None:
    bound, values = sqlserver._key_after(("a", "b", "c"), (1, 2, 3))
    assert bound.startswith("[a] >= ? AND "), bound
    assert sqlserver._key_after(("id",), (7,)) == ("[id] > ?", [7])
    # The bound means exactly (a, b, c) > (x, y, z), checked against SQLite's row values.
    conn = sqlite3.connect(":memory:")
    try:
        grid = list(product(range(3), repeat=3))
        conn.execute("CREATE TABLE t (a INT, b INT, c INT)")
        conn.executemany("INSERT INTO t VALUES (?, ?, ?)", grid)
        for after in grid:
            bound, values = sqlserver._key_after(("a", "b", "c"), after)
            sql = "SELECT a, b, c FROM t WHERE " + bound.replace("[", "").replace("]", "")
            got = sorted(conn.execute(sql + " ORDER BY a, b, c", values).fetchall())
            assert got == [k for k in sorted(grid) if k > after], after
    finally:
        conn.close()


# --- item 37: the help and docstring spell the status as the command prints it ------------------


def test_the_not_covered_status_is_spelled_as_printed() -> None:
    parser, _dispatch = cli._build_parser()
    helps = {
        choice.dest: choice.help or ""
        for action in parser._actions
        if hasattr(action, "_choices_actions")
        for choice in action._choices_actions
    }
    for text in (helps["cipher-audit"], cli._cipher_audit.__doc__ or ""):
        assert "3 NOT_COVERED" in text
        assert "NOT COVERED" not in text
