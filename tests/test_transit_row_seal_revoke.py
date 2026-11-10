# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A revoke under the Transit sealer still ends every session (decisions
d20261109T165402853-83b348 and d20261109T165406730-2505f2 on ADR 0217). Synthetic data only.

The account-epoch raise a revoke runs first goes without the raise on a Forged, Unverifiable or
Outage answer, as it went without it on a Forged one before; an Outage pages
``authority-seal-transit``. A Transit refusal of the kept session's re-stamp declines it, so that
session is ended too. SQLite runs on a real store with an in-memory Transit stand-in; Postgres and
SQL Server run their twins with the write helpers replaced, since a live server is not needed to
see what each catch takes.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import (
    RowSealError,
    RowSealKeyRetiredError,
    RowSealUnverifiableError,
    TransitRowSealer,
    TransitSealUnavailableError,
    TransitSealUnverifiableError,
)
from messagefoundry.store.store import (
    KeptSessionRestamp,
    MessageStore,
    RevokeSealOutcome,
    SessionRecord,
)
from tests._transit_seal_fake import FakeBackend, with_version


@pytest.fixture
def pages() -> list[str]:
    """Each page a store armed on it took, as ``<subject>|<reason>``."""
    return []


def _arm(store: Any, pages: list[str]) -> None:
    """Arm ``store``'s own seal pager on ``pages`` (decision d20261109T200352805-599b24, item 5)."""
    store.seal_pager().arm(lambda subject, reason: pages.append(f"{subject}|{reason}"))


@pytest.fixture
async def transit(
    tmp_path: Path, pages: list[str]
) -> AsyncIterator[tuple[MessageStore, FakeBackend, Path]]:
    path = tmp_path / "revoke.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    backend = FakeBackend()
    store._row_sealer = TransitRowSealer(backend)
    _arm(store, pages)
    try:
        yield store, backend, path
    finally:
        await store.close()


def _sql(path: Path, sql: str, params: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(sql, params).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def _plant(path: Path, table: str, column: str, key: str, value: str) -> None:
    """A well-formed seal naming version 5, which the stand-in does not hold: Unverifiable."""
    (seal,) = _sql(path, f"SELECT {column} FROM {table} WHERE {key}=?", (value,))[0]
    _sql(
        path, f"UPDATE {table} SET {column}=? WHERE {key}=?", (with_version(str(seal), "5"), value)
    )


async def _user(store: MessageStore, user_id: str) -> None:
    await store.create_user(
        user_id=user_id,
        username=f"name-{user_id}",
        auth_provider="local",
        password_hash="synthetic-hash",
        password_generated=False,
        audits=(),
    )


async def _session(store: MessageStore, user_id: str) -> str:
    token = mint_token()
    assert await store.create_session(
        token_hash=hash_token(token), user_id=user_id, expires_at=time.time() + 3600
    )
    return token


def _live(path: Path, user_id: str) -> int:
    ((n,),) = _sql(
        path, "SELECT COUNT(*) FROM sessions WHERE user_id=? AND revoked_at IS NULL", (user_id,)
    )
    return int(str(n))


# --- SQLite ---------------------------------------------------------------------------------------


async def test_an_unverifiable_account_still_has_every_session_ended(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    store, _, path = transit
    await _user(store, "u-1")
    for _ in range(2):
        await _session(store, "u-1")
    _plant(path, "users", "authz_seal", "id", "u-1")
    result = await store.revoke_user_sessions("u-1")
    assert result.count == 2 and _live(path, "u-1") == 0
    # Unverifiable is no Outage, so no authority-seal-transit page; since decision
    # d20261109T200352805-599b24 item 4 it pages under its own capped subject instead.
    assert [p.split("|")[0].rsplit(":", 2)[0] for p in pages] == [
        "authority-seal-transit-unverifiable:user"
    ]


async def test_an_outage_at_the_epoch_raise_still_ends_every_session_and_pages(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    store, backend, path = transit
    await _user(store, "u-1")
    for _ in range(2):
        await _session(store, "u-1")
    store._row_sealer = TransitRowSealer(backend)  # nothing cached: the raise meets Transit
    backend.down = True
    try:
        result = await store.revoke_user_sessions("u-1")
    finally:
        backend.down = False
    assert result.count == 2 and _live(path, "u-1") == 0
    assert len(pages) == 1 and "transit outage" in pages[0]


async def test_revoke_all_with_one_unverifiable_account_ends_every_session(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    store, _, path = transit
    for user in ("u-1", "u-2"):
        await _user(store, user)
        await _session(store, user)
    _plant(path, "users", "authz_seal", "id", "u-1")
    result = await store.revoke_all_sessions()
    assert result.count == 2 and _live(path, "u-1") == 0 and _live(path, "u-2") == 0


async def test_an_unverifiable_kept_session_is_ended_too(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    """Control first: a kept session whose seal holds is kept."""
    store, _, path = transit
    await _user(store, "u-1")
    await _session(store, "u-1")
    kept = await _session(store, "u-1")
    result = await store.revoke_user_sessions("u-1", except_token_hash=hash_token(kept))
    assert result.kept and _live(path, "u-1") == 1
    other = await _session(store, "u-1")
    _plant(path, "sessions", "seal", "token_hash", hash_token(kept))
    result = await store.revoke_user_sessions("u-1", except_token_hash=hash_token(kept))
    assert not result.kept and result.ended_kept and _live(path, "u-1") == 0
    assert other


# --- Postgres and SQL Server twins ----------------------------------------------------------------


def _server(backend: str, pages: list[str] | None = None) -> Any:
    import importlib

    from messagefoundry.store.row_seal import SealPager

    module = importlib.import_module(f"messagefoundry.store.{backend}")
    cls = getattr(module, "PostgresStore" if backend == "postgres" else "SqlServerStore")
    store = cls.__new__(cls)
    store._seal_pager = SealPager()
    if pages is not None:
        _arm(store, pages)
    return store


_REFUSALS: list[type[Exception]] = [
    RowSealError,
    RowSealUnverifiableError,
    TransitSealUnverifiableError,
    TransitSealUnavailableError,
]


def _raise(kind: type[Exception]) -> Exception:
    if kind is TransitSealUnavailableError:
        return TransitSealUnavailableError()
    if kind is TransitSealUnverifiableError:
        return TransitSealUnverifiableError("user", 5, 1)
    return kind("user", "")


@pytest.mark.parametrize("kind", _REFUSALS, ids=lambda k: k.__name__)
@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_server_epoch_raise_goes_without_on_every_refusal(
    backend: str, kind: type[Exception], pages: list[str]
) -> None:
    store = _server(backend, pages)

    async def refused(*_args: Any, **_kwargs: Any) -> None:
        raise _raise(kind)

    store._write_user = refused
    outcome = RevokeSealOutcome(store.seal_pager())
    assert await store._bump_session_epoch(object(), "u-1", outcome) is None
    # Decision d20261110T004916856-814db8, Q5: nothing pages until the revoke has committed.
    assert pages == []
    outcome.refusals.clear()  # the Forged and Unverifiable rows' report is item 4's test

    async def no_audit(*_args: Any, **_kwargs: Any) -> None:
        return None

    await outcome.report(no_audit)
    assert len(pages) == (1 if kind is TransitSealUnavailableError else 0)


class _PgConn:
    async def execute(self, sql: str, *args: Any) -> str:
        return "UPDATE 1"


class _MssqlCur:
    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        return None

    async def fetchall(self) -> list[Any]:
        return [("x",)]


@pytest.mark.parametrize(
    "kind",
    [
        RowSealUnverifiableError,
        TransitSealUnverifiableError,
        TransitSealUnavailableError,
        RowSealKeyRetiredError,  # ruling 3, slice 1b-iv: ended quietly with the rest
    ],
    ids=lambda k: k.__name__,
)
@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_server_kept_session_refused_by_transit_is_ended(
    backend: str, kind: type[Exception], pages: list[str]
) -> None:
    store = _server(backend, pages)

    async def refused(*_args: Any, **_kwargs: Any) -> SessionRecord | None:
        raise _raise(kind)

    store._write_session = refused
    conn: Any = _PgConn() if backend == "postgres" else _MssqlCur()
    restamp = KeptSessionRestamp("u-1", None, None)
    outcome = RevokeSealOutcome(store.seal_pager())
    result = await store._keep_or_end_session(conn, 3, "c" * 64, restamp, 1.0, outcome)
    assert not result.kept and result.ended_kept and result.count == 4


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_server_forged_kept_session_still_raises_as_on_main(backend: str) -> None:
    store = _server(backend)

    async def forged(*_args: Any, **_kwargs: Any) -> SessionRecord | None:
        raise RowSealError("session", "")

    store._write_session = forged
    conn: Any = _PgConn() if backend == "postgres" else _MssqlCur()
    with pytest.raises(RowSealError):
        await store._keep_or_end_session(
            conn, 0, "c" * 64, KeptSessionRestamp("u", None, None), 1.0, RevokeSealOutcome()
        )


# --- decision d20261109T200352805-599b24, item 2: stop calling Transit after the first Outage ----


def _epoch(path: Path, user_id: str) -> int:
    ((n,),) = _sql(path, "SELECT session_epoch FROM users WHERE id=?", (user_id,))
    return int(str(n))


async def test_revoke_all_stops_calling_transit_after_the_first_outage(
    transit: tuple[MessageStore, FakeBackend, Path],
    pages: list[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    store, backend, path = transit
    users = ("u-1", "u-2", "u-3")
    for user in users:
        await _user(store, user)
        await _session(store, user)
    kept = await _session(store, "u-1")
    store._row_sealer = TransitRowSealer(backend)  # nothing cached: each raise would meet Transit
    calls = len(backend.inputs)
    backend.down = True
    try:
        result = await store.revoke_all_sessions(except_token_hash=hash_token(kept))
    finally:
        backend.down = False
    assert len(backend.inputs) - calls == 1  # the first account's raise only, no kept re-stamp
    assert result.ended_kept and all(_live(path, u) == 0 for u in users)
    assert len(pages) == 1
    assert any("2 further account epoch raise" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("answer", ["forged", "unverifiable"])
async def test_a_forged_or_unverifiable_account_does_not_stop_the_raises_after_it(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str], answer: str
) -> None:
    store, _, path = transit
    for user in ("u-1", "u-2"):
        await _user(store, user)
        await _session(store, user)
    before = _epoch(path, "u-2")
    if answer == "forged":
        _sql(path, "UPDATE users SET display_name=? WHERE id=?", ("bent", "u-1"))
    else:
        _plant(path, "users", "authz_seal", "id", "u-1")
    await store.revoke_all_sessions()
    assert _epoch(path, "u-2") == before + 1
    assert _live(path, "u-1") == 0 and _live(path, "u-2") == 0


async def test_a_forged_account_still_runs_the_kept_sessions_seal_check(
    transit: tuple[MessageStore, FakeBackend, Path],
    pages: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, path = transit
    await _user(store, "u-1")
    kept = await _session(store, "u-1")
    _sql(path, "UPDATE users SET display_name=? WHERE id=?", ("bent", "u-1"))
    writes: list[str] = []
    write_session = store._write_session

    async def counting(token_hash: str, change: Any) -> Any:
        writes.append(token_hash)
        return await write_session(token_hash, change)

    monkeypatch.setattr(store, "_write_session", counting)
    result = await store.revoke_user_sessions("u-1", except_token_hash=hash_token(kept))
    assert writes == [hash_token(kept)] and not result.kept and _live(path, "u-1") == 0


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_server_outage_trips_the_revoke_and_skips_the_rest(
    backend: str, pages: list[str]
) -> None:
    store = _server(backend, pages)
    attempts: list[str] = []

    async def refused(_conn: Any, user_id: str, _bump: Any) -> None:
        attempts.append(user_id)
        raise TransitSealUnavailableError()

    async def no_session_write(*_args: Any, **_kwargs: Any) -> SessionRecord | None:
        raise AssertionError("the kept session's re-stamp ran after the Outage")

    locked: list[str] = []

    async def lock(_conn: Any, user_id: str) -> None:
        locked.append(user_id)

    store._write_user = refused
    store._write_session = no_session_write
    store._lock_account_row = lock
    outcome = RevokeSealOutcome(store.seal_pager())
    for user in ("u-1", "u-2", "u-3"):
        assert await store._bump_session_epoch(object(), user, outcome) is None
    assert attempts == ["u-1"] and outcome.skipped == 2 and pages == []  # paged after commit
    # Each skipped account's row is still locked before the sweep, with no Transit call.
    assert locked == ["u-2", "u-3"]
    conn: Any = _PgConn() if backend == "postgres" else _MssqlCur()
    result = await store._keep_or_end_session(
        conn, 3, "c" * 64, KeptSessionRestamp("u-1", None, None), 1.0, outcome
    )
    assert not result.kept and result.ended_kept and result.count == 4


# --- decision d20261109T200352805-599b24, item 5: each store pages through its own hook ----------


async def _outage_revoke(store: MessageStore, backend: FakeBackend, user_id: str) -> None:
    store._row_sealer = TransitRowSealer(backend)  # nothing cached: the raise meets Transit
    backend.down = True
    try:
        await store.revoke_user_sessions(user_id)
    finally:
        backend.down = False


async def test_each_store_pages_through_its_own_hook(tmp_path: Path) -> None:
    """Two stores in one process: an Outage on one pages that store's hook only. Control: the
    other store's revoke pages its own."""
    stores: list[MessageStore] = []
    backends = [FakeBackend(), FakeBackend()]
    seen: list[list[str]] = [[], []]
    try:
        for n in range(2):
            store = await MessageStore.open(
                tmp_path / f"own-{n}.db", cipher=make_cipher(generate_key(), write_v2=True)
            )
            stores.append(store)
            store._row_sealer = TransitRowSealer(backends[n])
            _arm(store, seen[n])
            await _user(store, "u-1")
            await _session(store, "u-1")
        await _outage_revoke(stores[0], backends[0], "u-1")
        assert len(seen[0]) == 1 and seen[1] == []
        await _outage_revoke(stores[1], backends[1], "u-1")
        assert len(seen[0]) == 1 and len(seen[1]) == 1
    finally:
        for store in stores:
            await store.close()


@pytest.mark.parametrize("order", ["newest_first", "oldest_first"])
def test_a_disarm_removes_only_its_own_registration(order: str) -> None:
    """One teardown never silences a page another registration armed, in either order."""
    from messagefoundry.store.row_seal import SealPager

    pager = SealPager()
    first: list[str] = []
    second: list[str] = []
    disarm_first = pager.arm(lambda subject, reason: first.append(reason))
    disarm_second = pager.arm(lambda subject, reason: second.append(reason))
    pager.outage("a")
    assert first == [] and second == ["a"]  # the newest registration takes the page
    if order == "newest_first":
        disarm_second()
        pager.outage("b")
        assert first == ["b"]
        disarm_first()
    else:
        disarm_first()
        pager.outage("b")
        assert second == ["a", "b"]
        disarm_second()
    assert not pager.armed
    pager.outage("c")  # no hook: nothing pages, nothing raises
    assert "c" not in first + second


async def test_a_page_that_raises_never_breaks_the_revoke(
    transit: tuple[MessageStore, FakeBackend, Path], caplog: pytest.LogCaptureFixture
) -> None:
    store, backend, path = transit

    def broken(subject: str, reason: str) -> None:
        raise RuntimeError("synthetic sink failure")

    store.seal_pager().arm(broken)
    await _user(store, "u-1")
    for _ in range(2):
        await _session(store, "u-1")
    await _outage_revoke(store, backend, "u-1")
    assert _live(path, "u-1") == 0
    assert any("page could not be delivered" in r.getMessage() for r in caplog.records)


class _DriftSink(LoggingAlertSink):
    def __init__(self) -> None:
        self.subjects: list[str] = []

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        self.subjects.append(name)


async def test_a_bare_engine_pages_and_its_stop_keeps_an_earlier_registration(
    tmp_path: Path,
) -> None:
    """An engine started without the serve lifespan arms its store's pager on its own sink; its
    stop removes only that registration, so one armed before it, as the lifespan's is, still
    pages. Control: before the engine starts, the earlier registration takes the page."""
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline.engine import Engine
    from messagefoundry.store.row_seal import TRANSIT_OUTAGE_SUBJECT

    store = await MessageStore.open(tmp_path / "engine.db", cipher=make_cipher(generate_key()))
    try:
        earlier: list[str] = []
        _arm(store, earlier)
        store.seal_pager().outage("before")
        assert len(earlier) == 1
        sink = _DriftSink()
        engine = Engine(
            store, alert_sink=sink, egress_settings=EgressSettings(deny_by_default=False)
        )
        try:
            await engine.start()
            store.seal_pager().outage("during")
            assert sink.subjects == [TRANSIT_OUTAGE_SUBJECT] and len(earlier) == 1
        finally:
            await engine.stop()
        assert store.seal_pager().armed
        store.seal_pager().outage("after")
        assert len(earlier) == 2 and len(sink.subjects) == 1
    finally:
        await store.close()


def test_the_cli_revoke_pages_through_the_logging_sink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``admin-revoke-sessions`` arms the store's pager on the logging sink before its revoke, so
    an Outage there pages. The revoke is wrapped to page as an Outage would; the store is keyless,
    as the CLI's other tests open it."""
    import asyncio

    from messagefoundry.__main__ import main
    from tests._phi_gate_provisions import setenv_at_rest_opt_out
    from tests.test_b2614_revoke_all_route_cli import _seed

    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    asyncio.run(_seed(db))
    revoke = MessageStore.revoke_all_sessions
    armed: list[bool] = []

    async def paging(self: MessageStore, **kwargs: Any) -> Any:
        armed.append(self.seal_pager().armed)
        self.seal_pager().outage("a synthetic outage during the CLI revoke")
        return await revoke(self, **kwargs)

    monkeypatch.setattr(MessageStore, "revoke_all_sessions", paging)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 0
    assert armed == [True]
    # The CLI configures its own logging, which writes to stderr.
    assert "ALERT integrity_drift: 'authority-seal-transit'" in capsys.readouterr().err


# --- decision d20261109T200352805-599b24, item 4: a revoke audits and pages each seal refusal ----


async def _audits(store: MessageStore, action: str) -> list[dict[str, Any]]:
    import json

    rows = await store.list_audit(action=action, limit=50)
    return [json.loads(str(row["detail"])) for row in rows]


def _subjects(pages: list[str]) -> list[str]:
    return [page.split("|", 1)[0] for page in pages]


def _post_commit_audit(store: MessageStore, seen: list[bool]) -> None:
    """Record, for each audit row the store writes, whether its writer transaction was open."""
    record = store.record_audit

    async def watched(*args: Any, **kwargs: Any) -> Any:
        seen.append(bool(store._db.in_transaction))
        return await record(*args, **kwargs)

    store.record_audit = watched  # type: ignore[method-assign]


async def test_an_unverifiable_account_is_audited_and_paged_after_the_revoke_commits(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    from messagefoundry.store.row_seal import unverifiable_subject

    store, _, path = transit
    await _user(store, "u-1")
    await _session(store, "u-1")
    _plant(path, "users", "authz_seal", "id", "u-1")
    in_txn: list[bool] = []
    _post_commit_audit(store, in_txn)
    await store.revoke_user_sessions("u-1")
    assert in_txn == [False]
    (detail,) = await _audits(store, "integrity.authority_seal_unverifiable")
    assert detail["kind"] == "user" and detail["user_id"] == "u-1" and detail["during"] == "revoke"
    assert detail["stored_version"] == 5 and isinstance(detail["probe_version"], int)
    assert _subjects(pages) == [unverifiable_subject("user", "u-1")]
    assert await _audits(store, "integrity.authority_seal_failed") == []


async def test_a_forged_account_is_audited_and_paged_as_main_pages_one(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    from messagefoundry.store.row_seal import AUTHORITY_SEAL_FAILED_SUBJECT

    store, _, path = transit
    await _user(store, "u-1")
    await _session(store, "u-1")
    _sql(path, "UPDATE users SET display_name=? WHERE id=?", ("bent", "u-1"))
    await store.revoke_all_sessions()
    (detail,) = await _audits(store, "integrity.authority_seal_failed")
    assert detail == {"kind": "user", "user_id": "u-1", "during": "revoke"}
    assert _subjects(pages) == [AUTHORITY_SEAL_FAILED_SUBJECT]
    assert _live(path, "u-1") == 0


async def test_an_unverifiable_kept_session_is_audited_by_its_ref_only(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    store, _, path = transit
    await _user(store, "u-1")
    kept = await _session(store, "u-1")
    _plant(path, "sessions", "seal", "token_hash", hash_token(kept))
    result = await store.revoke_user_sessions("u-1", except_token_hash=hash_token(kept))
    assert result.ended_kept
    (detail,) = await _audits(store, "integrity.authority_seal_unverifiable")
    assert detail["kind"] == "session" and detail["session"] == hash_token(kept)[:12]
    assert hash_token(kept) not in str(detail) and hash_token(kept) not in "".join(pages)
    assert len(pages) == 1


@pytest.mark.parametrize("fault", [RuntimeError, NotImplementedError], ids=["refusal", "defect"])
async def test_a_refused_audit_row_still_pages_and_keeps_the_revoke(
    transit: tuple[MessageStore, FakeBackend, Path],
    pages: list[str],
    caplog: pytest.LogCaptureFixture,
    fault: type[Exception],
) -> None:
    """The revoke has committed, so neither a store refusal nor a defect in the audit write
    raises out of it: each is logged and the page still goes."""
    store, _, path = transit
    await _user(store, "u-1")
    await _session(store, "u-1")
    _plant(path, "users", "authz_seal", "id", "u-1")

    async def refused(*_args: Any, **_kwargs: Any) -> None:
        raise fault("synthetic audit fault")

    store.record_audit = refused  # type: ignore[method-assign]
    result = await store.revoke_user_sessions("u-1")
    assert result.count == 1 and _live(path, "u-1") == 0
    assert len(pages) == 1
    assert any("could not be written" in r.getMessage() for r in caplog.records)


async def test_unverifiable_pages_are_capped_per_store(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    from messagefoundry.store.row_seal import UNVERIFIABLE_SUBJECT_CAP, UNVERIFIABLE_SUBJECT_PREFIX

    store, _, path = transit
    users = [f"u-{n}" for n in range(UNVERIFIABLE_SUBJECT_CAP + 2)]
    for user in users:
        await _user(store, user)
        _plant(path, "users", "authz_seal", "id", user)
    await store.revoke_all_sessions()
    subjects = _subjects(pages)
    assert len(subjects) == len(users)
    named = [s for s in subjects if not s.endswith(":*")]
    assert len(set(named)) == UNVERIFIABLE_SUBJECT_CAP
    assert subjects.count(f"{UNVERIFIABLE_SUBJECT_PREFIX}:*") == 2
    assert len(await _audits(store, "integrity.authority_seal_unverifiable")) == len(users)


async def test_the_restore_revoke_audits_its_refusals_after_it_commits(
    tmp_path: Path, pages: list[str]
) -> None:
    from messagefoundry.store.store import write_restore_marker

    path = tmp_path / "restored.db"
    key = generate_key()
    backend = FakeBackend()
    store = await MessageStore.open(path, cipher=make_cipher(key, write_v2=True))
    store._row_sealer = TransitRowSealer(backend)
    await _user(store, "u-1")
    await store.close()
    _plant(path, "users", "authz_seal", "id", "u-1")
    write_restore_marker(
        path, archive_sha256="ab" * 32, archive_created_at=None, last_audit_at=None, restored_at=5.0
    )
    store = await MessageStore.open(path, cipher=make_cipher(key, write_v2=True))
    try:
        store._row_sealer = TransitRowSealer(backend)
        _arm(store, pages)
        in_txn: list[bool] = []
        _post_commit_audit(store, in_txn)
        assert await store.consume_restore_record() is not None
        assert in_txn == [False]
        assert len(await _audits(store, "integrity.authority_seal_unverifiable")) == 1
        assert len(pages) == 1
    finally:
        await store.close()


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_server_revoke_holds_each_refusal_for_its_report(backend: str) -> None:
    """The server twins take a Forged and an Unverifiable raise into the outcome, for the report
    each public revoke runs after its commit. An Outage is held too, and paged by that report
    (decision d20261110T004916856-814db8, Q5)."""
    store = _server(backend)
    answers = iter([_raise(RowSealError), _raise(TransitSealUnverifiableError)])

    async def refused(*_args: Any, **_kwargs: Any) -> None:
        raise next(answers)

    store._write_user = refused
    outcome = RevokeSealOutcome(store.seal_pager())
    for user in ("u-1", "u-2"):
        assert await store._bump_session_epoch(object(), user, outcome) is None
    assert [(r.unverifiable, r.ident) for r in outcome.refusals] == [
        (False, "u-1"),
        (True, "u-2"),
    ]
    assert outcome.refusals[1].stored_version == 5 and not outcome.tripped


def test_the_store_side_names_match_the_service_and_alert_names() -> None:
    """The store may not import ``auth/`` or ``pipeline/``, so it spells these itself."""
    from messagefoundry.auth.service import AUTHORITY_SEAL_FAILED_ACTION
    from messagefoundry.pipeline.alerts import AUTHORITY_SEAL_SUBJECT
    from messagefoundry.pipeline.security_signals import MAX_SUBJECT_ALERTS
    from messagefoundry.store.row_seal import (
        AUTHORITY_SEAL_FAILED_SUBJECT,
        UNVERIFIABLE_SUBJECT_CAP,
    )
    from messagefoundry.store.store import AUTHORITY_SEAL_FAILED_AUDIT_ACTION

    assert AUTHORITY_SEAL_FAILED_SUBJECT == AUTHORITY_SEAL_SUBJECT
    assert UNVERIFIABLE_SUBJECT_CAP == MAX_SUBJECT_ALERTS
    assert AUTHORITY_SEAL_FAILED_AUDIT_ACTION == AUTHORITY_SEAL_FAILED_ACTION


def test_a_page_no_sink_took_spends_no_capped_slot() -> None:
    """A sink that raises, through the engine's own adapter, spends none of the cap's named slots;
    the control is a working sink, armed after, whose next row still pages under its own name."""
    from messagefoundry.pipeline.alerts import authority_seal_page
    from messagefoundry.store.row_seal import (
        UNVERIFIABLE_SUBJECT_CAP,
        SealPager,
        unverifiable_subject,
    )

    class _Broken(LoggingAlertSink):
        def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
            raise RuntimeError("synthetic sink failure")

    pager = SealPager()
    disarm = pager.arm(authority_seal_page(_Broken()))
    for n in range(UNVERIFIABLE_SUBJECT_CAP + 1):
        pager.unverifiable("user", f"u-{n}", "synthetic")
    disarm()
    good = _DriftSink()
    pager.arm(authority_seal_page(good))
    pager.unverifiable("user", "u-next", "synthetic")
    assert good.subjects == [unverifiable_subject("user", "u-next")]


def test_a_surrogate_bearing_id_pages_rather_than_raising() -> None:
    """A lone surrogate a driver let through still keys a row and pages under its own subject, so
    a page after a committed revoke never raises; a well-formed id keys as strict UTF-8 does."""
    import hashlib

    from messagefoundry.pipeline.alerts import authority_seal_page
    from messagefoundry.store.row_seal import SealPager, seal_row_digest, unverifiable_subject

    odd = "u-\udcff"
    sink = _DriftSink()
    pager = SealPager()
    pager.arm(authority_seal_page(sink))
    pager.unverifiable("user", odd, "synthetic")
    assert sink.subjects == [unverifiable_subject("user", odd)]

    def part(value: bytes) -> bytes:
        return len(value).to_bytes(4, "big") + value

    strict = hashlib.sha256(part(b"user") + part("u-\u00e9".encode())).hexdigest()
    assert seal_row_digest("user", "u-\u00e9") == strict  # as stored, never case-folded


def test_a_held_refusal_keeps_its_whole_id_out_of_the_repr() -> None:
    """A session's held refusal carries the whole token hash for the digest; neither the refusal's
    repr nor its outcome's carries it, so a stray ``%r`` or a traceback of locals logs none."""
    from messagefoundry.store.row_seal import SealPager
    from messagefoundry.store.store import RevokeSealOutcome, _RevokeSealRefusal

    whole = "ab" * 32
    refusal = _RevokeSealRefusal(True, "session", whole, 2, 3)
    outcome = RevokeSealOutcome(SealPager())
    outcome.refusals.append(refusal)
    assert refusal.ident == whole
    assert whole not in repr(refusal)
    assert whole not in repr(outcome)


# --- decision d20261110T004916856-814db8, Q5: the Outage page goes after the commit ---------------


async def test_an_outage_revoke_pages_after_it_commits(tmp_path: Path) -> None:
    """The Outage page of a revoke that commits is sent once the writer transaction has closed,
    with the text that says the revoke went ahead."""
    store = await MessageStore.open(
        tmp_path / "outage.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    backend = FakeBackend()
    try:
        store._row_sealer = TransitRowSealer(backend)
        await _user(store, "u-1")
        await _session(store, "u-1")
        seen: list[tuple[bool, str]] = []
        store.seal_pager().arm(
            lambda subject, reason: seen.append((bool(store._db.in_transaction), reason))
        )
        await _outage_revoke(store, backend, "u-1")
        assert [in_txn for in_txn, _ in seen] == [False]
        assert seen[0][1].endswith("the revoke went ahead without it")
    finally:
        await store.close()


async def test_an_outage_revoke_that_fails_before_its_commit_pages_its_own_text(
    tmp_path: Path,
) -> None:
    """A revoke that met an Outage and then failed before its commit pages text that says so,
    never that it went ahead; the failure still propagates."""
    store = await MessageStore.open(
        tmp_path / "outage-rollback.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    backend = FakeBackend()
    try:
        store._row_sealer = TransitRowSealer(backend)
        await _user(store, "u-1")
        await _session(store, "u-1")
        seen: list[str] = []
        _arm(store, seen)

        async def commit_fails() -> None:
            raise sqlite3.OperationalError("synthetic: disk I/O error at commit")

        store._commit = commit_fails  # type: ignore[method-assign]
        with pytest.raises(sqlite3.OperationalError):
            await _outage_revoke(store, backend, "u-1")
        assert len(seen) == 1
        assert "failed before its commit was confirmed" in seen[0]
        assert "went ahead" not in seen[0]
    finally:
        del store._commit
        await store.close()


async def test_a_cancel_after_the_commit_drops_no_page() -> None:
    """``report`` runs after the revoke has committed. A cancel that lands while the first held
    refusal's audit row is waiting still lets every row be written and every page be sent, held
    Outage included, then re-raises the cancel (decision d20261110T004916856-814db8, Q5)."""
    import asyncio

    from messagefoundry.store.row_seal import SealPager
    from messagefoundry.store.store import RevokeSealOutcome, _RevokeSealRefusal

    seen: list[str] = []
    pager = SealPager()
    pager.arm(lambda subject, reason: seen.append(subject))
    outcome = RevokeSealOutcome(pager)
    outcome.outages.append("an account's session epoch raise")
    outcome.refusals.extend(
        [_RevokeSealRefusal(True, "user", "u-1", 2, 3), _RevokeSealRefusal(False, "user", "u-2")]
    )
    waiting = asyncio.Event()
    release = asyncio.Event()
    written: list[str] = []

    async def slow_audit(action: str, **_kwargs: Any) -> None:
        if not written:
            waiting.set()
            await release.wait()
        written.append(action)

    task = asyncio.ensure_future(outcome.report(slow_audit))
    await waiting.wait()
    task.cancel()
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(written) == 2
    assert len(seen) == 3  # the Outage, then one page per held refusal


# --- the ref rule (ADR 0217, *A ref is for reading*): as stored, scrubbed, bounded ----------------


def test_ids_that_differ_only_by_case_key_and_page_apart() -> None:
    """The digest is of the id as stored, so a planted ``U-1`` beside a genuine ``u-1`` on a
    case-sensitive collation is its own cap key and its own subject."""
    from messagefoundry.store.row_seal import seal_row_digest, seal_row_ref, unverifiable_subject

    assert seal_row_digest("user", "U-1") != seal_row_digest("user", "u-1")
    assert unverifiable_subject("user", "U-1") != unverifiable_subject("user", "u-1")
    assert seal_row_ref("user", "U-1") == "U-1"


@pytest.mark.parametrize("planted", ["u-\udcff", "u-\x07\u202e1"], ids=["surrogate", "control"])
def test_a_planted_id_pages_through_a_sink_that_encodes_the_subject(planted: str) -> None:
    """A sink that encodes its subject strictly, as a mail header or a driver insert does, takes
    the named page of a row whose stored id carries a lone surrogate or a control character: the
    ref is escaped, and bounded, before it reaches the subject or the reason."""
    from messagefoundry.store.row_seal import SealPager, seal_row_ref, unverifiable_subject

    seen: list[str] = []

    def strict(subject: str, reason: str) -> None:
        subject.encode("ascii")
        reason.encode("ascii")
        seen.append(subject)

    pager = SealPager()
    pager.arm(strict)
    ref = seal_row_ref("user", planted)
    pager.unverifiable("user", planted, f"synthetic ({ref})")
    assert seen == [unverifiable_subject("user", planted)]
    assert ref.isascii() and ref.isprintable()
    assert len(seal_row_ref("user", "u" * 500)) <= 64


def test_a_named_page_the_sink_refuses_falls_back_to_the_shared_subject() -> None:
    """A named Unverifiable page the hook raises on still pages, under ``<prefix>:*``, so a planted
    row cannot suppress its own page; no named slot is spent."""
    from messagefoundry.store.row_seal import UNVERIFIABLE_SUBJECT_PREFIX, SealPager

    seen: list[str] = []

    def refuses_named(subject: str, reason: str) -> None:
        if not subject.endswith(":*"):
            raise UnicodeEncodeError("ascii", subject, 0, 1, "synthetic sink refusal")
        seen.append(subject)

    pager = SealPager()
    pager.arm(refuses_named)
    pager.unverifiable("user", "u-1", "synthetic")
    assert seen == [f"{UNVERIFIABLE_SUBJECT_PREFIX}:*"]


async def test_the_skipped_raise_count_is_logged_after_the_commit(tmp_path: Path) -> None:
    """``log_skipped``'s "every session is still ended" is logged once the revoke has committed."""
    store = await MessageStore.open(
        tmp_path / "skipped.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    backend = FakeBackend()
    try:
        store._row_sealer = TransitRowSealer(backend)
        for user in ("u-1", "u-2", "u-3"):
            await _user(store, user)
            await _session(store, user)
        store._row_sealer = TransitRowSealer(backend)  # nothing cached: the raises meet Transit
        in_txn: list[bool] = []
        log_skipped = RevokeSealOutcome.log_skipped

        def watched(self: RevokeSealOutcome) -> None:
            if self.skipped:
                in_txn.append(bool(store._db.in_transaction))
            log_skipped(self)

        RevokeSealOutcome.log_skipped = watched  # type: ignore[method-assign]
        backend.down = True
        try:
            await store.revoke_all_sessions()
        finally:
            backend.down = False
            RevokeSealOutcome.log_skipped = log_skipped  # type: ignore[method-assign]
        assert in_txn == [False]
    finally:
        await store.close()


# --- decision d20261110T042322305-2ffc60: a failed revoke still reports what it held ------------


def _forged_kept_session(monkeypatch: pytest.MonkeyPatch, store: MessageStore) -> None:
    """The kept session's re-stamp meets a Forged seal, which raises and rolls the revoke back."""

    async def forged(*_args: Any, **_kwargs: Any) -> Any:
        raise RowSealError("session", "")

    monkeypatch.setattr(store, "_write_session", forged)


@pytest.mark.parametrize("audit_up", [True, False], ids=["audit_up", "audit_refused"])
async def test_a_revoke_that_fails_audits_and_pages_its_held_refusals(
    transit: tuple[MessageStore, FakeBackend, Path],
    pages: list[str],
    monkeypatch: pytest.MonkeyPatch,
    audit_up: bool,
) -> None:
    """An Unverifiable account the revoke held, then a Forged kept session that rolls the revoke
    back: the held refusal is still audited and paged, with text that says the revoke failed, and
    the revoke's own exception propagates, whether or not the audit write is refused."""
    store, _, path = transit
    await _user(store, "u-1")
    kept = await _session(store, "u-1")
    await _session(store, "u-1")
    _plant(path, "users", "authz_seal", "id", "u-1")
    _forged_kept_session(monkeypatch, store)
    if not audit_up:

        async def refused(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("synthetic audit refusal")

        monkeypatch.setattr(store, "record_audit", refused)
    with pytest.raises(RowSealError):
        await store.revoke_user_sessions("u-1", except_token_hash=hash_token(kept))
    assert _live(path, "u-1") == 2  # rolled back
    assert len(pages) == 1
    assert "failed before its commit was confirmed" in pages[0]
    assert "ended the sessions anyway" not in pages[0]
    monkeypatch.undo()
    rows = await _audits(store, "integrity.authority_seal_unverifiable")
    if audit_up:
        (detail,) = rows
        assert detail["user_id"] == "u-1" and detail["committed"] is False
    else:
        assert rows == []


async def test_a_refusal_is_logged_only_after_the_outcome_is_known(
    transit: tuple[MessageStore, FakeBackend, Path], pages: list[str]
) -> None:
    """``refused``'s line is written after the commit, with the committed wording; while the
    writer transaction is open, nothing claims the revoke ended the sessions."""
    import logging

    store, _, path = transit
    await _user(store, "u-1")
    await _session(store, "u-1")
    _plant(path, "users", "authz_seal", "id", "u-1")
    seen: list[tuple[bool, str]] = []

    class _Watch(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append((bool(store._db.in_transaction), record.getMessage()))

    logger = logging.getLogger("messagefoundry.store.store")
    handler = _Watch(level=logging.WARNING)
    logger.addHandler(handler)
    try:
        await store.revoke_user_sessions("u-1")
    finally:
        logger.removeHandler(handler)
    refused = [(in_txn, m) for in_txn, m in seen if "was refused" in m]
    assert refused == [
        (
            False,
            "an account's session epoch raise was refused (RowSealUnverifiableError); the"
            " revoke ended the sessions anyway",
        )
    ]
