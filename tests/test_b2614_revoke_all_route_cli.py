# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``DELETE /sessions`` and ``messagefoundry admin-revoke-sessions`` end every session (BACKLOG #2614).

The route takes ``users:manage``, the per-account revoke's permission, behind a single-use proof
bound to ``revoke_all_sessions``: a login-seeded window is not enough, nor is a grant minted for
another action. It keeps the caller's own session. The CLI command is the same act from the host,
for when the API is not trusted, on admin-unlock's gate. Both write an ``auth.session_revoked``
row with scope and count.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.__main__ import main
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import (
    STEP_UP_ACTION_REVOKE_ALL_SESSIONS,
    STEP_UP_ACTION_SESSION_TERMINATE,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore, OperatorAudit, RevokeResult, no_audit_row
from tests._admin_account import create_local_user_chosen
from tests._phi_gate_provisions import setenv_at_rest_opt_out
from tests.test_api_auth import PW, _clear_must_change
from tests.test_b2614_restore_record import _revoked
from tests.test_b2614_revoke_all import _sqlite_raw


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "b2614_route.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(
            login_rate_limit_enabled=False, admin_write_min_interval_seconds=0, require_mfa=False
        ),
    )
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 123))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _local(service: AuthService, username: str, role: Role) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="test",
    )
    await _clear_must_change(service, user_id)


async def _login(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def _reauth(c: httpx.AsyncClient, token: str, purpose: str) -> str:
    r = await c.post("/me/reauth", json={"password": PW, "purpose": purpose}, headers=_auth(token))
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def _alive(c: httpx.AsyncClient, token: str) -> bool:
    return (await c.get("/auth/me", headers=_auth(token))).status_code == 200


async def test_the_route_ends_every_session_but_the_callers(engine: Engine) -> None:
    service = await _service(engine)
    await _local(service, "root", Role.ADMINISTRATOR)
    await _local(service, "ops", Role.OPERATOR)
    async with _client(engine, service) as c:
        root = await _login(c, "root")
        root_elsewhere = await _login(c, "root")
        ops = await _login(c, "ops")

        # Only the login window: refused, with the action named so the console can mint it.
        r = await c.delete("/sessions", headers=_auth(root))
        assert r.status_code == 403, r.text
        assert r.headers.get("X-Step-Up-Action") == STEP_UP_ACTION_REVOKE_ALL_SESSIONS
        # A grant minted for ending one's own other sessions is not this grant.
        root = await _reauth(c, root, STEP_UP_ACTION_SESSION_TERMINATE)
        r = await c.delete("/sessions", headers=_auth(root))
        assert r.status_code == 403, r.text
        assert await _alive(c, ops) and await _alive(c, root_elsewhere)  # nothing ended yet

        root = await _reauth(c, root, STEP_UP_ACTION_REVOKE_ALL_SESSIONS)
        r = await c.delete("/sessions", headers=_auth(root))
        assert r.status_code == 200, r.text
        assert "this session was kept" in r.json()["detail"]
        assert not await _alive(c, ops)
        assert not await _alive(c, root_elsewhere)
        assert await _alive(c, root)

        # The grant was single-use: a second call needs a new proof.
        r = await c.delete("/sessions", headers=_auth(root))
        assert r.status_code == 403, r.text

    rows = await engine.store.list_audit(action="auth.session_revoked", limit=10)
    details = [json.loads(row["detail"]) for row in rows]
    assert {"scope": "all_but_caller", "count": 2} in details
    assert any(row["actor"] == "root" for row in rows)


async def test_the_route_refuses_a_caller_without_users_manage(engine: Engine) -> None:
    service = await _service(engine)
    await _local(service, "ops", Role.OPERATOR)
    await _local(service, "root", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        root = await _login(c, "root")
        ops = await _login(c, "ops")
        ops = await _reauth(c, ops, STEP_UP_ACTION_REVOKE_ALL_SESSIONS)
        r = await c.delete("/sessions", headers=_auth(ops))
        assert r.status_code == 403, r.text
        assert "X-Step-Up-Action" not in r.headers  # the permission refusal, not the proof's
        assert await _alive(c, root)


async def test_a_kept_session_that_fails_its_seal_is_counted_with_the_rest(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A kept session whose seal fails makes the store write nothing, so the service ends every
    session, the caller's own included. The count in the reply and the audit row must include that
    session: ended first by the seal-failure handler, the sweep found it gone and both were one
    short. The seal failure is injected at the store's keep-one revoke, the call that raises it."""
    from messagefoundry.store.row_seal import SESSION_KIND, RowSealError

    service = await _service(engine)
    await _local(service, "root", Role.ADMINISTRATOR)
    await _local(service, "ops", Role.OPERATOR)
    async with _client(engine, service) as c:
        root = await _login(c, "root")
        await _login(c, "root")
        await _login(c, "ops")

    store = engine.store
    real = store.revoke_all_sessions

    async def _refuse_the_keep(
        *, except_token_hash: str | None = None, now: float | None = None
    ) -> RevokeResult:
        if except_token_hash is not None:
            raise RowSealError(SESSION_KIND)
        return await real(now=now)

    monkeypatch.setattr(store, "revoke_all_sessions", _refuse_the_keep)
    revoked, kept = await service.revoke_every_session(
        actor="root", keep_token_hash=hash_token(root)
    )
    assert (revoked, kept) == (3, False)
    rows = await store.list_audit(action="auth.session_revoked", limit=10)
    assert [json.loads(row["detail"]) for row in rows] == [{"scope": "all", "count": 3}]
    row = await store.get_session(hash_token(root))
    assert row is not None and row.revoked_at is not None


async def _miss(store: MessageStore, db: Path, token_hash: str) -> str:
    """Leave the session ``token_hash`` names where an earlier per-account sweep's miss leaves
    it, and return its account. It has already passed the gate, as a request that straddles that
    sweep's commit has."""
    snapshot = await store.get_session(token_hash)
    assert snapshot is not None and snapshot.revoked_at is None
    await store.revoke_user_sessions(snapshot.user_id, audit=no_audit_row)
    await _sqlite_raw(db)(
        "UPDATE sessions SET revoked_at=NULL, seal=? WHERE token_hash=?",
        (snapshot.seal, token_hash),
    )
    return snapshot.user_id


async def test_a_caller_session_the_revoke_declines_is_ended_and_said_to_be(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Follow-up to BACKLOG #4975: the every-account revoke does not stamp a kept session an
    earlier sweep missed, and ends it in its own transaction. So the reply's "this session was
    ended too" is true, the count in the reply and the audit row includes it, and presenting the
    session afterwards is refused as ended, with no seal-failure alert. The control is the first
    test here, where the same call keeps it."""
    service = await _service(engine)
    await _local(service, "root", Role.ADMINISTRATOR)
    await _local(service, "ops", Role.OPERATOR)
    store = engine.store
    assert isinstance(store, MessageStore)
    db = tmp_path / "b2614_route.db"
    real = store.revoke_all_sessions
    live: list[int] = []

    async def _missed_first(
        *, except_token_hash: str | None = None, now: float | None = None
    ) -> RevokeResult:
        if except_token_hash is not None:
            await _miss(store, db, except_token_hash)
            conn = sqlite3.connect(db)
            try:
                live.append(
                    conn.execute(
                        "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL"
                    ).fetchone()[0]
                )
            finally:
                conn.close()
        return await real(except_token_hash=except_token_hash, now=now)

    async with _client(engine, service) as c:
        root = await _login(c, "root")
        ops = await _login(c, "ops")
        root = await _reauth(c, root, STEP_UP_ACTION_REVOKE_ALL_SESSIONS)
        monkeypatch.setattr(store, "revoke_all_sessions", _missed_first)
        r = await c.delete("/sessions", headers=_auth(root))
        assert r.status_code == 200, r.text
        assert live and live[0] >= 2  # the caller's row and ops', both unrevoked at the revoke
        assert r.json()["detail"] == (
            f"ended {live[0]} unrevoked session row(s), expired ones included; "
            "this session was ended too"
        )
        # Read before anything presents the token: the gate would end a live one it refuses.
        assert await _revoked(store, root)  # ended by the revoke itself
        assert not await _alive(c, root)
        assert not await _alive(c, ops)
    rows = await store.list_audit(action="auth.session_revoked", limit=1)
    assert json.loads(rows[0]["detail"]) == {"scope": "all", "count": live[0]}
    assert not await store.list_audit(action="integrity.authority_seal_failed", limit=1)


async def test_signing_out_elsewhere_from_a_declined_session_counts_the_others_only(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Follow-up to BACKLOG #4975: signing out everywhere else from a session an earlier sweep
    missed ends that session too, in the revoke's own transaction. The reply still counts the
    other sessions only, so it stays true, and the audit row says the caller's own ended. Presenting
    that session afterwards is refused as ended, with no seal-failure alert."""
    service = await _service(engine)
    await _local(service, "root", Role.ADMINISTRATOR)
    store = engine.store
    assert isinstance(store, MessageStore)
    db = tmp_path / "b2614_route.db"
    real = store.revoke_user_sessions

    async def _missed_first(
        user_id: str,
        *,
        except_token_hash: str | None = None,
        now: float | None = None,
        audit: OperatorAudit[RevokeResult],
    ) -> RevokeResult:
        if except_token_hash is not None:
            await _miss(store, db, except_token_hash)
            # One other session, minted after the sweep, so it is current: the revoke ends it.
            await store.create_session(
                token_hash=hash_token(mint_token()), user_id=user_id, expires_at=4_000_000_000.0
            )
        return await real(user_id, except_token_hash=except_token_hash, now=now, audit=audit)

    async with _client(engine, service) as c:
        root = await _login(c, "root")
        root = await _reauth(c, root, STEP_UP_ACTION_SESSION_TERMINATE)
        monkeypatch.setattr(store, "revoke_user_sessions", _missed_first)
        r = await c.delete("/me/sessions", headers=_auth(root))
        assert r.status_code == 200, r.text
        assert r.json()["detail"] == "signed out 1 other session(s)"
        assert await _revoked(store, root)  # ended by the revoke, before the gate saw it
        assert not await _alive(c, root)
    rows = await store.list_audit(action="auth.session_revoked", limit=1)
    assert json.loads(rows[0]["detail"]) == {"scope": "self_all", "count": 1}
    assert not await store.list_audit(action="integrity.authority_seal_failed", limit=1)


async def _seed(db: Path) -> list[str]:
    store = await MessageStore.open(db)
    try:
        tokens = []
        for user_id in ("cli-a", "cli-b"):
            await store.create_user(
                user_id=user_id,
                username=user_id,
                auth_provider="local",
                display_name=None,
                email=None,
                password_hash="h",
                now=0.0,
                password_generated=False,
                audits=(),
            )
            token = mint_token()
            await store.create_session(
                token_hash=hash_token(token),
                user_id=user_id,
                expires_at=4_000_000_000.0,
                client="192.0.2.10",
                auth_mechanism="password",
            )
            tokens.append(token)
        return tokens
    finally:
        await store.close()


async def _state(db: Path, tokens: list[str]) -> tuple[list[bool], list[dict[str, object]]]:
    store = await MessageStore.open(db)
    try:
        revoked = []
        for token in tokens:
            row = await store.get_session(hash_token(token))
            revoked.append(row is not None and row.revoked_at is not None)
        audits = await store.list_audit(action="auth.session_revoked", limit=10)
        return revoked, [dict(a) for a in audits]
    finally:
        await store.close()


def test_the_cli_command_ends_every_session_and_audits_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)  # a keyless store, as the admin-unlock tests use
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))
    assert asyncio.run(_state(db, tokens))[0] == [False, False]  # control

    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "revoked": 2}
    revoked, audits = asyncio.run(_state(db, tokens))
    assert revoked == [True, True]
    assert len(audits) == 1
    assert json.loads(str(audits[0]["detail"])) == {"scope": "all", "count": 2}
    assert str(audits[0]["actor"]).startswith("cli:")


def test_the_cli_command_refuses_a_missing_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "nope.db"
    assert main(["admin-revoke-sessions", "--db", str(missing), "--json"]) == 2
    assert "refusing to create one" in json.loads(capsys.readouterr().out)["error"]
    assert not missing.exists()


# --- BACKLOG #5093: a revoke whose link to the store failed is reported as unknown ---------------


class _LinkLost(RuntimeError):
    """A stand-in for a server driver's lost-connection error: asyncpg's carry a ``sqlstate``
    attribute, and class 08 is a connection exception. A ``RuntimeError``, so it is one of
    ``store_call_errors()`` with no server driver installed."""

    sqlstate = "08006"


@pytest.mark.parametrize(
    "lost",
    [lambda: OSError("connection reset by peer"), _LinkLost],
    ids=["OSError", "sqlstate-08"],
)
@pytest.mark.parametrize("committed", [True, False], ids=["after-commit", "before-commit"])
def test_a_link_lost_during_the_revoke_reads_as_unknown_and_is_recorded(
    lost: Callable[[], Exception],
    committed: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A link that fails during the revoke may fail after the server applied the COMMIT, so the
    command says the outcome is unknown, never "nothing was revoked", and its row records the
    attempt. The after-commit arm is the case the old text misreported: the sessions ended."""
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))
    revoke = MessageStore.revoke_all_sessions

    async def losing(self: MessageStore, **kwargs: object) -> RevokeResult:
        if committed:
            await revoke(self)
        raise lost()  # a fresh instance per case, so no traceback is shared between them

    monkeypatch.setattr(MessageStore, "revoke_all_sessions", losing)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert "whether it took effect is unknown" in error, error
    assert "nothing was revoked" not in error, error
    assert "records the attempt" in error and "Re-run the command" in error, error
    revoked, audits = asyncio.run(_state(db, tokens))
    assert revoked == [committed, committed]
    assert len(audits) == 1
    assert json.loads(str(audits[0]["detail"])) == {
        "scope": "all",
        "count": None,
        "outcome": "unknown",
    }
    assert str(audits[0]["actor"]).startswith("cli:")


def test_a_rollback_error_that_masks_a_lost_commit_reads_as_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A backend that rolls back in an ``except`` block and re-raises loses the COMMIT's lost
    link to the rollback's own error on the dead connection, which carries it only as its
    implicit context. That is still an unknown outcome, never "nothing was revoked"; the sessions did end here."""
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))
    revoke = MessageStore.revoke_all_sessions

    async def masked(self: MessageStore, **kwargs: object) -> RevokeResult:
        await revoke(self)
        try:
            raise _LinkLost()  # the COMMIT's lost link
        except _LinkLost:
            # The implicit context is the case under test.
            raise sqlite3.OperationalError("cannot rollback: the connection is closed")  # noqa: B904

    monkeypatch.setattr(MessageStore, "revoke_all_sessions", masked)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert "whether it took effect is unknown" in error, error
    assert "nothing was revoked" not in error, error
    revoked, audits = asyncio.run(_state(db, tokens))
    assert revoked == [True, True] and len(audits) == 1


def test_a_pool_timeout_raised_from_a_timeout_error_stays_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The pool's ``StoreAcquireTimeout`` is raised ``from`` a ``TimeoutError``, an OSError, before
    any transaction began. An explicit cause is not followed, so it stays "nothing was revoked"
    and writes no row."""
    from messagefoundry.store.base import StoreAcquireTimeout

    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))

    async def borrow_timed_out(self: MessageStore, **kwargs: object) -> RevokeResult:
        try:
            raise TimeoutError
        except TimeoutError as exc:
            raise StoreAcquireTimeout("store pool acquire timed out after 5s") from exc

    monkeypatch.setattr(MessageStore, "revoke_all_sessions", borrow_timed_out)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert error.startswith("nothing was revoked: ") and "unknown" not in error, error
    assert asyncio.run(_state(db, tokens)) == ([False, False], [])


def test_a_pyodbc_rollback_error_over_a_lost_commit_reads_as_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """SQL Server's shape of the masked commit: the COMMIT's link fails with 08S01, and the
    rollback on the dead connection raises pyodbc's bare ``Error`` root, HY000, carrying the 08S01
    only as its context. The sessions ended, so the outcome is unknown and the row records it,
    not the defect a bare root otherwise reports. pyodbc is not installed on every leg, so the
    stand-ins the transit-bound tests use take its place."""
    from messagefoundry.store.base import store_call_errors
    from tests.test_keyless_chain_every_command import _PyodbcError, _ServerDriverError
    from tests.test_transit_bound_attestation import _stand_in_server_drivers

    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))
    # Warmed before the stand-ins: the tuple is cached, and a first call under them would
    # keep the stand-in in it for every later test on this worker.
    store_call_errors()
    _stand_in_server_drivers(monkeypatch)
    revoke = MessageStore.revoke_all_sessions

    async def masked(self: MessageStore, **kwargs: object) -> RevokeResult:
        await revoke(self)
        try:
            raise _ServerDriverError("08S01", "[08S01] link failure (10054) (SQLEndTran)")
        except _ServerDriverError:
            raise _PyodbcError("HY000", "[HY000] connection is busy (0) (SQLEndTran)")  # noqa: B904

    monkeypatch.setattr(MessageStore, "revoke_all_sessions", masked)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert "whether it took effect is unknown" in error, error
    assert "_StoreDefect" not in error, error
    revoked, audits = asyncio.run(_state(db, tokens))
    assert revoked == [True, True] and len(audits) == 1
    assert json.loads(str(audits[0]["detail"]))["outcome"] == "unknown"


@pytest.mark.parametrize(
    ("sqlstate", "defect"), [("07002", True), ("40001", False)], ids=["bind-count", "deadlock"]
)
def test_a_bare_pyodbc_root_is_a_defect_unless_its_state_is_transient(
    sqlstate: str,
    defect: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The pyodbc-root arm with no lost link: a bind-count mismatch is a defect the dispatch floor
    reports by class and SQLSTATE, and a deadlock victim is a refusal that rolled back."""
    from messagefoundry.store.base import store_call_errors
    from tests.test_keyless_chain_every_command import _PyodbcError
    from tests.test_transit_bound_attestation import _stand_in_server_drivers

    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))
    # Warmed before the stand-ins: the tuple is cached, and a first call under them would
    # keep the stand-in in it for every later test on this worker.
    store_call_errors()
    _stand_in_server_drivers(monkeypatch)

    async def refused(self: MessageStore, **kwargs: object) -> RevokeResult:
        raise _PyodbcError(sqlstate, f"[{sqlstate}] refused (0) (SQLExecDirectW)")

    monkeypatch.setattr(MessageStore, "revoke_all_sessions", refused)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    if defect:
        assert error.startswith("_StoreDefect: ") and f"SQLSTATE {sqlstate}" in error, error
    else:
        assert error.startswith("nothing was revoked: ") and "unknown" not in error, error
    assert asyncio.run(_state(db, tokens)) == ([False, False], [])


def test_a_suppressed_context_is_not_read_as_a_lost_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: a refusal raised ``from None`` names its context irrelevant, so a lost link
    there does not make the outcome unknown."""
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))

    async def suppressed(self: MessageStore, **kwargs: object) -> RevokeResult:
        try:
            raise _LinkLost()
        except _LinkLost:
            raise sqlite3.OperationalError("database is locked") from None

    monkeypatch.setattr(MessageStore, "revoke_all_sessions", suppressed)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert error.startswith("nothing was revoked: "), error
    assert asyncio.run(_state(db, tokens)) == ([False, False], [])


def test_an_unknown_outcome_whose_row_is_refused_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """When the row that would record an unknown outcome is refused too, the command says to
    record the attempt by hand rather than claim a row it did not write."""
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))
    record = MessageStore.record_audit

    async def losing(self: MessageStore, **kwargs: object) -> RevokeResult:
        raise OSError("connection reset by peer")

    async def refusing(self: MessageStore, action: str, **kwargs: Any) -> Any:
        if action == "auth.session_revoked":
            raise OSError("connection reset by peer")
        return await record(self, action, **kwargs)

    monkeypatch.setattr(MessageStore, "revoke_all_sessions", losing)
    monkeypatch.setattr(MessageStore, "record_audit", refusing)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert "whether it took effect is unknown" in error, error
    assert "could not be written either" in error and "record the attempt by hand" in error
    assert "records the attempt" not in error, error
    assert asyncio.run(_state(db, tokens)) == ([False, False], [])


def test_a_refused_revoke_still_says_nothing_was_revoked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: a refusal that is not a lost link rolled the revoke back, so the command says
    nothing was revoked and writes no row."""
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))

    async def busy(self: MessageStore, **kwargs: object) -> RevokeResult:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(MessageStore, "revoke_all_sessions", busy)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert error.startswith("nothing was revoked: ") and "unknown" not in error, error
    assert error.endswith(
        "Retry; if the engine is running on this SQLite store, stop it and re-run"
    )
    assert asyncio.run(_state(db, tokens)) == ([False, False], [])


def test_a_refusal_that_is_not_a_lock_gets_no_stop_the_engine_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control for the hint: only a lock is fixed by stopping a SQLite engine."""
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    asyncio.run(_seed(db))

    async def refused(self: MessageStore, **kwargs: object) -> RevokeResult:
        raise sqlite3.OperationalError("disk is full")

    monkeypatch.setattr(MessageStore, "revoke_all_sessions", refused)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert error.startswith("nothing was revoked: ") and error.endswith("Retry"), error


def test_an_os_user_that_cannot_be_named_revokes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The OS user is named before the store opens, as admin-unlock names it, so a shell that
    cannot name it ends no session it would then fail to record."""
    import getpass

    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))

    def nobody() -> str:
        raise OSError("no such user")

    monkeypatch.setattr(getpass, "getuser", nobody)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert error.startswith("cannot name the OS user") and "nothing was revoked" in error, error
    assert asyncio.run(_state(db, tokens)) == ([False, False], [])


def test_a_close_that_fails_after_the_revoke_still_reports_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A close that fails once the revoke and its row have committed warns, and the command still
    reports the revoke it made."""
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))
    close = MessageStore.close

    async def failing_close(self: MessageStore) -> None:
        await close(self)
        raise OSError("close failed")

    monkeypatch.setattr(MessageStore, "close", failing_close)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"ok": True, "revoked": 2}
    assert "closing the store failed (OSError)" in captured.err
    monkeypatch.setattr(MessageStore, "close", close)
    revoked, audits = asyncio.run(_state(db, tokens))
    assert revoked == [True, True] and len(audits) == 1


def test_a_transit_refusal_of_the_row_after_the_revoke_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A row refused after the revoke committed by an error outside ``store_call_errors()``, here
    the ``CipherError`` a vault_transit store raises when it cannot compute the chain's MAC, is
    still reported as the command's own refusal: the sessions are ended, record the act by hand."""
    from messagefoundry.store.crypto import CipherError

    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    tokens = asyncio.run(_seed(db))
    record = MessageStore.record_audit

    async def refusing(self: MessageStore, action: str, **kwargs: Any) -> Any:
        if action == "auth.session_revoked":
            raise CipherError("transit unreachable")
        return await record(self, action, **kwargs)

    monkeypatch.setattr(MessageStore, "record_audit", refusing)
    assert main(["admin-revoke-sessions", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert error.startswith("ended 2 unrevoked session row(s), but the audit row could not be")
    assert "record the act by hand" in error, error
    assert asyncio.run(_state(db, tokens)) == ([True, True], [])


def test_the_cli_text_says_what_the_count_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5095 step 2: the count is the unrevoked rows the sweep ended, an expired one never
    purged among them, so the text says so; the global epoch is what ends every other session."""
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "cli.db"
    asyncio.run(_seed(db))

    async def expired_row() -> None:
        store = await MessageStore.open(db)
        try:
            await store.create_session(
                token_hash=hash_token(mint_token()),
                user_id="cli-a",
                expires_at=1.0,  # long expired, and never purged
                client="192.0.2.10",
                auth_mechanism="password",
            )
        finally:
            await store.close()

    asyncio.run(expired_row())
    assert main(["admin-revoke-sessions", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    # Two live sessions and the expired row: the count is every unrevoked row the sweep ended.
    assert out.startswith("OK: ended 3 unrevoked session row(s), expired ones included"), out
    assert "raised the global session epoch" in out, out


_ROOT = Path(__file__).resolve().parents[1]

#: BACKLOG #5095 step 3: phrases the every-account revoke's texts no longer say, by file. Each
#: claimed more than the code does, at least where an account's record fails its seal check, a
#: count holds expired rows, the audit row follows the commit, or the step-up is turned off.
_RETRACTED = {
    "messagefoundry/__main__.py": (
        "The engine may be running or stopped.",
        "OK: revoked {revoked} session(s); every signed-in user must sign in again",
    ),
    "messagefoundry/api/auth_routes.py": ("Audited, with the count, even when nothing was live.",),
    "messagefoundry/api/app.py": ("and raises every account's epoch.",),
    "messagefoundry/store/store.py": (
        "then every account's epoch, as :meth:`revoke_user_sessions` raises one",
        "The first start still raises every account's session epoch",
    ),
    "messagefoundry/pipeline/dr_backup.py": ("open session(s)",),
    "docs/SECURITY.md": ("or ending every session (BACKLOG #2614)",),
}


def _flat(path: str) -> str:
    """The file's text with every run of whitespace as one space, so a phrase a re-wrap split
    across lines is still found."""
    return " ".join((_ROOT / path).read_text("utf-8").split())


@pytest.mark.parametrize("path", sorted(_RETRACTED))
def test_the_retracted_revoke_all_phrases_stay_out(path: str) -> None:
    text = _flat(path)
    assert text  # the control: the file was read
    for phrase in _RETRACTED[path]:
        assert phrase not in text, f"{path} says {phrase!r} again"


def test_the_store_contract_states_the_transaction_and_reseal_rules() -> None:
    """BACKLOG #5095 step 3, its second half: ``AuthStore.revoke_all_sessions`` states that the
    raises, the sweep and the kept session's re-seal are one transaction, and that a refused
    re-seal or a missing global epoch rolls it back."""
    text = _flat("messagefoundry/store/base.py")
    contract = text[text.index("async def revoke_all_sessions(") :]
    contract = contract[: contract.index("async def consume_restore_record(")]
    for rule in (
        "In one transaction it raises the store's global session epoch",
        "re-seals the kept session under its account's new epoch and the new global one",
        "(an account whose raise a seal refusal stops goes without it, and so does every account "
        "after a Vault Transit outage trips the revoke",
        "either way the transaction rolls back",
    ):
        assert rule in contract, rule
