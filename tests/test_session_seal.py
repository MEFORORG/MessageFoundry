# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Session-row integrity seals on SQLite, and the static guards that keep them whole (BACKLOG #2592).

The behavioural contract is ``tests/_session_seal_contract.py``; the Postgres and SQL Server suites
run the same one on their own legs. This file runs it on SQLite, and adds what only one place needs
to hold: the list of columns a seal leaves out, the single reader in the service, the list of every
statement that writes a session row, and the denial's audit row and alert. It also drives the MFA
verify leg with the store refusing a session stamp for its seal, which must end the session.
"""

from __future__ import annotations

import ast
import pathlib
import sqlite3
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth import totp
from messagefoundry.auth.service import AUTHORITY_SEAL_FAILED_ACTION, AuthService, Elevation
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import (
    SESSION_SEAL_EXCLUDED,
    MessageStore,
    SessionRecord,
    session_seal_ok,
)
from tests._admin_account import ADMIN_USERNAME, login_admin
from tests._session_seal_contract import (
    assert_session_columns,
    assert_session_seal_contract,
    dollar_placeholders,
)
from tests._totp_clock import pin_totp_clock

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_STORE_DIR = _ROOT / "messagefoundry" / "store"


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, Path]]:
    path = tmp_path / "sealed.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        yield store, path
    finally:
        await store.close()


def _raw_for(path: Path) -> Any:
    """Runs one statement on its own stdlib connection, which holds no store key."""

    async def raw(sql: str, params: tuple[Any, ...]) -> None:
        conn = sqlite3.connect(path)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    return raw


async def test_the_session_seal_contract_holds_on_sqlite(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, path = keyed
    await assert_session_seal_contract(store, _raw_for(path))


async def test_the_contract_fails_when_the_service_checks_no_seal(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the contract: with the service's seal check switched off it must fail, so
    a green contract is evidence that the check runs."""
    import messagefoundry.auth.service as service_module

    store, path = keyed
    monkeypatch.setattr(service_module, "session_seal_ok", lambda sealer, record: True)
    with pytest.raises(AssertionError):
        await assert_session_seal_contract(store, _raw_for(path))


def test_the_columns_a_session_seal_leaves_out_are_pinned() -> None:
    # A change here is a decision about what a writer may alter unseen; it needs a reason beside it.
    assert dict(SESSION_SEAL_EXCLUDED).keys() == {"last_used_at", "seal"}
    assert all(reason for reason in SESSION_SEAL_EXCLUDED.values())


def test_a_session_seal_covers_every_other_field_by_default() -> None:
    record = SessionRecord(
        token_hash="t",
        user_id="u",
        created_at=1.0,
        expires_at=2.0,
        last_used_at=1.0,
        revoked_at=None,
        client=None,
    )
    covered = [name for name, _ in record.seal_fields()]
    expected = [f.name for f in fields(SessionRecord) if f.name not in SESSION_SEAL_EXCLUDED]
    assert covered == expected
    assert "user_id" in covered and "user_epoch" in covered and "token_hash" in covered


async def test_the_session_record_matches_the_sessions_table(
    keyed: tuple[MessageStore, Path],
) -> None:
    _, path = keyed
    conn = sqlite3.connect(path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
    finally:
        conn.close()
    assert_session_columns(columns)
    assert dollar_placeholders("a=? AND b=?") == "a=$1 AND b=$2"


async def test_a_key_rotation_ends_every_session(tmp_path: Path) -> None:
    """A session seal verifies only under the active key's root, so ``rotate-key``'s re-encrypt
    pass ends every session rather than leave rows that would each be refused and alerted on."""
    old, new = generate_key(), generate_key()
    path = tmp_path / "rotated.db"
    store = await MessageStore.open(path, cipher=make_cipher(old, write_v2=True))
    try:
        await store.create_user(
            user_id="u", username="u", auth_provider="local", password_generated=False
        )
        token = mint_token()
        await store.create_session(
            token_hash=hash_token(token), user_id="u", expires_at=time.time() + 3600
        )
    finally:
        await store.close()
    rotated = await MessageStore.open(path, cipher=make_cipher(new, [old], write_v2=True))
    try:
        assert await rotated.get_session(hash_token(token)) is not None  # control: still there
        await rotated.reencrypt_to_active()
        assert await rotated.get_session(hash_token(token)) is None
    finally:
        await rotated.close()


async def test_a_session_sealed_under_a_retired_key_ends_without_an_alert(tmp_path: Path) -> None:
    """A key change without ``rotate-key`` leaves rows a retired key genuinely sealed. They are
    refused and ended, but they are a key change, not an integrity failure, so nothing alerts. The
    control: a row changed outside the store under the same retired key still alerts."""
    old, new = generate_key(), generate_key()
    path = tmp_path / "rekeyed.db"
    store = await MessageStore.open(path, cipher=make_cipher(old, write_v2=True))
    try:
        await store.create_user(
            user_id="u", username="u", auth_provider="local", password_generated=False
        )
        stale, bent = mint_token(), mint_token()
        for token in (stale, bent):
            await store.create_session(
                token_hash=hash_token(token), user_id="u", expires_at=time.time() + 3600
            )
    finally:
        await store.close()
    await _raw_for(path)(
        "UPDATE sessions SET client=? WHERE token_hash=?", ("192.0.2.8", hash_token(bent))
    )
    rekeyed = await MessageStore.open(path, cipher=make_cipher(new, [old], write_v2=True))
    try:
        alerts: list[str] = []
        service = AuthService(rekeyed, AuthSettings(), integrity_alert=alerts.append)
        assert await service.identity_for_token(stale) is None
        assert alerts == []
        row = await rekeyed.get_session(hash_token(stale))
        assert row is not None and row.revoked_at is not None
        assert await service.identity_for_token(bent) is None
        assert len(alerts) == 1
    finally:
        await rekeyed.close()


async def test_the_inventory_hides_a_session_from_an_older_epoch(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, path = keyed
    service = AuthService(store, AuthSettings())
    await store.create_user(
        user_id="u", username="u", auth_provider="local", password_generated=False
    )
    token = mint_token()
    await store.create_session(
        token_hash=hash_token(token), user_id="u", expires_at=time.time() + 3600
    )
    assert [s.token_hash for s in await service.list_sessions("u")] == [hash_token(token)]
    await _raw_for(path)("UPDATE users SET session_epoch=session_epoch+1 WHERE id=?", ("u",))
    assert await service.list_sessions("u") == []
    assert await service.identity_for_token(token) is None


async def test_a_keyless_store_writes_no_seal_and_checks_none(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "plain.db")
    try:
        assert store.row_sealer() is None
        await store.create_user(
            user_id="u", username="u", auth_provider="local", password_generated=False
        )
        token = mint_token()
        await store.create_session(
            token_hash=hash_token(token), user_id="u", expires_at=time.time() + 3600
        )
        row = await store.get_session(hash_token(token))
        assert row is not None and row.seal == "" and session_seal_ok(None, row)
        assert await AuthService(store, AuthSettings()).identity_for_token(token) is not None
    finally:
        await store.close()


async def test_a_refused_session_is_audited_and_alerted_once_per_interval(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, path = keyed
    alerts: list[str] = []
    service = AuthService(store, AuthSettings(), integrity_alert=alerts.append)
    await store.create_user(
        user_id="u", username="u", auth_provider="local", password_generated=False
    )
    good = mint_token()
    await store.create_session(
        token_hash=hash_token(good), user_id="u", expires_at=time.time() + 3600
    )
    assert await service.identity_for_token(good) is not None
    assert alerts == []  # control: a sealed row raises nothing

    bad = mint_token()
    await store.create_session(
        token_hash=hash_token(bad), user_id="u", expires_at=time.time() + 3600
    )
    await _raw_for(path)(
        "UPDATE sessions SET client=? WHERE token_hash=?", ("192.0.2.5", hash_token(bad))
    )
    for _ in range(3):
        assert await service.identity_for_token(bad) is None
    assert len(alerts) == 1 and hash_token(bad)[:12] in alerts[0]
    assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1
    # The listing drops the refused row and keeps the good one.
    listed = {s.token_hash for s in await service.list_sessions("u")}
    assert hash_token(good) in listed and hash_token(bad) not in listed


async def test_signing_out_elsewhere_ends_every_session_when_the_callers_own_fails(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, path = keyed
    service = AuthService(store, AuthSettings())
    await store.create_user(
        user_id="u", username="u", auth_provider="local", password_generated=False
    )
    tokens = [mint_token() for _ in range(3)]
    for token in tokens:
        await store.create_session(
            token_hash=hash_token(token), user_id="u", expires_at=time.time() + 3600
        )
    identity = await service.identity_for_token(tokens[0])
    assert identity is not None
    await _raw_for(path)(
        "UPDATE sessions SET reauth_at=? WHERE token_hash=?", (1.0, hash_token(tokens[0]))
    )
    await service.revoke_other_sessions(identity, hash_token(tokens[0]), actor="u")
    for token in tokens:
        row = await store.get_session(hash_token(token))
        assert row is not None and row.revoked_at is not None


async def test_signing_out_elsewhere_keeps_the_callers_own_session(
    keyed: tuple[MessageStore, Path],
) -> None:
    # Control for the test above: with the caller's row intact, only the others end.
    store, _ = keyed
    service = AuthService(store, AuthSettings())
    await store.create_user(
        user_id="u", username="u", auth_provider="local", password_generated=False
    )
    tokens = [mint_token() for _ in range(3)]
    for token in tokens:
        await store.create_session(
            token_hash=hash_token(token), user_id="u", expires_at=time.time() + 3600
        )
    identity = await service.identity_for_token(tokens[0])
    assert identity is not None
    assert await service.revoke_other_sessions(identity, hash_token(tokens[0]), actor="u") == 2
    assert await service.identity_for_token(tokens[0]) is not None
    assert all([await service.identity_for_token(t) is None for t in tokens[1:]])


# --- a refused stamp in the MFA verify leg ----------------------------------------------------


async def _pending_factor(
    service: AuthService, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, str, str]:
    """Enrol TOTP for a local administrator, sign in again so the new session owes its factor, and
    return ``(user id, that session's token, a code the verify will accept)``.

    The clock is pinned so the enrolment and the verify sit in different steps: enrolment spends
    the step it activates on (BACKLOG #1021)."""
    identity, token, password = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    t0 = 1_000_000.0
    pin_totp_clock(monkeypatch, t0)
    confirmed = await service.confirm_mfa_enrollment(
        identity, totp.totp(enroll.secret, now=t0), token=token
    )
    assert confirmed.ok
    out = await service.login(ADMIN_USERNAME, password)
    assert out.ok and out.mfa_required and out.token is not None
    t1 = t0 + totp.DEFAULT_PERIOD
    pin_totp_clock(monkeypatch, t1)
    return identity.user_id, out.token, totp.totp(enroll.secret, now=t1)


def _spy(
    calls: list[str],
    name: str,
    method: Callable[..., Awaitable[Any]],
    before: Callable[[], Awaitable[None]] | None,
) -> Callable[..., Awaitable[Any]]:
    """Wrap a store method to record its name, run ``before`` if given, then call the real one."""

    async def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(name)
        if before is not None:
            await before()
        return await method(*args, **kwargs)

    return spy


_WATCHED = ("mark_session_mfa_verified", "mark_session_reauthed", "record_login_success")
_COUNTED = ("auth.mfa_verified", "auth.mfa_failed", AUTHORITY_SEAL_FAILED_ACTION)


@dataclass
class _Run:
    """What one :func:`_verify` run did: the verify's answer, the store writes it asked for in
    order, the integrity alerts raised, and how many audit rows of each :data:`_COUNTED` action it
    added."""

    out: Elevation
    token: str
    user_id: str
    calls: list[str]
    alerts: list[str]
    added: dict[str, int]


async def _verify(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch, *, tamper: str | None
) -> _Run:
    """Run ``verify_mfa`` with a good code on a local session that owes its factor.

    With ``tamper`` naming one of the two session stamps, the session row is changed outside the
    store just before that stamp, so the store's own write helper refuses the stamp for its seal.
    That is the real refusal path, not an injected exception."""
    store, path = keyed
    alerts: list[str] = []
    service = AuthService(
        store, AuthSettings(mfa_verify_min_elapsed_seconds=0), integrity_alert=alerts.append
    )
    user_id, token, code = await _pending_factor(service, monkeypatch)

    async def tamper_row() -> None:
        await _raw_for(path)(
            "UPDATE sessions SET client=? WHERE token_hash=?", ("192.0.2.77", hash_token(token))
        )

    calls: list[str] = []
    for name in _WATCHED:
        before = tamper_row if name == tamper else None
        monkeypatch.setattr(store, name, _spy(calls, name, getattr(store, name), before))
    counts = {a: len(await store.list_audit(action=a)) for a in _COUNTED}

    out = await service.verify_mfa(token, code, client="192.0.2.9")

    added = {a: len(await store.list_audit(action=a)) - counts[a] for a in _COUNTED}
    return _Run(out, token, user_id, calls, alerts, added)


async def _assert_session_ended(keyed: tuple[MessageStore, Path], run: _Run) -> None:
    """The refused-stamp outcome (BACKLOG #2592): the session is gone, nothing records a success,
    and nothing is charged to the second-step counter."""
    store, _ = keyed
    assert run.out.session_lost and not run.out.ok and run.out.token is None
    row = await store.get_session(hash_token(run.token))
    assert row is not None and row.revoked_at is not None
    assert run.added == {
        "auth.mfa_verified": 0,
        "auth.mfa_failed": 0,
        AUTHORITY_SEAL_FAILED_ACTION: 1,
    }
    assert len(run.alerts) == 1 and hash_token(run.token)[:12] in run.alerts[0]
    assert "record_login_success" not in run.calls
    user = await store.get_user(run.user_id)
    assert user is not None and user.second_step_failed_attempts == 0


async def test_verify_mfa_ends_the_session_when_the_factor_stamp_is_refused(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    run = await _verify(keyed, monkeypatch, tamper="mark_session_mfa_verified")
    await _assert_session_ended(keyed, run)
    # The leg stops at the first refusal: the reauth stamp is never asked for.
    assert run.calls == ["mark_session_mfa_verified"]


async def test_verify_mfa_ends_the_session_when_the_reauth_stamp_is_refused(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    run = await _verify(keyed, monkeypatch, tamper="mark_session_reauthed")
    await _assert_session_ended(keyed, run)
    assert run.calls == ["mark_session_mfa_verified", "mark_session_reauthed"]


async def test_verify_mfa_succeeds_when_no_stamp_is_refused(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Control for the two tests above: the same flow and the same spies, with no row changed. It
    # also shows the session takes the non-OIDC branch, so the reauth test reaches its stamp.
    run = await _verify(keyed, monkeypatch, tamper=None)
    assert run.out.ok and not run.out.session_lost and run.out.token is not None
    assert run.calls == list(_WATCHED)
    assert run.added == {
        "auth.mfa_verified": 1,
        "auth.mfa_failed": 0,
        AUTHORITY_SEAL_FAILED_ACTION: 0,
    }
    assert run.alerts == []
    service = AuthService(keyed[0], AuthSettings())
    assert await service.mfa_satisfied(run.out.token) is True


# --- static guards --------------------------------------------------------------------------


def test_the_service_reads_sessions_through_one_loader() -> None:
    """``AuthService._load_session`` is the only reader of ``AuthStore.get_session``: a second
    reader would act on a row nobody checked."""
    tree = ast.parse((_ROOT / "messagefoundry" / "auth" / "service.py").read_text("utf-8"))
    owners: list[str] = []
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for node in ast.walk(func):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "get_session"
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "_store"
            ):
                owners.append(func.name)
    assert owners == ["_load_session"]
    # Control: the same walk finds the store's other session readers, so it is reading this file.
    assert "self._store.list_sessions(" in (_ROOT / "messagefoundry/auth/service.py").read_text(
        "utf-8"
    )


#: Where each backend may write a sealed session row: the sealed insert and the one re-seal.
_SEALING_STATEMENTS: dict[str, frozenset[str]] = {
    "store.py": frozenset({"_SESSION_INSERT", "_SESSION_RESEAL"}),
    "postgres.py": frozenset({"_PG_SESSION_INSERT", "_PG_SESSION_RESEAL"}),
    "sqlserver.py": frozenset({"_SESSION_INSERT", "_MSSQL_SESSION_RESEAL"}),
}
_SEALING_FUNCTIONS = frozenset({"create_session", "_write_session"})
_WRITE_PREFIXES = ("INSERT INTO SESSIONS", "UPDATE SESSIONS", "DELETE FROM SESSIONS", "MERGE")


def _literal_text(node: ast.AST) -> str | None:
    """The SQL a node spells, when it is literal: a string, an f-string's literal parts, or a
    ``+`` of those. ``None`` for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "{}"
            for v in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal_text(node.left), _literal_text(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _session_write(text: str) -> bool:
    flat = " ".join(text.upper().split())
    return any(flat.startswith(p) for p in _WRITE_PREFIXES) and "SESSIONS" in flat


def _kind(text: str) -> str:
    """What a session write may be without a seal: it destroys one, or it changes only the column
    the seal leaves out. Anything else must be a sealing statement."""
    flat = " ".join(text.split())
    if flat.upper().startswith("DELETE FROM SESSIONS"):
        return "destroys"
    if flat.startswith("UPDATE sessions SET revoked_at=") and "seal=''" in flat:
        return "destroys"
    if flat.startswith("UPDATE sessions SET last_used_at=") and "," not in flat.split("WHERE")[0]:
        return "volatile"
    return "sealing"


def _scan(source: str, sealing: frozenset[str]) -> list[str]:
    """Every session write in ``source`` that is neither a listed exception nor one of
    ``sealing`` used inside a sealing function. Returns one line per problem."""
    tree = ast.parse(source)
    problems: list[str] = []
    # Module-level statements: a sealing statement must be one of the named constants.
    for node in tree.body:
        if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            name = target.id if isinstance(target, ast.Name) else "?"
            text = _literal_text(node.value)
            if text and _session_write(text) and _kind(text) == "sealing" and name not in sealing:
                problems.append(f"module constant {name}: {text[:60]}")
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for inner in ast.walk(func):
            text = _literal_text(inner) if isinstance(inner, ast.expr) else None
            if text and _session_write(text) and _kind(text) == "sealing":
                problems.append(f"{func.name}: an inline sealed-column write: {text[:60]}")
            if (
                isinstance(inner, ast.Name)
                and inner.id in sealing
                and func.name not in _SEALING_FUNCTIONS
            ):
                problems.append(f"{func.name}: uses {inner.id} outside the sealing helpers")
    return problems


@pytest.mark.parametrize("module", sorted(_SEALING_STATEMENTS))
def test_every_session_write_is_sealed_or_listed(module: str) -> None:
    source = (_STORE_DIR / module).read_text("utf-8")
    problems = _scan(source, _SEALING_STATEMENTS[module])
    assert not problems, "\n".join(problems)
    # Liveness: the scan finds this backend's sealing statements and its listed exceptions.
    tree = ast.parse(source)
    texts = [t for n in ast.walk(tree) if (t := _literal_text(n)) and _session_write(t)]
    kinds = {_kind(t) for t in texts}
    assert {"sealing", "destroys", "volatile"} <= kinds, f"{module}: scanned {len(texts)} writes"


def test_the_write_scan_catches_an_unsealed_write() -> None:
    planted = (
        "async def mark_something(self, h):\n"
        "    await self._db.execute('UPDATE sessions SET mfa_verified_at=? WHERE token_hash=?', (1, h))\n"
        "async def stray(self):\n"
        "    await self._db.execute(_SESSION_RESEAL, ())\n"
    )
    problems = _scan(planted, frozenset({"_SESSION_RESEAL"}))
    assert len(problems) == 2, problems
