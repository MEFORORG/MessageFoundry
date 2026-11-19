# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5902: the password-change route's two unmapped refusals.

An unusable bundled breach corpus raised ``BreachCorpusUnavailable`` out of the route as a generic
500; it is now a named 503 that still refuses the change. And a caller whose user row was deleted
after its session was resolved, before or during the write, got a success and an
``auth.password_changed`` row, or an enrolment refusal, for an account that no longer exists; the
service now refuses with ``ValueError("no such user")``, which the route answers as a 401. A row
that fails its integrity seal is refused (423) rather than written as an account the MFA
requirement does not cover, and a write that lost its compare is a 409. Synthetic accounts only.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import AsyncIterator, Callable, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.notifications import PASSWORD_CHANGED
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import (
    AUTHORITY_SEAL_FAILED_ACTION,
    USER_SEAL_REFUSED,
    AuthService,
    FactorEnrolmentRequired,
    PasswordChangeNotApplied,
    UserSealRefused,
    _SealCheck,
)
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.base import Store
from messagefoundry.store.crypto import CipherError, generate_key, make_cipher
from messagefoundry.store.row_seal import (
    USER_KIND,
    RowSealError,
    RowSealUnverifiableError,
    TransitSealUnavailableError,
    TransitSealUnverifiableError,
)
from messagefoundry.store.store import MessageStore
from tests.test_api_auth import _auth, _login
from tests.test_password_corpus_guard import bundled_corpus as bundled_corpus  # noqa: F401

_PASSWORD = "Str0ng-Synthetic-Pass!!"
_NEW_PASSWORD = "An0ther-Synthetic-Pass!!"


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


async def _account(store: Store, *, require_mfa: bool = False) -> tuple[AuthService, Any]:
    """Local account u1, named bob, holding viewer; returns the service and its login identity."""
    service = AuthService(store, AuthSettings(require_mfa=require_mfa))
    await service.initialize()
    await store.create_user(
        user_id="u1",
        username="bob",
        auth_provider="local",
        email="bob@example.org",
        password_hash=hash_password(_PASSWORD),
        password_generated=False,
        audits=(),
    )
    await store.set_user_roles("u1", ["viewer"], assigned_by="test", audits=())
    out = await service.login("bob", _PASSWORD)
    assert out.ok and out.identity is not None
    return service, out.identity


async def _changed_rows(store: Store) -> list[Any]:
    return [r for r in await store.list_audit(limit=200) if r["action"] == "auth.password_changed"]


def _delete_during_write(monkeypatch: pytest.MonkeyPatch, store: Store, user_id: str) -> None:
    """Delete ``user_id`` just before the store's password write runs, the concurrent deletion."""
    real = store.set_password

    async def racing(uid: str, **kwargs: Any) -> bool:
        await store.delete_user(user_id)
        return await real(uid, **kwargs)

    monkeypatch.setattr(store, "set_password", racing)


async def test_a_row_deleted_before_the_change_is_refused(store: MessageStore) -> None:
    service, identity = await _account(store)
    await store.delete_user("u1")
    with pytest.raises(ValueError, match="no such user"):
        await service.change_password(identity, _NEW_PASSWORD)
    # The answer does not depend on the password typed: a weak one is not a policy refusal here.
    with pytest.raises(ValueError, match="no such user"):
        await service.change_password(identity, "weak")
    assert await _changed_rows(store) == []


async def test_a_row_deleted_during_the_write_is_refused(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store)
    _delete_during_write(monkeypatch, store, "u1")
    with pytest.raises(ValueError, match="no such user"):
        await service.change_password(identity, _NEW_PASSWORD)
    assert await _changed_rows(store) == []


async def test_a_covered_row_deleted_during_the_write_is_not_an_enrolment_refusal(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store, require_mfa=True)

    async def way_past(_user: Any) -> None:
        return None  # stand in for a factor that passes the early refusal

    monkeypatch.setattr(service, "_refuse_rotation_without_way_past", way_past)
    _delete_during_write(monkeypatch, store, "u1")
    with pytest.raises(ValueError, match="no such user"):
        await service.change_password(identity, _NEW_PASSWORD)
    assert await _changed_rows(store) == []


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "b5902.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _signed_in(engine: Engine) -> tuple[httpx.AsyncClient, AuthService, dict[str, str]]:
    service, _identity = await _account(engine.store)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 123))
    c = httpx.AsyncClient(transport=transport, base_url="http://t")
    login = await _login(c, "bob", _PASSWORD)
    assert login.status_code == 200, login.text
    return c, service, _auth(login.json()["token"])


async def _post_change(c: httpx.AsyncClient, headers: dict[str, str]) -> httpx.Response:
    return await c.post(
        "/me/password",
        headers=headers,
        json={"current_password": _PASSWORD, "new_password": _NEW_PASSWORD},
    )


async def test_an_unusable_corpus_is_a_named_503_and_no_change(
    engine: Engine,
    bundled_corpus: Callable[[Sequence[str] | None], None],  # noqa: F811
    tmp_path: Path,
) -> None:
    c, _service, headers = await _signed_in(engine)
    try:
        bundled_corpus(None)  # no corpus file at all: the screen cannot run
        r = await _post_change(c, headers)
    finally:
        await c.aclose()
    assert r.status_code == 503, r.text
    assert "password screening is unavailable" in r.json()["detail"]
    # The decoded detail: a Windows path in the raw JSON body carries escaped backslashes.
    assert str(tmp_path) not in r.json()["detail"]
    assert await _changed_rows(engine.store) == []


async def test_a_deleted_account_is_a_401_not_a_success(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    c, _service, headers = await _signed_in(engine)
    # The row goes after the gate and the current-password check, as the store write starts.
    _delete_during_write(monkeypatch, engine.store, "u1")
    try:
        r = await _post_change(c, headers)
    finally:
        await c.aclose()
    assert r.status_code == 401, r.text
    assert r.json()["detail"] == "session ended; sign in again"
    assert await _changed_rows(engine.store) == []


async def test_a_write_that_lost_a_race_is_not_reported_as_a_change(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store)
    before = await store.get_user("u1")
    assert before is not None

    async def lost(_uid: str, **_kwargs: Any) -> bool:
        return False  # the row is still there; the write's compare lost to another writer

    monkeypatch.setattr(store, "set_password", lost)
    with pytest.raises(PasswordChangeNotApplied):
        await service.change_password(identity, _NEW_PASSWORD)
    assert await _changed_rows(store) == []
    after = await store.get_user("u1")
    assert after is not None and after.password_hash == before.password_hash


async def test_a_row_that_fails_its_seal_cannot_change_its_password(tmp_path: Path) -> None:
    path = tmp_path / "sealed.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        service, identity = await _account(store, require_mfa=True)
        before = await store.get_user("u1")  # unchecked read: it still returns a bent row
        assert before is not None
        # Bend a sealed field behind the store's back, so the record fails its seal on every read.
        conn = sqlite3.connect(path)
        try:
            conn.execute("UPDATE users SET display_name=? WHERE id=?", ("bent", "u1"))
            conn.commit()
        finally:
            conn.close()
        with pytest.raises(UserSealRefused):
            await service.change_password(identity, _NEW_PASSWORD)
        # Refused before the policy check, so the password typed does not change the answer.
        with pytest.raises(UserSealRefused):
            await service.change_password(identity, "weak")
        after = await store.get_user("u1")
        assert after is not None and after.password_hash == before.password_hash
        assert await _changed_rows(store) == []
        assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1
    finally:
        await store.close()


async def test_a_raced_first_read_still_writes_with_the_way_past_condition(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A first check that races a write and settles nothing is read again, so a covered account is
    still judged covered: the write carries ``require_way_past`` rather than running unconditioned."""
    service, identity = await _account(store, require_mfa=True)
    real_verified = service._verified
    raced = [True]

    async def verified(raw: Any) -> Any:
        if raced:
            raced.pop()
            return _SealCheck()  # neither passes nor fails: a row re-keyed between its reads
        return await real_verified(raw)

    async def way_past(_user: Any) -> None:
        return None  # stand in for a factor that passes the early refusal

    seen: list[Any] = []
    real_write = store.set_password

    async def recording(uid: str, **kwargs: Any) -> bool:
        seen.append(kwargs["require_way_past"])
        return await real_write(uid, **kwargs)

    monkeypatch.setattr(service, "_verified", verified)
    monkeypatch.setattr(service, "_refuse_rotation_without_way_past", way_past)
    monkeypatch.setattr(store, "set_password", recording)
    # The account holds no factor, so the conditioned write declines and the change is refused; the
    # stubbed early refusal passes the re-judgement too, so the answer is the lost-write 409.
    with pytest.raises(PasswordChangeNotApplied):
        await service.change_password(identity, _NEW_PASSWORD)
    assert raced == [] and len(seen) == 1 and seen[0] is not None
    assert await _changed_rows(store) == []


async def test_a_covered_lost_write_is_an_enrolment_refusal_only_with_no_way_past(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store, require_mfa=True)
    # One verdict per call of the early refusal: the first passes (a factor counted before the
    # write), the second is the re-judgement after the lost write.
    verdicts: list[bool] = []

    async def judged(_user: Any) -> None:
        if not verdicts.pop(0):
            raise FactorEnrolmentRequired()

    async def lost(_uid: str, **_kwargs: Any) -> bool:
        return False

    monkeypatch.setattr(service, "_refuse_rotation_without_way_past", judged)
    monkeypatch.setattr(store, "set_password", lost)
    verdicts[:] = [True, False]  # the factor went between the early check and the write
    with pytest.raises(FactorEnrolmentRequired):
        await service.change_password(identity, _NEW_PASSWORD)
    verdicts[:] = [True, True]  # the factor is still there: the write lost only a compare
    with pytest.raises(PasswordChangeNotApplied):
        await service.change_password(identity, _NEW_PASSWORD)
    assert verdicts == []
    assert await _changed_rows(store) == []


async def test_a_covered_row_deleted_during_the_early_check_is_not_an_enrolment_refusal(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store, require_mfa=True)

    async def deleted_meanwhile(_user: Any) -> None:
        await store.delete_user("u1")  # its factors go with it, so it reads as having none
        raise FactorEnrolmentRequired()

    monkeypatch.setattr(service, "_refuse_rotation_without_way_past", deleted_meanwhile)
    with pytest.raises(ValueError, match="no such user"):
        await service.change_password(identity, _NEW_PASSWORD)
    assert await _changed_rows(store) == []


async def test_an_unverifiable_record_at_the_passkey_re_read_is_the_seal_refusal(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The early way-past check reads the passkeys through ``_verified_passkeys``, which re-reads
    the record when the set does not match its digest. Vault transit failing to verify it on that
    re-read is the seal refusal (the route's 423), reported, with nothing written, not an
    unhandled error (BACKLOG #5902)."""
    service, identity = await _account(store, require_mfa=True)
    reported: list[str] = []

    async def unverifiable(_uid: str) -> Any:
        raise TransitSealUnverifiableError(USER_KIND, 1, 2)

    async def held_gate_passkey(user: Any) -> bool:
        # The real passkey read, made to take its re-read branch: a sealed store whose set does
        # not match the digest the record holds.
        monkeypatch.setattr(store, "row_sealer", lambda: object())
        monkeypatch.setattr("messagefoundry.auth.service.passkey_digest", lambda _creds: "moved")
        monkeypatch.setattr(service, "_load_user", unverifiable)
        return bool(await service._verified_passkeys(user))

    async def report(user_id: str, _exc: Any) -> None:
        reported.append(user_id)

    monkeypatch.setattr(service, "_holds_gate_passkey", held_gate_passkey)
    monkeypatch.setattr(service, "_user_seal_unverifiable", report)
    with pytest.raises(UserSealRefused):
        await service.change_password(identity, _NEW_PASSWORD)
    assert reported == ["u1"]
    monkeypatch.undo()
    assert await _changed_rows(store) == []
    assert (await service.login("bob", _PASSWORD)).ok


async def test_a_seal_refusal_at_the_write_is_refused_and_reported(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store)

    async def refused(_uid: str, **_kwargs: Any) -> bool:
        raise RowSealError(USER_KIND, "u1")  # the record failed its seal under the write's lock

    monkeypatch.setattr(store, "set_password", refused)
    with pytest.raises(UserSealRefused):
        await service.change_password(identity, _NEW_PASSWORD)
    assert await _changed_rows(store) == []
    assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1


async def test_an_unverifiable_seal_at_the_write_is_refused_and_reported(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store)
    reported: list[str] = []

    async def unverifiable(_uid: str, **_kwargs: Any) -> bool:
        raise RowSealUnverifiableError(USER_KIND, "u1")

    async def report(user_id: str, _exc: Any) -> None:
        reported.append(user_id)

    monkeypatch.setattr(store, "set_password", unverifiable)
    monkeypatch.setattr(service, "_user_seal_unverifiable", report)
    with pytest.raises(UserSealRefused):
        await service.change_password(identity, _NEW_PASSWORD)
    assert reported == ["u1"]
    assert await _changed_rows(store) == []


async def test_an_outage_at_the_write_propagates_and_changes_nothing(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store)
    paged: list[str] = []

    async def outage(_uid: str, **_kwargs: Any) -> bool:
        raise TransitSealUnavailableError()

    monkeypatch.setattr(store, "set_password", outage)
    monkeypatch.setattr(service, "_user_seal_outage", paged.append)
    with pytest.raises(TransitSealUnavailableError):
        await service.change_password(identity, _NEW_PASSWORD)
    assert paged == ["password change"]
    assert await _changed_rows(store) == []


def _reads_refused_after_commit(
    monkeypatch: pytest.MonkeyPatch, store: Store, service: AuthService, refusal: Exception
) -> list[bool]:
    """Run the store's real password write; once it has written, any read of the account's record
    through ``checked_user`` or ``_load_user`` raises ``refusal``. Returns the committed marks."""
    committed: list[bool] = []
    real_write = store.set_password

    async def write(uid: str, **kwargs: Any) -> bool:
        written = await real_write(uid, **kwargs)
        if written:
            committed.append(True)
        return written

    monkeypatch.setattr(store, "set_password", write)
    for name in ("checked_user", "_load_user"):
        real_read = getattr(service, name)

        def guarded(real: Any) -> Any:
            async def read(uid: str) -> Any:
                if committed:
                    raise refusal
                return await real(uid)

            return read

        monkeypatch.setattr(service, name, guarded(real_read))
    return committed


async def test_a_transit_unverifiable_after_the_commit_still_reports_the_change(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After the write has committed, a record read that Vault transit cannot verify does not turn
    a made change into a refusal: no read after the commit is made at all."""
    service, identity = await _account(store)
    refusal = TransitSealUnverifiableError(USER_KIND, 1, 2)
    committed = _reads_refused_after_commit(monkeypatch, store, service, refusal)
    assert await service.change_password(identity, _NEW_PASSWORD) == []
    assert committed == [True]
    assert len(await _changed_rows(store)) == 1


async def test_the_notice_goes_to_the_checked_address(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, identity = await _account(store)
    refusal = AssertionError("the record was read again after the commit")
    _reads_refused_after_commit(monkeypatch, store, service, refusal)
    sent: list[tuple[str, str | None]] = []

    async def notify(event_type: str, *, email: str | None, **_kwargs: Any) -> bool:
        sent.append((event_type, email))
        return True

    monkeypatch.setattr(service, "_notify_security", notify)
    assert await service.change_password(identity, _NEW_PASSWORD) == []
    assert sent == [(PASSWORD_CHANGED, "bob@example.org")]


@pytest.mark.parametrize(
    "refusal",
    [CipherError("transit down"), sqlite3.OperationalError("database is locked"), RuntimeError()],
)
async def test_a_refused_audit_row_after_the_commit_still_reports_the_change(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    refusal: Exception,
) -> None:
    service, identity = await _account(store)
    sent: list[str | None] = []
    real_audit = service._audit

    async def refused(action: str, **kwargs: Any) -> None:
        if action == "auth.password_changed":
            raise refusal
        await real_audit(action, **kwargs)

    async def notify(_event_type: str, *, email: str | None, **_kwargs: Any) -> bool:
        sent.append(email)
        return True

    monkeypatch.setattr(service, "_audit", refused)
    monkeypatch.setattr(service, "_notify_security", notify)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
        assert await service.change_password(identity, _NEW_PASSWORD) == []
    assert sent == ["bob@example.org"]
    assert any("auth.password_changed row" in r.getMessage() for r in caplog.records)
    assert (await service.login("bob", _NEW_PASSWORD)).ok


async def test_a_passkey_only_row_deleted_at_the_re_judge_is_gone_not_an_enrolment_refusal(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A covered write that lost its compare re-judges the way past. A passkey-only row deleted
    while that re-judge runs takes its passkey with it; it is answered as gone (the route's 401),
    not as an account that must enrol (the route's 403)."""
    service, identity = await _account(store, require_mfa=True)
    calls: list[int] = []

    async def judged(_user: Any) -> None:
        calls.append(1)
        if len(calls) == 1:
            return None  # the early check: the passkey counts
        await store.delete_user("u1")
        raise FactorEnrolmentRequired()

    async def lost(_uid: str, **_kwargs: Any) -> bool:
        return False

    monkeypatch.setattr(service, "_refuse_rotation_without_way_past", judged)
    monkeypatch.setattr(store, "set_password", lost)
    with pytest.raises(ValueError, match="no such user"):
        await service.change_password(identity, _NEW_PASSWORD)
    assert len(calls) == 2
    assert await _changed_rows(store) == []


async def test_a_lost_write_is_a_409_on_the_route(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    c, _service, headers = await _signed_in(engine)

    async def lost(_uid: str, **_kwargs: Any) -> bool:
        return False  # the row is still there; the write's compare lost to another writer

    monkeypatch.setattr(engine.store, "set_password", lost)
    try:
        r = await _post_change(c, headers)
    finally:
        await c.aclose()
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == str(PasswordChangeNotApplied())
    assert await _changed_rows(engine.store) == []


async def test_a_seal_refused_row_is_a_423_on_the_route(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    c, service, headers = await _signed_in(engine)

    async def refused(_uid: str) -> Any:
        raise UserSealRefused(USER_SEAL_REFUSED)

    # Only change_password reads through checked_user on this route; the gate and the
    # current-password check read through _load_user, so they still pass.
    monkeypatch.setattr(service, "checked_user", refused)
    try:
        r = await _post_change(c, headers)
    finally:
        await c.aclose()
    assert r.status_code == 423, r.text
    assert r.json()["detail"] == USER_SEAL_REFUSED
    assert await _changed_rows(engine.store) == []


async def test_an_outage_is_a_503_on_the_route(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    c, service, headers = await _signed_in(engine)

    async def outage(_uid: str) -> Any:
        raise TransitSealUnavailableError()

    monkeypatch.setattr(service, "checked_user", outage)
    try:
        r = await _post_change(c, headers)
    finally:
        await c.aclose()
    assert r.status_code == 503, r.text
    assert "Retry-After" in r.headers
    assert await _changed_rows(engine.store) == []
