# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The combined sign-in must not leave a password oracle in the audit trail (BACKLOG #1131).

ADR 0197's "no oracle" property (section 4) is about what the *caller* learns: every refused
combined sign-in answers the same string, status and padded time. But the audit trail is read by a
SEPARATE, lower-privileged reader. The built-in ``AUDITOR`` role holds ``audit:read`` (+
``monitoring:read`` + ``audit:export``) and is **not** an administrator, so it cannot see the
per-account lock-state surface, only ``GET /audit`` and the monitoring stream.

If a refused combined sign-in records a different ``auth.login_failed`` reason when the password was
right (code wrong) than when both factors were wrong, that reader can tell a right candidate
password from a wrong one, one audit row per attempt. Since the sign-in lock does not refuse a
combined sign-in, an ``audit:read`` holder could arm a target's sign-in lock, send candidate
passwords with any six digits, and read the answer off the trail -- one request per candidate, up to
the global sign-in ceiling of about 86,400 a day, against ADR 0197's design bound of 35.

These tests read the audit trail through the exact store query ``GET /audit`` runs
(``list_audit(actor=..., action=...)``) and assert an ``audit:read`` holder cannot separate the two
outcomes on the ``auth.login_failed`` reason. The counting is ADR 0197's and stays unchanged: a
right password with a wrong code still charges the second-step counter; both wrong still charges the
sign-in counter (asserted below).

**The lock-event limb is closed by owner ruling 2026-09-28.** The second-step counter is fed only by
a right factor, so sending one candidate ``lockout_threshold`` times locks it iff the password was
right. The ruling makes the lock rows (``auth.account_locked``, ``auth.lock_notice``,
``auth.login_locked``, ``auth.admin_unlocked``) readable only with ``users:manage``, and gives every
refused attempt one uniform ``auth.login_failed`` row in every lock state. The engine still writes
every lock row (ADR 0197 AC-10), and an Administrator still reads them. The tests at the bottom read
through the real routes as the built-in Auditor.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from _totp_clock import pin_totp_clock

from messagefoundry.__main__ import main as cli_main
from messagefoundry.api import create_app
from messagefoundry.auth import Role, totp
from messagefoundry.auth.audit_visibility import (
    DIRECTORY_LOCKED_REFUSAL_DETAIL,
    HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE,
)
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.audit_exclusion import AuditExclusion
from messagefoundry.store.base import Store
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, login_admin
from tests._phi_gate_provisions import setenv_at_rest_opt_out

_LOCK_THRESHOLD = 3


def _lock_settings() -> AuthSettings:
    return AuthSettings(
        lockout_threshold=_LOCK_THRESHOLD, lockout_minutes=15, mfa_recovery_code_count=1
    )


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


class _Steps:
    """Pins the TOTP clock and hands out a code from a fresh step on every call."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, secret: str, start: float = 3_000_000.0
    ) -> None:
        self._monkeypatch = monkeypatch
        self._secret = secret
        self.now = start

    def next_code(self) -> str:
        self.now += totp.DEFAULT_PERIOD
        pin_totp_clock(self._monkeypatch, self.now)
        return totp.totp(self._secret, now=self.now)

    def wrong_code(self) -> str:
        live = totp.totp(self._secret, now=self.now)
        return f"{(int(live[0]) + 1) % 10}{live[1:]}"


async def _totp_admin(
    service: AuthService, monkeypatch: pytest.MonkeyPatch
) -> tuple[Identity, str, _Steps]:
    """An Administrator with TOTP active. Returns ``(identity, password, steps)``."""
    identity, token, password = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    steps = _Steps(monkeypatch, enroll.secret)
    assert (await service.confirm_mfa_enrollment(identity, steps.next_code(), token=token)).ok
    return identity, password, steps


async def _set_sign_in_lock(store: Store, user_id: str) -> None:
    await store.record_login_failure(user_id, failed_attempts=3, locked_until=time.time() + 900)


async def _failed_login_details(store: MessageStore) -> list[dict[str, Any]]:
    """Every ``auth.login_failed`` detail an ``audit:read`` holder would read, newest first."""
    rows = await store.list_audit(actor=ADMIN_USERNAME, action="auth.login_failed")
    return [json.loads(r["detail"] or "{}") for r in rows]


async def test_a_refused_combined_sign_in_leaves_no_password_oracle_in_the_audit_trail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The core oracle. Under a live sign-in lock, a right-password/wrong-code attempt and a
    both-wrong attempt must record byte-identical ``auth.login_failed`` details."""
    store = await _store()
    try:
        service = AuthService(store, _lock_settings())
        identity, password, steps = await _totp_admin(service, monkeypatch)
        await _set_sign_in_lock(store, identity.user_id)

        # Attempt 1: the RIGHT candidate password, with a wrong code.
        steps.next_code()
        out = await service.login(ADMIN_USERNAME, password, totp_code=steps.wrong_code())
        assert not out.ok and out.error == "invalid credentials"

        # Attempt 2: a WRONG candidate password, with a wrong code.
        steps.next_code()
        out = await service.login(
            ADMIN_USERNAME, "not-the-passphrase", totp_code=steps.wrong_code()
        )
        assert not out.ok and out.error == "invalid credentials"

        details = await _failed_login_details(store)
        assert len(details) == 2, details
        # ``list_audit`` is newest-first, so index 0 is attempt 2 (both wrong) and index 1 is
        # attempt 1 (right password).
        both_wrong, right_password = details[0], details[1]
        assert right_password == both_wrong, (
            "the audit trail distinguishes a right candidate password from a wrong one: "
            f"right-password={right_password} both-wrong={both_wrong}"
        )
    finally:
        await store.close()


async def test_the_wrong_password_right_code_outcome_matches_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The third combined-failure shape (wrong password, right code) must record the same detail as
    the other two, so no arm of the routing table is separable in the trail."""
    store = await _store()
    try:
        service = AuthService(store, _lock_settings())
        identity, password, steps = await _totp_admin(service, monkeypatch)
        await _set_sign_in_lock(store, identity.user_id)

        code = steps.next_code()
        out = await service.login(ADMIN_USERNAME, "not-the-passphrase", totp_code=code)
        assert not out.ok

        steps.next_code()
        out = await service.login(ADMIN_USERNAME, password, totp_code=steps.wrong_code())
        assert not out.ok

        details = await _failed_login_details(store)
        assert len(details) == 2
        assert details[0] == details[1], details
    finally:
        await store.close()


async def test_a_single_refused_combined_attempt_emits_no_lock_row_visible_to_audit_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SINGLE refused combined attempt writes only ``auth.login_failed`` -- no
    ``auth.account_locked`` and no ``auth.lock_notice`` -- whichever factor was wrong, so an
    ``audit:read`` holder sees the identical single row per attempt. This covers only the one-attempt
    case; the multi-attempt campaign is covered at the bottom of this file."""
    for label, use_right_password in (("right-password", True), ("both-wrong", False)):
        store = await _store()
        try:
            service = AuthService(store, _lock_settings())
            identity, password, steps = await _totp_admin(service, monkeypatch)
            await _set_sign_in_lock(store, identity.user_id)
            steps.next_code()
            sent_pw = password if use_right_password else "not-the-passphrase"
            out = await service.login(ADMIN_USERNAME, sent_pw, totp_code=steps.wrong_code())
            assert not out.ok, label
            for action in ("auth.account_locked", "auth.lock_notice"):
                rows = await store.list_audit(actor=ADMIN_USERNAME, action=action)
                assert rows == [], f"{label}: unexpected {action} row: {rows}"
        finally:
            await store.close()


async def test_counting_is_unchanged_right_password_charges_the_second_step_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ADR 0197's counting must survive the fix: a right password with a wrong code charges the
    SECOND-STEP counter, and both wrong charges the SIGN-IN counter."""
    store = await _store()
    try:
        service = AuthService(store, _lock_settings())
        identity, password, steps = await _totp_admin(service, monkeypatch)

        steps.next_code()
        assert not (await service.login(ADMIN_USERNAME, password, totp_code=steps.wrong_code())).ok
        user = await store.get_user(identity.user_id)
        assert user is not None
        assert user.second_step_failed_attempts == 1, (
            "right password/wrong code left second-step alone"
        )
        assert user.failed_attempts == 0, "right password/wrong code touched the sign-in counter"

        steps.next_code()
        assert not (await service.login(ADMIN_USERNAME, "wrong", totp_code=steps.wrong_code())).ok
        user = await store.get_user(identity.user_id)
        assert user is not None
        assert user.failed_attempts == 1, "both wrong left the sign-in counter alone"
        assert user.second_step_failed_attempts == 1, "both wrong touched the second-step counter"
    finally:
        await store.close()


class _FakeNotifier:
    """Captures out-of-band security events instead of emailing them, so ``_lock_notice_due`` sees a
    wired notifier and writes its ``auth.lock_notice`` row."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    async def notify(self, event: Any) -> None:
        self.events.append(event)


# --- The lock-event limb, closed by owner ruling 2026-09-28 --------------------------------------
#
# The second-step counter is fed only by a right factor, so ``lockout_threshold`` combined attempts
# with ONE candidate password lock it iff the candidate was right. The owner ruled (2026-09-28) that
# the lock rows that follow are readable only with ``users:manage``, and that every refused attempt
# shows a reader without it the same single ``auth.login_failed`` row. These tests read the trail the
# way that reader does -- through the real routes, as the built-in Auditor -- and compare the two
# campaigns row for row.

#: The four actions the ruling hides from a reader without ``users:manage``. Named here, not
#: imported, so a change to the engine's set has to change this test as well.
_HIDDEN_LOCK_ACTIONS = (
    "auth.account_locked",
    "auth.lock_notice",
    "auth.login_locked",
    "auth.admin_unlocked",
)
_READER_PASSWORD = "a-strong-test-passphrase"
_AUDITOR = "test-auditor"
_SECOND_ADMIN = "test-admin-two"
_PEER = ("127.0.0.1", 123)
#: The readers' own rows (their sign-ins, their exports) are theirs, not the target's, and differ by
#: which reads ran first, so every comparison leaves them out.
_READERS = frozenset({_AUDITOR, _SECOND_ADMIN})

#: One visible row as the routes return it: ``(actor, action, client, detail)``. The timestamp is
#: left out because two campaigns run at different instants; everything else must match exactly.
_Row = tuple[str | None, str, str | None, str | None]


def _route_settings() -> AuthSettings:
    # require_mfa off only so the two READER accounts sign in with a password alone; the target
    # still has TOTP enrolled, and the combined sign-in does not read this setting.
    return AuthSettings(
        lockout_threshold=_LOCK_THRESHOLD,
        lockout_minutes=15,
        mfa_recovery_code_count=1,
        require_mfa=False,
    )


async def _add_reader(service: AuthService, username: str, role: Role) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=_READER_PASSWORD,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    # A wired notifier makes the API refuse an account with no notification address.
    await service.store.set_user_notify_email(user_id, email=f"{username}@example.test")


@dataclass
class _World:
    """One engine with a TOTP-enrolled target under a live sign-in lock, plus two readers."""

    engine: Engine
    service: AuthService
    target_id: str
    password: str
    steps: _Steps
    db: Path
    since: float


async def _open_world(tmp: Path, monkeypatch: pytest.MonkeyPatch) -> _World:
    tmp.mkdir(parents=True, exist_ok=True)
    db = tmp / "oracle.db"
    engine = await Engine.create(db, poll_interval=0.02)
    service = AuthService(engine.store, _route_settings(), security_notifier=_FakeNotifier())
    identity, password, steps = await _totp_admin(service, monkeypatch)
    await engine.store.set_user_notify_email(identity.user_id, email="owner@example.test")
    await _add_reader(service, _AUDITOR, Role.AUDITOR)
    await _add_reader(service, _SECOND_ADMIN, Role.ADMINISTRATOR)
    await _set_sign_in_lock(engine.store, identity.user_id)
    # Every row the comparison reads is written after this instant, so setup rows (which carry
    # per-world ids) never enter it.
    since = time.time()
    return _World(engine, service, identity.user_id, password, steps, db, since)


def _client(world: _World, *, serve_ui: bool = False) -> httpx.AsyncClient:
    app = create_app(world.engine, auth=world.service, serve_ui=serve_ui)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=_PEER), base_url="http://t"
    )


async def _bearer(c: httpx.AsyncClient, reader: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login",
        json={"username": reader, "password": _READER_PASSWORD, "provider": "local"},
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def _read_trail(world: _World, reader: str) -> list[_Row]:
    """What ``reader`` reads through ``GET /audit`` since the campaign began, newest first, with the
    readers' own rows removed."""
    async with _client(world) as c:
        h = await _bearer(c, reader)
        r = await c.get("/audit", params={"since": world.since, "limit": 1000}, headers=h)
        assert r.status_code == 200, r.text
        entries = r.json()["entries"]
    return [
        (e["actor"], e["action"], e["client"], e["detail"])
        for e in entries
        if e["actor"] not in _READERS
    ]


async def _read_export(world: _World, reader: str) -> list[_Row]:
    """The same read through ``GET /audit/export``'s CSV."""
    async with _client(world) as c:
        h = await _bearer(c, reader)
        r = await c.get(
            "/audit/export",
            params={"format": "csv", "since": world.since, "limit": 1000},
            headers=h,
        )
        assert r.status_code == 200, r.text
    rows = list(csv.DictReader(io.StringIO(r.text)))
    return [
        (row["actor"] or None, row["action"], row["client"] or None, row["detail"] or None)
        for row in rows
        if row["actor"] not in _READERS
    ]


async def _campaign(world: _World, *, right_password: bool) -> None:
    """``lockout_threshold + 2`` combined attempts with ONE candidate and any six digits."""
    sent = world.password if right_password else "not-the-passphrase"
    for _ in range(_LOCK_THRESHOLD + 2):
        world.steps.next_code()
        out = await world.service.login(ADMIN_USERNAME, sent, totp_code=world.steps.wrong_code())
        assert not out.ok


async def _lapse_sign_in_lock_then_probe(world: _World, *, right_password: bool) -> None:
    """The sign-in lock lapses while a second-step lock (if the campaign armed one) is still live;
    the prober then sends its candidate as a PASSWORD-ONLY sign-in."""
    user = await world.engine.store.get_user(world.target_id)
    assert user is not None
    await world.engine.store.record_login_failure(
        world.target_id, failed_attempts=user.failed_attempts, locked_until=time.time() - 1
    )
    sent = world.password if right_password else "not-the-passphrase"
    out = await world.service.login(ADMIN_USERNAME, sent)
    assert not out.ok


async def _admin_unlock(world: _World, monkeypatch: pytest.MonkeyPatch) -> _World:
    """Run the real ``admin-unlock`` CLI against the world's database (engine stopped, as ADR 0171
    requires), then reopen the engine on the same file. Returns the reopened world."""
    await world.engine.stop()
    monkeypatch.chdir(world.db.parent)
    setenv_at_rest_opt_out(monkeypatch)
    argv = ["admin-unlock", "--username", ADMIN_USERNAME, "--db", str(world.db)]
    assert await asyncio.to_thread(cli_main, argv) == 0
    engine = await Engine.create(world.db, poll_interval=0.02)
    service = AuthService(engine.store, _route_settings(), security_notifier=_FakeNotifier())
    await service.initialize()
    return _World(
        engine, service, world.target_id, world.password, world.steps, world.db, world.since
    )


async def _two_worlds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[_World, _World]:
    right = await _open_world(tmp_path / "right", monkeypatch)
    wrong = await _open_world(tmp_path / "wrong", monkeypatch)
    return right, wrong


def _actions(rows: list[_Row]) -> list[str]:
    return [r[1] for r in rows]


async def test_the_lock_events_do_not_leak_which_factor_was_right(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lock-event limb of #1131. Over ``lockout_threshold + 2`` attempts, an Auditor reading
    ``GET /audit`` and the CSV export sees the SAME ordered rows -- action, count, detail, client --
    whether the candidate password was right or wrong. The right campaign really did arm the
    second-step lock (asserted), so the equality is not the vacuous case of no lock at all."""
    right, wrong = await _two_worlds(tmp_path, monkeypatch)
    try:
        await _campaign(right, right_password=True)
        await _campaign(wrong, right_password=False)

        user = await right.engine.store.get_user(right.target_id)
        assert user is not None and user.second_step_locked(time.time()), (
            "the right-password campaign did not arm the second-step lock; the comparison below "
            "would pass for the wrong reason"
        )

        for read in (_read_trail, _read_export):
            seen_right = await read(right, _AUDITOR)
            seen_wrong = await read(wrong, _AUDITOR)
            assert seen_right == seen_wrong, (
                f"{read.__name__}: an audit:read holder can tell a right candidate from a wrong "
                f"one: right={seen_right} wrong={seen_wrong}"
            )
            assert _actions(seen_right) == ["auth.login_failed"] * (_LOCK_THRESHOLD + 2), (
                read.__name__,
                seen_right,
            )
    finally:
        await right.engine.stop()
        await wrong.engine.stop()


async def test_an_administrator_still_reads_every_lock_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR 0197 AC-10 survives the ruling: the engine still WRITES every lock row, and a reader
    holding ``users:manage`` still reads them through the same routes."""
    world = await _open_world(tmp_path, monkeypatch)
    try:
        await _campaign(world, right_password=True)
        for read in (_read_trail, _read_export):
            actions = _actions(await read(world, _SECOND_ADMIN))
            assert actions.count("auth.account_locked") == 1, (read.__name__, actions)
            assert actions.count("auth.lock_notice") == 1, (read.__name__, actions)
            # The two attempts after the lock landed are refused before any verify.
            assert actions.count("auth.login_locked") == 2, (read.__name__, actions)
    finally:
        await world.engine.stop()


async def test_a_password_only_probe_under_a_live_second_step_lock_is_indistinguishable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After the campaign the sign-in lock lapses, while the second-step lock (armed only by a right
    candidate) is still live. The prober sends its candidate as a password-only sign-in: under the
    live lock that is refused before any verify, and otherwise it is an ordinary wrong password. The
    Auditor's view must not tell the two apart."""
    right, wrong = await _two_worlds(tmp_path, monkeypatch)
    try:
        await _campaign(right, right_password=True)
        await _campaign(wrong, right_password=False)
        await _lapse_sign_in_lock_then_probe(right, right_password=True)
        await _lapse_sign_in_lock_then_probe(wrong, right_password=False)

        for read in (_read_trail, _read_export):
            seen_right = await read(right, _AUDITOR)
            seen_wrong = await read(wrong, _AUDITOR)
            assert seen_right == seen_wrong, (
                f"{read.__name__}: right={seen_right} wrong={seen_wrong}"
            )
            assert _actions(seen_right) == ["auth.login_failed"] * (_LOCK_THRESHOLD + 3), (
                read.__name__,
                seen_right,
            )
        # The administrator's view of the right world names the lock that refused the probe.
        admin_actions = _actions(await _read_trail(right, _SECOND_ADMIN))
        assert admin_actions[0] == "auth.login_locked", admin_actions
    finally:
        await right.engine.stop()
        await wrong.engine.stop()


async def test_admin_unlock_leaves_no_trace_an_auditor_can_compare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``auth.admin_unlocked`` records both lock expiries and both cycle counts, so in the right world
    it names a second-step lock the wrong world never had. The whole row is users:manage-only: an
    Auditor sees the same trail in both worlds, and an administrator sees the row and its fields."""
    right, wrong = await _two_worlds(tmp_path, monkeypatch)
    try:
        await _campaign(right, right_password=True)
        await _campaign(wrong, right_password=False)
        right = await _admin_unlock(right, monkeypatch)
        wrong = await _admin_unlock(wrong, monkeypatch)

        for read in (_read_trail, _read_export):
            seen_right = await read(right, _AUDITOR)
            seen_wrong = await read(wrong, _AUDITOR)
            assert seen_right == seen_wrong, (
                f"{read.__name__}: right={seen_right} wrong={seen_wrong}"
            )
            assert "auth.admin_unlocked" not in _actions(seen_right), seen_right

        admin_rows = [
            r for r in await _read_trail(right, _SECOND_ADMIN) if r[1] == "auth.admin_unlocked"
        ]
        assert len(admin_rows) == 1, admin_rows
        detail = json.loads(admin_rows[0][3] or "{}")
        assert detail["was_second_step_locked_until"] is not None, detail
    finally:
        await right.engine.stop()
        await wrong.engine.stop()


#: The locked-refusal rows of the other legs, which say "a lock is live" in their detail rather than
#: their action. Hidden exactly, as ``(action, detail)``.
_HIDDEN_LOCKED_REFUSALS = (
    ("auth.mfa_failed", '{"reason": "locked"}'),
    ("auth.webauthn_failed", '{"reason": "locked"}'),
    ("auth.login_failed", '{"provider": "ad", "reason": "locked"}'),
)
#: Rows that share an action with a hidden refusal and must stay visible.
_VISIBLE_CONTROLS = (
    ("auth.login_failed", '{"provider": "local", "reason": "bad_credentials"}'),
    ("auth.mfa_failed", None),
    ("auth.webauthn_failed", '{"reason": "expired"}'),
    ("auth.login_success", '{"mfa_required": false, "provider": "local"}'),
)


async def test_the_routes_hide_lock_rows_from_a_reader_without_users_manage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every read path an ``audit:read`` holder has -- ``GET /audit``, ``GET /audit?action=``, the
    CSV export and the console's ``/ui/audit`` page -- omits the hidden rows for the Auditor and
    returns them to an Administrator. The visible controls share actions with hidden rows, so a
    filter that dropped whole actions too eagerly fails here too."""
    world = await _open_world(tmp_path, monkeypatch)
    store = world.engine.store
    try:
        for action in _HIDDEN_LOCK_ACTIONS:
            await store.record_audit(action, actor="probe-target", detail='{"lock": "second_step"}')
        for action, detail in (*_HIDDEN_LOCKED_REFUSALS, *_VISIBLE_CONTROLS):
            await store.record_audit(action, actor="probe-target", detail=detail)
        hidden = {(a, '{"lock": "second_step"}') for a in _HIDDEN_LOCK_ACTIONS} | set(
            _HIDDEN_LOCKED_REFUSALS
        )
        everything = hidden | set(_VISIBLE_CONTROLS)

        for read in (_read_trail, _read_export):
            auditor = {(r[1], r[3]) for r in await read(world, _AUDITOR) if r[0] == "probe-target"}
            admin = {
                (r[1], r[3]) for r in await read(world, _SECOND_ADMIN) if r[0] == "probe-target"
            }
            assert auditor == set(_VISIBLE_CONTROLS), (read.__name__, auditor)
            assert admin == everything, (read.__name__, admin)

        async with _client(world) as c:
            h = await _bearer(c, _AUDITOR)
            for action in _HIDDEN_LOCK_ACTIONS:
                r = await c.get("/audit", params={"action": action}, headers=h)
                assert r.status_code == 200 and r.json()["entries"] == [], (action, r.text)
            # The limit counts only visible rows, so a page of N never comes back short by the
            # number of hidden rows between them.
            r = await c.get("/audit", params={"actor": "probe-target", "limit": 2}, headers=h)
            assert len(r.json()["entries"]) == 2, r.text

        async with _client(world, serve_ui=True) as c:
            for reader, expect_hidden in ((_AUDITOR, False), (_SECOND_ADMIN, True)):
                c.cookies.clear()
                r = await c.post(
                    "/ui/login", data={"username": reader, "password": _READER_PASSWORD}
                )
                assert r.status_code == 303, r.text
                page = (await c.get("/ui/audit")).text
                for action in _HIDDEN_LOCK_ACTIONS:
                    assert (action in page) is expect_hidden, (reader, action)
    finally:
        await world.engine.stop()


async def test_the_own_security_events_feed_still_shows_the_holder_their_own_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``/me/security-events`` selects rows by the CALLER's own username, so it is no read path onto
    another account. The ruling does not reach it: the holder of a locked account still reads their
    own lock there (ASVS 6.3.5), and an Auditor's own feed does not show the target's."""
    world = await _open_world(tmp_path, monkeypatch)
    try:
        await _campaign(world, right_password=True)
        async with _client(world) as c:
            h = await _bearer(c, _AUDITOR)
            feed = (await c.get("/me/security-events", headers=h)).json()["events"]
        assert all(e["action"] not in _HIDDEN_LOCK_ACTIONS for e in feed), feed
        own = await world.service.security_events_for(ADMIN_USERNAME)
        assert "auth.account_locked" in [e["action"] for e in own]
    finally:
        await world.engine.stop()


async def test_the_hidden_refusal_details_match_what_the_writers_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The factor and directory lock refusals are hidden by EXACT detail text, so the text a writer
    stores and the text the exclusion names must be the same string. The TOTP and passkey writers
    use the shared constant; the directory writer builds its detail from the reason, so this pins
    it by running the real writer."""
    world = await _open_world(tmp_path, monkeypatch)
    try:
        await world.service._refuse_directory_row("probe-directory", "locked", client=None)
        rows = await world.engine.store.list_audit(actor="probe-directory")
        assert [(r["action"], r["detail"]) for r in rows] == [
            ("auth.login_failed", DIRECTORY_LOCKED_REFUSAL_DETAIL)
        ]
        assert ("auth.login_failed", DIRECTORY_LOCKED_REFUSAL_DETAIL) in (
            HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE.rows
        )
        assert set(_HIDDEN_LOCK_ACTIONS) == HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE.actions
        assert set(_HIDDEN_LOCKED_REFUSALS) == HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE.rows
    finally:
        await world.engine.stop()


def test_every_api_read_of_the_trail_goes_through_the_one_filtered_helper() -> None:
    """A new route that called ``store.list_audit`` directly would skip the exclusion. The API and
    the console packages may call it in ONE place, the helper that applies it."""
    root = Path(__file__).resolve().parents[1]
    calls: list[str] = []
    for package in ("messagefoundry/api", "messagefoundry_webconsole"):
        for path in sorted((root / package).rglob("*.py")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "store.list_audit(" in line:
                    calls.append(f"{path.relative_to(root).as_posix()}:{n}")
    assert len(calls) == 1 and calls[0].startswith("messagefoundry/api/auth_routes.py:"), calls
    source = (root / "messagefoundry/api/auth_routes.py").read_text(encoding="utf-8")
    helper = source[source.index("async def _read_audit(") :]
    helper = helper[: helper.index("\n    async def ", 1)]
    assert "store.list_audit(" in helper and "exclude=audit_exclusion_for(identity)" in helper


def test_an_empty_excluded_detail_is_refused() -> None:
    """An empty detail would also match every NULL-detail row of that action."""
    with pytest.raises(ValueError):
        AuditExclusion(rows=frozenset({("auth.mfa_failed", "")}))


def test_the_exclusion_binds_every_value_in_placeholder_order() -> None:
    """The Postgres backend numbers its placeholders by position (``$N``), so the clause text and
    the parameter list must be built in one order. This drives ``clauses`` with that backend's own
    ``bind`` shape, which the SQLite suite cannot exercise."""
    params: list[object] = ["actor-first"]

    def bind(value: str) -> str:
        params.append(value)
        return f"${len(params)}"

    clauses = HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE.clauses(bind)
    text = " AND ".join(clauses)
    for n, value in enumerate(params[1:], start=2):
        assert f"${n}" in text, (n, value, text)
    assert "locked" not in text and "auth." not in text, "a value reached the SQL text"
    assert params[1:5] == sorted(HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE.actions)


# --- The general log, which the ruling reaches too (Manager decision 2026-09-28) -----------------
#
# ``GET /logs/tail`` serves the application log to ``logs:view``, which the built-in Operator holds
# without ``users:manage``. A per-event line saying a lock notice could not be delivered appeared
# only when a lock landed, so it carried the same bit as the hidden audit rows.

#: The off-box audit tee copies every audit row to this logger, hidden ones included. That copy is
#: not a per-event notice line; ``/logs/tail`` withholds it from a reader without users:manage (see
#: the tail test below), so it is left out of the capture here.
_AUDIT_TEE_LOGGER = "messagefoundry.audit"


def _leaking(caplog: pytest.LogCaptureFixture, *needles: str) -> list[str]:
    return [
        f"{r.name}: {r.getMessage()}"
        for r in caplog.records
        if r.name != _AUDIT_TEE_LOGGER and any(n in r.getMessage() for n in needles)
    ]


async def test_a_lock_with_no_mail_relay_writes_no_log_line_naming_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """No relay is wired, so the lock notice cannot go. That used to log a WARNING naming the
    ``account_locked`` notice and the username, once per lock. Now nothing in the general log names
    either, and the undeliverable notice is recorded instead on the users:manage-only
    ``auth.lock_notice`` row as ``mailed: false``."""
    store = await _store()
    try:
        service = AuthService(store, _lock_settings())  # no security_notifier: no relay
        identity, password, steps = await _totp_admin(service, monkeypatch)
        await _set_sign_in_lock(store, identity.user_id)
        # From INFO: below it, the store driver's DEBUG lines echo every query's parameters, the
        # username among them, on every attempt in either world. Setup lines are cleared first.
        caplog.clear()
        with caplog.at_level(logging.INFO):
            for _ in range(_LOCK_THRESHOLD):
                steps.next_code()
                sent = await service.login(ADMIN_USERNAME, password, totp_code=steps.wrong_code())
                assert not sent.ok
        user = await store.get_user(identity.user_id)
        assert user is not None and user.second_step_locked(time.time()), "no lock landed"
        leaks = _leaking(caplog, "account_locked", ADMIN_USERNAME)
        assert leaks == [], leaks
        rows = await store.list_audit(actor=ADMIN_USERNAME, action="auth.lock_notice")
        assert [json.loads(r["detail"])["mailed"] for r in rows] == [False], rows
    finally:
        await store.close()


async def test_the_notifier_writes_no_log_line_for_an_undeliverable_lock_notice(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The relay's own three drops: no address, a full queue, and a failed send. For a lock notice
    none of them names the event or the account. The control is an address-change notice, which
    carries no lock bit and must still be reported, so the capture is known to work."""
    from messagefoundry.auth.notifications import ACCOUNT_LOCKED, EMAIL_CHANGED, SecurityEvent
    from messagefoundry.pipeline.security_notify import SecurityEventNotifier

    def boom(**_: Any) -> None:
        raise OSError("relay down")

    monkeypatch.setattr("messagefoundry.pipeline.security_notify.send_plain_email", boom)
    notifier = SecurityEventNotifier(host="smtp.example.test", port=25, sender="mf@example.test")
    with caplog.at_level(logging.INFO):
        # A full queue, before the worker starts: one slot, so the second lock notice is dropped.
        notifier._queue = asyncio.Queue(maxsize=1)
        await notifier.notify(SecurityEvent(ACCOUNT_LOCKED, username="lock-a", email="a@x.test"))
        await notifier.notify(SecurityEvent(ACCOUNT_LOCKED, username="lock-b", email="b@x.test"))
        notifier.start()
        await notifier.notify(SecurityEvent(ACCOUNT_LOCKED, username="lock-c", email=None))
        await notifier.aclose()  # drains lock-a, whose send fails
        leaks = _leaking(caplog, "account_locked", "lock-a", "lock-b", "lock-c")
        assert leaks == [], leaks

        control = SecurityEventNotifier(host="smtp.example.test", port=25, sender="mf@x.test")
        control.start()
        await control.notify(SecurityEvent(EMAIL_CHANGED, username="control-user", email=None))
        await control.aclose()
    assert _leaking(caplog, "control-user"), (
        "the capture saw nothing; the zero above proves nothing"
    )


def _tee_line(action: str, actor: str) -> str:
    record = {"event": "audit", "action": action, "actor": actor, "row_id": 7, "detail": None}
    return f"2026-09-28 12:00:00 INFO     {_AUDIT_TEE_LOGGER}: {json.dumps(record)}"


async def test_the_log_tail_withholds_the_audit_copy_from_a_reader_without_users_manage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The off-box tee writes every audit row into the general log, with its row number. Dropping
    only the lock rows there would leave numbered gaps, so ``/logs/tail`` withholds every audit copy
    from a reader without ``users:manage`` (the built-in Operator), in both log formats, before it
    pages, so ``total_lines`` does not count them either. An Administrator still reads them."""
    world = await _open_world(tmp_path, monkeypatch)
    try:
        await _add_reader(world.service, "test-operator", Role.OPERATOR)
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        json_copy = json.dumps(
            {
                "time": "2026-09-28T12:00:01Z",
                "level": "INFO",
                "logger": _AUDIT_TEE_LOGGER,
                "message": json.dumps({"event": "audit", "action": "auth.account_locked"}),
            }
        )
        lines = [
            "2026-09-28 12:00:00 INFO     messagefoundry.engine: engine started",
            _tee_line("auth.login_failed", ADMIN_USERNAME),
            _tee_line("auth.account_locked", ADMIN_USERNAME),
            json_copy,
            "2026-09-28 12:00:02 INFO     messagefoundry.engine: engine still running",
        ]
        (log_dir / "service.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
        app = create_app(world.engine, auth=world.service, log_dir=str(log_dir))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=_PEER), base_url="http://t"
        ) as c:
            seen: dict[str, dict[str, Any]] = {}
            for reader in ("test-operator", _SECOND_ADMIN):
                r = await c.get("/logs/tail", headers=await _bearer(c, reader))
                assert r.status_code == 200, r.text
                seen[reader] = r.json()
        operator = "\n".join(seen["test-operator"]["lines"])
        assert "engine started" in operator and "engine still running" in operator
        assert _AUDIT_TEE_LOGGER not in operator and "account_locked" not in operator, operator
        assert seen["test-operator"]["total_lines"] == 2
        assert seen[_SECOND_ADMIN]["total_lines"] == 5
        assert "account_locked" in "\n".join(seen[_SECOND_ADMIN]["lines"])
    finally:
        await world.engine.stop()


# --- The visible row's timestamp (Manager decision 2026-09-28) ------------------------------------


async def test_the_visible_rows_timestamp_does_not_tell_a_lock_refusal_from_a_verified_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the refusal's ``auth.login_failed`` row is written as its branch finishes.

    A refusal by a live lock does one dummy password check before its row; a verified refusal also
    reads the TOTP secret and counts the failure. The row's ``ts`` then sat nearer the request's
    start on the lock path, and only a right candidate arms the second-step lock. The rows are now
    written at the equalizer's floor, half a budget in, on both paths.

    Also RED when: the rows are written AFTER the pad. Then the ANSWER waits for them, and the two
    paths write different numbers of rows. So this pins the answer's slot too.

    Measured the way AC-6's timing arms in ``tests/test_mfa.py`` measure (BACKLOG #1943): a fixed
    40 ms verify, the failure count slowed by 300 ms so the gap is far wider than the host's jitter
    and still under half the budget, each audit write slowed by 150 ms, a lowered budget, and both
    offsets read in whole half-budget units, since that is where the write point sits."""
    import messagefoundry.auth.service as svc

    budget = 0.8
    monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", budget)

    async def measure(second_step_locked: bool) -> tuple[int, int]:
        store = await _store()
        try:
            service = AuthService(store, _lock_settings())
            identity, _, steps = await _totp_admin(service, monkeypatch)
            await _set_sign_in_lock(store, identity.user_id)
            if second_step_locked:
                for _ in range(_LOCK_THRESHOLD):
                    await store.increment_login_failure(
                        identity.user_id,
                        counter="second_step",
                        threshold=_LOCK_THRESHOLD,
                        lockout_seconds=900.0,
                        max_lockout_seconds=86_400.0,
                        now=time.time(),
                    )

            async def fixed_wrong(fn: Any, *args: Any) -> Any:
                await asyncio.sleep(0.04)
                return False

            real_increment = store.increment_login_failure

            async def slow_increment(*args: Any, **kwargs: Any) -> Any:
                await asyncio.sleep(0.3)
                return await real_increment(*args, **kwargs)

            real_record = store.record_audit

            async def slow_record(*args: Any, **kwargs: Any) -> Any:
                # Each row costs 150 ms, so an answer that waited for the lock path's two rows
                # would land a half-budget later than the verified path's one.
                await asyncio.sleep(0.15)
                return await real_record(*args, **kwargs)

            monkeypatch.setattr(service, "_argon2", fixed_wrong)
            monkeypatch.setattr(store, "increment_login_failure", slow_increment)
            monkeypatch.setattr(store, "record_audit", slow_record)
            steps.next_code()
            started = time.time()
            out = await service.login(ADMIN_USERNAME, "any-candidate", totp_code=steps.wrong_code())
            answered = time.time() - started
            assert not out.ok
            rows = await store.list_audit(actor=ADMIN_USERNAME, action="auth.login_failed", limit=1)
            row_at = float(rows[0]["ts"]) - started
            # The row: WHICH half-budget slot it lands in (floor), since the write point is that
            # slot's start. The answer: rounded to half-budget units, as AC-6 rounds to slots.
            return math.floor(row_at / (budget / 2)), round(answered / (budget / 2))
        finally:
            await store.close()

    lock_path = await measure(second_step_locked=True)
    verified_path = await measure(second_step_locked=False)
    assert lock_path == verified_path, (
        f"(row, answer) tells the paths apart: lock={lock_path} verified={verified_path}"
    )
    assert lock_path == (1, 2), lock_path


async def test_a_cancelled_refusal_still_writes_its_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rows now wait for a fixed point in the pad, so a caller who drops the request before it
    must not also drop the audit trail: the count-and-log rule holds for a refused attempt too."""
    import messagefoundry.auth.service as svc

    monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", 2.0)
    store = await _store()
    try:
        service = AuthService(store, _lock_settings())
        await _totp_admin(service, monkeypatch)

        async def fixed_wrong(fn: Any, *args: Any) -> Any:
            await asyncio.sleep(0.04)
            return False

        monkeypatch.setattr(service, "_argon2", fixed_wrong)
        before = len(await store.list_audit(actor=ADMIN_USERNAME, action="auth.login_failed"))
        attempt = asyncio.ensure_future(service.login(ADMIN_USERNAME, "wrong"))
        await asyncio.sleep(0.3)  # after the verify and the count, before the write point
        attempt.cancel()
        with pytest.raises(asyncio.CancelledError):
            await attempt
        for _ in range(50):
            rows = await store.list_audit(actor=ADMIN_USERNAME, action="auth.login_failed")
            if len(rows) > before:
                break
            await asyncio.sleep(0.05)
        assert len(rows) == before + 1, "a cancelled refusal lost its audit row"
    finally:
        await store.close()


# --- Round 3 (Manager decisions 2026-09-28): the status meter and three rarer log lines ------------


async def test_the_status_log_size_and_audit_count_are_withheld_from_a_reader_without_users_manage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``GET /status`` reports the log directory's byte total to ``monitoring:read``, which the
    Auditor and the Operator hold. That total counts the tee's copy of every hidden lock row, so it
    grows by one line when a lock lands. It is null for them now; an Administrator still reads it,
    and everyone keeps the free-space half the console's disk check reads."""
    world = await _open_world(tmp_path, monkeypatch)
    try:
        await _add_reader(world.service, "test-operator", Role.OPERATOR)
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        (log_dir / "service.log").write_text(_tee_line("auth.login_failed", "x") + "\n")
        app = create_app(world.engine, auth=world.service, log_dir=str(log_dir))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=_PEER), base_url="http://t"
        ) as c:
            logs: dict[str, dict[str, Any]] = {}
            audit_count: dict[str, Any] = {}
            for reader in (_AUDITOR, "test-operator", _SECOND_ADMIN):
                r = await c.get("/status", headers=await _bearer(c, reader))
                assert r.status_code == 200, r.text
                logs[reader] = r.json()["logs"]
                audit_count[reader] = r.json()["db"]["audit"]
        assert logs[_AUDITOR]["size_bytes"] is None, logs[_AUDITOR]
        assert logs["test-operator"]["size_bytes"] is None, logs["test-operator"]
        assert (
            isinstance(logs[_SECOND_ADMIN]["size_bytes"], int) and logs[_SECOND_ADMIN]["size_bytes"]
        )
        for reader in logs:
            assert logs[reader]["disk_free_bytes"] is not None, (reader, logs[reader])
        # The audit_log row count includes the hidden rows too, so it minus the rows GET /audit
        # returns was their exact number (review round 3).
        assert audit_count[_AUDITOR] is None and audit_count["test-operator"] is None, audit_count
        assert isinstance(audit_count[_SECOND_ADMIN], int) and audit_count[_SECOND_ADMIN] > 0
    finally:
        await world.engine.stop()


async def test_a_failed_throttle_read_names_neither_the_account_nor_the_lock(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The lock-notice throttle read runs only when a lock lands. When it fails, the line still
    tells an operator the read failed (the control), but names neither the account nor the notice."""
    store = await _store()
    try:
        service = AuthService(store, _lock_settings(), security_notifier=_FakeNotifier())
        identity, password, steps = await _totp_admin(service, monkeypatch)
        await store.set_user_notify_email(identity.user_id, email="owner@example.test")
        await _set_sign_in_lock(store, identity.user_id)
        real_list = store.list_audit

        async def failing_list(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("action") == "auth.lock_notice":
                raise RuntimeError("store read failed")
            return await real_list(*args, **kwargs)

        monkeypatch.setattr(store, "list_audit", failing_list)
        caplog.clear()
        with caplog.at_level(logging.INFO):
            for _ in range(_LOCK_THRESHOLD):
                steps.next_code()
                sent = await service.login(ADMIN_USERNAME, password, totp_code=steps.wrong_code())
                assert not sent.ok
        assert [r for r in caplog.records if "throttle read failed" in r.getMessage()], (
            "the control: the failed read was not reported at all"
        )
        leaks = _leaking(caplog, ADMIN_USERNAME, "account_locked", "lock-notice", "lock_notice")
        assert leaks == [], leaks
    finally:
        await store.close()


def test_a_broken_tee_sink_logs_once_and_names_no_action(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A line per failed tee row named the row's action, and the line count tracked the rows, the
    hidden lock rows included. The failure is now logged once per process, naming no action. The
    control is that first line: a broken sink is still reported."""
    from messagefoundry.store import audit_tee

    monkeypatch.setattr(audit_tee, "_TEE_FAILURE_LOGGED", False, raising=False)

    def broken(*_: Any, **__: Any) -> None:
        raise OSError("sink down")

    monkeypatch.setattr(audit_tee.audit_logger, "info", broken)
    with caplog.at_level(logging.WARNING, logger=audit_tee.log.name):
        for n, action in enumerate(
            ("auth.login_failed", "auth.account_locked", "auth.lock_notice")
        ):
            audit_tee.emit_audit_tee(
                action=action,
                actor=ADMIN_USERNAME,
                channel_id=None,
                detail=None,
                ts=1.0,
                row_id=n,
                row_hash="h",
            )
    lines = [r.getMessage() for r in caplog.records if r.name == audit_tee.log.name]
    assert len(lines) == 1, lines
    assert "tee failed" in lines[0]
    assert "account_locked" not in lines[0] and "auth." not in lines[0], lines[0]


def test_smtp_verification_off_is_logged_once_and_before_the_first_notice(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """``tls_verify=false`` logged a WARNING on every SMTP send, lock notices included. It is
    logged once per process for each relay. The security notifier logs it when it is built, so the
    first send, which may be a lock notice, adds no line. The control is that one line."""
    from messagefoundry.config import tls_policy
    from messagefoundry.pipeline.security_notify import SecurityEventNotifier

    monkeypatch.setattr(tls_policy, "_SMTP_VERIFY_OFF_WARNED", set(), raising=False)
    with caplog.at_level(logging.WARNING, logger=tls_policy.logger.name):
        SecurityEventNotifier(
            host="smtp.example.test",
            port=25,
            sender="mf@example.test",
            use_tls=True,
            tls_verify=False,
        )
        built = [r for r in caplog.records if "DISABLED" in r.getMessage()]
        assert len(built) == 1, "the control: verification-off was not reported at all"
        for _ in range(3):
            tls_policy.build_smtp_tls_context(
                host="smtp.example.test", cell="alerts SMTP transport", verify=False
            )
    lines = [r for r in caplog.records if "DISABLED" in r.getMessage()]
    assert len(lines) == 1, [r.getMessage() for r in lines]


def test_a_failed_key_exchange_pin_is_logged_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A TLS context is built per SMTP send, so a failed key-exchange pin logged once per mail, lock
    notices included. It is logged once per process. The control is that one line."""
    from types import SimpleNamespace
    from typing import cast

    from messagefoundry.config import tls_policy

    monkeypatch.setattr(tls_policy, "_KEX_PIN_WARNED", False, raising=False)

    def refuse(_groups: Any) -> None:
        raise ValueError("no such group")

    ctx = cast("Any", SimpleNamespace(set_groups=refuse))
    with caplog.at_level(logging.WARNING, logger=tls_policy.logger.name):
        for _ in range(3):
            assert tls_policy.harden_kex_groups(ctx) is None
    lines = [r for r in caplog.records if "key-exchange groups" in r.getMessage()]
    assert len(lines) == 1, [r.getMessage() for r in lines]


async def test_a_cancel_as_the_writes_finish_is_not_swallowed() -> None:
    """``_write_through_cancellation`` re-raises a cancel even when it lands in the turn the writes
    finish, so a caller's timeout still fires."""
    from messagefoundry.auth.service import _write_through_cancellation

    written: list[str] = []

    async def write() -> None:
        await asyncio.sleep(0.05)
        written.append("row")

    task = asyncio.ensure_future(_write_through_cancellation([write]))
    await asyncio.sleep(0.05)  # about when the write finishes
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert written == ["row"], "the write was abandoned"
