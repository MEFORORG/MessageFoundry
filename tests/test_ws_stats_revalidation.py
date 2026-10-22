# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SEC-018 — /ws/stats must stop streaming promptly after a session is revoked/downgraded.

The feed authorizes at handshake, then re-resolves the caller before EVERY frame, the first
included (BACKLOG #1154; it used to re-check every 3 s). These tests drive the real ASGI
``/ws/stats`` route through a tiny in-memory websocket harness on the test's own event loop (so the
engine/store stay loop-consistent), monkeypatch the frame interval small for speed, and assert a
1008 close lands at the next frame."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
from starlette.websockets import WebSocket

from messagefoundry.api import app as app_module
from messagefoundry.api import create_app
from messagefoundry.api.security import recheck_standing, recheck_standing_or_refusal
from messagefoundry.auth import Identity, Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen
from tests._refusal_log_capture import record_texts

PW = "Sup3rSecret!!"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "ws.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    return user_id


class _WSHarness:
    """A minimal in-memory ASGI websocket peer that drives the real /ws/stats route on this loop.

    Collects every frame the server sends and exposes the close code; ``run`` returns once the server
    half closes the connection (a 1008 revocation close or a disconnect)."""

    def __init__(self, app: object, token: str) -> None:
        self._app = app
        self._token = token
        self._to_server: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self.frames: list[dict[str, object]] = []
        self.close_code: int | None = None

    async def _receive(self) -> dict[str, object]:
        return await self._to_server.get()

    async def _send(self, message: dict[str, object]) -> None:
        kind = message["type"]
        if kind == "websocket.accept":
            return
        if kind == "websocket.send":
            self.frames.append(json.loads(message["text"]))  # type: ignore[arg-type]
            return
        if kind == "websocket.close":
            code = message.get("code", 1000)
            assert isinstance(code, int)
            self.close_code = code
            return

    async def run(self, timeout: float) -> None:
        scope = {
            "type": "websocket",
            "path": "/ws/stats",
            "headers": [(b"authorization", f"Bearer {self._token}".encode())],
            "query_string": b"",
            "subprotocols": [],
            "client": ("127.0.0.1", 9999),
            "scheme": "ws",
            "app": None,
        }
        # The handshake connect message; the server accepts then streams until it closes.
        await self._to_server.put({"type": "websocket.connect"})
        await asyncio.wait_for(self._app(scope, self._receive, self._send), timeout)  # type: ignore[operator]


async def _login_token(service: AuthService, username: str) -> str:
    token = (await service.login(username, PW)).token
    assert token is not None
    return token


#: Bound on waiting for the server's FIRST stats frame. Generous on purpose: this is a scheduling wait
#: on a possibly-loaded CI runner, not a behavioural timeout. The pytest-level timeout (60 s) is the
#: real backstop against a hang, and the deliberately-slow-`stats()` regression test below is what
#: proves the wait is load-bearing rather than decorative.
_FIRST_FRAME_TIMEOUT = 10.0

#: The harness's own budget must exceed the first-frame wait PLUS the close it then waits for, or the
#: harness would time out while we were still legitimately waiting and the failure would point at the
#: route instead of at the clock.
_HARNESS_TIMEOUT = 20.0


async def _wait_for_first_frame(harness: _WSHarness, task: asyncio.Task[None]) -> None:
    """Wait until the server has actually sent a frame, instead of sleeping a fixed 50 ms and hoping.

    The fixed sleep was a race, and it FAILED on `main` @ ``be2fc08c``, ``test (windows-2022,
    py3.14)``::

        assert harness.frames, "expected at least one stats frame before revocation"
        AssertionError: assert []

    50 ms had to cover scheduling the harness task, the handshake, the handshake-time authorize *and*
    the ``store.stats()`` query the first frame is built from — none of which these tests are
    measuring. Polling the **actual asserted condition** makes the precondition deterministic without
    weakening it: a frame is still required, and still required *before* the revocation. It also makes
    what the test exercises deterministic, which the sleep did not — on a slow box the revocation
    landed before the first send, silently exercising the pre-first-send path that
    ``test_revoke_before_first_send_yields_no_frames`` already owns.

    If the task dies first, surface THAT: a route that raised would otherwise be indistinguishable
    from a slow one, and "timed out waiting for a frame" is the least useful description of a
    traceback.
    """
    await _wait_for_frames(harness, task, 1)


async def _wait_for_frames(harness: _WSHarness, task: asyncio.Task[None], count: int) -> None:
    """:func:`_wait_for_first_frame` for ``count`` frames, with the same dead-task surfacing."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _FIRST_FRAME_TIMEOUT
    while len(harness.frames) < count:
        if task.done():
            task.result()  # re-raise the real failure if the route blew up
            raise AssertionError(
                f"the /ws/stats task finished after {len(harness.frames)} of {count} frames "
                f"(close_code={harness.close_code})"
            )
        if loop.time() >= deadline:
            raise AssertionError(
                f"fewer than {count} stats frames within {_FIRST_FRAME_TIMEOUT}s "
                f"(close_code={harness.close_code}, frames={harness.frames})"
            )
        await asyncio.sleep(0.01)


async def test_revoked_session_is_closed_promptly(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.1)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    task = asyncio.create_task(harness.run(timeout=_HARNESS_TIMEOUT))
    # Wait for the first frame to actually land, then revoke the session server-side.
    await _wait_for_first_frame(harness, task)
    assert harness.frames, "expected at least one stats frame before revocation"
    await service.revoke_sessions_for_user(uid, actor="admin")
    await task
    assert harness.close_code == 1008


async def test_disabled_account_is_closed(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.1)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    task = asyncio.create_task(harness.run(timeout=_HARNESS_TIMEOUT))
    # Wait for a frame first, so "mid-stream" is a fact rather than an aspiration. With the old fixed
    # sleep this test still PASSED on a slow box while exercising the wrong path — the account was
    # disabled before the first send, so the close came from the pre-first-send re-check instead of the
    # mid-stream re-check. Same 1008 either way, so nothing failed and the coverage quietly moved.
    await _wait_for_first_frame(harness, task)
    # disable the account mid-stream → identity_for_token returns None → the feed must close
    await engine.store.set_user_disabled(uid, disabled=True)
    await task
    assert harness.close_code == 1008


async def test_a_slow_first_stats_build_does_not_break_the_precondition(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reproduce the CI failure deterministically, so the fix is proven rather than observed.

    The first frame cannot be sent until ``store.stats()`` returns — the route awaits it, builds the
    frame, then sends. The old fixed 50 ms sleep had to cover that query *plus* task scheduling, the
    handshake and the handshake-time authorize. Stall the query well past 50 ms and the old form fails
    **every time** instead of once per loaded runner.

    This is the property the original flake never had: revert ``_wait_for_first_frame`` to
    ``await asyncio.sleep(0.05)`` and this test goes red on any machine, which is why it is worth more
    than a green CI run. A load-dependent failure that only reproduces on a busy Windows runner is not
    something you can iterate against.
    """
    real_stats = engine.store.stats

    async def slow_stats() -> dict[str, int]:
        await asyncio.sleep(0.4)  # 8x the old budget — deterministic on any machine
        return await real_stats()

    monkeypatch.setattr(engine.store, "stats", slow_stats)
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.1)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    task = asyncio.create_task(harness.run(timeout=_HARNESS_TIMEOUT))
    await _wait_for_first_frame(harness, task)
    assert harness.frames, "the slow stats build must still yield a frame, just later"
    await service.revoke_sessions_for_user(uid, actor="admin")
    await task
    assert harness.close_code == 1008


async def test_revoke_before_first_send_yields_no_frames(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A token revoked between handshake-authorize and the pre-first-send re-check must get NO frame.
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.1)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    # Revoke BEFORE running so the pre-first-send re-check closes it with zero frames.
    await service.revoke_sessions_for_user(uid, actor="admin")
    await harness.run(timeout=5.0)
    assert harness.frames == []
    assert harness.close_code == 1008


def _during_first_stats(
    monkeypatch: pytest.MonkeyPatch, engine: Engine, act: Callable[[], Awaitable[object]]
) -> None:
    """Run ``act`` once, inside the first frame's ``store.stats()`` call: after that frame's
    re-check and before its send, so that frame goes out and the second frame's re-check sees
    ``act``'s effect."""
    real_stats = engine.store.stats
    calls = 0

    async def stats_then_act() -> dict[str, int]:
        nonlocal calls
        calls += 1
        if calls == 1:
            await act()
        return await real_stats()

    monkeypatch.setattr(engine.store, "stats", stats_then_act)


async def test_no_frame_follows_a_revocation(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1154 (ASVS 8.3.2): the caller is re-resolved before EVERY frame, so a revocation
    lands before the next frame rather than within a 3 s window.

    The revocation runs inside the first frame's ``store.stats()`` call, which comes after that
    frame's re-check and before its send. So the first frame still goes out on the identity
    resolved for it, and the second frame's re-check must refuse: exactly one frame, on any
    machine speed. Under the old cadence (a re-check every 3 s, a frame every second) two more
    would follow."""
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.02)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    _during_first_stats(
        monkeypatch, engine, lambda: service.revoke_sessions_for_user(uid, actor="admin")
    )
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    await harness.run(timeout=_HARNESS_TIMEOUT)
    assert harness.close_code == 1008
    assert len(harness.frames) == 1, harness.frames


async def test_an_administrator_narrowing_closes_the_feed_rather_than_shrinking_a_frame(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3381. ``set_channel_scope`` revokes the session on every write, so an
    administrator's narrowing closes the feed with 1008 at the next frame. The narrowing runs to
    completion inside the first frame's ``store.stats()``, as in
    :func:`test_no_frame_follows_a_revocation`. So the revoke has landed before the second frame's
    re-check, and exactly one frame goes out. A re-check that ran between the scope write and its
    revoke could still send one frame on the smaller scope; this test does not reach that window."""
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.02)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    _during_first_stats(
        monkeypatch, engine, lambda: service.set_channel_scope(uid, ["IB_A"], actor="admin")
    )
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    await harness.run(timeout=_HARNESS_TIMEOUT)
    assert harness.close_code == 1008
    assert len(harness.frames) == 1, harness.frames


async def test_a_live_session_keeps_streaming_frame_after_frame(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the test above: with nothing withdrawn, the per-frame re-check passes and
    the feed keeps sending. A re-check that refused every caller would pass the revocation test.
    It also records no stop, so a stop row written on every frame, or on every pass of the
    re-check, cannot pass the stop-row tests below."""
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.02)
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    task = asyncio.create_task(harness.run(timeout=_HARNESS_TIMEOUT))
    try:
        await _wait_for_frames(harness, task, 3)
        assert harness.close_code is None
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    assert await _stop_rows(engine) == []


# --- BACKLOG #3404: a refused re-check records one stop row, naming why ----------------------------


async def _stop_rows(engine: Engine) -> list[dict[str, object]]:
    """Every ``ws_stats.stopped`` audit row, oldest first, as actor, client and parsed detail."""
    return [
        {"actor": row["actor"], "client": row["client"], **json.loads(row["detail"])}
        for row in reversed(await engine.store.list_audit(action="ws_stats.stopped", limit=50))
    ]


class _Notifier:
    """A wired security-notice channel. Wiring one is what makes an account with no notification
    address owe one (``AuthService.notify_email_required``)."""

    async def notify(self, event: object) -> bool:
        return True


async def _wire_a_notifier(service: AuthService, uid: str) -> None:
    service.attach_security_notifier(_Notifier())


async def _unmeet_the_second_factor(service: AuthService, uid: str) -> None:
    async def unmet(token: str | None) -> bool:
        return False

    service.mfa_satisfied = unmet  # type: ignore[method-assign]


async def _require_a_password_change(service: AuthService, uid: str) -> None:
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid,
        password_hash=user.password_hash,
        must_change_password=True,
        password_generated=False,
    )


async def _revoke(service: AuthService, uid: str) -> None:
    await service.revoke_sessions_for_user(uid, actor="admin")


@pytest.mark.parametrize(
    ("act", "reason"),
    [
        (_unmeet_the_second_factor, "mfa_unmet"),
        (_wire_a_notifier, "notify_email_due"),
        (_require_a_password_change, "password_change_due"),
        (_revoke, "session_ended"),
    ],
    ids=["second-factor", "notification-address", "password-change", "revoked"],
)
async def test_a_refused_recheck_records_one_stop_row_naming_why(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    act: Callable[[AuthService, str], Awaitable[None]],
    reason: str,
) -> None:
    """BACKLOG #3404. The per-frame re-check closed the feed with 1008 and recorded nothing, so an
    unmet second factor or a missing notification address ended a live feed with no trail. The
    gate's own refusals are audited (``auth.mfa_denied``, ``auth.permission_denied``); the
    re-check's were not.

    ``act`` runs inside the first frame's ``store.stats()``, as in
    :func:`test_no_frame_follows_a_revocation`, so exactly one frame goes out and the second
    frame's re-check refuses. The feed then writes exactly one row, naming the reason and the frames
    sent. The exact match is what keeps the token, or anything else, out of the row."""
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.02)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    _during_first_stats(monkeypatch, engine, lambda: act(service, uid))
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    await harness.run(timeout=_HARNESS_TIMEOUT)
    assert harness.close_code == 1008
    assert len(harness.frames) == 1, harness.frames
    assert await _stop_rows(engine) == [
        {"actor": "op", "client": "127.0.0.1", "reason": reason, "frames": 1}
    ]


async def test_a_refusal_before_the_first_frame_records_a_stop_with_no_frames(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3404, the pre-first-send re-check: a refusal between the handshake and the first
    frame records its stop too, with no frames sent."""
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.1)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    real_accept = WebSocket.accept

    async def accept_then_unmeet(self: WebSocket) -> None:
        await real_accept(self)
        await _unmeet_the_second_factor(service, uid)

    monkeypatch.setattr(WebSocket, "accept", accept_then_unmeet)
    harness = _WSHarness(app, token)
    await harness.run(timeout=_HARNESS_TIMEOUT)
    assert harness.frames == []
    assert harness.close_code == 1008
    assert await _stop_rows(engine) == [
        {"actor": "op", "client": "127.0.0.1", "reason": "mfa_unmet", "frames": 0}
    ]


async def test_the_refusal_names_a_permission_the_caller_does_not_hold(engine: Engine) -> None:
    """BACKLOG #3404, the reason the route cannot reach: a role change revokes the session, so the
    feed sees ``session_ended``. Asked directly, a permission the caller lacks names its own reason,
    and :func:`recheck_standing` still answers ``None`` for it and the identity for a live caller."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    assert (
        await recheck_standing_or_refusal(service, token, Permission.USERS_MANAGE)
        == "permission_withdrawn"
    )
    assert await recheck_standing(service, token, Permission.USERS_MANAGE) is None
    current = await recheck_standing_or_refusal(service, token, Permission.MONITORING_READ)
    assert isinstance(current, Identity) and current.username == "op"
    assert await recheck_standing(service, token, Permission.MONITORING_READ) == current


async def test_a_lapsed_factor_is_named_before_a_missing_address(engine: Engine) -> None:
    """BACKLOG #3404: the re-check runs in the gates' order, the factor first, so a session that
    fails both is named ``mfa_unmet``, as ``authorize_ws`` would audit it ``auth.mfa_denied``. The
    first assertion is the control: the missing address alone is named."""
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    await _wire_a_notifier(service, uid)
    assert (
        await recheck_standing_or_refusal(service, token, Permission.MONITORING_READ)
        == "notify_email_due"
    )
    await _unmeet_the_second_factor(service, uid)
    assert (
        await recheck_standing_or_refusal(service, token, Permission.MONITORING_READ) == "mfa_unmet"
    )


async def test_a_session_that_ends_during_the_factor_check_is_named_ended(engine: Engine) -> None:
    """BACKLOG #3404: the factor check reads the session again. A session that ends between the
    first resolve and that read fails the factor check, and must still be named ``session_ended``,
    not a lapsed factor on an account that may just have proved one."""
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    real_mfa_satisfied = service.mfa_satisfied

    async def revoke_then_check(token: str | None) -> bool:
        await service.revoke_sessions_for_user(uid, actor="admin")
        return await real_mfa_satisfied(token)

    service.mfa_satisfied = revoke_then_check  # type: ignore[method-assign]
    assert (
        await recheck_standing_or_refusal(service, token, Permission.MONITORING_READ)
        == "session_ended"
    )


def _replace_the_stop_row_write(
    monkeypatch: pytest.MonkeyPatch,
    engine: Engine,
    write: Callable[[], Awaitable[None]],
) -> None:
    """Run ``write`` in place of the ``ws_stats.stopped`` row's store write; other rows still land."""
    real_record_audit = engine.store.record_audit

    async def record_audit(action: str, **kwargs: Any) -> Any:
        if action == "ws_stats.stopped":
            return await write()
        return await real_record_audit(action, **kwargs)

    monkeypatch.setattr(engine.store, "record_audit", record_audit)


async def _refuse() -> None:
    raise RuntimeError("store refused the write")


@pytest.mark.parametrize("close_raises", [False, True], ids=["close-lands", "client-gone"])
async def test_a_failed_stop_row_write_is_logged_and_the_feed_still_closes(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    close_raises: bool,
) -> None:
    """BACKLOG #3404: a store that refuses the stop row leaves an ERROR record naming the actor, the
    client, the reason and the frames, and never the token. ``client-gone`` is the case the first build lost: the close
    raised too, Starlette turned that into ``WebSocketDisconnect``, and the route's catch of it
    swallowed the write's error. ``close-lands`` is the control, and pins the 1008 close."""
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.02)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    _replace_the_stop_row_write(monkeypatch, engine, _refuse)
    _during_first_stats(monkeypatch, engine, lambda: _revoke(service, uid))
    harness = _WSHarness(create_app(engine, auth=service), token)
    if close_raises:
        real_send = harness._send

        async def send_fails_on_close(message: dict[str, object]) -> None:
            if message["type"] == "websocket.close":
                raise OSError("client gone")
            await real_send(message)

        harness._send = send_fails_on_close  # type: ignore[method-assign]
    caplog.set_level(logging.ERROR, logger=app_module.__name__)
    await harness.run(timeout=_HARNESS_TIMEOUT)
    assert harness.close_code == (None if close_raises else 1008)
    assert len(harness.frames) == 1, harness.frames
    lost = [
        record
        for record in caplog.records
        if record.name == app_module.__name__ and record.levelno == logging.ERROR
    ]
    assert len(lost) == 1, caplog.records
    assert lost[0].getMessage() == (
        "ws_stats.stopped audit row not written. Lost row: actor=op client=127.0.0.1"
        " reason=session_ended frames=1"
    )
    assert lost[0].exc_info is not None
    assert not any(token in text for r in caplog.records for text in record_texts(r))


async def test_the_close_does_not_wait_for_the_stop_row(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3404: the feed closes, and gives its slot back, before it writes the stop row. A
    write that blocks would otherwise hold a refused caller's socket open and keep its slot from a
    new monitor socket, which the cap answers with 1013."""
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.02)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    write_started = asyncio.Event()
    release_write = asyncio.Event()

    async def blocking_write() -> None:
        write_started.set()
        await release_write.wait()

    _replace_the_stop_row_write(monkeypatch, engine, blocking_write)
    _during_first_stats(monkeypatch, engine, lambda: _revoke(service, uid))
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    task = asyncio.create_task(harness.run(timeout=_HARNESS_TIMEOUT))
    try:
        await asyncio.wait_for(write_started.wait(), _HARNESS_TIMEOUT)
        assert harness.close_code == 1008
        assert app.state.ws_count == 0
        assert not task.done()
    finally:
        release_write.set()
        await task


async def test_a_client_that_disconnects_mid_feed_records_no_stop(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3404: only a refused re-check writes a stop row. A client that goes away while its
    session still stands ends the feed through ``WebSocketDisconnect`` and records none, as
    SECURITY.md says. The first frame lands, so the send that fails is a later one."""
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.02)
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    harness = _WSHarness(create_app(engine, auth=service), token)
    real_send = harness._send

    async def gone_after_one_frame(message: dict[str, object]) -> None:
        if message["type"] == "websocket.send" and harness.frames:
            raise OSError("client gone")
        await real_send(message)

    harness._send = gone_after_one_frame  # type: ignore[method-assign]
    await harness.run(timeout=_HARNESS_TIMEOUT)
    assert len(harness.frames) == 1, harness.frames
    assert harness.close_code is None
    assert await _stop_rows(engine) == []
