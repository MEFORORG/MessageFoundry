# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SEC-018 — /ws/stats must stop streaming promptly after a session is revoked/downgraded.

The feed authorizes once at handshake then revalidates the session on an elapsed-time cadence
(``_WS_REVALIDATE_SECONDS``) AND once before the first post-accept send. These tests drive the real
ASGI ``/ws/stats`` route through a tiny in-memory websocket harness on the test's own event loop (so
the engine/store stay loop-consistent), monkeypatch the cadence small for determinism, and assert a
1008 close lands within ~the new cadence rather than waiting a full window."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.api import app as app_module
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "Sup3rSecret!!"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "ws.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    user_id = await service.create_local_user(
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
        user_id, password_hash=user.password_hash, must_change_password=False
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
            import json

            self.frames.append(json.loads(message["text"]))  # type: ignore[arg-type]
            return
        if kind == "websocket.close":
            self.close_code = int(message.get("code", 1000))  # type: ignore[arg-type]
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
    return (await service.login(username, PW)).token


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
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _FIRST_FRAME_TIMEOUT
    while not harness.frames:
        if task.done():
            task.result()  # re-raise the real failure if the route blew up
            raise AssertionError(
                f"the /ws/stats task finished before sending any frame "
                f"(close_code={harness.close_code})"
            )
        if loop.time() >= deadline:
            raise AssertionError(
                f"no stats frame within {_FIRST_FRAME_TIMEOUT}s "
                f"(close_code={harness.close_code}, frames={harness.frames})"
            )
        await asyncio.sleep(0.01)


async def test_revoked_session_is_closed_promptly(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "_WS_REVALIDATE_SECONDS", 0.1)
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
    monkeypatch.setattr(app_module, "_WS_REVALIDATE_SECONDS", 0.1)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    task = asyncio.create_task(harness.run(timeout=_HARNESS_TIMEOUT))
    # Wait for a frame first, so "mid-stream" is a fact rather than an aspiration. With the old fixed
    # sleep this test still PASSED on a slow box while exercising the wrong path — the account was
    # disabled before the first send, so the close came from the pre-first-send re-check instead of the
    # mid-stream revalidation. Same 1008 either way, so nothing failed and the coverage quietly moved.
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
    monkeypatch.setattr(app_module, "_WS_REVALIDATE_SECONDS", 0.1)
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
    monkeypatch.setattr(app_module, "_WS_REVALIDATE_SECONDS", 0.1)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    # Revoke BEFORE running so the pre-first-send revalidation closes it with zero frames.
    await service.revoke_sessions_for_user(uid, actor="admin")
    await harness.run(timeout=5.0)
    assert harness.frames == []
    assert harness.close_code == 1008
