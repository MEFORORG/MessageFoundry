# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5908: the managed lifespan builds its two notifiers and the AuthService in a worker
thread, so their blocking work does not stall the event loop during startup.

What each build blocks on is stated once, in the lifespan's comments in messagefoundry/api/app.py.
Each spy records the thread it ran on; the loop's own thread is the one
this test runs on. A failure raised in the worker thread must still unwind what the lifespan
opened, so the store and the alert notifier close as they did when the build ran inline.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.api.app as appmod
from messagefoundry.api import create_managed_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AlertsSettings, AuthSettings, EgressSettings
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.security_notify import SecurityEventNotifier
from messagefoundry.store import open_store

_SECURITY = "security_notifier_from_settings"
_AUTH = "AuthService"


class _Seen:
    def __init__(self) -> None:
        self.threads: dict[str, int] = {}
        self.store: Any = None
        self.store_closed = False
        self.notifier: Any = None
        self.security_notifier: SecurityEventNotifier | None = None
        # Set only by a close of a STARTED sink, so a never-started one cannot pass as drained.
        self.notifier_drained = False


def _app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seen: _Seen, *, raises_in: str = ""
) -> Any:
    def _probe(name: str) -> None:
        seen.threads[name] = threading.get_ident()
        if raises_in == name:
            raise RuntimeError(f"PROBE: deliberate failure in {name}")

    def _notifier(*_args: Any, **_kwargs: Any) -> NotifierAlertSink:
        seen.threads["notifier_from_settings"] = threading.get_ident()
        sink: Any = NotifierAlertSink([])
        real_aclose = sink.aclose

        async def _aclose() -> None:
            if sink._task is not None:
                seen.notifier_drained = True
            await real_aclose()

        sink.aclose = _aclose
        seen.notifier = sink
        return sink

    def _security_notifier(*_args: Any, **_kwargs: Any) -> SecurityEventNotifier:
        _probe(_SECURITY)
        # A real, unstarted notifier: bare AlertsSettings configures no SMTP, so the real factory
        # would return None and leave the lifespan's start() of it untested.
        notifier = SecurityEventNotifier(
            host="smtp.example.test",
            port=587,
            sender="mf@example.test",
            allowed_hosts=("smtp.example.test",),
        )
        seen.security_notifier = notifier
        return notifier

    class _SpyAuthService(AuthService):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            _probe(_AUTH)
            super().__init__(*args, **kwargs)

    async def _open(*args: Any, **kwargs: Any) -> Any:
        store: Any = await open_store(*args, **kwargs)
        real_close = store.close

        async def _close() -> None:
            seen.store_closed = True
            await real_close()

        store.close = _close
        seen.store = store
        return store

    monkeypatch.setattr(appmod, "notifier_from_settings", _notifier)
    monkeypatch.setattr(appmod, "security_notifier_from_settings", _security_notifier)
    monkeypatch.setattr(appmod, "AuthService", _SpyAuthService)
    monkeypatch.setattr(appmod, "open_store", _open)
    return create_managed_app(
        db_path=tmp_path / "probe.db",
        poll_interval=0.05,
        auth_settings=AuthSettings(),
        # The written waiver, so the notice gate does not refuse an empty store's start.
        alerts_settings=AlertsSettings(security_notifications_required=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )


async def _close_leftovers(seen: _Seen) -> None:
    # Red, the lifespan left these open; close them so the test process can still exit.
    if seen.security_notifier is not None and seen.security_notifier._task is not None:
        await seen.security_notifier.aclose()
    if seen.notifier is not None and seen.notifier._task is not None:
        await seen.notifier.aclose()
    if seen.store is not None and not seen.store_closed:
        await seen.store.close()


async def test_the_lifespan_builds_both_notifiers_and_the_auth_service_off_the_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _Seen()
    app = _app(tmp_path, monkeypatch, seen)
    loop_thread = threading.get_ident()
    try:
        async with app.router.lifespan_context(app):
            # start() stays on the loop: the notifier built in the thread is the one running.
            assert seen.notifier is not None and seen.notifier._task is not None
            assert seen.security_notifier is not None
            assert seen.security_notifier._task is not None
        assert seen.store_closed
        assert seen.security_notifier._task is None, "the security notifier was not drained"
    finally:
        await _close_leftovers(seen)
    # The spies record their thread only while the lifespan builds, so these read the same
    # record after it exits. They sit at the test's top level, where the vacuous-absence lint
    # (tests/test_vacuous_absence_assert_lint.py) reads a guard; inside the try it reads none.
    # The control: every spy ran, so an absent entry cannot pass as off the loop.
    assert set(seen.threads) == {"notifier_from_settings", _SECURITY, _AUTH}
    # Implied by the line above at runtime; it is the count the lint reads as the guard.
    assert len(seen.threads) >= 3
    on_loop = sorted(name for name, ident in seen.threads.items() if ident == loop_thread)
    assert not on_loop, f"built on the event loop's thread: {on_loop}"


@pytest.mark.parametrize("raises_in", [_SECURITY, _AUTH])
async def test_a_raise_in_a_threaded_build_closes_the_store_and_notifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raises_in: str
) -> None:
    seen = _Seen()
    app = _app(tmp_path, monkeypatch, seen, raises_in=raises_in)
    try:
        with pytest.raises(RuntimeError, match=f"PROBE: deliberate failure in {raises_in}"):
            async with app.router.lifespan_context(app):
                pytest.fail("startup should have failed")
        # The controls: the probe ran in a worker thread, after the store opened.
        assert seen.threads[raises_in] != threading.get_ident()
        assert seen.store is not None
        assert seen.store_closed, "the store was left open"
        assert seen.notifier_drained, "the alert notifier was never started and drained"
        assert seen.notifier._task is None, "the alert notifier's drain task was left running"
    finally:
        await _close_leftovers(seen)


async def test_a_value_error_from_the_threaded_notifier_factory_still_refuses_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no CA refusal beside it, the factory's ValueError is re-raised, not swallowed."""
    seen = _Seen()
    app = _app(tmp_path, monkeypatch, seen)

    def _refuse(*_args: Any, **_kwargs: Any) -> NotifierAlertSink:
        seen.threads["notifier_from_settings"] = threading.get_ident()
        raise ValueError("PROBE: deliberate notifier refusal")

    monkeypatch.setattr(appmod, "notifier_from_settings", _refuse)
    with pytest.raises(ValueError, match="PROBE: deliberate notifier refusal"):
        async with app.router.lifespan_context(app):
            pytest.fail("startup should have failed")
    assert seen.threads["notifier_from_settings"] != threading.get_ident()
    # Refused before the store opens, so there is nothing to close.
    assert seen.store is None
