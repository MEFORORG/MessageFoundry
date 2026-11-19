# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness sign-in dialog keeps the GUI thread free while the engine answers (BACKLOG #5946).

Both of its engine calls, the provider read at construction and the sign-in itself, used to run on
the Qt main thread, so a stalled engine or a slow directory froze the dialog until the client
timeout. Each fake call here blocks until the test releases it: on the old code the constructor or
``_attempt`` would not return until then, and the test would deadlock against its own gate.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

pytest.importorskip("PySide6")

from harness._login import LoginDialog  # noqa: E402
from messagefoundry.api.auth_models import (  # noqa: E402
    CurrentUser,
    LoginResponse,
    ProvidersInfo,
)

_WAIT = 10.0


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


class _GatedClient:
    """Each call blocks until its gate opens, then answers. A gate left shut times out, failing
    loudly, so a regression to a GUI-thread call cannot hang the suite."""

    def __init__(self) -> None:
        self.providers_gate = threading.Event()
        self.login_gate = threading.Event()
        self.login_threads: list[threading.Thread] = []

    def providers(self) -> ProvidersInfo:
        if not self.providers_gate.wait(_WAIT):
            raise TimeoutError("providers gate never opened")
        return ProvidersInfo(local=True, ad=True)

    def login(self, *_a: object, **_kw: object) -> LoginResponse:
        self.login_threads.append(threading.current_thread())
        if not self.login_gate.wait(_WAIT):
            raise TimeoutError("login gate never opened")
        return LoginResponse(
            token="t",
            must_change_password=False,
            user=CurrentUser(
                user_id="u", username="op", auth_provider="local", roles=[], permissions=[]
            ),
        )


def _until(qapp: Any, cond: Any) -> bool:
    deadline = time.time() + _WAIT
    while time.time() < deadline:
        qapp.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    return False


def test_the_provider_read_and_the_sign_in_run_off_the_gui_thread(qapp: Any) -> None:
    client = _GatedClient()
    started = time.monotonic()
    dialog = LoginDialog(client)  # type: ignore[arg-type]
    try:
        assert time.monotonic() - started < _WAIT / 2, "the provider read blocked the constructor"
        assert not dialog._sign_in.isEnabled()  # one engine call at a time on the client
        client.providers_gate.set()
        assert _until(qapp, lambda: not dialog._busy)
        assert dialog._provider.count() == 2  # the AD option the late reply named

        dialog._username.setText("op")
        dialog._password.setText("pw")
        started = time.monotonic()
        dialog._attempt()
        assert time.monotonic() - started < _WAIT / 2, "the sign-in blocked the GUI thread"
        assert _until(qapp, lambda: bool(client.login_threads))
        assert client.login_threads[0] is not threading.main_thread()
        assert not dialog._sign_in.isEnabled()

        # Closing while the sign-in is in flight would drop a session the engine may have made.
        finished: list[int] = []
        dialog.finished.connect(finished.append)
        dialog.reject()
        assert finished == []
        assert dialog._signing_in

        client.login_gate.set()
        assert _until(qapp, lambda: finished == [dialog.DialogCode.Accepted.value])
    finally:
        client.providers_gate.set()
        client.login_gate.set()
        dialog.done(dialog.DialogCode.Rejected)


def test_a_close_during_the_provider_read_is_taken_when_it_answers(qapp: Any) -> None:
    client = _GatedClient()
    dialog = LoginDialog(client)  # type: ignore[arg-type]
    finished: list[int] = []
    dialog.finished.connect(finished.append)
    try:
        started = time.monotonic()
        dialog.reject()  # held, not a blocking wait on the worker
        assert time.monotonic() - started < 1.0
        assert finished == []
        assert "Waiting for the engine" in dialog._error.text()
        client.providers_gate.set()
        assert _until(qapp, lambda: finished == [dialog.DialogCode.Rejected.value])
    finally:
        client.providers_gate.set()
        client.login_gate.set()
