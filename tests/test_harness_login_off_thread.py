# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness sign-in dialog keeps the GUI thread free while the engine answers (BACKLOG #5946).

Both of its engine calls, the provider read at construction and the sign-in itself, used to run on
the Qt main thread, so a stalled engine or a slow directory froze the dialog until the client
timeout. Each fake call here blocks until the test releases it: on the old code the constructor or
``_attempt`` would not return until then, and the test would deadlock against its own gate.
"""

from __future__ import annotations

import logging
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
from messagefoundry.apiclient import ApiError  # noqa: E402

_WAIT = 10.0
_TOKEN = "synthetic-session-token"  # nosec B105 (a fake for the gated client)
# A forged log line, then a body far past the bound. Synthetic text only.
_HOSTILE = "refused\r\nFORGED harness._login: signed in as admin\n" + "x" * 5000


def _one_bounded_quoted_record(
    caplog: pytest.LogCaptureFixture, *, hostile: bool = True
) -> logging.LogRecord:
    """The dialog logged exactly one record for the hostile text: cut to the client's bound and
    quoted with %r, so no CR or LF reaches the formatted line."""
    from messagefoundry.apiclient.client import _REVOKE_LOG_CHARS

    logged = [r for r in caplog.records if r.name == "harness._login"]
    assert len(logged) == 1
    record = logged[0]
    assert record.exc_info is None  # a traceback would carry the raw text again
    line = record.getMessage()
    assert "\r" not in line and "\n" not in line
    if hostile:
        assert "FORGED" in line  # quoted, not dropped
    assert len(line) < _REVOKE_LOG_CHARS + 200
    return record


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
        self.logout_threads: list[threading.Thread] = []
        self.logout_error: BaseException | None = None
        self.logout_gate = threading.Event()
        self.logout_gate.set()
        self.token: str | None = None
        self.providers_error: BaseException | None = None
        self.login_error: BaseException | None = None

    def providers(self) -> ProvidersInfo:
        if not self.providers_gate.wait(_WAIT):
            raise TimeoutError("providers gate never opened")
        if self.providers_error is not None:
            raise self.providers_error
        return ProvidersInfo(local=True, ad=True)

    def login(self, *_a: object, **_kw: object) -> LoginResponse:
        self.login_threads.append(threading.current_thread())
        if not self.login_gate.wait(_WAIT):
            raise TimeoutError("login gate never opened")
        if self.login_error is not None:
            raise self.login_error
        self.token = _TOKEN
        return LoginResponse(
            token=_TOKEN,
            must_change_password=False,
            user=CurrentUser(
                user_id="u", username="op", auth_provider="local", roles=[], permissions=[]
            ),
        )

    def logout(self) -> None:
        # As EngineClient.logout: the token is cleared after the attempt, whatever its outcome.
        self.logout_threads.append(threading.current_thread())
        try:
            if not self.logout_gate.wait(_WAIT):
                raise TimeoutError("logout gate never opened")
            if self.logout_error is not None:
                raise self.logout_error
        finally:
            self.token = None


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

        # A close while the sign-in is in flight is held until it answers, then taken: the cancel
        # wins over a sign-in that succeeded, so the dialog is rejected, not accepted.
        finished: list[int] = []
        dialog.finished.connect(finished.append)
        dialog.reject()
        assert finished == []
        assert dialog._signing_in

        client.login_gate.set()
        assert _until(qapp, lambda: finished == [dialog.DialogCode.Rejected.value])
        assert dialog.entered_password == ""  # nothing handed back to the caller
        # The cancelled sign-in's session was ended once, off the GUI thread, before the reject.
        assert len(client.logout_threads) == 1
        assert client.logout_threads[0] is not threading.main_thread()
        assert client.token is None
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


def test_an_unexpected_sign_in_error_is_logged(qapp: Any, caplog: pytest.LogCaptureFixture) -> None:
    # A non-ApiError is a fault in the dialog or the client, not the engine's answer: it is shown,
    # and logged with its traceback so the cause is not lost (REVIEW-STANDARDS R8).
    import logging

    from messagefoundry.apiclient import ApiError

    client = _GatedClient()
    client.providers_gate.set()
    dialog = LoginDialog(client)  # type: ignore[arg-type]
    try:
        assert _until(qapp, lambda: not dialog._busy)
        with caplog.at_level(logging.ERROR, logger="harness._login"):
            dialog._on_login_error(RuntimeError("boom"))
            dialog._on_login_error(ApiError("refused", status=401))
        logged = [r for r in caplog.records if r.name == "harness._login"]
        assert len(logged) == 1
        assert logged[0].exc_info is not None
        raised = logged[0].exc_info[1]
        assert isinstance(raised, RuntimeError) and raised.args == ("boom",)
        assert dialog._error.text() == "Sign-in failed."
    finally:
        client.login_gate.set()
        dialog.done(dialog.DialogCode.Rejected)


@pytest.mark.parametrize(
    "error",
    [
        ApiError("engine refused", status=500),
        TimeoutError("timed out"),
        ApiError(_HOSTILE, status=500),
    ],
    ids=["refused", "stalled", "hostile-text"],
)
def test_a_failed_logout_after_a_cancelled_sign_in_is_logged_and_still_rejects(
    qapp: Any, caplog: pytest.LogCaptureFixture, error: BaseException
) -> None:
    client = _GatedClient()
    client.providers_gate.set()
    client.logout_gate.clear()
    client.logout_error = error
    dialog = LoginDialog(client)  # type: ignore[arg-type]
    finished: list[int] = []
    dialog.finished.connect(finished.append)
    try:
        assert _until(qapp, lambda: not dialog._busy)
        dialog._username.setText("op")
        dialog._password.setText("pw")
        dialog._attempt()
        dialog.reject()
        with caplog.at_level(logging.ERROR, logger="harness._login"):
            client.login_gate.set()
            assert _until(qapp, lambda: bool(client.logout_threads))
            # The logout is stalled: the dialog stays open and busy until it answers.
            dialog.reject()
            assert finished == []
            client.logout_gate.set()
            assert _until(qapp, lambda: finished == [dialog.DialogCode.Rejected.value])
        record = _one_bounded_quoted_record(caplog, hostile=error.args[0] == _HOSTILE)
        assert type(error).__name__ in record.getMessage()
        assert "until it expires" in record.getMessage()
        assert dialog.session_may_remain  # the caller is told, not only the log
        assert client.logout_threads[0] is not threading.main_thread()
        assert client.token is None
    finally:
        client.login_gate.set()
        client.logout_gate.set()
        dialog.done(dialog.DialogCode.Rejected)


def test_a_provider_read_refusal_is_logged_bounded_and_quoted(
    qapp: Any, caplog: pytest.LogCaptureFixture
) -> None:
    client = _GatedClient()
    client.providers_error = ApiError(_HOSTILE, status=503)
    with caplog.at_level(logging.INFO, logger="harness._login"):
        dialog = LoginDialog(client)  # type: ignore[arg-type]
        try:
            client.providers_gate.set()
            assert _until(qapp, lambda: not dialog._busy)
        finally:
            client.login_gate.set()
            dialog.done(dialog.DialogCode.Rejected)
            # The raised error's traceback holds the dialog's frame; drop it so no Qt cycle is left.
            if client.providers_error is not None:
                client.providers_error.__traceback__ = None
    _one_bounded_quoted_record(caplog)
    assert dialog._provider.count() == 1  # Local only


def test_a_sign_in_refusal_after_a_held_close_is_logged_bounded_and_quoted(
    qapp: Any, caplog: pytest.LogCaptureFixture
) -> None:
    # The close is taken when the refusal lands, so nothing shows it: the log is its only trace (R8).
    client = _GatedClient()
    client.providers_gate.set()
    client.login_error = ApiError(_HOSTILE, status=403)
    dialog = LoginDialog(client)  # type: ignore[arg-type]
    finished: list[int] = []
    dialog.finished.connect(finished.append)
    try:
        assert _until(qapp, lambda: not dialog._busy)
        dialog._username.setText("op")
        dialog._password.setText("pw")
        dialog._attempt()
        dialog.reject()
        with caplog.at_level(logging.INFO, logger="harness._login"):
            client.login_gate.set()
            assert _until(qapp, lambda: finished == [dialog.DialogCode.Rejected.value])
        _one_bounded_quoted_record(caplog)
        assert client.logout_threads == []  # no session was made, so none is ended
        assert not dialog.session_may_remain
    finally:
        client.login_gate.set()
        dialog.done(dialog.DialogCode.Rejected)
        # The raised error's traceback holds the worker's frames; drop it so no Qt cycle is left.
        if client.login_error is not None:
            client.login_error.__traceback__ = None
        client.login_error = None
