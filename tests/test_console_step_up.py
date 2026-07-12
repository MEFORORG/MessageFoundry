# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless tests for the console step-up re-verification flow (WP-L3-16, ASVS 7.5.3):
the EngineClient 403->prompt->retry logic, and the ReauthDialog. The client tests need no Qt; the
dialog tests run Qt offscreen with a fake client (skipped if PySide6 isn't installed)."""

from __future__ import annotations

import json
import os

import httpx
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from messagefoundry.console.client import ApiError, EngineClient  # noqa: E402

_STEP_UP = {"X-Step-Up-Required": "1"}


def _mock_client(handler) -> EngineClient:
    c = EngineClient("http://127.0.0.1:8765")  # loopback plaintext is allowed
    c._http = httpx.Client(base_url=c.base_url, transport=httpx.MockTransport(handler))
    return c


class _Prompter:
    """Stand-in for the GUI step-up handler: records how often it was asked, returns a canned outcome."""

    def __init__(self, succeed: bool) -> None:
        self.succeed = succeed
        self.count = 0

    def __call__(self) -> bool:
        self.count += 1
        return self.succeed


# --- EngineClient step-up retry (no Qt) ------------------------------------------------------
def test_step_up_prompts_and_retries_on_success() -> None:
    n = {"req": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        n["req"] += 1
        if n["req"] == 1:
            return httpx.Response(403, headers=_STEP_UP, json={"detail": "step-up required"})
        return httpx.Response(200, json={"requeued": 1})

    c = _mock_client(handler)
    prompter = _Prompter(succeed=True)
    c.set_step_up_handler(prompter)
    resp = c._request("POST", "/dead-letters/replay")
    assert resp.status_code == 200
    assert prompter.count == 1  # prompted exactly once
    assert n["req"] == 2  # the original request + one retry


def test_step_up_declined_raises_403() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, headers=_STEP_UP, json={"detail": "step-up required"})

    c = _mock_client(handler)
    prompter = _Prompter(succeed=False)  # user cancels or enters the wrong password
    c.set_step_up_handler(prompter)
    with pytest.raises(ApiError) as ei:
        c._request("POST", "/dead-letters/replay")
    assert ei.value.status == 403
    assert prompter.count == 1  # asked once, then gave up (no retry loop)


def test_step_up_without_handler_raises_403() -> None:
    c = _mock_client(lambda r: httpx.Response(403, headers=_STEP_UP, json={"detail": "x"}))
    with pytest.raises(ApiError) as ei:
        c._request("POST", "/dead-letters/replay")
    assert ei.value.status == 403


def test_plain_403_does_not_prompt() -> None:
    # A permission-denied 403 (no X-Step-Up-Required header) is NOT a step-up — never prompt.
    c = _mock_client(lambda r: httpx.Response(403, json={"detail": "missing permission"}))
    prompter = _Prompter(succeed=True)
    c.set_step_up_handler(prompter)
    with pytest.raises(ApiError) as ei:
        c._request("GET", "/connections")
    assert ei.value.status == 403
    assert prompter.count == 0


def test_reauth_posts_password_without_recursing() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"detail": "re-verified"})

    c = _mock_client(handler)
    c.set_step_up_handler(_Prompter(succeed=True))  # would loop forever if reauth() triggered it
    c.reauth("s3cret-pw")
    assert seen["path"] == "/me/reauth"
    assert json.loads(seen["body"]) == {"password": "s3cret-pw"}


def test_reauth_wrong_password_raises_403() -> None:
    c = _mock_client(lambda r: httpx.Response(403, json={"detail": "re-verification failed"}))
    with pytest.raises(ApiError) as ei:
        c.reauth("wrong")
    assert ei.value.status == 403


def test_action_step_up_binds_purpose_into_reauth() -> None:
    # ADR 0077: a per-action step-up 403 names the action in X-Step-Up-Action; the client stashes it and
    # the reauth() the handler calls carries it as `purpose`, so the engine mints a grant bound to it.
    reauth_seen: dict[str, object] = {}
    n = {"req": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/me/reauth":
            reauth_seen["body"] = json.loads(request.content.decode())
            return httpx.Response(200, json={"detail": "re-verified"})
        n["req"] += 1
        if n["req"] == 1:
            return httpx.Response(
                403,
                headers={"X-Step-Up-Required": "1", "X-Step-Up-Action": "mfa_enroll"},
                json={"detail": "step-up required"},
            )
        return httpx.Response(200, json={"secret": "S"})

    c = _mock_client(handler)
    c.set_step_up_handler(lambda: (c.reauth("pw"), True)[1])  # the real handler flow: prompt→reauth
    resp = c._request("POST", "/me/mfa/enroll")
    assert resp.status_code == 200  # original 403 → reauth → retry succeeds
    assert reauth_seen["body"] == {"password": "pw", "purpose": "mfa_enroll"}  # bound to the action


def test_plain_step_up_reauth_carries_no_purpose_after_action() -> None:
    # A per-action step-up is single-use on the client too: the stashed action is cleared once consumed,
    # so a later PLAIN session-window step-up (no header) reauths with just the password.
    bodies: list[dict[str, object]] = []
    n = {"req": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/me/reauth":
            bodies.append(json.loads(request.content.decode()))
            return httpx.Response(200, json={"detail": "re-verified"})
        n["req"] += 1
        # First call names an action; the third (a different endpoint) is a plain step-up (no action).
        if n["req"] == 1:
            return httpx.Response(
                403,
                headers={"X-Step-Up-Required": "1", "X-Step-Up-Action": "mfa_enroll"},
                json={"detail": "x"},
            )
        if n["req"] == 2:
            return httpx.Response(200, json={"ok": True})  # retry of the action route
        if n["req"] == 3:
            return httpx.Response(403, headers={"X-Step-Up-Required": "1"}, json={"detail": "x"})
        return httpx.Response(200, json={"ok": True})  # retry of the plain route

    c = _mock_client(handler)
    c.set_step_up_handler(lambda: (c.reauth("pw"), True)[1])
    assert c._request("POST", "/me/mfa/enroll").status_code == 200
    assert c._request("POST", "/dead-letters/replay").status_code == 200
    assert bodies == [{"password": "pw", "purpose": "mfa_enroll"}, {"password": "pw"}]


# --- ReauthDialog (Qt offscreen) -------------------------------------------------------------
@pytest.fixture(scope="module")
def qapp():
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def _current_user(provider: str = "local"):
    from messagefoundry.api.auth_models import CurrentUser

    return CurrentUser(
        user_id="u1", username="alice", auth_provider=provider, roles=["operator"], permissions=[]
    )


class FakeReauthClient:
    """Duck-typed EngineClient for ReauthDialog: a `current_user` property + a recording `reauth`."""

    def __init__(self, *, error: ApiError | None = None, provider: str = "local") -> None:
        self.error = error
        self.calls: list[str] = []
        self._provider = provider

    @property
    def current_user(self):
        return _current_user(self._provider)

    def reauth(self, password: str) -> None:
        self.calls.append(password)
        if self.error is not None:
            raise self.error


def test_reauth_dialog_success(qapp) -> None:
    from PySide6.QtWidgets import QDialog

    from messagefoundry.console.reauth import ReauthDialog

    client = FakeReauthClient()
    dlg = ReauthDialog(client)  # type: ignore[arg-type]
    dlg._password.setText("pw")
    dlg._attempt()
    assert client.calls == ["pw"]
    assert dlg.result() == QDialog.DialogCode.Accepted
    assert dlg._password.text() == ""  # plaintext cleared on success


def test_reauth_dialog_wrong_password(qapp) -> None:
    from PySide6.QtWidgets import QDialog

    from messagefoundry.console.reauth import ReauthDialog

    client = FakeReauthClient(error=ApiError("403: re-verification failed", status=403))
    dlg = ReauthDialog(client)  # type: ignore[arg-type]
    dlg._password.setText("bad")
    dlg._attempt()
    assert "incorrect" in dlg._error.text().lower()
    assert dlg.result() != QDialog.DialogCode.Accepted  # stays open to retry
    assert client.calls == ["bad"]


def test_reauth_dialog_empty_blocked(qapp) -> None:
    from messagefoundry.console.reauth import ReauthDialog

    client = FakeReauthClient()
    dlg = ReauthDialog(client)  # type: ignore[arg-type]
    dlg._attempt()  # nothing entered
    assert dlg._error.text()
    assert client.calls == []  # no server call on a local validation failure


def test_reauth_dialog_ad_prompt_mentions_directory(qapp) -> None:
    from PySide6.QtWidgets import QLabel

    from messagefoundry.console.reauth import ReauthDialog

    client = FakeReauthClient(provider="ad")
    dlg = ReauthDialog(client)  # type: ignore[arg-type]
    texts = " ".join(lbl.text() for lbl in dlg.findChildren(QLabel))
    assert "Active Directory" in texts
