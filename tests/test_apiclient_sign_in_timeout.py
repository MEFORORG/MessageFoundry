# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The sign-in and the other calls that queue per account get a longer timeout (vault BACKLOG
#2950).

``EngineClient.login`` names the token it replaces, and the engine ends that session inside the
sign-in (BACKLOG #2281). A sign-in waiting in the engine's per-account queue could outlast the
client's 5 s default, and a lost reply then leaves the client holding a token the engine ended.
``login``, ``reauth``, ``verify_mfa``, ``confirm_mfa`` and ``change_password`` now wait at least
``SIGN_IN_TIMEOUT_SECONDS`` for their reply, which matches the IDE's ``SIGN_IN_TIMEOUT_MS``, or
the client's own timeout when that is longer; their other phases, and every other request, keep
the client's own timeout. The engine's 120 s request deadline is longer than that read, so this
makes the lost reply rarer, not impossible.

The transport is an ``httpx.MockTransport``: what is pinned is the timeout each request carries,
read from ``request.extensions["timeout"]``, not what an engine does with it.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.apiclient.client import SIGN_IN_TIMEOUT_SECONDS

_BASE = "http://127.0.0.1:8765"
_USER = {
    "user_id": "u1",
    "username": "jdoe",
    "auth_provider": "local",
    "roles": ["viewer"],
    "permissions": [],
}
#: Synthetic, low-entropy stand-ins for a session token.
_TOKEN = "t" * 43
_ROTATED = "r" * 43


def _reply(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/auth/login":
        body: object = {"token": _TOKEN, "user": _USER}
    elif path in ("/me/reauth", "/auth/mfa-verify"):
        body = {"detail": "re-verified", "token": _ROTATED}
    elif path == "/me/mfa/confirm":
        body = {"recovery_codes": ["code-one"], "token": _ROTATED, "other_sessions": 0}
    else:
        body = _USER
    return httpx.Response(200, json=body)


def _recording_client(
    timeout: float | None = None,
) -> tuple[EngineClient, dict[str, dict[str, float | None]]]:
    """An ``EngineClient`` over a mock transport, and the timeout each path's request carried.
    ``timeout`` is the client's own; with None the client is built with its real default."""
    seen: dict[str, dict[str, float | None]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen[request.url.path] = dict(request.extensions["timeout"])
        return _reply(request)

    client = EngineClient(_BASE) if timeout is None else EngineClient(_BASE, timeout=timeout)
    default = client._http.timeout
    client._http.close()
    # The client's own timeout, as _open_transport sets it, so the default is the one under test.
    client._http = httpx.Client(
        base_url=_BASE, timeout=default, transport=httpx.MockTransport(handler)
    )
    return client, seen


def _every_phase(seconds: float) -> dict[str, float | None]:
    return {"connect": seconds, "read": seconds, "write": seconds, "pool": seconds}


#: The requests that wait in the engine's per-account queue.
_QUEUED = ("/auth/login", "/me/reauth", "/auth/mfa-verify", "/me/mfa/confirm", "/me/password")


def _send_every_queued_call_then_a_control(client: EngineClient) -> None:
    """Each queued call once, then ``/auth/me``, the request that must keep the client's own
    timeout. ``change_password`` signs the client out, so it runs after the control."""
    try:
        client.login("jdoe", "a-strong-test-passphrase")
        client.reauth("a-strong-test-passphrase")
        client.verify_mfa("123456")
        assert client.confirm_mfa("123456").recovery_codes == ("code-one",)
        client.me()
        client.change_password("a-strong-test-passphrase", "another-strong-test-passphrase")
    finally:
        client.close()


def test_the_sign_in_and_the_queued_elevations_wait_longer_for_their_reply() -> None:
    """RED when: ``/auth/login``, ``/me/reauth``, ``/auth/mfa-verify``, ``/me/mfa/confirm`` or
    ``/me/password`` waits only the client's 5 s default for its reply (vault BACKLOG #2950,
    ``/me/password`` by its step 5), when anything but the read phase is raised, or when
    ``/auth/me`` loses that default."""
    client, seen = _recording_client()
    _send_every_queued_call_then_a_control(client)
    # Only the read phase waits out the queue; connect, write and pool keep the client's bound,
    # so an unreachable engine is still reported as fast as before.
    longer = {**_every_phase(5.0), "read": SIGN_IN_TIMEOUT_SECONDS}
    for path in _QUEUED:
        assert seen[path] == longer, path
    # The control: any other request keeps the client's default.
    assert seen["/auth/me"] == _every_phase(5.0)


def test_a_client_built_with_a_longer_timeout_keeps_it_on_the_queued_calls() -> None:
    """RED when: a client built with a timeout above ``SIGN_IN_TIMEOUT_SECONDS`` gets a SHORTER
    read on a queued call than on any other request (vault BACKLOG #2950 step 5, #3751 item 4).
    The sign-in timeout is a floor on the read phase, never a ceiling: a caller that asked to wait
    longer would otherwise lose the reply sooner, the case the timeout exists to make rarer."""
    own = SIGN_IN_TIMEOUT_SECONDS * 2
    client, seen = _recording_client(timeout=own)
    _send_every_queued_call_then_a_control(client)
    for path in (*_QUEUED, "/auth/me"):
        assert seen[path] == _every_phase(own), path


def test_change_password_sends_no_password_over_a_cleartext_hop() -> None:
    """RED when: ``change_password`` lets its two passwords reach the transport on a permitted
    cleartext non-loopback hop. With no token held, ``_request`` has no bearer to refuse, so only
    the entry-point refusal stops the body, as it does for ``login`` and ``reauth``."""
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={})

    client = EngineClient("http://engine.example.com:8765", allow_insecure=True)
    client._http.close()
    client._http = httpx.Client(base_url=client.base_url, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(ApiError, match="never a credential") as excinfo:
            client.change_password("a-strong-test-passphrase", "another-strong-test-passphrase")
        assert "a password" in str(excinfo.value)
    finally:
        client.close()
    assert sent == [], "a password reached the transport before the refusal"


def test_the_timeout_matches_the_ides_sign_in_timeout() -> None:
    """At the default client timeout, the two clients of the same queue wait the same time; a
    client built with a longer timeout waits that instead. The IDE's constant is read from its
    source, so a change on either side reds here."""
    source = Path(__file__).resolve().parents[1] / "ide" / "src" / "signInSession.ts"
    line = next(
        ln for ln in source.read_text(encoding="utf-8").splitlines() if "SIGN_IN_TIMEOUT_MS =" in ln
    )
    milliseconds = int(line.split("=", 1)[1].strip().rstrip(";").replace("_", ""))
    assert milliseconds == SIGN_IN_TIMEOUT_SECONDS * 1000


def test_confirm_mfa_sends_the_enrolment_code_only_when_given() -> None:
    """ADR 0207: a directory account's first factor needs the Administrator's code on an
    unstamped session, so the shared client must be able to carry it. RED when it cannot."""
    import json

    bodies: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return _reply(request)

    client = EngineClient(_BASE)
    client._http.close()
    client._http = httpx.Client(base_url=_BASE, transport=httpx.MockTransport(handler))
    try:
        client.confirm_mfa("123456")
        client.confirm_mfa("123456", enrolment_code="ABCD-EFGH")
    finally:
        client.close()
    assert bodies == [{"code": "123456"}, {"code": "123456", "enrolment_code": "ABCD-EFGH"}]
