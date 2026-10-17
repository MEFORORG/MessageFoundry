# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The sign-in and the two elevations that queue per account get a longer timeout (vault BACKLOG
#2950).

``EngineClient.login`` names the token it replaces, and the engine ends that session inside the
sign-in (BACKLOG #2281). A sign-in waiting in the engine's per-account queue could outlast the
client's 5 s default, and a lost reply then leaves the client holding a token the engine ended.
``login``, ``reauth``, ``verify_mfa`` and ``confirm_mfa`` now wait ``SIGN_IN_TIMEOUT_SECONDS``
for their reply, which matches the IDE's ``SIGN_IN_TIMEOUT_MS``; their other phases, and every
other request, keep the client's own timeout. The queue has no bound, so this makes the lost reply
rarer, not impossible.

The transport is an ``httpx.MockTransport``: what is pinned is the timeout each request carries,
read from ``request.extensions["timeout"]``, not what an engine does with it.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from messagefoundry.apiclient import EngineClient
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
        body = {"recovery_codes": ["code-one"], "token": _ROTATED}
    else:
        body = _USER
    return httpx.Response(200, json=body)


def _recording_client() -> tuple[EngineClient, dict[str, dict[str, float | None]]]:
    """An ``EngineClient`` over a mock transport, and the timeout each path's request carried."""
    seen: dict[str, dict[str, float | None]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen[request.url.path] = dict(request.extensions["timeout"])
        return _reply(request)

    client = EngineClient(_BASE)
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
_QUEUED = ("/auth/login", "/me/reauth", "/auth/mfa-verify", "/me/mfa/confirm")


def test_the_sign_in_and_the_queued_elevations_wait_longer_for_their_reply() -> None:
    """RED when: ``/auth/login``, ``/me/reauth``, ``/auth/mfa-verify`` or ``/me/mfa/confirm``
    waits only the client's 5 s default for its reply (vault BACKLOG #2950), when anything but
    the read phase is raised, or when ``/auth/me`` loses that default."""
    client, seen = _recording_client()
    try:
        client.login("jdoe", "a-strong-test-passphrase")
        client.reauth("a-strong-test-passphrase")
        client.verify_mfa("123456")
        assert client.confirm_mfa("123456") == ["code-one"]
        client.me()
    finally:
        client.close()
    # Only the read phase waits out the queue; connect, write and pool keep the client's bound,
    # so an unreachable engine is still reported as fast as before.
    longer = {**_every_phase(5.0), "read": SIGN_IN_TIMEOUT_SECONDS}
    for path in _QUEUED:
        assert seen[path] == longer, path
    # The control: any other request keeps the client's default.
    assert seen["/auth/me"] == _every_phase(5.0)


def test_the_timeout_matches_the_ides_sign_in_timeout() -> None:
    """The two clients of the same queue wait the same time. The IDE's constant is read from its
    source, so a change on either side reds here."""
    source = Path(__file__).resolve().parents[1] / "ide" / "src" / "signInSession.ts"
    line = next(
        ln for ln in source.read_text(encoding="utf-8").splitlines() if "SIGN_IN_TIMEOUT_MS =" in ln
    )
    milliseconds = int(line.split("=", 1)[1].strip().rstrip(";").replace("_", ""))
    assert milliseconds == SIGN_IN_TIMEOUT_SECONDS * 1000
