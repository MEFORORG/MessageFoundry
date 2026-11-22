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
the client's own timeout. Why that read outlasts the engine's request deadline is said once, on
``SIGN_IN_TIMEOUT_SECONDS``.

The transport is an ``httpx.MockTransport``: what is pinned is the timeout each request carries,
read from ``request.extensions["timeout"]``, not what an engine does with it.
"""

from __future__ import annotations

import ast
import inspect
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from messagefoundry.api.request_timeout import DEFAULT_REQUEST_TIMEOUT_SECONDS
from messagefoundry.apiclient import EngineClient
from messagefoundry.apiclient.client import (
    _ENGINE_REQUEST_DEADLINE_SECONDS,
    SIGN_IN_TIMEOUT_SECONDS,
)

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


def test_the_timeout_matches_the_ides_sign_in_timeout() -> None:
    """The two clients of the same queue wait the same time for the sign-in's reply. This pins the
    IDE's constant only: the IDE has no configurable client-wide timeout (its default POST
    deadline, ``POST_TIMEOUT_MS`` in ``engineClient.ts``, is this same constant), so the Python
    client's floor for a client built with a longer one has no IDE counterpart. The IDE's constant
    is read from its source, so a change on either side reds here."""
    source = Path(__file__).resolve().parents[1] / "ide" / "src" / "signInSession.ts"
    line = next(
        ln for ln in source.read_text(encoding="utf-8").splitlines() if "SIGN_IN_TIMEOUT_MS =" in ln
    )
    milliseconds = int(line.split("=", 1)[1].strip().rstrip(";").replace("_", ""))
    assert milliseconds == SIGN_IN_TIMEOUT_SECONDS * 1000


def test_the_sign_in_read_outlasts_the_engines_request_deadline() -> None:
    """RED when: ``SIGN_IN_TIMEOUT_SECONDS`` is less than 30 s above the engine's default request
    deadline (vault BACKLOG #2950 step 1), or the client's copy of that deadline stops matching the
    engine's. ``_PAST_ENGINE_DEADLINE_SECONDS`` says why the margin exists."""
    assert _ENGINE_REQUEST_DEADLINE_SECONDS == DEFAULT_REQUEST_TIMEOUT_SECONDS
    assert SIGN_IN_TIMEOUT_SECONDS - DEFAULT_REQUEST_TIMEOUT_SECONDS >= 30.0


@pytest.mark.parametrize(
    "own",
    [
        30.0,  # between the 5 s default and the floor
        SIGN_IN_TIMEOUT_SECONDS - 0.5,  # just under the floor
        SIGN_IN_TIMEOUT_SECONDS,  # exactly at the floor
    ],
)
def test_a_client_timeout_up_to_the_floor_gets_the_floor_on_the_queued_reads(own: float) -> None:
    """RED when: a client built with a timeout between the default and ``SIGN_IN_TIMEOUT_SECONDS``,
    or exactly at it, gets anything but the floor as its read on a queued call, or loses its own
    timeout on any other phase or request (vault BACKLOG #2950 added item 7). The two tests above
    cover only the 5 s default and a timeout above the floor."""
    client, seen = _recording_client(timeout=own)
    _send_every_queued_call_then_a_control(client)
    for path in _QUEUED:
        assert seen[path] == {**_every_phase(own), "read": SIGN_IN_TIMEOUT_SECONDS}, path
    assert seen["/auth/me"] == _every_phase(own)


def _methods_with_a_call(matches: Callable[[ast.Call], bool]) -> set[str]:
    """The ``EngineClient`` methods, ``async def`` ones included, whose body holds a call that
    ``matches``, read from its source."""
    tree = ast.parse(Path(inspect.getfile(EngineClient)).read_text(encoding="utf-8"))
    cls = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == EngineClient.__name__
    )
    return {
        fn.name
        for fn in cls.body
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(isinstance(node, ast.Call) and matches(node) for node in ast.walk(fn))
    }


def _methods_calling(name: str) -> set[str]:
    """The ``EngineClient`` methods whose body calls ``self.<name>()``."""
    return _methods_with_a_call(
        lambda call: (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == name
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "self"
        )
    )


def _methods_setting_a_read_timeout() -> set[str]:
    """The ``EngineClient`` methods that build an ``httpx.Timeout`` with its own ``read=``."""
    return _methods_with_a_call(
        lambda call: (
            (
                (isinstance(call.func, ast.Attribute) and call.func.attr == "Timeout")
                or (isinstance(call.func, ast.Name) and call.func.id == "Timeout")
            )
            and any(kw.arg == "read" for kw in call.keywords)
        )
    )


def test_the_census_of_queued_calls_matches_the_client() -> None:
    """RED when: an ``EngineClient`` method gains or loses the sign-in timeout without this
    census, and so ``_QUEUED``, moving with it (vault BACKLOG #2950 added item 10). The census is of
    the client's calls; which engine routes queue per account is read in ``auth/service.py``, not
    here. Control: the same scan finds ``_adopt_rotated``'s callers, a set it must not confuse."""
    queued = _methods_calling("_sign_in_timeout")
    assert queued == {"login", "reauth", "verify_mfa", "confirm_mfa", "change_password"}
    # Those five calls, sent once each, put the floor on exactly the _QUEUED paths and no other.
    client, seen = _recording_client()
    _send_every_queued_call_then_a_control(client)
    floored = {path for path, phases in seen.items() if phases["read"] == SIGN_IN_TIMEOUT_SECONDS}
    assert floored == set(_QUEUED)
    assert _methods_calling("_adopt_rotated") == {"reauth", "verify_mfa", "confirm_mfa"}


def test_no_method_builds_its_own_read_keyword_timeout() -> None:
    """RED when: an ``EngineClient`` method builds its own ``httpx.Timeout(..., read=...)`` rather
    than calling ``_sign_in_timeout``, so a longer reply wait escapes the census above. Control:
    the scan finds the one method that does build one, ``_sign_in_timeout`` itself. A positional
    ``httpx.Timeout(n)`` or a scalar ``timeout=`` is not scanned."""
    assert _methods_setting_a_read_timeout() == {"_sign_in_timeout"}


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
