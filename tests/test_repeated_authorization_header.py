# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2454: a request carrying more than one ``Authorization`` header is refused.

Starlette's ``headers.get`` returns the FIRST of two same-named lines. A front end that checked the
LAST would have authenticated a different credential from the one the engine reads. #2051 closed
the same gap at HTTP intake; this closes it on the engine API and the console's SSO leg. Every read
goes through ``security.sole_authorization``:

* the bearer read every gate makes (``bearer_token``): 400;
* ``POST /auth/negotiate``: 400;
* the ``/ws/stats`` handshake (``ws_token``): refused, 403 denial or a 1008 close;
* ``optional_identity``: the tokenless answer, to keep its never-raises contract.

Each refusal has a single-header control on the same app that still authenticates. The console's
``GET /ui/sso`` is driven in
``packaging/messagefoundry-webconsole/tests/test_ui_sso_repeated_authorization.py``. The last test
is the guard that keeps a new read from bypassing the helper.
"""

from __future__ import annotations

import functools
import re
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient, WebSocketDenialResponse

from messagefoundry.api import create_managed_app
from messagefoundry.api.security import REPEATED_AUTHORIZATION_DETAIL
from messagefoundry.auth import Role
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_api_auth import PW, _add
from tests.test_directory_sign_in_admin_alert import _NEGOTIATE, _Sink
from tests.test_directory_sign_in_admin_alert import _client as _directory_client
from tests.test_directory_sign_in_admin_alert import _service as _directory_service

_ROOT = Path(__file__).resolve().parents[1]
_EGRESS = EgressSettings(deny_by_default=False)
_REPEATED = {"detail": REPEATED_AUTHORIZATION_DETAIL}


def _twice(first: str, second: str) -> list[tuple[str, str]]:
    """Two ``Authorization`` lines. A list, because a dict cannot hold a repeated name."""
    return [("Authorization", first), ("Authorization", second)]


@pytest.fixture
def signed_in(tmp_path: Path) -> Iterator[tuple[TestClient, str]]:
    """A managed app with one signed-in Administrator: ``(client, bearer value)``."""
    app = create_managed_app(
        db_path=tmp_path / "repeated-authz.db",
        poll_interval=0.05,
        auth_settings=AuthSettings(
            require_mfa=False, notify_security_events=False, login_rate_limit_enabled=False
        ),
        egress_settings=_EGRESS,
    )
    with TestClient(app) as tc:
        assert tc.portal is not None
        tc.portal.call(functools.partial(_add, app.state.auth, "root", Role.ADMINISTRATOR))
        login = tc.post(
            "/auth/login", json={"username": "root", "password": PW, "provider": "local"}
        )
        assert login.status_code == 200, login.text
        yield tc, f"Bearer {login.json()['token']}"


def test_a_gated_route_refuses_a_repeated_bearer_header(signed_in: tuple[TestClient, str]) -> None:
    tc, bearer = signed_in
    # Control: the one header authenticates.
    assert tc.get("/auth/me", headers={"Authorization": bearer}).status_code == 200
    # The reported shape: a valid credential first, another after it.
    answer = tc.get("/auth/me", headers=_twice(bearer, "Bearer synthetic-other"))
    assert answer.status_code == 400 and answer.json() == _REPEATED
    # Reversed order, so the refusal does not depend on which line is valid.
    answer = tc.get("/auth/me", headers=_twice("Bearer synthetic-other", bearer))
    assert answer.status_code == 400 and answer.json() == _REPEATED
    # Identical values are refused too: a proxy may still split, merge or rewrite them.
    answer = tc.get("/auth/me", headers=_twice(bearer, bearer))
    assert answer.status_code == 400 and answer.json() == _REPEATED


def test_a_body_taking_route_refuses_before_the_body(signed_in: tuple[TestClient, str]) -> None:
    """The early-check step reads the bearer too, so a repeat is refused before any body parse."""
    tc, bearer = signed_in
    answer = tc.post(
        "/ai/chat",
        content=b"not json",
        headers=[*_twice(bearer, bearer), ("Content-Type", "application/json")],
    )
    assert answer.status_code == 400 and answer.json() == _REPEATED


def test_the_stats_socket_refuses_a_repeated_header(signed_in: tuple[TestClient, str]) -> None:
    tc, bearer = signed_in
    # Control: the one header opens the socket.
    with tc.websocket_connect("/ws/stats", headers={"Authorization": bearer}) as ws:
        assert "outbox_by_status" in ws.receive_json()
    with (
        pytest.raises(WebSocketDenialResponse) as denied,
        # httpx.Headers, because the test client calls setdefault on what it is given, and it keeps
        # both lines where a dict would merge them.
        tc.websocket_connect("/ws/stats", headers=httpx.Headers(_twice(bearer, bearer))),
    ):
        pass
    assert denied.value.status_code == 403


def test_optional_identity_answers_a_repeat_as_tokenless(
    signed_in: tuple[TestClient, str],
) -> None:
    """``GET /ai/policy`` resolves its caller through ``optional_identity``, which never raises. A
    repeat gets exactly the tokenless answer, never the signed-in one."""
    tc, bearer = signed_in
    tokenless = tc.get("/ai/policy")
    signed = tc.get("/ai/policy", headers={"Authorization": bearer})
    repeated = tc.get("/ai/policy", headers=_twice(bearer, bearer))
    assert tokenless.status_code == signed.status_code == repeated.status_code == 200
    assert signed.json() != tokenless.json(), "control: the signed-in answer differs"
    assert repeated.json() == tokenless.json()


async def test_negotiate_refuses_a_repeated_header(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _directory_service(engine, monkeypatch, frozenset())
    async with _directory_client(engine, service, _Sink()) as c:
        negotiate = _NEGOTIATE["Authorization"]
        # Control: the one header signs in.
        assert (await c.post("/auth/negotiate", headers=_NEGOTIATE)).status_code == 200
        answer = await c.post("/auth/negotiate", headers=_twice(negotiate, negotiate))
        assert answer.status_code == 400 and answer.json() == _REPEATED
        answer = await c.post("/auth/negotiate", headers=_twice("Bearer synthetic", negotiate))
        assert answer.status_code == 400 and answer.json() == _REPEATED


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "negotiate.db", poll_interval=0.02, egress_settings=_EGRESS
    )
    yield eng
    await eng.stop()


#: A read of the inbound ``Authorization`` header. It needs ``.headers`` as an ATTRIBUTE, or a raw
#: ``b"authorization"`` byte name, so an outbound ``headers["Authorization"] = ...`` built on a
#: local dict does not match. It still misses, at least, a header name held in a constant.
_DIRECT_READ = re.compile(
    r"""\.headers(?:\.get\(|\.getlist\(|\[)\s*["']authorization["']"""
    r"""|["']authorization["']\s+in\s+[\w.]+\.headers"""
    r"""|b["']authorization["']""",
    re.IGNORECASE,
)
#: The helper's own read: the one line allowed to match.
_HELPER = ("messagefoundry/api/security.py", 'conn.headers.getlist("Authorization")')


def test_every_authorization_read_goes_through_the_helper() -> None:
    """A new route that reads the header directly would reopen #2454 silently.

    Each spelling the pattern claims has a positive control, starting with the line this change
    replaced, so a pattern that cannot match fails here rather than passing."""
    for spelling in (
        'header = request.headers.get("Authorization", "")',
        'value = websocket.headers["authorization"]',
        'last = request.headers.getlist("Authorization")[-1]',
        'if "authorization" in request.headers:',
        'if name == b"authorization":',
    ):
        assert _DIRECT_READ.search(spelling), spelling
    assert not _DIRECT_READ.search('headers["Authorization"] = f"Bearer {token}"')
    sources = [
        path
        for package in ("messagefoundry", "messagefoundry_webconsole")
        for path in sorted((_ROOT / package).rglob("*.py"))
    ]
    assert len(sources) > 100, "the walk found too few source files to mean anything"
    hits = [
        (path.relative_to(_ROOT).as_posix(), n, line)
        for path in sources
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _DIRECT_READ.search(line)
    ]
    assert hits, "control: the walk must at least find the helper's own read"
    helper = [hit for hit in hits if hit[0] == _HELPER[0] and _HELPER[1] in hit[2]]
    assert len(helper) == 1, f"control: the helper's own read was not found once: {helper}"
    offenders = [f"{file}:{n}" for file, n, line in hits if (file, n, line) not in helper]
    assert offenders == [], offenders
