# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2454, the console half: ``GET /ui/sso`` refuses a repeated ``Authorization`` header.

The route reads the header through the engine's ``authorization_header``, so it answers 400 by the
same rule the engine's own reads use. The engine sites are driven in
``tests/test_repeated_authorization_header.py``.
"""

from __future__ import annotations

import httpx
import pytest
from test_ui_directory_admin_alert import _client, _service, _Sink

from messagefoundry.api.security import REPEATED_AUTHORIZATION_DETAIL
from messagefoundry.pipeline import Engine

_NEGOTIATE = "Negotiate c3BuZWdvLXRva2Vu"


@pytest.mark.parametrize(
    "first",
    [_NEGOTIATE, "Bearer synthetic"],
    ids=["identical", "different"],
)
async def test_sso_refuses_a_repeated_header(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, first: str
) -> None:
    service = await _service(engine, held=None, bind=False)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "jdoe")
    async with _client(engine, service, _Sink()) as c:
        # Control: the one header signs in and lands on the console.
        single = await c.get("/ui/sso", headers={"Authorization": _NEGOTIATE})
        assert single.status_code == 303 and single.headers["location"] == "/ui", single.headers
        repeated = await c.get(
            "/ui/sso",
            headers=httpx.Headers([("Authorization", first), ("Authorization", _NEGOTIATE)]),
        )
    assert repeated.status_code == 400, repeated.text
    assert repeated.json() == {"detail": REPEATED_AUTHORIZATION_DETAIL}
    assert "set-cookie" not in repeated.headers


#: Every rung's session-cookie name, each twice, so whichever name this connection reads repeats.
_DOUBLED_COOKIES = "; ".join(
    f"{name}={value}"
    for name in ("mf_session", "__Secure-mf_session", "__Host-mf_session")
    for value in ("synthetic-a", "synthetic-b")
)


async def test_sso_charges_the_sign_in_budget_once_per_repeated_cookie(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``GET /ui/sso`` charges the sign-in limiter, then reads the session cookie; the refusal's
    row draws its own budget (BACKLOG #2454). So the shipped budget of ten admits ten 400s, then
    the limiter's redirect, and each 400 writes one row. A refusal that also drew the sign-in
    budget would redirect from the sixth request on."""
    service = await _service(engine, held=None, bind=False)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "jdoe")
    headers = {"Authorization": _NEGOTIATE, "Cookie": _DOUBLED_COOKIES}
    async with _client(engine, service, _Sink()) as c:
        answers = [(await c.get("/ui/sso", headers=headers)).status_code for _ in range(10)]
        limited = await c.get("/ui/sso", headers=headers)
    assert answers == [400] * 10, answers
    assert (limited.status_code, limited.headers["location"]) == (303, "/ui/login?e=rate_limited")
    rows = await engine.store.list_audit(action="auth.repeated_credential", limit=100)
    assert len(rows) == 10
    assert all('"session_cookie"' in str(dict(row)["detail"]) for row in rows)
