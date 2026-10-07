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
