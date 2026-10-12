# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3186: a crafted SPNEGO token is an audited refusal, never an unaudited 500.

pyspnego's own Negotiate wrapper is the acceptor on any host without SSPI. Handed a first
``NegTokenResp``, it raises ``StopIteration`` (no ``supportedMech``) or ``KeyError`` (one naming a
mechanism it never set up). ``kerberos_principal`` caught neither, so the exception left the worker
thread. A ``StopIteration`` cannot even cross ``asyncio.to_thread``: the Future turns it into a
``RuntimeError``. Either way the sign-in wrote no audit row and the client got a 500.

These tests drive the REAL wrapper (``spnego._negotiate.NegotiateProxy``) with real crafted tokens,
not a stub that raises on cue. The tokens were found by mutating valid SPNEGO tokens against
pyspnego 0.12.4; those two types were the only ones outside the except tuple. The directory double
fails the test if it is asked anything: a refused token must never reach it.

PHI-free: synthetic tokens and names only.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import spnego
from spnego._context import GSSMech
from spnego._negotiate import NegotiateProxy
from spnego._spnego import NegTokenResp

from messagefoundry.api import create_app
from messagefoundry.auth.ldap import LdapError, kerberos_principal
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine

#: A first NegTokenResp with no supportedMech: the wrapper's ``next(iter({}))`` raises StopIteration.
_STOP_ITERATION = NegTokenResp(response_token=b"x").pack()
#: One naming Kerberos, a mechanism the wrapper never set up: its context lookup raises KeyError.
_KEY_ERROR = NegTokenResp(supported_mech=GSSMech.kerberos.value, response_token=b"x").pack()
_CRAFTED = [
    pytest.param(_STOP_ITERATION, "StopIteration", id="StopIteration"),
    pytest.param(_KEY_ERROR, "KeyError", id="KeyError"),
]


def _wrapper(**_kw: object) -> NegotiateProxy:
    """The pure-Python Negotiate acceptor, the one every non-SSPI host signs in through."""
    return NegotiateProxy(usage="accept", protocol="negotiate")


@pytest.fixture
def real_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(spnego, "server", _wrapper)


@pytest.mark.parametrize(("token", "error"), _CRAFTED)
def test_the_real_wrapper_raises_what_the_row_names(token: bytes, error: str) -> None:
    """The positive control: if pyspnego stops raising these, the tests below prove nothing."""
    with pytest.raises(BaseException) as caught:
        _wrapper().step(token)
    assert type(caught.value).__name__ == error


@pytest.mark.parametrize(("token", "error"), _CRAFTED)
def test_kerberos_principal_maps_a_crafted_token(
    real_wrapper: None, token: bytes, error: str
) -> None:
    with pytest.raises(LdapError) as caught:
        kerberos_principal(token, AuthSettings())
    assert type(caught.value.__cause__).__name__ == error


# --- where an operator meets it: the service and the JSON route --------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "kerberos_refused_token.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


class _UnaskedDirectory:
    """A directory that fails the test if asked: a refused token must never reach it."""

    def resolve_principal(self, username: str, **_: object) -> Any:
        raise AssertionError(f"the directory was asked about {username!r}")


async def _service(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> AuthService:
    async def no_sleep(_deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", no_sleep)
    settings = AuthSettings(
        ad_enabled=True,
        kerberos_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
        login_rate_limit_enabled=False,
        require_mfa=False,
    )
    service = AuthService(engine.store, settings, ldap=_UnaskedDirectory())  # type: ignore[arg-type]
    await service.initialize()
    return service


async def _refusal_rows(engine: Engine) -> list[dict[str, Any]]:
    rows = await engine.store.list_audit(action="auth.login_error")
    return [dict(r) for r in rows]


@pytest.mark.parametrize(("token", "error"), _CRAFTED)
async def test_the_service_audits_a_crafted_token(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, real_wrapper: None, token: bytes, error: str
) -> None:
    service = await _service(engine, monkeypatch)
    outcome = await service.authenticate_kerberos(token, client="192.0.2.7")
    assert not outcome.ok
    rows = await _refusal_rows(engine)
    assert len(rows) == 1, rows
    assert json.loads(rows[0]["detail"])["mech"] == "kerberos"
    assert rows[0]["client"] == "192.0.2.7"


@pytest.mark.parametrize(("token", "error"), _CRAFTED)
async def test_auth_negotiate_answers_a_crafted_token_with_401_and_a_row(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, real_wrapper: None, token: bytes, error: str
) -> None:
    """Before #3186 this was a 500 with no row."""
    service = await _service(engine, monkeypatch)
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service), raise_app_exceptions=False
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(
            "/auth/negotiate",
            headers={"Authorization": "Negotiate " + base64.b64encode(token).decode()},
        )
    assert r.status_code == 401, r.text
    assert len(await _refusal_rows(engine)) == 1
