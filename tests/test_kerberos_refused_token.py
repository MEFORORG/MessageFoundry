# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A crafted SPNEGO token is an audited refusal that stores no text from the token.

**BACKLOG #3186.** pyspnego's own Negotiate wrapper is the acceptor on any host without SSPI. Handed
a first ``NegTokenResp``, it raises ``StopIteration`` (no ``supportedMech``) or ``KeyError`` (one
naming a mechanism it never set up). ``kerberos_principal`` caught neither, so the exception left
the worker thread. A ``StopIteration`` cannot even cross ``asyncio.to_thread``: the Future turns it
into a ``RuntimeError``. Either way the sign-in wrote no audit row and the client got a 500.

**BACKLOG #3196.** The token errors it did catch became an ``LdapError`` carrying ``str(exc)``, so
the row stored text parsed from the caller's token, and a spray read as a directory outage
(``auth.login_error``). A ``supportedMech`` OID pyspnego does not know is the plain case: the
``ValueError`` quotes it. Now the row is ``auth.login_failed`` with the closed reason
``token_refused`` and the exception's type. Separately, ``POST /auth/negotiate`` wrote no row for a
token that is not base64, while ``GET /ui/sso`` audits it as ``malformed_token``. Both write that
row now.

These tests drive the REAL wrapper (``spnego._negotiate.NegotiateProxy``) with real crafted tokens,
not a stub that raises on cue. The tokens were found by mutating valid SPNEGO tokens against
pyspnego 0.12.4; ``StopIteration`` and ``KeyError`` were the only types outside the old except
tuple. The directory double fails the test if it is asked anything: a refused token must never
reach it.

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
from messagefoundry.auth.ldap import KerberosTokenRefused, kerberos_principal
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine

#: Stands for text the caller chose. It must never reach an audit row or the refusal's message.
_LEAK = "1.3.6.1.4.1.31337.7"
#: A first NegTokenResp with no supportedMech: the wrapper's ``next(iter({}))`` raises StopIteration.
_STOP_ITERATION = NegTokenResp(response_token=b"x").pack()
#: One naming Kerberos, a mechanism the wrapper never set up: its context lookup raises KeyError.
_KEY_ERROR = NegTokenResp(supported_mech=GSSMech.kerberos.value, response_token=b"x").pack()
#: One naming an OID pyspnego does not know: the ValueError's message quotes the caller's OID.
_VALUE_ERROR = NegTokenResp(supported_mech=_LEAK, response_token=b"x").pack()
_CRAFTED = [
    pytest.param(_STOP_ITERATION, "StopIteration", id="StopIteration"),
    pytest.param(_KEY_ERROR, "KeyError", id="KeyError"),
    pytest.param(_VALUE_ERROR, "ValueError", id="ValueError-quoting-the-token"),
]
#: The row both Kerberos routes write for a header that is not base64.
_MALFORMED = {"provider": "ad", "mech": "kerberos", "reason": "malformed_token"}


def _wrapper(**_kw: object) -> NegotiateProxy:
    """The pure-Python Negotiate acceptor, the one every non-SSPI host signs in through."""
    return NegotiateProxy(usage="accept", protocol="negotiate")


@pytest.fixture
def real_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(spnego, "server", _wrapper)


@pytest.mark.parametrize(("token", "error"), _CRAFTED)
def test_the_real_wrapper_raises_what_the_rows_name(token: bytes, error: str) -> None:
    """The positive control: if pyspnego stops raising these, the tests below prove nothing."""
    with pytest.raises(BaseException) as caught:
        _wrapper().step(token)
    assert type(caught.value).__name__ == error
    if error == "ValueError":
        assert _LEAK in str(caught.value), "the leak marker no longer reaches the message"


@pytest.mark.parametrize(("token", "error"), _CRAFTED)
def test_kerberos_principal_refuses_a_crafted_token_by_type_only(
    real_wrapper: None, token: bytes, error: str
) -> None:
    with pytest.raises(KerberosTokenRefused) as caught:
        kerberos_principal(token, AuthSettings())
    assert caught.value.error_type == error
    assert type(caught.value.__cause__).__name__ == error
    assert _LEAK not in str(caught.value)


# --- where an operator meets it: the service and both routes -----------------------------------


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


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, serve_ui=True)
    # A 500 must come back as a response the test can read, not as a raised exception.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _rows(engine: Engine, action: str) -> list[dict[str, Any]]:
    return [dict(r) for r in await engine.store.list_audit(action=action)]


async def _assert_refused_rows(engine: Engine, error: str, client: str, count: int) -> None:
    """``count`` token_refused rows, each naming only the type, and no outage row at all."""
    rows = await _rows(engine, "auth.login_failed")
    assert len(rows) == count, rows
    for row in rows:
        assert json.loads(row["detail"]) == {
            "provider": "ad",
            "mech": "kerberos",
            "reason": "token_refused",
            "error": error,
        }
        assert row["client"] == client
        assert _LEAK not in json.dumps(row)
    assert await _rows(engine, "auth.login_error") == []


@pytest.mark.parametrize(("token", "error"), _CRAFTED)
async def test_the_service_audits_a_crafted_token_as_a_refusal(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, real_wrapper: None, token: bytes, error: str
) -> None:
    service = await _service(engine, monkeypatch)
    outcome = await service.authenticate_kerberos(token, client="192.0.2.7")
    assert not outcome.ok
    await _assert_refused_rows(engine, error, "192.0.2.7", count=1)


@pytest.mark.parametrize(("token", "error"), _CRAFTED)
async def test_both_routes_refuse_a_crafted_token_with_a_row(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, real_wrapper: None, token: bytes, error: str
) -> None:
    """Before #3186 the StopIteration and KeyError arms were a 500 with no row on both routes."""
    service = await _service(engine, monkeypatch)
    header = {"Authorization": "Negotiate " + base64.b64encode(token).decode()}
    async with _client(engine, service) as c:
        r = await c.post("/auth/negotiate", headers=header)
        assert r.status_code == 401, r.text
        r = await c.get("/ui/sso", headers=header)
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_failed"
    # The ASGI transport presents the client as 127.0.0.1.
    await _assert_refused_rows(engine, error, "127.0.0.1", count=2)


async def test_both_routes_write_the_same_row_for_a_token_that_is_not_base64(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before #3196, ``POST /auth/negotiate`` answered 400 and wrote nothing."""
    service = await _service(engine, monkeypatch)
    header = {"Authorization": "Negotiate !!!not-base64!!!"}
    async with _client(engine, service) as c:
        r = await c.post("/auth/negotiate", headers=header)
        assert r.status_code == 400, r.text
        negotiate_rows = await _rows(engine, "auth.login_failed")
        r = await c.get("/ui/sso", headers=header)
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_failed"
    rows = await _rows(engine, "auth.login_failed")
    assert len(negotiate_rows) == 1 and len(rows) == 2, rows
    assert [json.loads(row["detail"]) for row in rows] == [_MALFORMED, _MALFORMED]
    assert [(row["actor"], row["client"]) for row in rows] == [("<kerberos>", "127.0.0.1")] * 2
