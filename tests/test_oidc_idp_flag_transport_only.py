# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1948's residual: only a TRANSPORT failure may mark the IdP unavailable.

``oidc_available`` hides the federated link on ``/ui/login`` and in ``/auth/providers`` for every
visitor. PR 1643 stopped a 4xx from setting it, but a faulty IdP that answers a caller's bad code
with a 5xx still hid the link. The Manager decision of 2026-10-06 (ADR 0142 Amendment E) draws the
line at whether an answer arrived: any received status, 5xx included, fails the sign-in and is
audited, and leaves the flag as it was. Each test pairs an answer with a transport failure, the
control that still marks.
"""

from __future__ import annotations

import http.client
import json
import urllib.error
from collections.abc import Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import oidc
from messagefoundry.auth.service import IDP_ANSWER_UNUSABLE
from messagefoundry.store.store import MessageStore
from messagefoundry.transports.bounded_read import MalformedReplyHeadError
from tests.test_auth_oidc_service import AUTH_CODE, _audit_rows, _flow, _oidc_login, _service
from tests.test_oidc_step_up import _begin, _staged

ORIGIN = "https://ops.example"


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(autouse=True)
def _no_failure_pad(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_sleep(deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_sleep)


def _exchange_raises(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    def fail(**_kwargs: Any) -> Mapping[str, object]:
        raise exc

    monkeypatch.setattr(oidc, "exchange_code", fail)


#: (id, the failure, whether it is a transport failure, the sign-in outcome's reason)
_CASES = [
    pytest.param(
        oidc.TokenRefusedError("token endpoint returned HTTP 503", status=503),
        False,
        "token_refused",
        id="5xx-answer",
    ),
    pytest.param(
        oidc.TokenRefusedError("token endpoint response carries no id_token", status=200),
        False,
        "token_refused",
        id="2xx-without-a-token",
    ),
    # The JWKS fetch raises raw urllib errors, so a status from it reaches the outage arm itself.
    pytest.param(
        urllib.error.HTTPError("https://idp.example/jwks", 503, "down", {}, None),  # type: ignore[arg-type]
        False,
        IDP_ANSWER_UNUSABLE,
        id="jwks-status",
    ),
    # A JWKS reply whose header block did not parse: a reply arrived, so it is an answer.
    pytest.param(
        MalformedReplyHeadError("JWKS reply header block did not parse", reason="a bare CR"),
        False,
        IDP_ANSWER_UNUSABLE,
        id="jwks-bad-header-block",
    ),
    # The request over the length bound, refused before anything is sent: the engine's own fault.
    pytest.param(
        oidc.FlowError("the token-endpoint request url is over the limit"),
        False,
        IDP_ANSWER_UNUSABLE,
        id="request-over-length",
    ),
    pytest.param(
        oidc.TokenEndpointUnreachableError("token endpoint unreachable: URLError"),
        True,
        "idp_unavailable",
        id="token-endpoint-unreachable",
    ),
    pytest.param(urllib.error.URLError("refused"), True, "idp_unavailable", id="raw-urlerror"),
    pytest.param(TimeoutError("timed out"), True, "idp_unavailable", id="timeout"),
    pytest.param(http.client.BadStatusLine("garbage"), True, "idp_unavailable", id="bad-status"),
]


@pytest.mark.parametrize(("exc", "transport", "reason"), _CASES)
async def test_only_a_transport_failure_marks_the_idp_on_sign_in(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    exc: BaseException,
    transport: bool,
    reason: str,
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        assert service.oidc_available is True
        _exchange_raises(monkeypatch, exc)
        out = await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri=f"{ORIGIN}/ui/oidc/callback", client="192.0.2.7"
        )
        assert not out.ok and out.token is None
        assert out.reason == reason
        assert service.oidc_available is (not transport)
        # Every arm is audited with the client address, whatever it does to the flag.
        rows = [
            *(await _audit_rows(store, "auth.login_error")),
            *(await _audit_rows(store, "auth.login_failed")),
        ]
        assert [r["client"] for r in rows] == ["192.0.2.7"]
    finally:
        await store.close()


async def test_a_5xx_answer_records_its_status_and_no_body(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        _exchange_raises(monkeypatch, oidc.TokenRefusedError("returned HTTP 503", status=503))
        await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri=f"{ORIGIN}/ui/oidc/callback", client="192.0.2.7"
        )
        [row] = await _audit_rows(store, "auth.login_failed")
        detail = json.loads(row["detail"])
        assert detail["reason"] == "token_refused" and detail["status"] == 503
        assert await _audit_rows(store, "auth.login_error") == []
    finally:
        await store.close()


@pytest.mark.parametrize(("exc", "transport", "reason"), _CASES)
async def test_only_a_transport_failure_marks_the_idp_on_step_up(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    exc: BaseException,
    transport: bool,
    reason: str,
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        signed_in = await _oidc_login(service, monkeypatch, rsa_key)
        assert signed_in.ok and signed_in.token is not None
        assert service.oidc_available is True
        flow_id, _url = await _begin(service, signed_in.token)
        flow = _staged(service, flow_id)
        _exchange_raises(monkeypatch, exc)
        out = await service.complete_oidc_step_up(
            flow_id=flow_id,
            state=flow.state,
            code=AUTH_CODE,
            client="10.0.0.9",
            public_origin=ORIGIN,
        )
        assert not out.elevation.ok
        assert out.reason == reason
        assert service.oidc_available is (not transport)
        # The refusal row carries the received status where there was one, as the sign-in leg's
        # does, so a 503 is not filed the same as a junk code's 400.
        row = json.loads((await _audit_rows(store, "auth.reauth"))[0]["detail"])
        assert row["reason"] == reason
        status = getattr(exc, "status", getattr(exc, "code", None))
        if isinstance(status, int):
            assert row["status"] == status
    finally:
        await store.close()


async def test_a_jwks_status_is_audited_with_its_status_on_sign_in(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, rsa_key)
        _exchange_raises(
            monkeypatch,
            urllib.error.HTTPError("https://idp.example/jwks", 404, "gone", {}, None),  # type: ignore[arg-type]
        )
        await service.authenticate_oidc(
            AUTH_CODE, _flow(), redirect_uri=f"{ORIGIN}/ui/oidc/callback", client="192.0.2.7"
        )
        [row] = await _audit_rows(store, "auth.login_error")
        detail = json.loads(row["detail"])
        assert detail["error"] == "HTTPError" and detail["status"] == 404
    finally:
        await store.close()
