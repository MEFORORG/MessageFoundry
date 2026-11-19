# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A bearer token request that cannot be built is classified, on REST and FHIR (BACKLOG #5795, #5797).

The token provider raises ``DeliveryError`` for a failed mint, but a request it cannot build or
encode (an over-length token URL or proxy credential, a header value ``http.client`` refuses) raises
a plain ``ValueError``. Before these rows that escaped ``send()`` and the test-connection probe
unclassified. A delivery now gets a permanent configuration fault, so the lane stops and the queue
is kept; a probe gets a plain ``DeliveryError``, its only failure type.
"""

from __future__ import annotations

import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import FHIR, Rest
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.fhir import FhirDestination
from messagefoundry.transports.rest import TOKEN_REQUEST_REFUSED_CODE, RestDestination

REST_URL = "https://api.example.com/ingest"
FHIR_URL = "https://fhir.example.org/fhir"
SECRET = "proxy-credential-value"
SYNTHETIC_PATIENT = '{"resourceType": "Patient", "id": "synthetic-1"}'


def _rest() -> RestDestination:
    d = build_destination(
        Destination(name="OB_REST", type=ConnectorType.REST, settings=Rest(url=REST_URL).settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, RestDestination)
    return d


def _fhir() -> FhirDestination:
    d = build_destination(
        Destination(name="OB_FHIR", type=ConnectorType.FHIR, settings=FHIR(url=FHIR_URL).settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, FhirDestination)
    return d


class _UnbuildableTokenRequest:
    """A provider whose token request cannot be built: the ValueError quotes a credential, as an
    http.client header check does."""

    def __init__(self) -> None:
        self.invalidated = False

    def access_token(self) -> str:
        raise ValueError(f"Invalid header value {SECRET!r}")

    def invalidate(self) -> None:
        self.invalidated = True


class _LongToken:
    def __init__(self) -> None:
        self.invalidated = False

    def access_token(self) -> str:
        return "T" * 9000

    def invalidate(self) -> None:
        self.invalidated = True


class _Opener:
    def __init__(self) -> None:
        self.calls = 0

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> object:
        self.calls += 1
        raise AssertionError("nothing may be sent")


@pytest.mark.parametrize("make", [_rest, _fhir], ids=["rest", "fhir"])
async def test_an_unbuildable_token_request_is_a_configuration_fault(make: object) -> None:
    dest = make()  # type: ignore[operator]
    dest._token_provider = _UnbuildableTokenRequest()
    opener = _Opener()
    dest._opener = opener
    with pytest.raises(NegativeAckError) as err:
        await dest.send(SYNTHETIC_PATIENT)
    assert err.value.permanent is True
    assert err.value.config_fault is True
    assert err.value.code == TOKEN_REQUEST_REFUSED_CODE
    assert "ValueError" in str(err.value)
    # Raised outside the handler: the ValueError, which quotes the credential, is not chained.
    assert err.value.__cause__ is None and err.value.__context__ is None
    assert SECRET not in str(err.value)
    assert opener.calls == 0


@pytest.mark.parametrize("make", [_rest, _fhir], ids=["rest", "fhir"])
async def test_an_unbuildable_token_request_fails_the_probe_as_a_delivery_error(
    make: object,
) -> None:
    dest = make()  # type: ignore[operator]
    dest._token_provider = _UnbuildableTokenRequest()
    opener = _Opener()
    dest._opener = opener
    with pytest.raises(DeliveryError) as err:
        await dest.test_connection()
    assert type(err.value) is DeliveryError
    assert err.value.__cause__ is None and err.value.__context__ is None
    assert SECRET not in str(err.value)
    assert opener.calls == 0


@pytest.mark.parametrize("make", [_rest, _fhir], ids=["rest", "fhir"])
async def test_the_probe_retypes_the_length_gate_refusal(make: object) -> None:
    """BACKLOG #5795, #5797: the probe's send-time length gate raises NegativeAckError; the probe
    raises only a plain DeliveryError, and still drops the over-length cached token."""
    dest = make()  # type: ignore[operator]
    provider = _LongToken()
    dest._token_provider = provider
    opener = _Opener()
    dest._opener = opener
    with pytest.raises(DeliveryError) as err:
        await dest.test_connection()
    assert type(err.value) is DeliveryError
    assert isinstance(err.value.__cause__, NegativeAckError)
    assert provider.invalidated is True
    assert "T" * 20 not in str(err.value)
    assert opener.calls == 0


class _RefusingRequest:
    def __init__(self, *args: object, **kwargs: object) -> None:
        raise ValueError("unknown url type")


async def test_a_rest_request_urllib_cannot_build_is_classified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5797: building the delivery Request sat outside the classifying try. Its ValueError
    is now a permanent bad-request-value, as the open's ValueError arm does."""
    dest = _rest()
    opener = _Opener()
    dest._opener = opener  # type: ignore[assignment]
    monkeypatch.setattr(urllib.request, "Request", _RefusingRequest)
    with pytest.raises(NegativeAckError) as err:
        await dest.send(SYNTHETIC_PATIENT)
    assert (err.value.code, err.value.permanent, err.value.config_fault) == (
        "bad-request-value",
        True,
        False,
    )
    assert opener.calls == 0


@pytest.mark.parametrize("make", [_rest, _fhir], ids=["rest", "fhir"])
async def test_a_probe_request_urllib_cannot_build_is_a_delivery_error(
    make: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = make()  # type: ignore[operator]
    opener = _Opener()
    dest._opener = opener
    monkeypatch.setattr(urllib.request, "Request", _RefusingRequest)
    with pytest.raises(DeliveryError, match="rejected an invalid request value") as err:
        await dest.test_connection()
    assert type(err.value) is DeliveryError
    assert opener.calls == 0
