# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Handler's per-message headers meet the static header allowlist at send (vault BACKLOG #3533 item 6).

The owner's 2026-10-26 ruling on item 7 holds a ``verify_tls = false`` hop's static headers to
``VERIFY_OFF_STATIC_HEADER_ALLOWLIST``. Item 4 holds plain http off this machine to the same list.
Before item 6 the rule read settings only, so a header a Handler stamped under ``dynamic_headers``
crossed either hop whatever its name. These tests drive the REST and FHIR ``send`` with a fake wire
call, so a refusal is seen before any byte would cross, and a control reaches the wire.

Every value here is synthetic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import FHIR, Rest
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.fhir import FhirDestination
from messagefoundry.transports.rest import (
    DYNAMIC_HEADER_REFUSED_CODE,
    VERIFY_OFF_STATIC_HEADER_ALLOWLIST,
    RestDestination,
)

_ENFORCING = HopPosture(enforcing=True)
_PATIENT = '{"resourceType": "Patient", "id": "p1"}'

#: Each per-message header set the rule must refuse: a name off the allowlist, a credential under
#: an allowed name, and both together.
_REFUSED: dict[str, dict[str, str]] = {
    "neutral name": {"X-Session": "s1"},
    "credential value under an allowed name": {"X-Request-ID": "Bearer abc.def.ghi"},
    "two headers": {"X-Session": "s1", "If-Match": 'W/"3"'},
}


def _meta(headers: dict[str, str]) -> dict[str, str]:
    return {f"http.header.{name}": value for name, value in headers.items()}


def _build(ctype: ConnectorType, settings: dict[str, Any], **declared: Any) -> Any:
    with active_hop_posture(_ENFORCING):
        return build_destination(
            Destination(name="OB_DYN", type=ctype, settings=settings, **declared),
            egress=EgressSettings(deny_by_default=False),
        )


def _rest(url: str, *, verify_tls: bool = True, **declared: Any) -> RestDestination:
    settings = Rest(url=url, verify_tls=verify_tls, dynamic_headers=True).settings
    dest = _build(ConnectorType.REST, settings, **declared)
    assert isinstance(dest, RestDestination)
    return dest


def _fhir(url: str, *, verify_tls: bool = True, **declared: Any) -> FhirDestination:
    settings = FHIR(url=url, verify_tls=verify_tls, dynamic_headers=True).settings
    dest = _build(ConnectorType.FHIR, settings, **declared)
    assert isinstance(dest, FhirDestination)
    return dest


_Dest = RestDestination | FhirDestination

_ACCEPTED: dict[str, Any] = {
    "cleartext_accepted": True,
    "cleartext_reason": "legacy partner has no TLS listener",
}

#: Each hop the static rule holds to the allowlist, so the dynamic rule must too.
_HELD: dict[str, Callable[[], _Dest]] = {
    "rest verify-off loopback": lambda: _rest("https://127.0.0.1:8443/x", verify_tls=False),
    "rest cleartext off-box": lambda: _rest("http://partner.example.test/x", **_ACCEPTED),
    "fhir verify-off loopback": lambda: _fhir("https://127.0.0.1:8443/fhir", verify_tls=False),
    "fhir cleartext off-box": lambda: _fhir("http://partner.example.test/fhir", **_ACCEPTED),
}

#: Each hop the rule does not hold: a verified https hop, and plain http that stays on the box.
_FREE: dict[str, Callable[[], _Dest]] = {
    "rest verified": lambda: _rest("https://127.0.0.1:8443/x"),
    "rest cleartext loopback": lambda: _rest("http://127.0.0.1:8080/x"),
    "fhir verified": lambda: _fhir("https://127.0.0.1:8443/fhir"),
    "fhir cleartext loopback": lambda: _fhir("http://127.0.0.1:8080/fhir"),
}


def _wire(dest: RestDestination | FhirDestination, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Replace the blocking wire call with a recorder that answers 200 with no body."""
    sent: list[Any] = []
    if isinstance(dest, RestDestination):

        def post(payload: str, dynamic: dict[str, str] | None = None) -> tuple[str, int, dict]:
            sent.append(dynamic)
            return "", 200, {}

        monkeypatch.setattr(dest, "_post", post)
    else:

        def exchange(payload: str, request: Any, extra: dict[str, str]) -> tuple:
            sent.append(extra)
            return "", 200, {}, None

        monkeypatch.setattr(dest, "_exchange", exchange)
    return sent


@pytest.mark.parametrize("hop", list(_HELD))
@pytest.mark.parametrize("case", list(_REFUSED))
def test_a_held_hop_refuses_the_header_at_send(
    hop: str, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = _HELD[hop]()
    sent = _wire(dest, monkeypatch)
    with pytest.raises(NegativeAckError) as exc:
        asyncio.run(dest.send(_PATIENT, metadata=_meta(_REFUSED[case])))
    assert sent == []
    assert exc.value.code == DYNAMIC_HEADER_REFUSED_CODE
    assert exc.value.permanent is True
    text = str(exc.value)
    assert "connection 'OB_DYN'" in text
    count = len(_REFUSED[case])
    assert f"stamped {count} per-message header" in text
    # Neither a name nor a value: at send both are message-derived. The text lists the allowlist
    # itself, so an allowed name is checked only by its value.
    for name, value in _REFUSED[case].items():
        assert value not in text
        if name.lower() not in VERIFY_OFF_STATIC_HEADER_ALLOWLIST:
            assert name not in text


@pytest.mark.parametrize("hop", list(_HELD))
def test_control_a_held_hop_sends_an_allowlisted_header(
    hop: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The arm above refuses for the header, not for the hop: an allowlisted name with a plain
    value reaches the wire."""
    dest = _HELD[hop]()
    sent = _wire(dest, monkeypatch)
    asyncio.run(dest.send(_PATIENT, metadata=_meta({"X-Request-ID": "r1", "Accept": "a/b"})))
    assert len(sent) == 1


@pytest.mark.parametrize("hop", list(_FREE))
def test_control_a_free_hop_sends_any_header(hop: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A verified hop, and plain http on the box, keep sending what the Handler stamps."""
    dest = _FREE[hop]()
    sent = _wire(dest, monkeypatch)
    asyncio.run(dest.send(_PATIENT, metadata=_meta(_REFUSED["two headers"])))
    assert len(sent) == 1
