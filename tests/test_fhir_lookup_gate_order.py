# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #8299 items 2, 3, 4, 6, 8 and 9: the order of the FhirLookupExecutor's checks and gates.

The checks ``_planned`` runs come for every lookup before any lookup reaches a hop gate, so a
lookup one of them refuses leaves no crossing record, from itself or from a lookup built before
it. Synthetic values only.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from types import MappingProxyType
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.transports import build_destination
from messagefoundry.transports import fhir as fhir_mod
from messagefoundry.transports import smart as smart_mod
from messagefoundry.transports.fhir import FhirLookupExecutor

_OPEN = EgressSettings(deny_by_default=False)
_WARN_DIAL = HopPosture(enforcing=False)

#: A cleartext lookup off this machine whose acceptance is declared: under a non-enforcing posture
#: its hop gate WARNs, naming the host, which is the crossing record these tests look for.
_FIRST = {
    "url": "http://first.partner.invalid/fhir",
    "cleartext_accepted": True,
    "cleartext_reason": "synthetic test peer has no TLS",
}
_SECOND_OK = {"url": "https://second.partner.invalid/fhir"}

_GATES = (
    "egress_route_from_settings",
    "refuse_cleartext_credentials",
    "refuse_cleartext_egress",
    "refuse_verify_off",
    "refuse_unrevoked_verified_hop",
)


@pytest.fixture
def gates(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[str, str]]]:
    """Every hop-gate call the executor makes, as ``(gate, connection)``, in order."""
    calls: list[tuple[str, str]] = []

    def spy(name: str, real: Any) -> Any:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            calls.append((name, str(kwargs.get("connection"))))
            return real(*args, **kwargs)

        return wrapper

    for name in _GATES:
        monkeypatch.setattr(fhir_mod, name, spy(name, getattr(fhir_mod, name)))
    real_token = smart_mod.token_provider_from_settings

    def token_spy(s: Any, **kwargs: Any) -> Any:
        calls.append(("token_provider_from_settings", ""))
        return real_token(s, **kwargs)

    monkeypatch.setattr(smart_mod, "token_provider_from_settings", token_spy)
    yield calls


def _build(connections: dict[str, dict[str, Any]]) -> FhirLookupExecutor:
    with active_hop_posture(_WARN_DIAL):
        return FhirLookupExecutor(connections, egress=_OPEN)


def _crossed(caplog: pytest.LogCaptureFixture, host: str) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.WARNING and host in r.getMessage()
    ]


def test_the_control_an_accepted_cleartext_lookup_records_its_crossing(
    gates: list[tuple[str, str]], caplog: pytest.LogCaptureFixture
) -> None:
    """THE CONTROL for every test below: the instrument sees a crossing when one is made."""
    caplog.set_level(logging.WARNING)
    ex = _build({"first": dict(_FIRST), "second": dict(_SECOND_OK)})
    assert ex.connections == {"first", "second"}
    assert _crossed(caplog, "first.partner.invalid")
    assert ("refuse_cleartext_egress", "fhir_lookup:first") in gates


@pytest.mark.parametrize(
    "bad",
    [
        {"url": "https://second.partner.invalid/fhir x"},  # the static-request screen
        {"url": "https://second.partner.invalid/fhir", "timeout_seconds": 0},
        {
            "url": "https://second.partner.invalid/fhir",
            "cleartext_accepted": True,  # an acceptance with no reason
        },
        {"url": "https://second.partner.invalid/fhir", "headers": {"X-Pad": "a" * 9000}},
    ],
    ids=["screen", "timeout", "acceptance-pair", "over-length"],
)
def test_a_lookup_refused_by_a_pure_check_leaves_no_crossing_from_an_earlier_lookup(
    gates: list[tuple[str, str]], caplog: pytest.LogCaptureFixture, bad: dict[str, Any]
) -> None:
    """Items 2, 3 and 6: the first lookup crosses in cleartext, the second fails a check that
    needs no I/O, so no gate runs for either and nothing is recorded."""
    caplog.set_level(logging.WARNING)
    with pytest.raises(ValueError, match="FhirLookup 'second'"):
        _build({"first": dict(_FIRST), "second": bad})
    assert gates == []
    assert _crossed(caplog, "first.partner.invalid") == []


def test_an_over_length_lookup_is_refused_before_its_own_gates_and_named(
    gates: list[tuple[str, str]],
) -> None:
    """Items 2 and 9: the length refusal names the lookup and runs before its hop gates."""
    with pytest.raises(ValueError, match=r"^FhirLookup 'big': outbound header 'X-Pad'"):
        _build(
            {"big": {"url": "https://big.partner.invalid/fhir", "headers": {"X-Pad": "a" * 9000}}}
        )
    assert gates == []


def test_the_static_credential_check_runs_before_the_token_provider_is_built(
    gates: list[tuple[str, str]],
) -> None:
    """Item 4: a SMART lookup over cleartext http is refused for its bearer before the provider
    (and its token hop's gates) is built."""
    settings = {
        "url": "http://fhir.partner.invalid/fhir",
        "smart_token_url": "https://auth.partner.invalid/token",
        "smart_client_id": "cid",
        "smart_private_key": "not-a-key-and-never-read",
    }
    with pytest.raises(ValueError, match="cleartext"):
        _build({"smart": settings})
    names = [name for name, _ in gates]
    assert "token_provider_from_settings" not in names
    assert "refuse_cleartext_credentials" in names
    # The control: on https the cleartext check passes, and the spy sees the provider built.
    gates.clear()
    with pytest.raises(ValueError, match="signing-key file"):
        _build({"smart": {**settings, "url": "https://fhir.partner.invalid/fhir"}})
    assert [name for name, _ in gates][-1] == "token_provider_from_settings"


@pytest.mark.parametrize(
    ("over", "match"),
    [
        ({"headers": ["X-Site", "1"]}, "'headers' must be a table"),
        ({"basic_user": "u"}, "basic_user and basic_password must be set together"),
        ({"headers": []}, "'headers' must be a table"),
        ({"headers": MappingProxyType({"X-Site": "1"})}, "'headers' must be a table"),
        ({"basic_password": "p"}, "basic_user and basic_password must be set together"),
        ({"basic_user": "a:b", "basic_password": "p"}, "basic_user must not contain ':'"),
        (
            {"basic_user": "u", "basic_password": "p", "bearer_token": "t"},
            "both bearer_token and basic_user",
        ),
    ],
    ids=[
        "headers-list",
        "user-only",
        "headers-empty-list",
        "headers-mapping-proxy",
        "password-only",
        "colon",
        "bearer-and-basic",
    ],
)
def test_a_static_credential_the_lookup_would_drop_is_refused(
    over: dict[str, Any], match: str
) -> None:
    """Item 8: these used to build, and the lookup sent no headers, no Basic credential, or Basic
    in place of the bearer, without a word."""
    with pytest.raises(ValueError, match=match) as ei:
        _build({"epic": {"url": "https://fhir.partner.invalid/fhir", **over}})
    assert str(ei.value).startswith("FhirLookup 'epic': ")


@pytest.mark.parametrize(
    "over",
    [
        {"headers": {"X-Site": "1"}},
        {"basic_user": "u", "basic_password": "p"},
        {"bearer_token": "t"},
    ],
    ids=["headers-table", "basic-pair", "bearer"],
)
def test_the_control_a_whole_static_credential_still_builds(over: dict[str, Any]) -> None:
    ex = _build({"epic": {"url": "https://fhir.partner.invalid/fhir", **over}})
    assert ex.connections == {"epic"}


def _destination(**over: Any) -> object:
    settings = {"url": "https://fhir.partner.invalid/fhir", **over}
    return build_destination(
        Destination(name="OB_FHIR", type=ConnectorType.FHIR, settings=settings), egress=_OPEN
    )


@pytest.mark.parametrize(
    ("over", "match"),
    [
        ({"headers": ["X-Site", "1"]}, "'headers' must be a table"),
        ({"basic_user": "u"}, "basic_user and basic_password must be set together"),
        ({"basic_password": "p"}, "basic_user and basic_password must be set together"),
        ({"basic_user": "a:b", "basic_password": "p"}, "basic_user must not contain ':'"),
        (
            {"basic_user": "u", "basic_password": "p", "bearer_token": "t"},
            "both bearer_token and basic_user",
        ),
    ],
    ids=["headers-list", "user-only", "password-only", "colon", "bearer-and-basic"],
)
def test_the_fhir_destination_refuses_the_same_dropped_credentials(
    over: dict[str, Any], match: str
) -> None:
    """Item 8, on the destination's own copy of ``_build_headers``."""
    with pytest.raises(ValueError, match=match) as ei:
        _destination(**over)
    assert str(ei.value).startswith("connection 'OB_FHIR'; FHIR destination")


def test_the_control_the_fhir_destination_still_builds_a_whole_credential() -> None:
    assert _destination(basic_user="u", basic_password="p", headers={"X-Site": "1"})
