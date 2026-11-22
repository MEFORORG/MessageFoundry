# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5911 added steps 3 to 5 and 11: the build-time screen of static HTTP request values.

A static url, token url or header that ``http.client`` could never send is the connection's fault,
so it fails construction instead of every message (or every token mint) at send time. Synthetic
values only.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.transports import build_destination
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.http_auth import OAuth2ClientCredentialsProvider
from messagefoundry.transports.rest import refuse_unsendable_static_request
from messagefoundry.transports.smart import SmartBackendTokenProvider

_OPEN = EgressSettings(deny_by_default=False)

_URLS = {
    ConnectorType.REST: "https://rest.example.org/in",
    ConnectorType.SOAP: "https://soap.example.org/svc",
    ConnectorType.DICOMWEB: "https://dicomweb.example.org/rs",
}


def _build(kind: ConnectorType, **settings: Any) -> object:
    return build_destination(
        Destination(name="OB_SCREEN", type=kind, settings={"url": _URLS[kind], **settings}),
        egress=_OPEN,
    )


_KINDS = list(_URLS)


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("tail", ["/a b", "/café", "/a b"])
def test_an_unsendable_static_url_is_refused_at_construction(
    kind: ConnectorType, tail: str
) -> None:
    """Step 5: REST, SOAP and DICOMweb get the screen FHIR has."""
    with pytest.raises(ValueError, match="'url' must be ASCII with no whitespace") as ei:
        _build(kind, url=_URLS[kind] + tail)
    assert ei.value.__context__ is None


@pytest.mark.parametrize("kind", [ConnectorType.REST, ConnectorType.SOAP])
def test_a_fragment_is_not_refused_where_the_url_is_sent_as_it_stands(kind: ConnectorType) -> None:
    """REST and SOAP append no path to the url, so urllib only drops a fragment there."""
    assert _build(kind, url=_URLS[kind] + "#part") is not None


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("name", ["X Site", "X(Site)", "Xé"])
def test_a_static_header_name_that_is_not_a_token_is_refused(
    kind: ConnectorType, name: str
) -> None:
    """Step 4: http.client sends a name with a space or a parenthesis; RFC 9110 does not allow it."""
    with pytest.raises(ValueError, match="not a header name the engine sends"):
        _build(kind, headers={name: "1"})


@pytest.mark.parametrize("kind", [ConnectorType.REST, ConnectorType.SOAP])
@pytest.mark.parametrize("value", ["a\x00b", "a\r\n b", "a\x7fb"])
def test_a_static_header_value_with_a_control_character_is_refused(
    kind: ConnectorType, value: str
) -> None:
    """Step 4: http.client sends a NUL and a folded line; RFC 9110 allows no control but HTAB."""
    with pytest.raises(ValueError, match="X-Site") as ei:
        _build(kind, headers={"X-Site": value})
    assert value not in str(ei.value)


def test_a_tab_in_a_static_header_value_still_constructs() -> None:
    """Positive control: HTAB is legal in a field value."""
    refuse_unsendable_static_request(
        "https://h.example.org/", {"X-Site": "a\tb"}, setting="test destination"
    )


@pytest.mark.parametrize("kind", _KINDS)
def test_a_clean_static_request_still_constructs(kind: ConnectorType) -> None:
    """Positive control: a percent-encoded url and a token-named header build."""
    assert _build(kind, url=_URLS[kind] + "/caf%C3%A9", headers={"X-Site": "café one"})


@pytest.mark.parametrize(
    "provider",
    [SmartBackendTokenProvider, OAuth2ClientCredentialsProvider],
    ids=["smart", "oauth2"],
)
@pytest.mark.parametrize(
    "token_url",
    ["https://as.example.org/to ken", "https://as.example.org/töken", "https://as.exāmple.org/t"],
)
def test_an_unsendable_token_url_is_refused_at_construction(
    provider: type[SmartBackendTokenProvider | OAuth2ClientCredentialsProvider], token_url: str
) -> None:
    """Step 3: smart_token_url and oauth2_token_url get the static-url screen."""
    with pytest.raises(ValueError, match="must be ASCII with no whitespace"):
        provider._check_token_url(token_url, connection="OB_SCREEN")


@pytest.mark.parametrize(
    "provider",
    [SmartBackendTokenProvider, OAuth2ClientCredentialsProvider],
    ids=["smart", "oauth2"],
)
def test_a_clean_token_url_passes_the_screen(
    provider: type[SmartBackendTokenProvider | OAuth2ClientCredentialsProvider],
) -> None:
    assert provider._check_token_url("https://as.example.org/token", connection=None) == "https"


def test_a_refused_lookup_leaves_no_crossing_record_from_an_earlier_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Step 11: every lookup is screened before any is built, so the first lookup's hop gates
    never run when the second is refused."""
    from messagefoundry.transports.rest import egress_route_from_settings as real

    built: list[str] = []

    def _spy(*args: Any, **kwargs: Any) -> Any:
        built.append(str(kwargs.get("connection")))
        return real(*args, **kwargs)

    monkeypatch.setattr("messagefoundry.transports.fhir.egress_route_from_settings", _spy)
    with pytest.raises(ValueError, match="FhirLookup 'second'"):
        FhirLookupExecutor(
            {
                "first": {"url": "https://fhir.example.org/fhir"},
                "second": {"url": "https://fhir.example.org/fhir x"},
            },
            egress=_OPEN,
        )
    assert built == []
