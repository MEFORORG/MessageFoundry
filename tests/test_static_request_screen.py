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
@pytest.mark.parametrize("tail", ["/a b", "/café", "/a\u00a0b"])
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


def test_a_lookup_the_static_screen_refuses_runs_no_gate_for_an_earlier_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Step 11: every lookup is screened before any is built, so the first lookup's proxy route
    is never built when the second fails the static-request screen. Only that screen's refusal is
    tested here; tests/test_fhir_lookup_gate_order.py covers a cleartext first lookup and the
    other checks that run before any lookup is built (BACKLOG #8299 item 6)."""
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
    # The control: with a second lookup the screen passes, both proxy routes are built.
    FhirLookupExecutor(
        {
            "first": {"url": "https://fhir.example.org/fhir"},
            "second": {"url": "https://fhir.example.org/fhir/x"},
        },
        egress=_OPEN,
    )
    assert built == ["fhir_lookup:first", "fhir_lookup:second"]


@pytest.mark.parametrize("kind", [ConnectorType.REST, ConnectorType.SOAP])
@pytest.mark.parametrize(
    "wrapped", [" {}", "{}\n", "{} "], ids=["lead-space", "trail-lf", "trail-space"]
)
def test_whitespace_urllib_strips_is_not_refused_where_the_url_is_sent_as_is(
    kind: ConnectorType, wrapped: str
) -> None:
    """urllib's Request unwraps the url before it sends it, so these delivered on main and must
    still build (round-16b7ce9851 finding 2)."""
    assert _build(kind, url=wrapped.format(_URLS[kind])) is not None


def test_a_trailing_space_in_a_dicomweb_base_is_refused() -> None:
    """The STOW-RS target appends /studies after it, so the space lands inside the request line."""
    with pytest.raises(ValueError, match="'url' must be ASCII with no whitespace"):
        _build(ConnectorType.DICOMWEB, url=_URLS[ConnectorType.DICOMWEB] + " ")


def test_a_fragment_is_refused_on_soap_with_ws_addressing() -> None:
    """wsa:To carries the url as written, fragment included, while the POST drops it."""
    with pytest.raises(ValueError, match="no '#' when ws_addressing"):
        _build(
            ConnectorType.SOAP,
            url=_URLS[ConnectorType.SOAP] + "#part",
            ws_addressing=True,
            soap_version="1.2",
        )


def _smart(token_url: str, **over: Any) -> SmartBackendTokenProvider:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=3072)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    return SmartBackendTokenProvider(token_url=token_url, client_id="cid", private_key=pem, **over)


def test_a_fragment_in_a_smart_token_url_with_the_default_audience_is_refused() -> None:
    """The default aud is the token URL as written, fragment included, while the POST drops it."""
    with pytest.raises(ValueError, match="no '#' unless smart_audience is set"):
        _smart("https://as.example.org/token#x")
    audience = "https://as.example.org/token"
    assert _smart("https://as.example.org/token#x", audience=audience).audience == audience


def test_a_control_character_in_a_proxy_named_value_is_refused_on_fhir() -> None:
    """The value check runs on a proxy-named header too where the screen judges it at all
    (round-16b7ce9851 finding 5); the value never reaches the refusal."""
    with pytest.raises(ValueError, match="control character") as ei:
        refuse_unsendable_static_request(
            "https://h.example.org/",
            {"Proxy-Authorization": "Basic a\x00bc"},
            setting="FHIR destination",
        )
    assert "a\x00bc" not in str(ei.value)


@pytest.mark.parametrize("kind", [ConnectorType.REST, ConnectorType.SOAP])
def test_the_part_between_two_hashes_is_judged(kind: ConnectorType) -> None:
    """urllib splits the fragment at the LAST '#', so the part before it is sent and judged
    (round-4104477e09 finding 1)."""
    with pytest.raises(ValueError, match="'url' must be ASCII with no whitespace"):
        _build(kind, url=_URLS[kind] + "#a b#c")


def test_a_smart_token_url_with_whitespace_and_the_default_audience_is_refused() -> None:
    """The default aud keeps the whitespace the POST strips (round-4104477e09 finding 3)."""
    with pytest.raises(ValueError, match="no whitespace around it"):
        _smart("https://as.example.org/token \n")


def test_a_soap_url_with_surrounding_controls_is_refused_with_ws_addressing() -> None:
    """wsa:To carries the url as written (round-4104477e09 finding 4)."""
    with pytest.raises(ValueError, match="no whitespace around it"):
        _build(
            ConnectorType.SOAP,
            url=_URLS[ConnectorType.SOAP] + "\x0b",
            ws_addressing=True,
            soap_version="1.2",
        )


@pytest.mark.parametrize("kind", [ConnectorType.REST, ConnectorType.SOAP])
def test_a_url_with_trailing_whitespace_is_refused_with_digest(kind: ConnectorType) -> None:
    """The Digest password is stored under the url as written, and the lookup keeps a trailing
    space the request drops (round-4104477e09 finding 5)."""
    with pytest.raises(
        ValueError, match="must not end in whitespace the Digest password lookup keeps"
    ):
        _build(
            kind,
            url=_URLS[kind] + " ",
            http_auth="digest",
            http_auth_user="u",
            http_auth_password="synthetic",
        )


@pytest.mark.parametrize("kind", [ConnectorType.REST, ConnectorType.SOAP])
@pytest.mark.parametrize("wrapped", ["{}#frag", " {}"], ids=["fragment", "leading-space"])
def test_a_url_the_digest_lookup_still_matches_builds_with_digest(
    kind: ConnectorType, wrapped: str
) -> None:
    """The lookup's own split drops a fragment and leading whitespace on both sides, so these
    authenticate as on main and must build (round-4656d6176e finding 4)."""
    assert _build(
        kind,
        url=wrapped.format(_URLS[kind]),
        http_auth="digest",
        http_auth_user="u",
        http_auth_password="synthetic",
    )


def test_a_proxy_named_name_http_client_refuses_names_that_rule() -> None:
    """The tchar check is skipped for it, so the refusal names http.client's rule
    (round-4104477e09 finding 7)."""
    with pytest.raises(ValueError, match="not a header name http.client can send"):
        refuse_unsendable_static_request(
            "https://h.example.org/", {"Proxy-Authorization:x": "1"}, setting="FHIR destination"
        )
