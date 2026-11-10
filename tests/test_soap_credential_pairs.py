# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5526: the SOAP destination's credential pairs are both or neither, the WS-Security
UsernameToken no longer borrows the HTTP Basic pair, and a configured credential owns the one
``Authorization`` header.

Before this change a half Basic pair built and sent no ``Authorization`` header, a half
UsernameToken pair built and stamped an empty password, and ``ws_security`` with only the Basic
pair sent the same password twice: once as HTTP Basic and once in the UsernameToken (ADR 0015
amendment of 2026-11-10). The refusal runs in ``SoapDestination.__init__``, on the resolved
settings, so an ``env()`` that resolves to an empty string is refused as well as an omitted key.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.static_credentials import _http_static
from messagefoundry.config.wiring import Soap
from messagefoundry.transports import build_destination
from messagefoundry.transports.http_auth import (
    is_authorization_header_name,
    with_oauth2_client_credentials,
)
from messagefoundry.transports.soap import SoapDestination

URL = "https://api.example.com/svc"
_PW = "pw-synthetic"  # noqa: S105 -- a synthetic test credential, not a real secret


def _build(settings: dict[str, object]) -> SoapDestination:
    d = build_destination(
        Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, SoapDestination)
    return d


def _dest(**over: object) -> SoapDestination:
    return _build(Soap(url=URL, **over).settings)  # type: ignore[arg-type]


def _auth_keys(d: SoapDestination) -> list[str]:
    # The same spelling rule the purge uses, so a surviving "Authorization\t" key is counted.
    return [k for k in d._headers if is_authorization_header_name(k)]


# --- HTTP Basic: both halves or neither -----------------------------------------------------


@pytest.mark.parametrize(
    "half",
    [{"basic_user": "svc"}, {"basic_password": _PW}],
    ids=["user-only", "password-only"],
)
def test_a_half_basic_pair_is_refused_at_construction(half: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="basic_user and basic_password") as ei:
        _dest(**half)
    assert _PW not in str(ei.value)
    assert "OB_SOAP" in str(ei.value)


def test_an_env_value_that_resolves_empty_is_a_half_pair() -> None:
    """The factory sees EnvRef objects; the connector sees the resolved values, so the refusal lives
    there. An empty resolved password is refused like an omitted one."""
    settings = Soap(url=URL).settings
    settings.update({"basic_user": "svc", "basic_password": ""})
    with pytest.raises(ValueError, match="basic_user and basic_password"):
        _build(settings)


def test_control_a_whole_basic_pair_builds_and_sends_basic() -> None:
    d = _dest(basic_user="svc", basic_password=_PW)
    assert d._headers["Authorization"].startswith("Basic ")


# --- WS-Security UsernameToken: both halves or neither, and no borrowing ------------------------


@pytest.mark.parametrize(
    "half",
    [{"ws_username": "svc"}, {"ws_password": _PW}],
    ids=["user-only", "password-only"],
)
def test_a_half_username_token_pair_is_refused_with_ws_security(half: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="ws_username and ws_password") as ei:
        _dest(soap_version="1.2", ws_security=True, **half)
    assert _PW not in str(ei.value)


def test_ws_security_with_no_username_token_pair_stamps_the_timestamp_only() -> None:
    """Decided in #5526: ``ws_security`` with neither half is a Timestamp-only header, a recognised
    WS-Security profile (for example beside mutual TLS), not a refusal."""
    d = _dest(soap_version="1.2", ws_security=True)
    env = d._wrap_envelope("<op/>")
    assert "<wsu:Timestamp" in env
    assert "UsernameToken" not in env


def test_ws_security_no_longer_borrows_the_basic_pair() -> None:
    """The double send: before #5526 the UsernameToken fell back to basic_user/basic_password, so
    the one password went out twice, in the Authorization header and in the envelope."""
    d = _dest(soap_version="1.2", ws_security=True, basic_user="svc", basic_password=_PW)
    assert d._headers["Authorization"].startswith("Basic ")
    env = d._wrap_envelope("<op/>")
    assert "UsernameToken" not in env
    assert _PW not in env
    # The posture reader agrees: HTTP Basic is presented, no UsernameToken is.
    census = {"basic_user": "svc", "basic_password": _PW, "ws_security": True}
    assert _http_static(ConnectorType.SOAP, census, False) == ["HTTP Basic"]


def test_control_a_whole_username_token_pair_stamps_the_token() -> None:
    d = _dest(soap_version="1.2", ws_security=True, ws_username="svc", ws_password=_PW)
    env = d._wrap_envelope("<op/>")
    assert "<wsse:Username>svc</wsse:Username>" in env
    assert _PW in env
    assert not _auth_keys(d)


# --- a configured credential owns the one Authorization header (hardening) ----------------------


@pytest.mark.parametrize(
    "casing",
    ["authorization", "AUTHORIZATION", "Authorization", "Authorization\t", " authorization"],
)
@pytest.mark.parametrize(
    "cred",
    [{"basic_user": "svc", "basic_password": _PW}, {"bearer_token": "tok-synthetic"}],
    ids=["basic", "bearer"],
)
def test_a_static_authorization_header_of_any_casing_is_purged(
    casing: str, cred: dict[str, str]
) -> None:
    """For a name in plain letters this is hardening: urllib capitalises header names and the last
    write wins, so the configured credential already reached the wire, though ``_headers`` held two
    keys. A name with a tab or a space at an end is not merged by urllib, so before this change the
    static value crossed as a second header beside the configured one. Now exactly one is held."""
    d = _dest(headers={casing: "Basic STATIC"}, **cred)
    keys = _auth_keys(d)
    assert keys == ["Authorization"]
    assert d._headers["Authorization"] != "Basic STATIC"


def test_a_minted_bearer_also_owns_the_authorization_header() -> None:
    """The OAuth2 provider writes Authorization per request in _post, after construction, so the
    static table is purged once the provider exists (simplify pass of #5526)."""
    spec = with_oauth2_client_credentials(
        Soap(url=URL, headers={"authorization": "Basic STATIC"}),
        token_url="https://auth.example.com/token",
        client_id="cid",
        client_secret="cs-synthetic",  # noqa: S106 -- a synthetic test credential
    )
    d = _build(spec.settings)
    assert d._token_provider is not None
    assert _auth_keys(d) == []


def test_control_a_static_authorization_header_alone_is_kept() -> None:
    d = _dest(headers={"authorization": "Basic STATIC"})
    assert _auth_keys(d) == ["authorization"]
