# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One refusal for a hop URL that names no host, at the sites BACKLOG #2207 names.

``tls_policy.is_loopback_hop_host("")`` is True. So a site that wrote ``hostname or ""`` took the
on-box carve-out for the one hop it could not classify. BACKLOG #1924 closed that in the four
construction guards in ``transports/rest.py``. This file covers the sites that still read an empty
host after it:

* the send-time re-check in ``_post`` and ``_probe`` of the four HTTP destinations, and in
  ``FhirLookupExecutor``;
* the two trust-anchor lookups, ``http_family_trust_anchor`` and ``vault_client_verify_kwargs``;
* ``FhirLookupExecutor``'s constructor, which took a verified ``https`` base with no host;
* the OIDC revocation guards, which stood a placeholder in and only warned outside ``enforce``.

All of them now read the host through ``tls_policy.hop_url_host``. Each case pairs the refusal
with a control on a real host, so a site that refused everything would fail too. Nothing here
touches the network: the openers are fakes, and the Vault clients are refused before any I/O.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.auth.oidc_http import build_idp_opener
from messagefoundry.auth.service import idp_revocation_guards
from messagefoundry.config import tls_policy
from messagefoundry.config.fhir_lookup import FhirLookupError
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.config.tls_policy import (
    SYSTEM_TRUST_ANCHOR,
    HopPosture,
    InsecureHopRefused,
    TrustAnchor,
    TrustAnchorPolicy,
    active_hop_posture,
    hop_url_host,
    is_loopback_hop_host,
    vault_client_verify_kwargs,
)
from messagefoundry.config.wiring import FHIR, DICOMweb, Rest, Soap
from messagefoundry.transports import build_destination, rest
from messagefoundry.transports.base import DeliveryError, DestinationConnector
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.http_auth import oauth2_cc_provider_from_settings
from messagefoundry.transports.rest import (
    HttpAuthError,
    InsecureHopGuard,
    http_family_trust_anchor,
)
from messagefoundry.transports.smart import SmartAuthError, token_provider_from_settings
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

_PROD = HopPosture(enforcing=True)
_STAGING = HopPosture(enforcing=False)

# Authorities that name no host: none at all, and a port with nothing in front of it.
_NO_HOST_AUTHORITIES = ["", ":8443"]


class _Resp:
    status = 200
    headers = None

    def read(self, amt: int = -1) -> bytes:
        return b""

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> None:
        return None


class _Opener:
    def __init__(self) -> None:
        self.calls = 0

    def open(self, req: object, timeout: float | None = None) -> _Resp:
        self.calls += 1
        return _Resp()


class _TokenProvider:
    def __init__(self) -> None:
        self.mints = 0

    def access_token(self) -> str:
        self.mints += 1
        return "synthetic-token"

    def invalidate(self) -> None:
        return None


def _open_guard() -> InsecureHopGuard:
    """A send-time guard with every way across switched on, on a non-enforcing posture.

    It permits any real host, so a refusal under it comes from the missing host and from nothing
    else. ``MEFOR_ALLOW_INSECURE_TLS`` is set by the tests that use it, for the verify-off arm."""
    return InsecureHopGuard(
        posture=_STAGING,
        attested=True,
        cell="HTTP cleartext egress",
        cleartext_accepted=True,
        weakened_tls=True,
        connection="OB",
    )


# --- the shared check ---------------------------------------------------------------------------


@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("authority", _NO_HOST_AUTHORITIES)
def test_the_shared_check_refuses_a_url_with_no_host(scheme: str, authority: str) -> None:
    with pytest.raises(ValueError, match="names no host") as err:
        hop_url_host(f"{scheme}://{authority}/x", cell="some cell")
    # A plain ValueError, as BACKLOG #1924 chose: the token and Digest seams add posture advice to
    # an InsecureHopRefused, and no posture fixes a missing host.
    assert type(err.value) is ValueError
    assert str(err.value).startswith("some cell: ")


def test_the_shared_check_refuses_a_string_that_is_not_a_url() -> None:
    for text in ("", "no-scheme.example.org/x"):
        with pytest.raises(ValueError, match="names no host"):
            hop_url_host(text, cell="c")


def test_the_shared_check_refuses_a_url_that_will_not_split_with_the_same_text() -> None:
    """``urlsplit`` raises on a malformed bracketed host, and its error quotes the URL. The check
    gives its own fixed text and chains nothing, so a caller may show the message."""
    with pytest.raises(ValueError) as plain:
        hop_url_host("https:///x", cell="c")
    with pytest.raises(ValueError, match="names no host") as err:
        hop_url_host("https://[not-an-address/secret-path", cell="c")
    assert str(err.value) == str(plain.value)
    assert err.value.__cause__ is None
    assert err.value.__context__ is None


def test_the_shared_check_returns_a_real_host() -> None:
    assert hop_url_host("https://API.example.com:8443/x", cell="c") == "api.example.com"
    assert hop_url_host("http://127.0.0.1:8080/x", cell="c") == "127.0.0.1"
    assert hop_url_host("https://[::1]:8443/x", cell="c") == "::1"


def test_the_rest_construction_guards_use_the_shared_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``rest._hop_guard_host`` is the name the four construction guards call. It must be the
    shared check and not a second copy of it."""
    seen: list[tuple[str, str]] = []

    def spy(url: str, *, cell: str) -> str:
        seen.append((url, cell))
        return "spied.example.org"

    monkeypatch.setattr(rest, "hop_url_host", spy)
    assert rest._hop_guard_host("https://a.example.org/x", cell="c") == "spied.example.org"
    assert seen == [("https://a.example.org/x", "c")]


# --- the send-time guard itself -----------------------------------------------------------------


def test_the_send_guard_refuses_an_empty_host_in_any_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    guard = _open_guard()
    guard.assert_send("api.example.com", "http://api.example.com/x")  # control: a real host crosses
    with pytest.raises(InsecureHopRefused, match="names no host") as err:
        guard.assert_send("", "")
    assert str(err.value).startswith("connection 'OB'")


@pytest.mark.parametrize(
    "url",
    [
        "http:///x",
        "http://:8443/x",
        "https:///x",
        "no-scheme/x",
        # A bracketed host that urlsplit refuses to split. Its own error quotes the URL.
        "http://[not-an-address/secret-path",
    ],
)
def test_the_send_guard_refuses_a_url_whose_host_it_cannot_read(
    url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    guard = _open_guard()
    guard.assert_send_url("http://api.example.com/x")  # control: a real host crosses
    with pytest.raises(InsecureHopRefused) as empty:
        guard.assert_send("", "")
    with pytest.raises(InsecureHopRefused, match="names no host") as err:
        guard.assert_send_url(url)
    # Fixed text: the same words whatever the URL, so no part of it and no urllib error text.
    assert str(err.value) == str(empty.value)
    # Nothing chained either: urlsplit's own error quotes the URL, and a traceback would print it.
    assert err.value.__cause__ is None
    assert err.value.__context__ is None


# --- the four HTTP destinations: _post and _probe -----------------------------------------------

# (ConnectorType, wiring factory, a cleartext URL to a real host, the name of the attribute the
# send-time re-check reads, the arguments one _post call takes).
_CELLS: dict[str, tuple[Any, Any, str, str, tuple[Any, ...]]] = {
    "REST": (ConnectorType.REST, Rest, "http://api.example.com/x", "url", ("x",)),
    "SOAP": (ConnectorType.SOAP, Soap, "http://api.example.com/svc", "url", ("<x/>",)),
    "FHIR": (
        ConnectorType.FHIR,
        FHIR,
        "http://fhir.example.org/fhir",
        "base_url",
        ("{}", "POST", "http://fhir.example.org/fhir/Patient", {}),
    ),
    "DICOMweb": (
        ConnectorType.DICOMWEB,
        DICOMweb,
        "http://pacs.example.org/dicom-web",
        "base_url",
        (b"DICM",),
    ),
}
_MINTING = ["REST", "FHIR"]


def _destination(cell: str) -> tuple[DestinationConnector, _Opener, str, tuple[Any, ...]]:
    """A built destination on a fake opener, with the open guard in place.

    The constructor refuses a URL with no host, so a send-time site can only meet one if the URL
    changes after construction. Each test below does that by hand, which is the reload or
    re-target the send-time re-check exists for (ADR 0092 decision 4)."""
    ctype, factory, url, attr, post_args = _CELLS[cell]
    with active_hop_posture(_PROD):
        dest = build_destination(
            Destination(
                name="OB",
                type=ctype,
                settings=factory(url=url).settings,
                cleartext_accepted=True,
                cleartext_reason="vendor firmware predates TLS",
            ),
            egress=EgressSettings(deny_by_default=False),
        )
    opener = _Opener()
    dest._opener = opener  # type: ignore[attr-defined]
    dest._hop_guard = _open_guard()  # type: ignore[attr-defined]
    assert getattr(dest, attr) == url
    return dest, opener, attr, post_args


@pytest.mark.parametrize("cell", list(_CELLS))
@pytest.mark.parametrize("authority", _NO_HOST_AUTHORITIES)
def test_a_send_to_a_url_with_no_host_is_refused_and_sends_nothing(
    cell: str, authority: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    dest, opener, attr, post_args = _destination(cell)

    dest._post(*post_args)  # type: ignore[attr-defined]
    assert opener.calls == 1  # control: with its real host, the same call reaches the opener

    setattr(dest, attr, f"http://{authority}/x")
    # The type _post already raises for a refused hop (test_hop_refusal_http pins it).
    with pytest.raises(InsecureHopRefused, match="names no host"):
        dest._post(*post_args)  # type: ignore[attr-defined]
    assert opener.calls == 1  # refused before a byte crossed


@pytest.mark.parametrize("cell", list(_CELLS))
@pytest.mark.parametrize("authority", _NO_HOST_AUTHORITIES)
async def test_a_probe_of_a_url_with_no_host_is_refused_and_sends_nothing(
    cell: str, authority: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    dest, opener, attr, _ = _destination(cell)
    provider = _TokenProvider()
    if cell in _MINTING:
        dest._token_provider = provider  # type: ignore[attr-defined]

    await dest.test_connection()
    assert opener.calls == 1  # control
    minted = provider.mints

    setattr(dest, attr, f"http://{authority}/x")
    with pytest.raises(DeliveryError, match="names no host") as err:
        await dest.test_connection()
    assert type(err.value) is DeliveryError
    assert isinstance(err.value.__cause__, InsecureHopRefused)
    assert opener.calls == 1  # the refused probe sent nothing
    assert provider.mints == minted  # and minted no bearer


# --- FhirLookupExecutor: its constructor and its send-time re-check ------------------------------


@pytest.mark.parametrize(
    ("url", "extra"),
    [
        ("https:///fhir", {}),  # verified https: this arm reached no guard, and built
        ("https://:8443/fhir", {}),
        ("https:///fhir", {"verify_tls": False}),
        ("http:///fhir", {}),
    ],
)
def test_a_fhir_lookup_whose_base_names_no_host_does_not_build(
    url: str, extra: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    for posture in (_PROD, _STAGING):
        with active_hop_posture(posture), pytest.raises(ValueError, match="names no host"):
            FhirLookupExecutor(
                {"L": {"url": url, **extra}}, egress=EgressSettings(deny_by_default=False)
            )


def test_the_fhir_lookup_refusal_names_the_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    """An executor holds several lookups, and nothing above it adds a name. So the refusal on the
    verified https arm, which comes from the anchor lookup, has to say which lookup it is."""
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    lookups = {"GOOD": {"url": "https://127.0.0.1:8443/fhir"}, "BAD": {"url": "https:///fhir"}}
    with active_hop_posture(_PROD), pytest.raises(ValueError, match="names no host") as err:
        FhirLookupExecutor(lookups, egress=EgressSettings(deny_by_default=False))
    assert str(err.value).startswith("FhirLookup 'BAD': ")


def test_a_fhir_lookup_with_a_real_host_still_builds(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the arm above: a loopback base builds on an enforcing posture."""
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD):
        ex = FhirLookupExecutor(
            {"L": {"url": "https://127.0.0.1:8443/fhir"}},
            egress=EgressSettings(deny_by_default=False),
        )
    assert ex.connections == frozenset({"L"})


class _JsonResp(_Resp):
    def __init__(self) -> None:
        self._body = b'{"resourceType":"Patient","id":"123"}'

    def read(self, amt: int = -1) -> bytes:
        body, self._body = (self._body, b"") if amt < 0 else (self._body[:amt], self._body[amt:])
        return body


class _JsonOpener(_Opener):
    def open(self, req: object, timeout: float | None = None) -> _JsonResp:
        self.calls += 1
        return _JsonResp()


async def test_a_fhir_lookup_read_and_probe_refuse_a_base_with_no_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with active_hop_posture(_PROD):
        ex = FhirLookupExecutor(
            {"L": {"url": "http://127.0.0.1:8080/fhir"}},
            egress=EgressSettings(deny_by_default=False),
        )
    opener = _JsonOpener()
    ex._opener["L"] = opener  # type: ignore[assignment]
    ex._hop_guard["L"] = _open_guard()

    # Control: with its real host, the read and the probe both reach the opener.
    assert (await ex.read("L", "Patient/123"))["id"] == "123"
    await ex.test_connection("L")
    assert opener.calls == 2

    ex._base["L"] = "http:///fhir"
    with pytest.raises(FhirLookupError, match="names no host") as read_err:
        await ex.read("L", "Patient/123")
    with pytest.raises(FhirLookupError, match="names no host") as probe_err:
        await ex.test_connection("L")
    for err in (read_err, probe_err):
        assert type(err.value) is FhirLookupError
        assert isinstance(err.value.__cause__, InsecureHopRefused)
    assert opener.calls == 2  # neither refused call sent anything


# --- the trust-anchor lookups -------------------------------------------------------------------


@pytest.mark.parametrize("authority", _NO_HOST_AUTHORITIES)
def test_the_http_family_anchor_lookup_refuses_a_url_with_no_host(authority: str) -> None:
    """Read as loopback, a URL with no host dropped the instance CA and the CRL. Each policy below
    would have resolved to the OS trust store for it."""
    for policy in (
        None,
        TrustAnchorPolicy(mode="pinned", internal_ca_file="ca.pem", crl_file="crl.pem"),
    ):
        with pytest.raises(ValueError, match="names no host"):
            http_family_trust_anchor({}, url=f"https://{authority}/x", trust_anchor_policy=policy)


def test_the_http_family_anchor_lookup_still_resolves_a_real_host() -> None:
    policy = TrustAnchorPolicy(mode="pinned", internal_ca_file="ca.pem", crl_file="crl.pem")
    assert (
        http_family_trust_anchor({}, url="https://api.example.com/x", trust_anchor_policy=None)
        == SYSTEM_TRUST_ANCHOR
    )
    # A remote host takes the instance CA and the CRL; a loopback host takes neither.
    remote = http_family_trust_anchor(
        {}, url="https://api.example.com/x", trust_anchor_policy=policy
    )
    assert (remote.cafile, remote.crl_file) == ("ca.pem", "crl.pem")
    local = http_family_trust_anchor({}, url="https://127.0.0.1/x", trust_anchor_policy=policy)
    assert (local.cafile, local.crl_file) == (None, None)


@pytest.mark.parametrize(
    "token_url", ["https:///token", "https://:8443/token", "idp.example/token"]
)
def test_a_token_endpoint_with_no_host_is_refused_by_name(token_url: str) -> None:
    """Both token-endpoint factories resolve the trust anchor before their provider checks the URL,
    so the anchor lookup is where a URL with no host is refused. The refusal leads with the
    setting's name. A plain ValueError, as BACKLOG #1924 chose for these seams."""
    with active_hop_posture(_PROD):
        with pytest.raises(ValueError, match="names no host") as oauth:
            oauth2_cc_provider_from_settings(
                {
                    "oauth2_token_url": token_url,
                    "oauth2_client_id": "synthetic-client",
                    "oauth2_client_secret": "synthetic",  # nosec B105 - a made-up test value
                }
            )
        with pytest.raises(ValueError, match="names no host") as smart:
            token_provider_from_settings(
                {"smart_token_url": token_url, "smart_client_id": "synthetic-client"}
            )
    # Exactly ValueError: the providers' own error types subclass it, and so does the refusal
    # that carries posture advice.
    assert type(oauth.value) is ValueError
    assert type(smart.value) is ValueError
    assert str(oauth.value).startswith("oauth2_token_url: ")
    assert str(smart.value).startswith("smart_token_url: ")


def test_a_token_endpoint_with_a_host_still_gets_its_providers_own_refusal() -> None:
    """The control: a URL that has a host passes the anchor lookup, and the provider's own check
    still answers, with its own error type."""
    with active_hop_posture(_PROD), pytest.raises(HttpAuthError, match="must be http or https"):
        oauth2_cc_provider_from_settings(
            {
                "oauth2_token_url": "ftp://idp.example/token",
                "oauth2_client_id": "synthetic-client",
                "oauth2_client_secret": "synthetic",  # nosec B105 - a made-up test value
            }
        )
    with active_hop_posture(_PROD), pytest.raises(SmartAuthError, match="must be http or https"):
        token_provider_from_settings(
            {"smart_token_url": "ftp://idp.example/token", "smart_client_id": "synthetic-client"}
        )


def _hosts_the_vault_lookup_resolves(
    monkeypatch: pytest.MonkeyPatch, addrs: list[str | None]
) -> list[str]:
    seen: list[str] = []

    def spy(*, connection_ca_file: str | None, host: str, policy: TrustAnchorPolicy) -> TrustAnchor:
        seen.append(host)
        return SYSTEM_TRUST_ANCHOR

    monkeypatch.setattr(tls_policy, "resolve_trust_anchor", spy)
    for addr in addrs:
        assert vault_client_verify_kwargs(ca_file=None, addr=addr, cell="[secrets] test") == {}
    return seen


def test_the_vault_anchor_lookup_never_reads_a_missing_host_as_on_box(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """This lookup does not raise: the client build refuses the address, with the provider's own
    error type (the test below). What it must not do is hand the anchor a host that reads as
    loopback. An unset address is the same case, because hvac then picks one this lookup cannot
    see."""
    unreadable: list[str | None] = [
        "https:///v1",
        "https://:8200",
        "http:///v1",
        "no-scheme/v1",
        "https://[not-an-address/v1",
        "",
        None,
    ]
    hosts = _hosts_the_vault_lookup_resolves(monkeypatch, unreadable)
    assert len(hosts) == len(unreadable)
    assert [h for h in hosts if is_loopback_hop_host(h)] == []


def test_the_vault_anchor_lookup_still_reads_a_real_host(monkeypatch: pytest.MonkeyPatch) -> None:
    hosts = _hosts_the_vault_lookup_resolves(
        monkeypatch, ["https://127.0.0.1:8200", "https://vault.example.org:8200"]
    )
    assert hosts == ["127.0.0.1", "vault.example.org"]
    assert [is_loopback_hop_host(h) for h in hosts] == [True, False]


@pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)
@pytest.mark.parametrize("addr", ["https:///v1", "https://:8200", "http:///v1"])
def test_a_vault_client_does_not_build_for_an_address_with_no_host(addr: str) -> None:
    """The refusal the lookup above leaves to the client build, for both providers. Each raises
    its own fail-closed type before any I/O, so no client exists to send a token with."""
    from messagefoundry.config import secretprovider_vault
    from messagefoundry.config.secretprovider import SecretProviderError
    from messagefoundry.store import keyprovider_vault
    from messagefoundry.store.keyprovider import KeyProviderError

    token = "s.synthetic-token"  # nosec B105 - a made-up test value, not a credential
    with pytest.raises(SecretProviderError):
        secretprovider_vault._build_client(addr, token)
    with pytest.raises(KeyProviderError):
        keyprovider_vault._build_client(addr, token)


# --- the OIDC revocation guards -----------------------------------------------------------------

_REAL_TOKEN = "https://idp.example.org/token"  # nosec B105 - a URL, not a credential
_REAL_JWKS = "https://idp.example.org/jwks"


def _auth(token_endpoint: str | None, jwks_uri: str | None) -> AuthSettings:
    """Unvalidated ``[auth]`` settings: the validator refuses these URLs, which is why the guard
    must not depend on it having run."""
    return AuthSettings.model_construct(oidc_token_endpoint=token_endpoint, oidc_jwks_uri=jwks_uri)


@pytest.mark.parametrize("posture", [_PROD, _STAGING, None])
@pytest.mark.parametrize(
    ("token_endpoint", "jwks_uri", "leg"),
    [
        ("https:///token", _REAL_JWKS, "token endpoint"),
        (None, _REAL_JWKS, "token endpoint"),
        (_REAL_TOKEN, "https://:8443/jwks", "jwks_uri endpoint"),
        (_REAL_TOKEN, None, "jwks_uri endpoint"),
    ],
)
def test_an_oidc_leg_with_no_host_is_refused_in_any_posture(
    posture: HopPosture | None, token_endpoint: str | None, jwks_uri: str | None, leg: str
) -> None:
    """Outside ``enforce`` the placeholder host only warned, and with no posture it did nothing."""
    opener = build_idp_opener(None)
    with pytest.raises(InsecureHopRefused, match="names no host") as err:
        idp_revocation_guards(_auth(token_endpoint, jwks_uri), opener, posture)
    # The type this hop's other refusal raises. serve and provision-admin report it as they report
    # that one; verify shows it as an ERROR on its revocation row.
    assert type(err.value) is InsecureHopRefused
    assert str(err.value).startswith(f"[auth] OIDC {leg}: ")


@pytest.mark.parametrize("posture", [_PROD, _STAGING, None])
def test_the_oidc_guards_still_capture_two_real_legs(posture: HopPosture | None) -> None:
    guards = idp_revocation_guards(_auth(_REAL_TOKEN, _REAL_JWKS), build_idp_opener(None), posture)
    assert [g.host for g in guards] == ["idp.example.org", "idp.example.org"]
