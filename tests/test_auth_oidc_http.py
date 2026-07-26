# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The OIDC relying party's outbound TLS wiring (ADR 0142, BACKLOG #274).

These guard the properties that make the IdP hop safe to carry an authentication assertion: TLS is
always verified, redirects are never followed, the JWKS read is bounded at the socket, and a bad CA
path refuses at construction instead of silently widening trust.
"""

from __future__ import annotations

import datetime
import ssl
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from messagefoundry.auth import oidc_http
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.oidc.jwks import _MAX_JWKS_BYTES
from messagefoundry.auth.trust_anchors import TrustAnchorError


def _handler_types(opener: urllib.request.OpenerDirector) -> set[str]:
    return {type(h).__name__ for h in opener.handlers}


def _https_context(opener: urllib.request.OpenerDirector) -> ssl.SSLContext:
    https = next(h for h in opener.handlers if type(h).__name__ == "HTTPSHandler")
    return https._context  # noqa: SLF001 - the context is not otherwise reachable


def test_opener_without_ca_file_verifies_via_the_os_store() -> None:
    opener = oidc_http.build_idp_opener(None)
    assert "_NoRedirectHandler" in _handler_types(opener)
    ctx = _https_context(opener)
    # Discriminating: assert the OS anchors are actually loaded. `build_opener()` always installs an
    # HTTPSHandler, so merely finding one proves nothing about which context it carries.
    assert len(ctx.get_ca_certs()) > 1
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_default_branch_uses_a_plain_stdlib_context_not_truststore() -> None:
    """truststore.SSLContext re-configures a SHARED inner context to CERT_NONE for the duration of
    each handshake and restores it before `_verify_peercerts` reads verify_mode back off it. One
    opener is shared across asyncio.to_thread workers here, so a concurrent login could observe
    CERT_NONE and skip validation outright — an authentication bypass on the hop that carries the
    identity assertion. Keep this branch on a context with no shared mutable verification state."""
    ctx = _https_context(oidc_http.build_idp_opener(None))
    assert type(ctx) is ssl.SSLContext, f"expected a plain stdlib context, got {type(ctx)!r}"
    assert "truststore" not in type(ctx).__module__


def _self_signed_ca_pem() -> bytes:
    """A throwaway self-signed CA PEM. Generated rather than copied from the platform bundle because
    Windows has no `cafile` at all (it uses the cert store), which would skip the pinned branch —
    the security-critical one — on the project's primary platform."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-test-idp-ca")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_opener_with_ca_file_pins_to_exactly_that_pem(tmp_path: Path) -> None:
    ca = tmp_path / "idp-ca.pem"
    ca.write_bytes(_self_signed_ca_pem())

    opener = oidc_http.build_idp_opener(str(ca))
    assert "_NoRedirectHandler" in _handler_types(opener)
    # Pinned-only, not additive: the supplied PEM is the ENTIRE anchor set, so a public-CA chain the
    # OS would otherwise accept is not trusted on this hop. The OS branch loads many more, so this
    # count discriminates between the two branches rather than restating a stdlib default.
    ctx = _https_context(opener)
    assert len(ctx.get_ca_certs()) == 1
    assert len(_https_context(oidc_http.build_idp_opener(None)).get_ca_certs()) > 1


def test_missing_ca_file_refuses_at_construction(tmp_path: Path) -> None:
    """Fail closed: a typo'd CA path must not fall back to a wider trust set."""
    with pytest.raises(OSError):
        oidc_http.build_idp_opener(str(tmp_path / "does-not-exist.pem"))


def test_group_writable_anchor_warns_not_refuses_in_warn_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#285 (ASVS 6.7.1): the construction seam must honor the [security].enforcement dial. In warn
    mode a group/world-writable anchor is warned+audited by the central preflight and MUST NOT refuse
    here — otherwise the owner-fork 'warn' outcome is unreachable for the OIDC anchor at serve startup
    (the seam previously hardcoded enforce)."""
    ca = tmp_path / "idp-ca.pem"
    ca.write_bytes(_self_signed_ca_pem())
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    opener = oidc_http.build_idp_opener(str(ca), enforcing=False)
    assert "_NoRedirectHandler" in _handler_types(opener)
    assert _https_context(opener).verify_mode is ssl.CERT_REQUIRED


def test_group_writable_anchor_refuses_in_enforce_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same group/world-writable anchor refuses at enforce, and the dial defaults fail-closed
    (omitting ``enforcing`` enforces)."""
    ca = tmp_path / "idp-ca.pem"
    ca.write_bytes(_self_signed_ca_pem())
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    with pytest.raises(TrustAnchorError, match="writable by a non-owner"):
        oidc_http.build_idp_opener(str(ca), enforcing=True)
    with pytest.raises(TrustAnchorError, match="writable by a non-owner"):
        oidc_http.build_idp_opener(str(ca))


def test_pin_mismatch_refuses_at_construction_regardless_of_dial(tmp_path: Path) -> None:
    """A configured SHA-256 pin that does not match the loaded PEM refuses at construction always —
    independent of the enforcement dial (so it fires even in warn mode)."""
    ca = tmp_path / "idp-ca.pem"
    ca.write_bytes(_self_signed_ca_pem())
    with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
        oidc_http.build_idp_opener(str(ca), pin="00" * 32, enforcing=False)


def test_redirects_are_never_followed() -> None:
    """An open redirect on the token endpoint would relocate a request carrying the client secret
    and the authorization code, so the handler must refuse rather than follow."""
    handler = oidc_http._NoRedirectHandler()
    req = urllib.request.Request("https://idp.example/token", method="POST")
    assert (
        handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/steal") is None
    )


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.read_sizes: list[int | None] = []

    def read(self, size: int | None = None) -> bytes:
        self.read_sizes.append(size)
        return self._body if size is None else self._body[:size]

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


class _FakeOpener:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResponse:
        self.requests.append(req)
        return self.response


def test_jwks_fetch_is_a_bounded_get() -> None:
    response = _FakeResponse(b'{"keys": []}')
    opener = _FakeOpener(response)
    fetch = oidc_http.jwks_fetcher("https://idp.example/jwks", opener)  # type: ignore[arg-type]

    assert fetch() == b'{"keys": []}'
    # Bounded ON the socket read, not after buffering: a hostile IdP cannot make the engine hold an
    # unbounded body before JwksCache's own length check runs.
    assert response.read_sizes == [_MAX_JWKS_BYTES + 1]
    assert opener.requests[0].get_method() == "GET"


def test_jwks_fetch_reads_one_byte_past_the_bound_so_oversize_is_detectable() -> None:
    """JwksCache rejects when len(body) > _MAX_JWKS_BYTES, which only works if the fetch returns the
    extra byte rather than truncating exactly at the bound."""
    response = _FakeResponse(b"x" * (_MAX_JWKS_BYTES + 50))
    fetch = oidc_http.jwks_fetcher("https://idp.example/jwks", _FakeOpener(response))  # type: ignore[arg-type]
    assert len(fetch()) == _MAX_JWKS_BYTES + 1
