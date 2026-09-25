# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1142, slice 2 (ASVS 6.7.1): the bytes the anchor check reads are the bytes the TLS
context loads.

Before this slice both consumers checked one read of the anchor file and then loaded the file again
by path: ``build_idp_opener`` through ``create_default_context(cafile=)``, and
``build_api_ssl_context`` through ``load_verify_locations(cafile=)``. A file swapped between the two
reads was trusted with no pin, ACL or path check. Now both load ``cadata=`` built from the checked
bytes.

What this file proves, and the instrument for each:

* **The swap.** The file is replaced with a second CA in the gap between the check's read and the
  load, by wrapping the path check, which runs after the read. The built context must hold the
  checked CA, and a real handshake must verify the checked CA's server and refuse the swapped one.
* **The control for the swap.** The same swap, then a ``cafile=`` load, must pick up the swapped CA.
  Without it, a swap that never happened would make the first test pass for the wrong reason.
* **Equivalence.** ``cadata=`` and ``cafile=`` over the same PEM must verify the right CA and refuse
  a wrong one, in real handshakes, client side and server side.
* **The text conversion.** ``cadata=`` takes ASCII only, so the conversion is pinned case by case.
* **The verify row.** ``fed.idp_tls`` for an anchored IdP, by verdict.
"""

from __future__ import annotations

import datetime
import hashlib
import ssl
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import PathVerdict
from messagefoundry.auth.oidc_http import build_idp_opener
from messagefoundry.auth.trust_anchors import AnchorSpec, TrustAnchorError, anchor_cadata
from messagefoundry.config.settings import ApiSettings, ServiceSettings
from messagefoundry.config.tls_policy import urllib_handler_context
from messagefoundry.verify.federation import run_federation_checks
from messagefoundry.verify.model import Status

_NB = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
_NA = datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC)
_SPEC = AnchorSpec("t", "[t].ca", "t.pem")


# --- a tiny PKI: two unrelated CAs, each with a localhost leaf, RFC 5280-conformant -----------------


@dataclass(frozen=True)
class _Ca:
    name: str
    pem: bytes
    cert: str  # the leaf, a file path
    key: str  # the leaf's key, a file path


def _ku() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        key_cert_sign=True,
        crl_sign=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False,
    )


def _make_ca(d: Path, cn: str) -> _Ca:
    """A CA and a ``localhost`` leaf for server and client auth. SKI, AKI and KeyUsage are present
    because the contexts under test turn on ``VERIFY_X509_STRICT``."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB)
        .not_valid_after(_NA)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .add_extension(_ku(), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB)
        .not_valid_after(_NA)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert, key = d / f"{cn}-leaf.pem", d / f"{cn}-leaf-key.pem"
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return _Ca(cn, ca.public_bytes(serialization.Encoding.PEM), str(cert), str(key))


@pytest.fixture(scope="module")
def cas(tmp_path_factory: pytest.TempPathFactory) -> tuple[_Ca, _Ca]:
    """``good`` is the anchor the operator pinned; ``evil`` is what an attacker swaps in."""
    d = tmp_path_factory.mktemp("pki")
    return _make_ca(d, "good-ca"), _make_ca(d, "evil-ca")


# --- the handshake instrument ----------------------------------------------------------------------


def _handshake(client: ssl.SSLContext, server: ssl.SSLContext) -> None:
    """Drive a real TLS handshake between two contexts in memory. Raises :class:`ssl.SSLError` from
    whichever side refuses. No socket and no thread: two ``MemoryBIO`` pairs pumped until both sides
    report done."""
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    c = client.wrap_bio(c_in, c_out, server_hostname="localhost")
    s = server.wrap_bio(s_in, s_out, server_side=True)
    done = {"c": False, "s": False}
    for _ in range(50):
        for name, obj in (("c", c), ("s", s)):
            if done[name]:
                continue
            try:
                obj.do_handshake()
                done[name] = True
            except ssl.SSLWantReadError:
                pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        if done["c"] and done["s"]:
            return
    raise AssertionError("handshake neither completed nor failed within 50 rounds")


def _server(leaf_of: _Ca) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(leaf_of.cert, leaf_of.key)
    return ctx


def _mtls_client(leaf_of: _Ca, trusting: _Ca) -> ssl.SSLContext:
    """A TLS 1.2 client presenting ``leaf_of``'s leaf. TLS 1.2 so the server's verdict on the client
    certificate lands inside the handshake."""
    ctx = ssl.create_default_context(cadata=trusting.pem.decode("ascii"))
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(leaf_of.cert, leaf_of.key)
    return ctx


def _https_context(opener: urllib.request.OpenerDirector) -> ssl.SSLContext:
    """The context inside ``opener``'s one ``HTTPSHandler``."""
    handlers: list[urllib.request.BaseHandler] = opener.handlers  # type: ignore[attr-defined]
    handler = next(h for h in handlers if isinstance(h, urllib.request.HTTPSHandler))
    return urllib_handler_context(handler, connector="test")


def _subjects(ctx: ssl.SSLContext) -> list[str]:
    """The common name of every anchor ``ctx`` holds."""
    names: list[str] = []
    for cert in ctx.get_ca_certs():
        subject: Any = cert["subject"]
        names += [value for rdn in subject for key, value in rdn if key == "commonName"]
    return names


def _api(tmp_path: Path, cas: tuple[_Ca, _Ca], anchor: Path, pin: str | None) -> ApiSettings:
    good, _ = cas
    return ApiSettings(
        tls_cert_file=good.cert,
        tls_key_file=good.key,
        tls_client_ca_file=str(anchor),
        tls_client_ca_pin=pin,
    )


@pytest.fixture
def swap_after_check(monkeypatch: pytest.MonkeyPatch) -> Callable[[Path, bytes], None]:
    """Arm a swap: the next anchor check replaces ``path`` with ``evil`` AFTER it has read the file.

    The path check runs after the read inside ``evaluate_anchor``, so wrapping it lands the swap in
    the exact gap a second read by path would fall into. It also pins the ACL and path verdicts to
    clean, so the result does not depend on this machine's ACLs."""

    def arm(path: Path, evil: bytes) -> None:
        def swapped(anchor: str) -> PathVerdict:
            path.write_bytes(evil)
            return PathVerdict(ok=True)

        monkeypatch.setattr(ta, "anchor_path_verdict", swapped)
        monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)

    return arm


# --- the swap: the loaded bytes are the checked bytes ------------------------------------------------


def test_the_idp_opener_loads_the_checked_bytes_not_the_swapped_file(
    tmp_path: Path, cas: tuple[_Ca, _Ca], swap_after_check: Callable[[Path, bytes], None]
) -> None:
    good, evil = cas
    anchor = tmp_path / "idp-ca.pem"
    anchor.write_bytes(good.pem)
    swap_after_check(anchor, evil.pem)

    ctx = _https_context(build_idp_opener(str(anchor), pin=hashlib.sha256(good.pem).hexdigest()))

    assert anchor.read_bytes() == evil.pem  # the swap happened
    assert _subjects(ctx) == ["good-ca"]
    _handshake(ctx, _server(good))
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(ctx, _server(evil))


def test_the_api_client_ca_loads_the_checked_bytes_not_the_swapped_file(
    tmp_path: Path, cas: tuple[_Ca, _Ca], swap_after_check: Callable[[Path, bytes], None]
) -> None:
    good, evil = cas
    anchor = tmp_path / "client-ca.pem"
    anchor.write_bytes(good.pem)
    swap_after_check(anchor, evil.pem)

    ctx = build_api_ssl_context(
        _api(tmp_path, cas, anchor, hashlib.sha256(good.pem).hexdigest()), enforcing=True
    )

    assert anchor.read_bytes() == evil.pem  # the swap happened
    assert _subjects(ctx) == ["good-ca"]
    _handshake(_mtls_client(good, trusting=good), ctx)
    with pytest.raises(ssl.SSLError):
        _handshake(_mtls_client(evil, trusting=good), ctx)


def test_control_a_second_read_by_path_picks_up_the_swap(
    tmp_path: Path, cas: tuple[_Ca, _Ca], swap_after_check: Callable[[Path, bytes], None]
) -> None:
    """The load this slice removed, run after the same swap. It trusts the attacker's CA under a pin
    that matched the operator's, which is the defect. If this stops holding, the swap tests above no
    longer discriminate."""
    good, evil = cas
    anchor = tmp_path / "idp-ca.pem"
    anchor.write_bytes(good.pem)
    swap_after_check(anchor, evil.pem)

    ta.enforce_anchor(
        AnchorSpec("oidc", "[x]", str(anchor), hashlib.sha256(good.pem).hexdigest()),
        enforcing=True,
    )
    ctx = ssl.create_default_context(cafile=str(anchor))

    assert _subjects(ctx) == ["evil-ca"]
    _handshake(ctx, _server(evil))


def test_a_pin_mismatch_still_refuses_both_consumers(tmp_path: Path, cas: tuple[_Ca, _Ca]) -> None:
    good, evil = cas
    anchor = tmp_path / "ca.pem"
    anchor.write_bytes(evil.pem)
    pin = hashlib.sha256(good.pem).hexdigest()
    with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
        build_idp_opener(str(anchor), pin=pin, enforcing=False)
    with pytest.raises(TrustAnchorError, match="does not match its configured SHA-256 pin"):
        build_api_ssl_context(_api(tmp_path, cas, anchor, pin), enforcing=False)


# --- equivalence: cadata= sets the same trust as cafile= ---------------------------------------------


@pytest.mark.parametrize("how", ["cafile", "cadata"])
def test_client_side_trust_is_the_same_for_cafile_and_cadata(
    how: str, tmp_path: Path, cas: tuple[_Ca, _Ca]
) -> None:
    good, evil = cas
    anchor = tmp_path / "ca.pem"
    anchor.write_bytes(good.pem)
    if how == "cafile":
        ctx = ssl.create_default_context(cafile=str(anchor))
    else:
        ctx = ssl.create_default_context(cadata=good.pem.decode("ascii"))
    assert len(ctx.get_ca_certs()) == 1  # pinned-only: the OS store is not added
    _handshake(ctx, _server(good))
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(ctx, _server(evil))


@pytest.mark.parametrize("how", ["cafile", "cadata"])
def test_server_side_trust_is_the_same_for_cafile_and_cadata(
    how: str, tmp_path: Path, cas: tuple[_Ca, _Ca]
) -> None:
    good, evil = cas
    anchor = tmp_path / "ca.pem"
    anchor.write_bytes(good.pem)
    ctx = _server(good)
    if how == "cafile":
        ctx.load_verify_locations(cafile=str(anchor))
    else:
        ctx.load_verify_locations(cadata=good.pem.decode("ascii"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    _handshake(_mtls_client(good, trusting=good), ctx)
    with pytest.raises(ssl.SSLError):
        _handshake(_mtls_client(evil, trusting=good), ctx)


def test_the_built_idp_opener_verifies_the_anchor_and_refuses_another_ca(
    tmp_path: Path, cas: tuple[_Ca, _Ca]
) -> None:
    good, evil = cas
    anchor = tmp_path / "idp-ca.pem"
    anchor.write_bytes(good.pem)
    ctx = _https_context(build_idp_opener(str(anchor), enforcing=False))
    assert len(ctx.get_ca_certs()) == 1
    _handshake(ctx, _server(good))
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(ctx, _server(evil))


def test_the_built_api_context_admits_the_anchor_and_refuses_another_ca(
    tmp_path: Path, cas: tuple[_Ca, _Ca]
) -> None:
    good, evil = cas
    anchor = tmp_path / "client-ca.pem"
    anchor.write_bytes(good.pem)
    ctx = build_api_ssl_context(_api(tmp_path, cas, anchor, None), enforcing=False)
    _handshake(_mtls_client(good, trusting=good), ctx)
    with pytest.raises(ssl.SSLError):
        _handshake(_mtls_client(evil, trusting=good), ctx)


# --- the text conversion ------------------------------------------------------------------------------


def test_plain_ascii_pem_passes_through_unchanged(cas: tuple[_Ca, _Ca]) -> None:
    good, _ = cas
    assert anchor_cadata(good.pem, _SPEC) == good.pem.decode("ascii")
    crlf = good.pem.replace(b"\n", b"\r\n")
    assert anchor_cadata(crlf, _SPEC) == crlf.decode("ascii")


@pytest.mark.parametrize(
    "wrap",
    [
        pytest.param(lambda pem: b"\xef\xbb\xbf" + pem, id="utf-8 byte-order mark"),
        pytest.param(
            lambda pem: b"Bag Attributes\n    friendlyName: M\xc3\xbcller CA\n" + pem,
            id="non-ASCII comment above the block",
        ),
        pytest.param(lambda pem: pem + b"trailer \xc3\xa9\n", id="non-ASCII trailer"),
    ],
)
def test_text_that_cafile_reads_also_loads_as_cadata(
    wrap: Callable[[bytes], bytes], tmp_path: Path, cas: tuple[_Ca, _Ca]
) -> None:
    """``cafile=`` reads each of these, and ``cadata=`` refuses each raw. The conversion must load
    the same certificates ``cafile=`` does."""
    good, _ = cas
    data = wrap(good.pem)
    anchor = tmp_path / "ca.pem"
    anchor.write_bytes(data)
    with pytest.raises(TypeError, match="ASCII"):
        ssl.create_default_context(cadata=data.decode("latin-1"))  # the raw text does not load
    by_file = ssl.create_default_context(cafile=str(anchor))
    by_data = ssl.create_default_context(cadata=anchor_cadata(data, _SPEC))
    assert by_data.get_ca_certs() == by_file.get_ca_certs()
    assert _subjects(by_data) == ["good-ca"]


def test_a_non_ascii_byte_inside_a_block_refuses(cas: tuple[_Ca, _Ca]) -> None:
    good, _ = cas
    lines = good.pem.split(b"\n")
    lines[2] = lines[2][:10] + b"\xc3\xbc" + lines[2][10:]
    with pytest.raises(TrustAnchorError, match="non-ASCII byte inside a PEM block"):
        anchor_cadata(b"\n".join(lines), _SPEC)


def test_a_trusted_certificate_block_refuses_rather_than_vanishing(cas: tuple[_Ca, _Ca]) -> None:
    """``cafile=`` reads a TRUSTED CERTIFICATE block and ``cadata=`` skips it silently, so beside a
    plain block it would drop out of the trust set without a word. The conversion refuses and names
    the re-export."""
    good, evil = cas
    trusted = evil.pem.replace(b"BEGIN CERTIFICATE", b"BEGIN TRUSTED CERTIFICATE").replace(
        b"END CERTIFICATE", b"END TRUSTED CERTIFICATE"
    )
    with pytest.raises(TrustAnchorError, match="TRUSTED CERTIFICATE"):
        anchor_cadata(good.pem + trusted, _SPEC)
    # The control: raw, cadata= keeps the plain block and drops the trusted one, with no error.
    assert _subjects(ssl.create_default_context(cadata=(good.pem + trusted).decode())) == [
        "good-ca"
    ]


# --- the verify row, anchored -------------------------------------------------------------------------


def _fed_settings(anchor: Path | None, pin: str | None = None, **security: Any) -> ServiceSettings:
    auth: dict[str, Any] = {
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "mefor-console",
        "oidc_client_secret": "shhh",
        "oidc_authorization_endpoint": "https://idp.example/authorize",
        "oidc_token_endpoint": "https://idp.example/token",
        "oidc_jwks_uri": "https://idp.example/jwks",
        "oidc_allowed_endpoints": ["idp.example"],
        "ad_enabled": True,
        "ad_server": "ldaps://x",
        "ad_user_search_base": "DC=x",
        "ad_bind_dn": "CN=svc,DC=x",
        "ad_bind_password": "x",
        "ad_domain": "corp.example",
    }
    if anchor is not None:
        auth["oidc_tls_ca_cert_file"] = str(anchor)
    if pin is not None:
        auth["oidc_tls_ca_cert_pin"] = pin
    return ServiceSettings.model_validate(
        {"auth": auth, "api": {"public_origin": "https://ops.example"}, "security": security}
    )


def _tls_row(settings: ServiceSettings) -> Any:
    return next(r for r in run_federation_checks(settings) if r.id == "fed.idp_tls")


@pytest.fixture
def anchored(tmp_path: Path, cas: tuple[_Ca, _Ca]) -> Path:
    anchor = tmp_path / "idp-ca.pem"
    anchor.write_bytes(cas[0].pem)
    return anchor


def _verdicts(monkeypatch: pytest.MonkeyPatch, *, acl: bool | None, path: bool | None) -> None:
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: acl)
    monkeypatch.setattr(
        ta, "anchor_path_verdict", lambda _p: PathVerdict(ok=path, engine="DOMAIN\\svc-check")
    )


def test_verify_passes_a_clean_anchor_and_names_the_account_it_ran_as(
    anchored: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _verdicts(monkeypatch, acl=True, path=True)
    row = _tls_row(_fed_settings(anchored))
    assert row.status is Status.PASS
    assert "DOMAIN\\svc-check" in row.detail
    assert "not as the service account" in row.detail
    assert "acl=owner-only" in row.evidence


@pytest.mark.parametrize(("acl", "path"), [(None, True), (True, None), (None, None)])
def test_verify_cannot_pass_an_anchor_it_could_not_judge(
    acl: bool | None, path: bool | None, anchored: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _verdicts(monkeypatch, acl=acl, path=path)
    row = _tls_row(_fed_settings(anchored))
    assert row.status is Status.MANUAL
    assert "not as the service account" in row.detail


@pytest.mark.parametrize(("acl", "path"), [(False, True), (True, False)])
def test_verify_fails_an_anchor_the_engine_refuses_at_enforce(
    acl: bool | None, path: bool | None, anchored: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _verdicts(monkeypatch, acl=acl, path=path)
    assert _tls_row(_fed_settings(anchored)).status is Status.FAIL


@pytest.mark.parametrize(("acl", "path"), [(False, True), (True, False)])
def test_verify_asks_a_person_about_an_anchor_warn_mode_loads(
    acl: bool | None, path: bool | None, anchored: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _verdicts(monkeypatch, acl=acl, path=path)
    row = _tls_row(_fed_settings(anchored, enforcement="warn"))
    assert row.status is Status.MANUAL


def test_verify_fails_a_pin_mismatch(
    anchored: Path, cas: tuple[_Ca, _Ca], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row now passes the configured pin, as the engine does. It used to build the opener
    without it, so a pin the engine would refuse on read as PASS here."""
    _verdicts(monkeypatch, acl=True, path=True)
    row = _tls_row(_fed_settings(anchored, pin=hashlib.sha256(cas[1].pem).hexdigest()))
    assert row.status is Status.FAIL
    assert "pin" in row.detail
