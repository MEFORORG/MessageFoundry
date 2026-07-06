# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Opt-in per-connection detached-JWS outbound signing (ASVS 4.1.5, ADR 0018).

Covers the signing core (RS256/PS256/ES256 sign + verify, detached-JWS shape, tamper detection,
key/alg validation, encrypted keys, PEM-file keys), the config model (``OutboundSigning`` +
``from_settings``), the REST/SOAP connectors (the signature header is added over the exact wire bytes,
off by default, RS256 deterministic), and the wiring (``_dest_config`` assembles ``Destination.sign``
with ``env()`` resolution; ``with_signing`` composes over the factory)."""

from __future__ import annotations

import base64
import json
import urllib.request
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import ValidationError

from messagefoundry.config.models import (
    ConnectorType,
    Destination,
    OutboundSigning,
    SignatureAlgorithm,
)
from messagefoundry.config.wiring import OutboundConnection, Rest, Soap, env
from messagefoundry.pipeline.wiring_runner import _dest_config
from messagefoundry.transports import build_destination
from messagefoundry.transports.rest import RestDestination
from messagefoundry.transports.signing import (
    MessageSigner,
    SigningError,
    signer_from_destination,
    verify_detached_jws,
    with_signing,
)
from messagefoundry.transports.soap import SoapDestination

REST_URL = "https://partner.example/ingest"
SOAP_URL = "https://partner.example/svc"
PAYLOAD = '{"patient": "synthetic", "mrn": "MF-0001"}'


# --- key fixtures (synthetic, generated per session) -------------------------


def _pem(key: object, password: bytes | None = None) -> str:
    enc: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    ).decode("ascii")


@pytest.fixture(scope="session")
def rsa_pem() -> str:
    return _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.fixture(scope="session")
def ec_pem() -> str:
    return _pem(ec.generate_private_key(ec.SECP256R1()))


# --- fake HTTP opener (mirrors test_rest_transport / test_soap_transport) -----


class _FakeResp:
    status = 200

    def read(self) -> bytes:
        return b""

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class _FakeOpener:
    def __init__(self) -> None:
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResp:
        self.requests.append(req)
        return _FakeResp()


def _header(req: urllib.request.Request, name: str) -> str | None:
    """A request header looked up case-insensitively (urllib title-cases header keys)."""
    return next((v for k, v in req.headers.items() if k.lower() == name.lower()), None)


def _rest(signing: OutboundSigning | None = None, **over: object) -> RestDestination:
    settings = Rest(url=REST_URL, **over).settings
    dest = build_destination(
        Destination(name="OB_REST", type=ConnectorType.REST, settings=settings, sign=signing)
    )
    assert isinstance(dest, RestDestination)
    return dest


def _soap(signing: OutboundSigning | None = None, **over: object) -> SoapDestination:
    settings = Soap(url=SOAP_URL, **over).settings
    dest = build_destination(
        Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=settings, sign=signing)
    )
    assert isinstance(dest, SoapDestination)
    return dest


# === signing core ============================================================


@pytest.mark.parametrize("alg", ["RS256", "PS256", "ES256"])
def test_detached_jws_roundtrips_and_has_detached_shape(
    alg: str, rsa_pem: str, ec_pem: str
) -> None:
    key = ec_pem if alg == "ES256" else rsa_pem
    signer = MessageSigner(OutboundSigning(algorithm=alg, private_key=key, key_id="kid-1"))
    body = PAYLOAD.encode()
    jws = signer.detached_jws(body)

    protected_b64, detached, sig_b64 = jws.split(".")
    assert detached == "", "RFC 7515 detached content: the payload segment is empty"
    header = json.loads(base64.urlsafe_b64decode(protected_b64 + "=="))
    assert header == {"alg": alg, "kid": "kid-1"}
    assert sig_b64, "a signature segment is present"

    # round-trips against the public key (the receiver's path), pinned to the expected alg
    verify_detached_jws(jws, body, signer.public_key, allowed_algorithms=[alg])
    signer.verify(jws, body)  # self-verify convenience


def test_rs256_is_deterministic_ps256_es256_are_randomized(rsa_pem: str, ec_pem: str) -> None:
    body = PAYLOAD.encode()
    rs = MessageSigner(OutboundSigning(algorithm="RS256", private_key=rsa_pem))
    assert rs.detached_jws(body) == rs.detached_jws(body)
    for alg, key in (("PS256", rsa_pem), ("ES256", ec_pem)):
        rnd = MessageSigner(OutboundSigning(algorithm=alg, private_key=key))
        a, b = rnd.detached_jws(body), rnd.detached_jws(body)
        assert a != b, f"{alg} signs with fresh randomness each call"
        rnd.verify(a, body)  # both still verify
        rnd.verify(b, body)


@pytest.mark.parametrize("alg", ["RS256", "PS256", "ES256"])
def test_verify_rejects_tampered_payload_and_signature(alg: str, rsa_pem: str, ec_pem: str) -> None:
    key = ec_pem if alg == "ES256" else rsa_pem
    signer = MessageSigner(OutboundSigning(algorithm=alg, private_key=key))
    body = PAYLOAD.encode()
    jws = signer.detached_jws(body)

    with pytest.raises(InvalidSignature):
        verify_detached_jws(jws, body + b" tampered", signer.public_key)

    protected_b64, _, sig_b64 = jws.split(".")
    bad_sig = (
        base64.urlsafe_b64encode(b"\x00" * len(base64.urlsafe_b64decode(sig_b64 + "==")))
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(InvalidSignature):
        verify_detached_jws(f"{protected_b64}..{bad_sig}", body, signer.public_key)


def test_es256_signature_is_64_byte_raw_rs(ec_pem: str) -> None:
    signer = MessageSigner(OutboundSigning(algorithm="ES256", private_key=ec_pem))
    sig_b64 = signer.detached_jws(b"x").split(".")[2]
    assert len(base64.urlsafe_b64decode(sig_b64 + "==")) == 64, "JOSE ES256 is fixed-width r||s"


def test_key_algorithm_mismatch_fails_loud(rsa_pem: str, ec_pem: str) -> None:
    with pytest.raises(SigningError, match="ES256 requires an EC"):
        MessageSigner(OutboundSigning(algorithm="ES256", private_key=rsa_pem))
    with pytest.raises(SigningError, match="RS256 requires an RSA"):
        MessageSigner(OutboundSigning(algorithm="RS256", private_key=ec_pem))


def test_wrong_ec_curve_rejected() -> None:
    p384 = _pem(ec.generate_private_key(ec.SECP384R1()))
    with pytest.raises(SigningError, match="P-256"):
        MessageSigner(OutboundSigning(algorithm="ES256", private_key=p384))


def test_unloadable_key_fails_loud() -> None:
    with pytest.raises(SigningError, match="could not load the signing private key"):
        MessageSigner(OutboundSigning(algorithm="RS256", private_key="-----BEGIN NOT A KEY-----"))


def test_encrypted_key_needs_the_password(rsa_pem: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted = _pem(key, password=b"s3cret")
    # correct password loads + signs
    signer = MessageSigner(
        OutboundSigning(algorithm="RS256", private_key=encrypted, private_key_password="s3cret")
    )
    signer.verify(signer.detached_jws(b"x"), b"x")
    # missing/wrong password fails loud
    with pytest.raises(SigningError):
        MessageSigner(OutboundSigning(algorithm="RS256", private_key=encrypted))


def test_key_from_pem_file_path(tmp_path: Path, ec_pem: str) -> None:
    key_file = tmp_path / "sign.pem"
    key_file.write_text(ec_pem)
    signer = MessageSigner(OutboundSigning(algorithm="ES256", private_key=str(key_file)))
    signer.verify(signer.detached_jws(b"x"), b"x")


def test_missing_key_file_fails_loud(tmp_path: Path) -> None:
    with pytest.raises(SigningError, match="could not read the signing-key file"):
        MessageSigner(OutboundSigning(algorithm="ES256", private_key=str(tmp_path / "nope.pem")))


def test_verify_rejects_malformed_jws_and_alg_pinning(rsa_pem: str, ec_pem: str) -> None:
    signer = MessageSigner(OutboundSigning(algorithm="ES256", private_key=ec_pem))
    body = b"x"
    jws = signer.detached_jws(body)
    with pytest.raises(SigningError, match="three '.'-separated"):
        verify_detached_jws("only.two", body, signer.public_key)
    with pytest.raises(SigningError, match="payload segment must be empty"):
        verify_detached_jws("h.NOT_EMPTY.s", body, signer.public_key)
    # an attacker can't downgrade alg past an allow-list
    with pytest.raises(SigningError, match="not in the allowed set"):
        verify_detached_jws(jws, body, signer.public_key, allowed_algorithms=["RS256"])


# === config model ============================================================


def test_from_settings_off_unless_key_present(ec_pem: str) -> None:
    assert OutboundSigning.from_settings({"url": REST_URL}) is None
    signing = OutboundSigning.from_settings(
        {"sign_private_key": ec_pem, "sign_algorithm": "ES256", "sign_key_id": "k9"}
    )
    assert signing is not None
    assert signing.algorithm is SignatureAlgorithm.ES256
    assert signing.key_id == "k9"
    assert signing.enabled is True


def test_from_settings_enabled_false_disables(ec_pem: str) -> None:
    signing = OutboundSigning.from_settings({"sign_private_key": ec_pem, "sign_enabled": False})
    assert signing is not None and signing.enabled is False
    dest = Destination(name="OB", type=ConnectorType.REST, settings={}, sign=signing)
    assert signer_from_destination(dest) is None


def test_outbound_signing_forbids_unknown_field(ec_pem: str) -> None:
    with pytest.raises(ValidationError):
        OutboundSigning(private_key=ec_pem, algoritm="RS256")  # type: ignore[call-arg]  # typo


# === REST connector ==========================================================


async def test_rest_adds_verifiable_signature_over_body(ec_pem: str) -> None:
    dest = _rest(OutboundSigning(algorithm="ES256", private_key=ec_pem, key_id="acme"))
    opener = _FakeOpener()
    dest._opener = opener
    await dest.send(PAYLOAD)

    req = opener.requests[0]
    jws = _header(req, "X-JWS-Signature")
    assert jws is not None
    # verifies against the exact bytes urllib will send, with the connection's public key
    verify_detached_jws(jws, req.data, dest._signer.public_key, allowed_algorithms=["ES256"])  # type: ignore[union-attr]


async def test_rest_unsigned_by_default_is_byte_identical(ec_pem: str) -> None:
    dest = _rest(bearer_token="tok", headers={"X-Source": "mf"})
    assert dest._signer is None
    opener = _FakeOpener()
    dest._opener = opener
    await dest.send(PAYLOAD)
    req = opener.requests[0]
    assert _header(req, "X-JWS-Signature") is None
    assert req.data == PAYLOAD.encode()


async def test_rest_rs256_header_is_deterministic(rsa_pem: str) -> None:
    dest = _rest(OutboundSigning(algorithm="RS256", private_key=rsa_pem))
    opener = _FakeOpener()
    dest._opener = opener
    await dest.send(PAYLOAD)
    await dest.send(PAYLOAD)
    assert _header(opener.requests[0], "X-JWS-Signature") == _header(
        opener.requests[1], "X-JWS-Signature"
    )


async def test_rest_custom_header_name(ec_pem: str) -> None:
    dest = _rest(
        OutboundSigning(algorithm="ES256", private_key=ec_pem, header_name="X-Partner-Signature")
    )
    opener = _FakeOpener()
    dest._opener = opener
    await dest.send(PAYLOAD)
    assert _header(opener.requests[0], "X-Partner-Signature") is not None


def test_rest_bad_signing_key_fails_at_construction(ec_pem: str) -> None:
    # like a bad TLS cert: the connector won't build (so check/dry-run/start fail loud)
    with pytest.raises(SigningError):
        _rest(OutboundSigning(algorithm="RS256", private_key=ec_pem))  # RSA alg, EC key


# === SOAP connector ==========================================================


async def test_soap_plain_signs_the_envelope(rsa_pem: str) -> None:
    dest = _soap(OutboundSigning(algorithm="PS256", private_key=rsa_pem))
    opener = _FakeOpener()
    dest._opener = opener
    envelope = "<soap:Envelope><soap:Body>hl7</soap:Body></soap:Envelope>"
    await dest.send(envelope)
    req = opener.requests[0]
    assert req.data == envelope.encode()
    verify_detached_jws(_header(req, "X-JWS-Signature"), req.data, dest._signer.public_key)  # type: ignore[arg-type,union-attr]


async def test_soap_ws_star_signs_the_wrapped_envelope(ec_pem: str) -> None:
    # WS-* mode wraps + stamps in send(); the signature must cover the FINAL wire bytes, not the
    # handler's <Body> fragment.
    dest = _soap(
        OutboundSigning(algorithm="ES256", private_key=ec_pem),
        soap_version="1.2",
        ws_security=True,
        soap_action="urn:Submit",
    )
    opener = _FakeOpener()
    dest._opener = opener
    await dest.send("<sub:Submit>HL7</sub:Submit>")
    req = opener.requests[0]
    assert b"wsse:Security" in req.data, "the envelope was wrapped before signing"
    verify_detached_jws(_header(req, "X-JWS-Signature"), req.data, dest._signer.public_key)  # type: ignore[arg-type,union-attr]


# === wiring (with_signing + _dest_config) ====================================


def test_with_signing_rejects_non_http_outbound() -> None:
    from messagefoundry.config.wiring import MLLP

    with pytest.raises(SigningError, match="REST/SOAP outbound only"):
        with_signing(MLLP(host="h", port=1), private_key="x")


def test_dest_config_assembles_sign_with_env_resolution(ec_pem: str) -> None:
    spec = with_signing(
        Rest(url=env("acme_url")),
        private_key=env("acme_sign_key"),
        algorithm="ES256",
        key_id="acme-2026",
    )
    oc = OutboundConnection(name="OB_ACME", spec=spec)
    dest_cfg = _dest_config(oc, {"acme_url": REST_URL, "acme_sign_key": ec_pem})

    assert dest_cfg.sign is not None
    assert dest_cfg.sign.algorithm is SignatureAlgorithm.ES256
    assert dest_cfg.sign.key_id == "acme-2026"
    # the env() ref was materialized into a usable key (the connector builds + signs)
    built = build_destination(dest_cfg)
    assert isinstance(built, RestDestination)
    assert built._signer is not None


async def test_with_signing_end_to_end_through_the_connector(ec_pem: str) -> None:
    spec = with_signing(Rest(url=env("u")), private_key=env("k"), algorithm="ES256")
    oc = OutboundConnection(name="OB", spec=spec)
    dest = build_destination(_dest_config(oc, {"u": REST_URL, "k": ec_pem}))
    assert isinstance(dest, RestDestination)
    opener = _FakeOpener()
    dest._opener = opener
    await dest.send(PAYLOAD)
    jws = _header(opener.requests[0], "X-JWS-Signature")
    assert jws is not None
    verify_detached_jws(jws, opener.requests[0].data, dest._signer.public_key)  # type: ignore[union-attr]
