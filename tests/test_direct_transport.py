# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Direct-Project S/MIME-over-SMTP outbound DIRECT destination (ADR 0085, PR1).

Proves the real crypto, not a smoke test: an ephemeral CA + signer + recipient cert are minted
in-test, and the send path is exercised end-to-end. The receiving side is then reproduced with the
recipient's private key:

  * **ENCRYPT→DECRYPT** — ``pkcs7_decrypt_der`` with the recipient key recovers the signed content
    (and fails with a different key), proving the message was encrypted *to the recipient cert*.
  * **SIGN→VERIFY** — the connector signs ``NoAttributes | Binary``, so the SignerInfo signature is a
    deterministic RSA-PKCS1v15-SHA256 signature over the exact content; the test recomputes that
    signature independently and asserts it is present in the decrypted blob (a genuine signature
    verification), alongside byte-exact recovery of the synthetic body.

Plus the construction fail-closed refusals (key↔cert mismatch, untrusted recipient, missing material,
cleartext), the DeliveryError mapping, the STARTTLS probe, and the ``[egress].allowed_direct`` gate. No
real SMTP server is ever contacted (an in-process fake).
"""

from __future__ import annotations

import datetime
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

import messagefoundry.transports.direct as direct_mod
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, EgressSettings
from messagefoundry.pipeline.wiring_runner import check_egress_allowed
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.direct import DirectDestination

# A synthetic (never-real-PHI) HL7 body for the crypto round-trip (CLAUDE.md §9).
_SYNTHETIC_HL7 = (
    "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101||ADT^A01|1|P|2.5\rPID|1||SYN123^^^FAC||DOE^JANE\r"
)


# --- ephemeral PKI minted in-test -------------------------------------------------------------------


def _mint_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Direct CA")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _mint_leaf(
    common_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """A leaf cert signed by the given CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _write_pem(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


@pytest.fixture
def pki(tmp_path: Path) -> dict[str, Any]:
    """A minted CA, a signer key/cert (issued by the CA), and a recipient key/cert (issued by the CA),
    written to PEM files under tmp_path. Returns the paths + the in-memory recipient key for decrypt."""
    ca_key, ca_cert = _mint_ca()
    signer_key, signer_cert = _mint_leaf("Sender Direct", ca_key, ca_cert)
    recip_key, recip_cert = _mint_leaf("recipient@hisp.example", ca_key, ca_cert)

    signing_cert_p = tmp_path / "signer.crt"
    signing_key_p = tmp_path / "signer.key"
    recipient_cert_p = tmp_path / "recip.crt"
    trust_anchor_p = tmp_path / "ca.crt"
    _write_pem(signing_cert_p, signer_cert)
    _write_key(signing_key_p, signer_key)
    _write_pem(recipient_cert_p, recip_cert)
    _write_pem(trust_anchor_p, ca_cert)

    return {
        "ca_key": ca_key,
        "ca_cert": ca_cert,
        "signer_key": signer_key,
        "signer_cert": signer_cert,
        "recip_key": recip_key,
        "recip_cert": recip_cert,
        "signing_cert": str(signing_cert_p),
        "signing_key": str(signing_key_p),
        "recipient_cert": str(recipient_cert_p),
        "trust_anchor": str(trust_anchor_p),
    }


def _dest(pki: dict[str, Any], **overrides: Any) -> Destination:
    settings: dict[str, Any] = {
        "host": "hisp.partner.example",
        "sender": "sender@hisp.example",
        "recipients": ["recipient@hisp.example"],
        "signing_cert": pki["signing_cert"],
        "signing_key": pki["signing_key"],
        "recipient_cert": pki["recipient_cert"],
        "trust_anchor": pki["trust_anchor"],
    }
    settings.update(overrides)
    return Destination(name="OB_DIRECT", type=ConnectorType.DIRECT, settings=settings)


# --- in-process fake SMTP (never dials) -------------------------------------------------------------


class _FakeSMTP:
    """A drop-in for ``smtplib.SMTP`` / ``SMTP_SSL`` recording the exchange. ``fail_at`` makes the named
    step raise so the DeliveryError mapping is exercised. Mirrors test_email_destination._FakeSMTP."""

    instances: list[_FakeSMTP] = []

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = 0.0,
        fail_at: str | None = None,
        context: ssl.SSLContext | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.fail_at = fail_at
        self.tls_context = context  # #323 — see test_email_destination._FakeSMTP
        self.started_tls = False
        self.logged_in: tuple[str, str] | None = None
        self.auth_mechanism: str | None = None
        self.user = ""
        self.password = ""
        self.esmtp_features = {"auth": "CRAM-MD5 PLAIN LOGIN"}
        self.sent: list[EmailMessage] = []
        self.did_ehlo = False
        self.did_noop = False
        _FakeSMTP.instances.append(self)
        if fail_at == "connect":
            raise OSError("connection refused")

    def __enter__(self) -> _FakeSMTP:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def starttls(self, context: ssl.SSLContext | None = None) -> None:
        if self.fail_at == "starttls":
            raise smtplib.SMTPException("STARTTLS not supported")
        self.tls_context = context
        self.started_tls = True

    def ehlo_or_helo_if_needed(self) -> None:
        self.did_ehlo = True

    def login(self, user: str, password: str) -> None:
        if self.fail_at == "login":
            raise smtplib.SMTPAuthenticationError(535, b"bad creds")
        self.logged_in = (user, password)

    # BACKLOG #1171: the connector drives auth() directly, NOT login(). login()'s preference order is
    # internal and tries CRAM-MD5 FIRST -- an HMAC over MD5. So this fake models the negotiation the
    # production code actually performs, and ADVERTISES CRAM-MD5 on purpose: if the code ever regresses
    # to login(), CRAM-MD5 is what it would pick, and a fake that offered only PLAIN/LOGIN could not
    # tell the difference.
    def has_extn(self, name: str) -> bool:
        return name.lower() == "auth"

    def auth(self, mechanism: str, authobject: Any, *, initial_response_ok: bool = True) -> None:
        if self.fail_at == "login":
            raise smtplib.SMTPAuthenticationError(535, b"bad creds")
        self.auth_mechanism = mechanism
        # smtp_login_approved sets .user/.password before calling auth(), exactly as login() does.
        self.logged_in = (self.user, self.password)

    def auth_plain(self, challenge: bytes | None = None) -> str:
        return ""

    def auth_login(self, challenge: bytes | None = None) -> str:
        return ""

    def noop(self) -> tuple[int, bytes]:
        self.did_noop = True
        return (250, b"OK")

    def send_message(self, msg: EmailMessage) -> dict[str, Any]:
        if self.fail_at == "send":
            raise smtplib.SMTPRecipientsRefused({"x@y.z": (550, b"no")})
        self.sent.append(msg)
        return {}


def _install_fake(
    monkeypatch: pytest.MonkeyPatch, *, fail_at: str | None = None
) -> type[_FakeSMTP]:
    _FakeSMTP.instances = []

    def factory(
        host: str, port: int, timeout: float = 0.0, context: ssl.SSLContext | None = None
    ) -> _FakeSMTP:
        return _FakeSMTP(host, port, timeout, fail_at=fail_at, context=context)

    monkeypatch.setattr(direct_mod.smtplib, "SMTP", factory)
    monkeypatch.setattr(direct_mod.smtplib, "SMTP_SSL", factory)
    return _FakeSMTP


def _sent_smime_bytes(smtp: _FakeSMTP) -> bytes:
    """Pull the enveloped-data payload bytes out of the single sent S/MIME EmailMessage."""
    [msg] = smtp.sent
    assert msg.get_content_type() == "application/pkcs7-mime"
    assert msg.get_param("smime-type", header="Content-Type") == "enveloped-data"
    payload = msg.get_payload(decode=True)
    assert isinstance(payload, bytes)
    return payload


# --- the load-bearing crypto: SIGN→VERIFY + ENCRYPT→DECRYPT round-trip -------------------------------


async def test_sign_then_encrypt_round_trip(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    _install_fake(monkeypatch)
    d = DirectDestination(_dest(pki, subject="Direct CCD"))
    result = await d.send(_SYNTHETIC_HL7)
    assert result is None  # one-way delivery, no captured reply

    [smtp] = _FakeSMTP.instances
    assert smtp.started_tls is True  # STARTTLS before send (the default posture)
    enveloped = _sent_smime_bytes(smtp)

    # ENCRYPT→DECRYPT: the recipient's private key recovers the signed content byte-exact (the connector
    # envelopes with PKCS7Options.Binary, so no text canonicalization corrupts the binary blob). A
    # holder of a DIFFERENT key cannot decrypt — proving the message was encrypted TO this recipient cert.
    signed = pkcs7.pkcs7_decrypt_der(enveloped, pki["recip_cert"], pki["recip_key"], [])
    body = _SYNTHETIC_HL7.encode("utf-8")
    assert body in signed  # the exact synthetic body is recovered

    # The recovered blob is a well-formed PKCS7 SignedData carrying the signer cert (identity binding).
    embedded = pkcs7.load_der_pkcs7_certificates(signed)
    assert any(c == pki["signer_cert"] for c in embedded)

    # SIGN→VERIFY: NoAttributes|Binary means the SignerInfo signature is RSA-PKCS1v15-SHA256 over the
    # content directly. RSA-PKCS1v15 is deterministic, so an independent signature by the signer key
    # over the exact body reproduces the bytes embedded in the signed structure — a real verification.
    expected_sig = pki["signer_key"].sign(body, padding.PKCS1v15(), hashes.SHA256())
    assert expected_sig in signed


async def test_decrypt_with_wrong_key_fails(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    _install_fake(monkeypatch)
    d = DirectDestination(_dest(pki))
    await d.send(_SYNTHETIC_HL7)
    [smtp] = _FakeSMTP.instances
    enveloped = _sent_smime_bytes(smtp)

    # A different (non-recipient) key must NOT be able to decrypt — confidentiality is real.
    wrong_key, wrong_cert = _mint_leaf("wrong@x.example", pki["ca_key"], pki["ca_cert"])
    with pytest.raises(Exception):  # cryptography raises on a recipient/key mismatch  # noqa: B017
        pkcs7.pkcs7_decrypt_der(enveloped, wrong_cert, wrong_key, [])


# --- construction fail-closed refusals --------------------------------------------------------------


def test_missing_material_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="signing_cert"):
        DirectDestination(_dest(pki, signing_cert=""))
    with pytest.raises(ValueError, match="signing_key"):
        DirectDestination(_dest(pki, signing_key=str(tmp_path / "nope.key")))
    with pytest.raises(ValueError, match="recipient_cert"):
        DirectDestination(_dest(pki, recipient_cert=str(tmp_path / "nope.crt")))
    with pytest.raises(ValueError, match="trust_anchor"):
        DirectDestination(_dest(pki, trust_anchor=str(tmp_path / "nope.ca")))


def test_key_cert_mismatch_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    # A different key that does not match the signing cert.
    other_key, _ = _mint_leaf("Other", pki["ca_key"], pki["ca_cert"])
    other_key_p = tmp_path / "other.key"
    _write_key(other_key_p, other_key)
    with pytest.raises(ValueError, match="does not match"):
        DirectDestination(_dest(pki, signing_key=str(other_key_p)))


def test_untrusted_recipient_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    # A recipient cert issued by a DIFFERENT CA — must not chain to the supplied trust anchor.
    rogue_ca_key, rogue_ca_cert = _mint_ca()
    _, rogue_recip = _mint_leaf("rogue@evil.example", rogue_ca_key, rogue_ca_cert)
    rogue_p = tmp_path / "rogue.crt"
    _write_pem(rogue_p, rogue_recip)
    with pytest.raises(ValueError, match="untrusted"):
        DirectDestination(_dest(pki, recipient_cert=str(rogue_p)))


def test_requires_host_sender_recipients(pki: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="host"):
        DirectDestination(_dest(pki, host=""))
    with pytest.raises(ValueError, match="sender"):
        DirectDestination(_dest(pki, sender=""))
    with pytest.raises(ValueError, match="recipients"):
        DirectDestination(_dest(pki, recipients=[]))


# --- cleartext / insecure_tls refusals (inherited EMAIL posture) ------------------------------------


def test_cleartext_refusals(monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]) -> None:
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with pytest.raises(ValueError, match="cleartext"):
        DirectDestination(_dest(pki, use_tls=False))
    # With the escape but credentials → still refused.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(ValueError, match="credentials"):
        DirectDestination(_dest(pki, use_tls=False, username="svc", password="pw"))
    # With the escape and no credentials → allowed (loud warning).
    d = DirectDestination(_dest(pki, use_tls=False))
    assert d.use_tls is False


# --- DeliveryError mapping + PHI/secret-safe error text ---------------------------------------------


@pytest.mark.parametrize("fail_at", ["connect", "starttls", "login", "send"])
async def test_send_failure_raises_delivery_error(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], fail_at: str
) -> None:
    _install_fake(monkeypatch, fail_at=fail_at)
    d = DirectDestination(_dest(pki, username="svc", password="pw"))
    with pytest.raises(DeliveryError):
        await d.send(_SYNTHETIC_HL7)


async def test_delivery_error_is_phi_and_secret_safe(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    _install_fake(monkeypatch, fail_at="send")
    d = DirectDestination(_dest(pki, username="svc", password="s3cret"))
    with pytest.raises(DeliveryError) as ei:
        await d.send(_SYNTHETIC_HL7)
    text = str(ei.value)
    assert "s3cret" not in text  # never the password
    assert "recipient@hisp.example" not in text  # never a recipient
    assert "SYN123" not in text  # never the (synthetic) body content


# --- test_connection probe: connect + EHLO + NOOP only, no MAIL FROM / DATA --------------------------


async def test_probe_does_not_send(monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]) -> None:
    _install_fake(monkeypatch)
    d = DirectDestination(_dest(pki, username="svc", password="pw"))
    await d.test_connection()
    [smtp] = _FakeSMTP.instances
    assert smtp.did_ehlo is True
    assert smtp.did_noop is True
    assert smtp.logged_in == ("svc", "pw")
    assert smtp.sent == []  # no real Direct message sent by a probe


# --- [egress].allowed_direct match / deny -----------------------------------------------------------


def _egress_dest(host: str, port: int = 587) -> Destination:
    return Destination(
        name="OB_DIRECT",
        type=ConnectorType.DIRECT,
        settings={"host": host, "port": port},
    )


def test_egress_allow_and_deny() -> None:
    # empty list = unrestricted (opt-in), like every other egress type
    check_egress_allowed(_egress_dest("any.hisp.example"), EgressSettings())  # no raise

    e = EgressSettings(allowed_direct=["hisp.partner.example:587", "10.0.0.9"])
    check_egress_allowed(_egress_dest("hisp.partner.example", 587), e)  # exact host:port
    check_egress_allowed(_egress_dest("10.0.0.9", 2525), e)  # host-only → any port
    with pytest.raises(Exception, match="allowed_direct"):
        check_egress_allowed(_egress_dest("evil.relay.example", 587), e)
    with pytest.raises(Exception, match="allowed_direct"):
        check_egress_allowed(_egress_dest("hisp.partner.example", 2525), e)  # wrong port


def test_egress_deny_by_default_refuses_empty() -> None:
    e = EgressSettings(deny_by_default=True)
    with pytest.raises(Exception, match="deny_by_default"):
        check_egress_allowed(_egress_dest("hisp.partner.example"), e)


def test_egress_separate_from_smtp() -> None:
    # A DIRECT host listed only on allowed_smtp is NOT permitted — the lists are independent (ADR 0085).
    e = EgressSettings(deny_by_default=True, allowed_smtp=["hisp.partner.example:587"])
    with pytest.raises(Exception, match="deny_by_default"):
        check_egress_allowed(_egress_dest("hisp.partner.example", 587), e)


# --- registry + factory surface ---------------------------------------------------------------------


def test_registered_in_destination_registry(pki: dict[str, Any]) -> None:
    from messagefoundry.transports.base import build_destination

    conn = build_destination(_dest(pki))
    assert isinstance(conn, DirectDestination)


def test_direct_factory_exported(pki: dict[str, Any]) -> None:
    import messagefoundry as mf

    spec = mf.Direct(
        host="hisp.partner.example",
        sender="s@hisp.example",
        recipients=["r@hisp.example"],
        signing_cert=pki["signing_cert"],
        signing_key=pki["signing_key"],
        recipient_cert=pki["recipient_cert"],
        trust_anchor=pki["trust_anchor"],
    )
    assert spec.type is ConnectorType.DIRECT
    assert spec.settings["host"] == "hisp.partner.example"
    assert spec.settings["port"] == 587
    assert "Direct" in mf.__all__


def test_check_hostname_false_refuses_credentials(pki: dict[str, Any]) -> None:
    # BACKLOG #1314, the THIRD weakening axis, mirroring the EMAIL connector. The chain IS
    # verified but the peer NAME is not, so any certificate chaining to the trust anchor is
    # accepted whatever it was issued to, and the AUTH exchange goes to an unidentified peer.
    #
    # This connector had NO else arm before #1314 -- the branch is new, so these three tests are
    # the only thing standing between it and a silent no-op.
    with pytest.raises(ValueError, match="tls_check_hostname=false"):
        DirectDestination(_dest(pki, tls_check_hostname=False, username="svc", password="pw"))


def test_check_hostname_false_without_credentials_still_constructs(pki: dict[str, Any]) -> None:
    # NEGATIVE CONTROL: the gate is keyed on the CREDENTIAL, not on the posture. Widening it to a
    # name-unchecked hop carrying no username is the "must not widen the existing arms" failure.
    DirectDestination(_dest(pki, tls_check_hostname=False))


def test_credentials_over_a_fully_verified_hop_still_construct(pki: dict[str, Any]) -> None:
    # POSITIVE CONTROL: proves the new gate can be PASSED, so the refusal test above is not green
    # merely because DirectDestination rejects every credentialed construction.
    DirectDestination(_dest(pki, username="svc", password="pw"))


# --- signature_padding: the ASVS 11.3.1 operator choice (BACKLOG #1168) ------------------------------
#
# Measured against the PINNED cryptography (50.0.1 in requirements.lock), not the interpreter that
# happened to be on the builder's box, which reported 49.0.0. `add_signer` takes a keyword-only
# `rsa_padding`; `PKCS7EnvelopeBuilder.add_recipient` takes none, so the ENVELOPE half is out of
# reach of this setting and is asserted as such below rather than left to inference.

#: DER encoding of the RSASSA-PSS algorithm OID 1.2.840.113549.1.1.10, as it appears in a SignerInfo.
_RSASSA_PSS_OID_DER = bytes.fromhex("06092a864886f70d01010a")


def _mint_ec_leaf(
    common_name: str, ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """An EC (P-256) leaf issued by the RSA test CA — the key type that reaches an approved signature
    with no padding parameter at all."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _ec_signer(pki: dict[str, Any], tmp_path: Path) -> dict[str, str]:
    """Overrides swapping the RSA signer for an EC one. Only the SIGNER changes — the recipient cert
    and trust anchor are untouched, so this isolates the key type."""
    key, cert = _mint_ec_leaf("EC Sender Direct", pki["ca_key"], pki["ca_cert"])
    cert_p = tmp_path / "ec_signer.crt"
    key_p = tmp_path / "ec_signer.key"
    _write_pem(cert_p, cert)
    key_p.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return {"signing_cert": str(cert_p), "signing_key": str(key_p)}


def test_signature_padding_defaults_to_pkcs1v15(pki: dict[str, Any]) -> None:
    # The default is deliberate and interoperability-driven, so pin it: a silent flip to PSS would
    # break any HISP peer whose S/MIME stack verifies only PKCS#1 v1.5.
    d = DirectDestination(_dest(pki))
    assert d.signature_padding == "pkcs1v15"
    assert d._rsa_padding is None  # None, not PKCS1v15() — the one branch EC keys also accept


async def test_signature_padding_pss_changes_the_signerinfo_algorithm(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    """`signature_padding='pss'` really reaches the CMS SignerInfo, and the default really does not."""
    body = _SYNTHETIC_HL7.encode("utf-8")

    _install_fake(monkeypatch)
    await DirectDestination(_dest(pki)).send(_SYNTHETIC_HL7)
    [smtp_default] = _FakeSMTP.instances
    signed_default = pkcs7.pkcs7_decrypt_der(
        _sent_smime_bytes(smtp_default), pki["recip_cert"], pki["recip_key"], []
    )

    _install_fake(monkeypatch)
    d = DirectDestination(_dest(pki, signature_padding="pss"))
    assert d.signature_padding == "pss"
    await d.send(_SYNTHETIC_HL7)
    [smtp_pss] = _FakeSMTP.instances
    signed_pss = pkcs7.pkcs7_decrypt_der(
        _sent_smime_bytes(smtp_pss), pki["recip_cert"], pki["recip_key"], []
    )

    # The algorithm identifier moves, and the NEGATIVE half is what makes this a measurement rather
    # than a presence check: the default must NOT carry the PSS OID.
    assert _RSASSA_PSS_OID_DER in signed_pss
    assert _RSASSA_PSS_OID_DER not in signed_default

    # The discriminating control. PKCS#1 v1.5 is deterministic, so the exact signature the default
    # produces is reproducible — and it must be ABSENT from the PSS blob. Without this, a change that
    # wrote a PSS algorithm identifier while still signing PKCS#1 v1.5 would pass the OID assertions.
    pkcs1_sig = pki["signer_key"].sign(body, padding.PKCS1v15(), hashes.SHA256())
    assert pkcs1_sig in signed_default
    assert pkcs1_sig not in signed_pss

    # Both blobs still carry the signer cert and the exact synthetic body — PSS changed the padding
    # and nothing else about the message.
    assert body in signed_pss
    assert any(c == pki["signer_cert"] for c in pkcs7.load_der_pkcs7_certificates(signed_pss))


def test_signature_padding_rejects_an_unknown_value(pki: dict[str, Any]) -> None:
    # Fail loud at construction (check/dry-run/start), never as a wire-time surprise.
    with pytest.raises(ValueError, match="signature_padding"):
        DirectDestination(_dest(pki, signature_padding="oaep"))


def test_signature_padding_pss_is_refused_on_an_ec_key(pki: dict[str, Any], tmp_path: Path) -> None:
    # cryptography raises `TypeError: Padding is only supported for RSA keys` from add_signer, which
    # would abort every delivery at wire time. Refuse it at construction instead, with an error that
    # says what to do.
    with pytest.raises(ValueError, match="requires an RSA 'signing_key'"):
        DirectDestination(_dest(pki, signature_padding="pss", **_ec_signer(pki, tmp_path)))


async def test_ec_signing_key_avoids_pkcs1_padding_entirely(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], tmp_path: Path
) -> None:
    # POSITIVE CONTROL for the refusal above, and the documented escape from the interoperability
    # dilemma: an EC signer needs no padding parameter, so it reaches an approved signature under the
    # DEFAULT setting. Proves the refusal is about `pss` on EC, not about EC keys being unusable.
    _install_fake(monkeypatch)
    d = DirectDestination(_dest(pki, **_ec_signer(pki, tmp_path)))
    assert d._rsa_padding is None
    await d.send(_SYNTHETIC_HL7)
    [smtp] = _FakeSMTP.instances
    signed = pkcs7.pkcs7_decrypt_der(
        _sent_smime_bytes(smtp), pki["recip_cert"], pki["recip_key"], []
    )
    assert _SYNTHETIC_HL7.encode("utf-8") in signed
    assert _RSASSA_PSS_OID_DER not in signed  # ECDSA, so no RSA padding identifier at all


def test_envelope_key_transport_is_out_of_reach_of_this_setting() -> None:
    """The ENVELOPE half of ASVS 11.3.1 is a reasoned cannot-pass on the pinned library, and this
    test is the instrument that would notice if a future bump changed that.

    `PKCS7EnvelopeBuilder.add_recipient` exposes no padding parameter, so a Direct message's key
    transport would be RSAES-PKCS1-v1_5 on a first deployment whatever `signature_padding` says.
    If a later `cryptography` adds the parameter, this test fails and the finding must be re-read.
    """
    import inspect

    params = inspect.signature(pkcs7.PKCS7EnvelopeBuilder.add_recipient).parameters
    assert "rsa_padding" not in params
    assert set(params) == {"self", "certificate"}


# --- key-strength floor on all three S/MIME surfaces (ASVS 11.2.3, BACKLOG #1166) -------------------
#
# Measured before the floor existed: a full RSA-1024 set (signing key, recipient cert, trust anchor)
# CONSTRUCTED without complaint, with an RSA-2048 set constructing in the same run as the positive
# control -- so the loaders were live and simply never asked how big the modulus was.


def _weak_pki(tmp_path: Path, bits: int = 1024) -> dict[str, Any]:
    """A complete Direct PKI at `bits`, minted the same way as the `pki` fixture. Separate rather than
    parameterized on the fixture so the default path in every other test stays at 2048.

    **CodeQL FLAGS THE TWO 1024-BIT GENERATIONS BELOW AS "use of weak cryptographic key", AND IT IS
    RIGHT ABOUT THE CODE AND WRONG ABOUT THE RISK.** These keys exist ONLY to be REFUSED: they are the
    negative controls for the `_require_key_strength` floor added under BACKLOG #1166, and deleting
    them to clear the alert would delete the only proof that the floor works, which is strictly worse
    security than the alert describes. No key minted here is ever offered to a peer, written outside
    `tmp_path`, or used to sign or encrypt anything -- every one is fed to a constructor that must
    raise. The repository already carries five fixtures of exactly this shape for the same reason, in
    `test_auth_oidc.py` and `test_outbound_signing.py`; those are unflagged only because the PR check
    reports alerts on CHANGED lines, not because they differ.

    Left unsuppressed deliberately. CodeQL is not a required context (verified 2026-09-06 against
    branch protection, not against the checked-in mirror), so this costs no merge, and an inline
    suppression directive whose effect nobody had measured would be a worse artifact than a comment
    a reader can check.
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Weak Direct CA")])
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def leaf(cn: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        c = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_cert.subject)
            .public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(ca_key, hashes.SHA256())
        )
        return k, c

    signer_key, signer_cert = leaf("Weak Sender")
    recip_key, recip_cert = leaf("weak@hisp.example")
    tag = f"weak{bits}"
    paths = {
        "signing_cert": tmp_path / f"{tag}_signer.crt",
        "signing_key": tmp_path / f"{tag}_signer.key",
        "recipient_cert": tmp_path / f"{tag}_recip.crt",
        "trust_anchor": tmp_path / f"{tag}_ca.crt",
    }
    _write_pem(paths["signing_cert"], signer_cert)
    _write_key(paths["signing_key"], signer_key)
    _write_pem(paths["recipient_cert"], recip_cert)
    _write_pem(paths["trust_anchor"], ca_cert)
    out: dict[str, Any] = {k: str(v) for k, v in paths.items()}
    out["recip_key"] = recip_key
    return out


def test_weak_signing_key_is_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    weak = _weak_pki(tmp_path)
    with pytest.raises(ValueError, match="signing_key.*RSA-1024"):
        DirectDestination(
            _dest(pki, signing_cert=weak["signing_cert"], signing_key=weak["signing_key"])
        )


def test_weak_recipient_cert_is_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    # A counterparty-chosen surface. Refused anyway, because no certificate policy governing Direct
    # permits RSA-1024 -- so this cannot break a correspondent who is following their own rules.
    weak = _weak_pki(tmp_path)
    with pytest.raises(ValueError, match="recipient_cert.*RSA-1024"):
        DirectDestination(_dest(pki, recipient_cert=weak["recipient_cert"]))


def test_weak_trust_anchor_is_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    weak = _weak_pki(tmp_path)
    with pytest.raises(ValueError, match="trust_anchor.*RSA-1024"):
        DirectDestination(_dest(pki, trust_anchor=weak["trust_anchor"]))


def test_a_weak_anchor_is_refused_even_when_another_anchor_issues_the_recipient(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    """The discriminating case for WHERE the anchor check sits.

    The issuance loop returns on the first anchor that verifies, so a floor applied inside it would
    leave a weak sibling anchor unexamined and still trusted for every future recipient. This bundles
    the real (2048) anchor with a weak one and requires a refusal even though the real one matches.
    """
    weak = _weak_pki(tmp_path)
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(
        Path(pki["trust_anchor"]).read_bytes() + Path(weak["trust_anchor"]).read_bytes()
    )
    with pytest.raises(ValueError, match="trust_anchor.*RSA-1024"):
        DirectDestination(_dest(pki, trust_anchor=str(bundle)))


def test_the_default_2048_pki_still_constructs(pki: dict[str, Any]) -> None:
    # POSITIVE CONTROL for all four refusals above: the floor admits what every Direct certificate
    # policy requires, so the refusals are not green merely because construction always fails.
    DirectDestination(_dest(pki))


def test_an_ec_p256_signer_clears_the_floor(pki: dict[str, Any], tmp_path: Path) -> None:
    # P-256 is 128-bit and therefore actually MEETS ASVS 11.2.3, which the RSA-2048 floor does not.
    DirectDestination(_dest(pki, **_ec_signer(pki, tmp_path)))


def test_an_unapproved_ec_curve_is_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP192R1())
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "p192")]))
        .issuer_name(pki["ca_cert"].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(pki["ca_key"], hashes.SHA256())
    )
    cert_p = tmp_path / "p192.crt"
    key_p = tmp_path / "p192.key"
    _write_pem(cert_p, cert)
    key_p.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="secp192r1"):
        DirectDestination(_dest(pki, signing_cert=str(cert_p), signing_key=str(key_p)))
