# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

The library-capability tripwire section is a different kind of test: it exercises no engine code and
needs no fixture. It watches the pinned ``cryptography`` for the CMS key-encryption seam whose absence
is why ASVS 11.3.1 cannot pass on this connector (BACKLOG #1168). The content-cipher section after it
reads the envelope's AES-256-CBC OID out of the DER structure.
"""

from __future__ import annotations

import datetime
import functools
import inspect
import smtplib
import ssl
import traceback
import types
from collections.abc import Callable, Iterator, Sequence
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.exceptions import InternalError, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
    x448,
    x25519,
)
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.direct import DirectDestination
from messagefoundry.transports.egress import check_egress_allowed
from tests.test_email_destination import (
    _ALL_ATEXT_SENDER,
    _DOMAIN_ON_THE_WIRE,
    _NORMALISED_RECIPIENTS,
    _PARTIAL_RECIPIENTS,
    _PARTIAL_REFUSED,
    _REFUSED_ADDRESS_IDS,
    _REFUSED_ADDRESSES,
    _WireCapture,
    assert_partial_refusal,
    assert_total_refusal,
    refuse_every_recipient,
)

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


def _with_san(
    builder: x509.CertificateBuilder,
    common_name: str,
    addresses: Sequence[str] | None = None,
    dns_names: Sequence[str] = (),
) -> x509.CertificateBuilder:
    """``builder`` with the subjectAltName a Direct leaf carries, unchanged when it names nothing.
    ``addresses`` defaults to the common name when it is a mail address, so a leaf minted for a
    mailbox names it (BACKLOG #5631: the Direct trust check binds every recipient to the recipient
    cert's SAN)."""
    if addresses is None:
        addresses = (common_name,) if "@" in common_name else ()
    general: list[x509.GeneralName] = [x509.RFC822Name(a) for a in addresses]
    general += [x509.DNSName(d) for d in dns_names]
    if not general:
        return builder
    return builder.add_extension(x509.SubjectAlternativeName(general), critical=False)


def _mint_leaf(
    common_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    *,
    addresses: Sequence[str] | None = None,
    dns_names: Sequence[str] = (),
    valid_from: datetime.timedelta = datetime.timedelta(days=-1),
    valid_to: datetime.timedelta = datetime.timedelta(days=365),
    extensions: Sequence[x509.ExtensionType] = (),
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """A leaf cert signed by the given CA, naming ``addresses`` and ``dns_names`` in its SAN (see
    :func:`_with_san`), valid from ``now + valid_from`` to ``now + valid_to``, and carrying any
    further ``extensions`` (non-critical)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + valid_from)
        .not_valid_after(now + valid_to)
    )
    builder = _with_san(builder, common_name, addresses, dns_names)
    for extension in extensions:
        builder = builder.add_extension(extension, critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


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
    # The dNSName covers the hospital.example recipients the envelope tests borrow from the Email
    # destination's tests, as an organisation certificate would.
    recip_key, recip_cert = _mint_leaf(
        "recipient@hisp.example", ca_key, ca_cert, dns_names=("hospital.example",)
    )

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

    def send_message(
        self,
        msg: EmailMessage,
        from_addr: str | None = None,
        to_addrs: list[str] | None = None,
    ) -> dict[str, Any]:
        if self.fail_at == "send":
            raise smtplib.SMTPRecipientsRefused({"x@y.z": (550, b"no")})
        self.sent.append(msg)
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        return {}


def _install_fake(
    monkeypatch: pytest.MonkeyPatch, *, fail_at: str | None = None
) -> type[_FakeSMTP]:
    _FakeSMTP.instances = []

    def factory(
        host: str, port: int, timeout: float = 0.0, context: ssl.SSLContext | None = None
    ) -> _FakeSMTP:
        return _FakeSMTP(host, port, timeout, fail_at=fail_at, context=context)

    monkeypatch.setattr("messagefoundry.transports.direct.smtplib.SMTP", factory)
    monkeypatch.setattr("messagefoundry.transports.direct.smtplib.SMTP_SSL", factory)
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


def test_key_cert_match_is_compared_in_constant_time(
    pki: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """ASVS 11.2.4 (BACKLOG #1167): the key/cert public-key compare uses ``hmac.compare_digest``.

    Red while the compare is a bare ``!=``, which never reaches the spy. The operands must be the
    DER SubjectPublicKeyInfo bytes, the same encoding the bare compare used.
    """
    import hmac

    seen: list[tuple[object, object]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        seen.append((a, b))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    DirectDestination(_dest(pki))
    spki = (
        pki["signer_cert"]
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    assert (spki, spki) in seen, "the key/cert compare never reached compare_digest"


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
    with (
        active_hop_posture(HopPosture(enforcing=False)),
        pytest.raises(ValueError, match="credentials"),
    ):
        DirectDestination(_dest(pki, use_tls=False, username="svc", password="pw"))
    # With the escape and no credentials, on a warn posture, allowed (loud warning). With no
    # posture the escape alone is refused (vault BACKLOG #2354).
    with active_hop_posture(None), pytest.raises(ValueError, match="cleartext"):
        DirectDestination(_dest(pki, use_tls=False))
    with active_hop_posture(HopPosture(enforcing=False)):
        d = DirectDestination(_dest(pki, use_tls=False))
    assert d.use_tls is False


def test_an_explicit_none_tls_setting_takes_its_default(pki: dict[str, Any]) -> None:
    """Vault BACKLOG #3230: ``None`` used to read as off, which would have dropped STARTTLS, the
    certificate check and the name check. It now takes each default, as absence does."""
    d = DirectDestination(_dest(pki, use_tls=None, tls_verify=None, tls_check_hostname=None))
    assert (d.use_tls, d.tls_verify, d.tls_check_hostname) == (True, True, True)


# --- the SMTP envelope on the wire (vault BACKLOG #2870) ---------------------------------------------
#
# Each test reads the MAIL and RCPT lines a loopback listener received, so it checks what a relay
# would act on rather than what the connector handed smtplib.


@pytest.fixture
def wire() -> Iterator[_WireCapture]:
    capture = _WireCapture()
    try:
        yield capture
    finally:
        capture.close()


def _wire_direct(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], port: int, **overrides: Any
) -> DirectDestination:
    """A Direct destination aimed at the capture listener. Cleartext needs the escape and a warn
    posture; the S/MIME body is built as usual."""
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    settings: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": port,
        "use_tls": False,
        "timeout_seconds": 5.0,
        **overrides,
    }
    with active_hop_posture(HopPosture(enforcing=False)):
        return DirectDestination(_dest(pki, **settings))


@pytest.mark.parametrize(
    "setting, address",
    list(_NORMALISED_RECIPIENTS.values()),
    ids=list(_NORMALISED_RECIPIENTS),
)
async def test_direct_mail_from_and_rcpt_name_exactly_the_checked_addresses(
    monkeypatch: pytest.MonkeyPatch,
    pki: dict[str, Any],
    wire: _WireCapture,
    setting: str,
    address: str,
) -> None:
    d = _wire_direct(monkeypatch, pki, wire.port, sender=_ALL_ATEXT_SENDER, recipients=[setting])
    await d.send(_SYNTHETIC_HL7)
    assert wire.mail_lines == [("mail from:<" + _ALL_ATEXT_SENDER + ">").encode()]
    assert wire.rcpt_lines == [("rcpt to:<" + address + ">").encode()]
    # The headers are built from the same checked text, so no display name or group reaches them.
    [from_line] = [line for line in wire.data if line.lower().startswith(b"from:")]
    assert from_line.rstrip(b"\r\n") == ("From: " + _ALL_ATEXT_SENDER).encode()
    [to_line] = [line for line in wire.data if line.lower().startswith(b"to:")]
    assert to_line.rstrip(b"\r\n") == ("To: " + address).encode()


async def test_direct_envelope_does_not_follow_the_headers(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], wire: _WireCapture
) -> None:
    # A plain address reads the same either way, so change both headers after the build: MAIL FROM
    # and RCPT TO must still be the checked settings, which they are only when passed explicitly.
    build = DirectDestination._build_smime

    def changed_headers(self: DirectDestination, payload: str) -> EmailMessage:
        msg = build(self, payload)
        msg.replace_header("From", "another@partner.example")
        msg.replace_header("To", "another@partner.example")
        return msg

    monkeypatch.setattr(DirectDestination, "_build_smime", changed_headers)
    d = _wire_direct(monkeypatch, pki, wire.port)
    await d.send(_SYNTHETIC_HL7)
    # The change reached the wire, so the test is not passing because nothing changed.
    headers = [line.rstrip(b"\r\n") for line in wire.data if line.startswith((b"From: ", b"To: "))]
    assert headers == [b"From: another@partner.example", b"To: another@partner.example"]
    assert wire.mail_lines == [b"mail from:<sender@hisp.example>"]
    assert wire.rcpt_lines == [b"rcpt to:<recipient@hisp.example>"]


@pytest.mark.parametrize("quit_ok", [True, False], ids=["quit-221", "quit-refused"])
async def test_a_partial_rcpt_refusal_fails_the_direct_delivery(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], wire: _WireCapture, quit_ok: bool
) -> None:
    # One of two recipients refused (vault BACKLOG #2924): a permanent refusal, never a delivery,
    # and a QUIT refused after it does not turn it into a retry.
    wire.refuse_rcpt = frozenset({_PARTIAL_REFUSED.encode()})
    if not quit_ok:
        wire.quit_reply = b"500 no\r\n"
    d = _wire_direct(monkeypatch, pki, wire.port, recipients=_PARTIAL_RECIPIENTS)
    with pytest.raises(NegativeAckError) as caught:
        await d.send(_SYNTHETIC_HL7)
    assert_partial_refusal(caught.value, f"Direct 127.0.0.1:{wire.port}", wire)


@pytest.mark.parametrize("quit_ok", [True, False], ids=["quit-221", "quit-refused"])
async def test_a_permanent_refusal_of_every_recipient_fails_the_direct_delivery_for_good(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], wire: _WireCapture, quit_ok: bool
) -> None:
    # Every recipient refused with a 5xx (vault BACKLOG #2884, #2924 step 5): permanent, as a
    # partial refusal is, and content-free. RED on main: a retried DeliveryError.
    refuse_every_recipient(wire, quit_ok=quit_ok)
    d = _wire_direct(monkeypatch, pki, wire.port, recipients=_PARTIAL_RECIPIENTS)
    with pytest.raises(NegativeAckError) as caught:
        await d.send(_SYNTHETIC_HL7)
    assert_total_refusal(caught.value, f"Direct 127.0.0.1:{wire.port}", wire, "550")


async def test_a_temporary_refusal_of_every_recipient_is_a_retried_direct_failure(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], wire: _WireCapture
) -> None:
    refuse_every_recipient(wire, b"450")
    d = _wire_direct(monkeypatch, pki, wire.port, recipients=_PARTIAL_RECIPIENTS)
    with pytest.raises(DeliveryError) as caught:
        await d.send(_SYNTHETIC_HL7)
    assert_total_refusal(caught.value, f"Direct 127.0.0.1:{wire.port}", wire, "450")


@pytest.mark.parametrize(
    "field, value",
    _REFUSED_ADDRESSES,
    ids=_REFUSED_ADDRESS_IDS,
)
def test_direct_refuses_an_address_that_is_not_one_plain_mailbox_before_any_connection(
    monkeypatch: pytest.MonkeyPatch,
    pki: dict[str, Any],
    wire: _WireCapture,
    field: str,
    value: str,
) -> None:
    setting: Any = [value] if field == "recipients" else value
    with pytest.raises(ValueError, match="sender" if field == "sender" else "recipient"):
        _wire_direct(monkeypatch, pki, wire.port, **{field: setting})
    assert wire.connections == 0
    assert wire.mail_lines == []


def test_direct_refuses_a_bare_ip_domain_by_the_domain_rule(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], wire: _WireCapture
) -> None:
    # The reason pins the domain rule as what refused, not some later recipient check
    # (vault BACKLOG #2911).
    with pytest.raises(ValueError, match="start with a letter"):
        _wire_direct(
            monkeypatch, pki, wire.port, recipients=[_DOMAIN_ON_THE_WIRE["domain-hex-last-part"]]
        )
    assert wire.connections == 0


async def test_direct_send_passes_both_halves_of_the_envelope(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    _install_fake(monkeypatch)
    await DirectDestination(_dest(pki)).send(_SYNTHETIC_HL7)
    [smtp] = _FakeSMTP.instances
    assert smtp.from_addr == "sender@hisp.example"
    assert smtp.to_addrs == ["recipient@hisp.example"]


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


#: A synthetic body that cannot encode as ASCII. The marker stands in for PHI: it must not be
#: reachable from the raised error by any route, printed or by attribute.
_ENCODE_MARKER = "ZZSYNTHMARKER42"
_UNENCODABLE_HL7 = (
    "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101||ADT^A01|1|P|2.5\r"
    f"PID|1||{_ENCODE_MARKER}^^^FAC||MUÑOZ^ANA\r"
)


async def test_encode_failure_leaves_no_exception_chain(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    """BACKLOG #1920. A body the configured codec cannot encode raises ``UnicodeEncodeError``, whose
    ``.object`` is the WHOLE payload. Chained onto the ``DeliveryError`` -- as ``__cause__`` by
    ``from exc``, or as ``__context__`` by a raise inside the handler -- it would put the body in
    front of any logger, serializer or crash reporter that walks the chain. Both links must be empty,
    and neither the marker nor the offending character may appear in the formatted traceback."""
    _install_fake(monkeypatch)
    d = DirectDestination(_dest(pki, encoding="ascii"))
    with pytest.raises(DeliveryError) as ei:
        await d.send(_UNENCODABLE_HL7)
    exc = ei.value
    assert exc.__cause__ is None
    assert exc.__context__ is None
    rendered = "".join(traceback.format_exception(exc))
    assert _ENCODE_MARKER not in rendered
    assert "\\xd1" not in rendered and "Ñ" not in rendered  # the offending character
    assert "ascii" in rendered  # still actionable: names the codec
    assert _FakeSMTP.instances == []  # nothing dialled for a message that never built


# BACKLOG #1919. A message that cannot be BUILT will not build on a retry either, so it must reach
# the delivery worker as a permanent NegativeAckError, which it dead-letters on the first attempt. A
# plain DeliveryError is the transient class: the worker retries it up to the attempt ceiling.


async def test_encode_failure_is_permanent(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    _install_fake(monkeypatch)
    d = DirectDestination(_dest(pki, encoding="ascii"))
    with pytest.raises(NegativeAckError) as ei:
        await d.send(_UNENCODABLE_HL7)
    assert ei.value.permanent is True
    assert ei.value.credential_fault is False  # a bad message, not a bad credential


async def test_crypto_build_failure_is_permanent_and_content_free(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    # A real library failure, not a stub: an EC recipient cert reaching the envelope builder raises
    # `TypeError: Only RSA keys are supported at this time` on the pinned cryptography. Construction
    # now refuses that cert (#1918), so it is swapped in afterwards -- the "slipped past construction"
    # case the send-time arm exists for.
    _install_fake(monkeypatch)
    d = DirectDestination(_dest(pki))
    _, ec_cert = _mint_ec_leaf("ec-recipient@hisp.example", pki["ca_key"], pki["ca_cert"])
    d._recipient_cert = ec_cert
    with (
        caplog.at_level("WARNING", logger="messagefoundry.transports.direct"),
        pytest.raises(NegativeAckError) as ei,
    ):
        await d.send(_SYNTHETIC_HL7)
    exc = ei.value
    assert exc.permanent is True
    assert exc.credential_fault is False
    assert "TypeError" in str(exc)
    assert exc.__cause__ is None and exc.__context__ is None  # the #1920 shape holds here too
    assert "SYN123" not in "".join(traceback.format_exception(exc))  # no body content
    assert _FakeSMTP.instances == []
    # The dead-letter is logged, by type name only: neither the body nor the library's own text.
    [record] = [r for r in caplog.records if "S/MIME build failed" in r.getMessage()]
    assert "TypeError" in record.getMessage()
    assert "SYN123" not in record.getMessage()
    assert "Only RSA" not in record.getMessage()


async def test_unsupported_algorithm_from_the_envelope_build_is_permanent(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    """BACKLOG #1921. Reported: under a FIPS-enabled OpenSSL, constructing PKCS7EnvelopeBuilder raises
    UnsupportedAlgorithm, which subclasses Exception and not ValueError, so it escaped the build arm
    and reached the delivery worker as an "internal error". NOT reproduced -- no FIPS OpenSSL here --
    so this simulates the raise and pins the mapping: permanent, content-free, chain severed."""

    def _fips_refusal() -> Any:
        raise UnsupportedAlgorithm("synthetic FIPS refusal ZZLIBDETAIL")

    _install_fake(monkeypatch)
    d = DirectDestination(_dest(pki))
    monkeypatch.setattr(
        "messagefoundry.transports.direct.pkcs7.PKCS7EnvelopeBuilder", _fips_refusal
    )
    with pytest.raises(NegativeAckError) as ei:
        await d.send(_SYNTHETIC_HL7)
    exc = ei.value
    assert exc.permanent is True
    assert "UnsupportedAlgorithm" in str(exc)
    assert "ZZLIBDETAIL" not in "".join(traceback.format_exception(exc))
    assert exc.__cause__ is None and exc.__context__ is None
    assert _FakeSMTP.instances == []


# The construction probe (code review of #1918-#1921). Every build input except the body is fixed at
# construction, so a fault in one of them would fail every send. The send-time arm dead-letters such
# a failure message by message, so each of these must fail at check/dry-run/start instead.


def test_construction_probe_refuses_an_unsupported_algorithm(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    # The #1921 FIPS shape, one step earlier: a builder that refuses at every call refuses here too.
    def _fips_refusal() -> Any:
        raise UnsupportedAlgorithm("synthetic FIPS refusal")

    monkeypatch.setattr(
        "messagefoundry.transports.direct.pkcs7.PKCS7EnvelopeBuilder", _fips_refusal
    )
    with pytest.raises(ValueError, match="could not build an S/MIME message.*UnsupportedAlgorithm"):
        DirectDestination(_dest(pki))


def test_construction_probe_refuses_a_subject_with_a_line_break(pki: dict[str, Any]) -> None:
    # email.message refuses a header value with CR or LF INSIDE it, on every build. A lone TRAILING
    # newline is not refused (it is RFC 2047-encoded into the Subject), so the break here is embedded,
    # which is the header-injection shape.
    with pytest.raises(ValueError, match="could not build an S/MIME message.*ValueError"):
        DirectDestination(_dest(pki, subject="Referral\nBcc: someone@hisp.example"))


@pytest.mark.parametrize("code", [0xD800, 0xDC80])
def test_a_subject_with_a_lone_surrogate_is_refused_at_construction(
    pki: dict[str, Any], code: int
) -> None:
    # vault BACKLOG #2842. The construction probe already refused U+D800, whose build raises. It
    # accepted U+DC80, which goes out as a garbled header, while the Email destination refuses both.
    subject = f"Referral {chr(code)} note"
    with pytest.raises(ValueError, match="'subject' holds a lone surrogate") as caught:
        DirectDestination(_dest(pki, subject=subject))
    assert subject not in str(caught.value)


def test_construction_probe_refuses_a_cryptography_internal_error(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    # InternalError is how cryptography surfaces an OpenSSL error it does not map. Like
    # UnsupportedAlgorithm it subclasses Exception, not ValueError. Simulated, not reproduced.
    def _openssl_refusal() -> Any:
        raise InternalError("synthetic unmapped OpenSSL error", [])

    monkeypatch.setattr(
        "messagefoundry.transports.direct.pkcs7.PKCS7EnvelopeBuilder", _openssl_refusal
    )
    with pytest.raises(ValueError, match="could not build an S/MIME message.*InternalError"):
        DirectDestination(_dest(pki))


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
    check_egress_allowed(
        _egress_dest("any.hisp.example"), EgressSettings(deny_by_default=False)
    )  # no raise

    e = EgressSettings(allowed_direct=["hisp.partner.example:587", "10.0.0.9"])
    check_egress_allowed(_egress_dest("hisp.partner.example", 587), e)  # exact host:port
    check_egress_allowed(_egress_dest("10.0.0.9", 2525), e)  # host-only → any port
    with pytest.raises(Exception, match="allowed_direct"):
        check_egress_allowed(_egress_dest("evil.relay.example", 587), e)
    with pytest.raises(Exception, match="allowed_direct"):
        check_egress_allowed(_egress_dest("hisp.partner.example", 2525), e)  # wrong port


def test_egress_deny_by_default_refuses_empty() -> None:
    e = EgressSettings(deny_by_default=True)
    with pytest.raises(Exception, match="block_unlisted_outbound"):
        check_egress_allowed(_egress_dest("hisp.partner.example"), e)


def test_egress_separate_from_smtp() -> None:
    # A DIRECT host listed only on allowed_smtp is NOT permitted — the lists are independent (ADR 0085).
    e = EgressSettings(deny_by_default=True, allowed_smtp=["hisp.partner.example:587"])
    with pytest.raises(Exception, match="block_unlisted_outbound"):
        check_egress_allowed(_egress_dest("hisp.partner.example", 587), e)


# --- registry + factory surface ---------------------------------------------------------------------


def test_registered_in_destination_registry(pki: dict[str, Any]) -> None:
    from messagefoundry.transports.base import build_destination

    conn = build_destination(_dest(pki), egress=EgressSettings(deny_by_default=False))
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


@pytest.mark.parametrize(
    "weak",
    [{"use_tls": False}, {"tls_verify": False}, {"tls_check_hostname": False}],
    ids=["cleartext", "verify-off", "name-off"],
)
def test_a_credential_refusal_names_the_connection_and_no_escape(
    pki: dict[str, Any], weak: dict[str, bool], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3230: the credential refusal runs before the body refusal, which offers the
    escape, so an enforcing instance is told the fix that works rather than one that does not."""
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with pytest.raises(ValueError, match="authentication credentials") as info:
        DirectDestination(_dest(pki, username="svc", password="synthetic", **weak))
    message = str(info.value)
    assert "connection 'OB_DIRECT'" in message and "tls_ca_file" in message
    assert INSECURE_TLS_ESCAPE_ENV not in message and "synthetic" not in message


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
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    return key, _with_san(builder, common_name).sign(ca_key, hashes.SHA256())


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
        b = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_cert.subject)
            .public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
        )
        return k, _with_san(b, cn).sign(ca_key, hashes.SHA256())

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

    The issuance loop skips every anchor that does not issue the recipient, so a floor applied
    inside it would leave a weak sibling anchor unexamined and still trusted. This bundles
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


# --- key-type allow-list on all three S/MIME surfaces (ASVS 11.2.3, BACKLOG #3384) ----------------
#
# The floor used to pass any key type it could not classify, DSA included. Measured before the
# allow-list: an RSA recipient cert issued by a 2048-bit DSA CA constructed cleanly. Each surface
# below takes a DSA key and an unlisted type (X25519, a key-agreement type that can sit in a cert).
# On the signer and recipient surfaces a stricter type gate refuses them before the floor does,
# by design; the trust anchor is where the floor's own type list refuses.
# The RSA controls are `test_the_default_2048_pki_still_constructs`; the EC controls are
# `test_an_ec_p256_signer_clears_the_floor` and `test_an_ec_trust_anchor_issuing_an_rsa_recipient_
# still_constructs`. The recipient surface has no EC control, because it is RSA-only (#1918).


@functools.cache
def _dsa_key() -> dsa.DSAPrivateKey:
    # 2048-bit, so a refusal is about the TYPE and cannot be read as a size floor. Cached because
    # DSA parameter generation is the slow part and every DSA test only needs some DSA key.
    return dsa.generate_private_key(key_size=2048)


def _cert_for(
    public_key: Any,
    cn: str,
    issuer_key: Any,
    issuer_name: x509.Name | None = None,
    *,
    ca: bool = False,
    addresses: Sequence[str] | None = None,
) -> x509.Certificate:
    """A cert carrying ``public_key``, signed by ``issuer_key``. Self-signed when ``issuer_name`` is
    None. EdDSA issuers sign with no separate hash, so the hash is None for them. The SAN follows
    :func:`_with_san`."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name or name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    builder = _with_san(builder, cn, addresses)
    eddsa = isinstance(issuer_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))
    return builder.sign(issuer_key, None if eddsa else hashes.SHA256())


def _signer_files(pki: dict[str, Any], tmp_path: Path, key: Any, tag: str) -> dict[str, str]:
    """Overrides for a signer of any key type, its cert issued by the RSA test CA."""
    cert = _cert_for(key.public_key(), f"{tag} Sender", pki["ca_key"], pki["ca_cert"].subject)
    cert_p = tmp_path / f"{tag}_signer.crt"
    key_p = tmp_path / f"{tag}_signer.key"
    _write_pem(cert_p, cert)
    key_p.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return {"signing_cert": str(cert_p), "signing_key": str(key_p)}


def _recipient_file(pki: dict[str, Any], tmp_path: Path, public_key: Any, tag: str) -> str:
    cert = _cert_for(public_key, f"{tag}@hisp.example", pki["ca_key"], pki["ca_cert"].subject)
    path = tmp_path / f"{tag}_recip.crt"
    _write_pem(path, cert)
    return str(path)


def _anchor_issuing_an_rsa_recipient(tmp_path: Path, ca_key: Any, tag: str) -> dict[str, str]:
    """A self-signed CA on ``ca_key`` and an RSA-2048 recipient it issues, as overrides."""
    ca_cert = _cert_for(ca_key.public_key(), f"{tag} Direct CA", ca_key, ca=True)
    recip_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    recip_cert = _cert_for(
        recip_key.public_key(),
        f"rsa-recip-of-{tag}",
        ca_key,
        ca_cert.subject,
        addresses=("recipient@hisp.example",),
    )
    anchor_p = tmp_path / f"{tag}_ca.crt"
    recip_p = tmp_path / f"rsa_recip_of_{tag}_ca.crt"
    _write_pem(anchor_p, ca_cert)
    _write_pem(recip_p, recip_cert)
    return {"recipient_cert": str(recip_p), "trust_anchor": str(anchor_p)}


def test_a_dsa_signing_key_is_refused_and_named(pki: dict[str, Any], tmp_path: Path) -> None:
    # Refused by the RSA-or-EC signer gate, which runs before the floor on this surface.
    files = _signer_files(pki, tmp_path, _dsa_key(), "dsa")
    with pytest.raises(ValueError, match="'signing_key' key type is DSA; S/MIME signing"):
        DirectDestination(_dest(pki, **files))


def test_an_unlisted_signing_key_type_is_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    files = _signer_files(pki, tmp_path, x25519.X25519PrivateKey.generate(), "x25519")
    with pytest.raises(ValueError, match="'signing_key' key type is X25519; S/MIME signing"):
        DirectDestination(_dest(pki, **files))


@pytest.mark.parametrize(
    "make",
    [ed25519.Ed25519PrivateKey.generate, ed448.Ed448PrivateKey.generate],
    ids=["ed25519", "ed448"],
)
def test_an_eddsa_signer_is_refused_by_the_signer_gate(
    pki: dict[str, Any], tmp_path: Path, make: Callable[[], Any]
) -> None:
    """EdDSA is on the floor's list, but ``add_signer`` takes only RSA and EC, so the signer's own
    type gate refuses it and names the type. The tripwire below watches the library limit."""
    files = _signer_files(pki, tmp_path, make(), "eddsa")
    with pytest.raises(ValueError, match="'signing_key' key type is Ed(25519|448); S/MIME signing"):
        DirectDestination(_dest(pki, **files))


def test_pkcs7_add_signer_still_refuses_an_eddsa_key() -> None:
    """Library-drift tripwire for the signer gate. If a later ``cryptography`` signs with EdDSA,
    this fails, and the gate is refusing a key the library could now use -- re-read BACKLOG #3384
    before widening it."""
    key = ed25519.Ed25519PrivateKey.generate()
    cert = _cert_for(key.public_key(), "ed25519 signer", key)
    # Typed Any on purpose: the stubs already say add_signer takes only RSA and EC, and this test
    # asks whether the RUNTIME still agrees.
    signer: Any = key
    with pytest.raises(TypeError, match="Only RSA & EC"):
        pkcs7.PKCS7SignatureBuilder().set_data(b"synthetic").add_signer(
            cert, signer, hashes.SHA256()
        )


def test_a_dsa_recipient_cert_is_refused_and_named(pki: dict[str, Any], tmp_path: Path) -> None:
    # Refused by the RSA-only gate, which runs before the floor on this surface and names the type.
    path = _recipient_file(pki, tmp_path, _dsa_key().public_key(), "dsa")
    with pytest.raises(ValueError, match="'recipient_cert' key type is DSA; S/MIME encryption"):
        DirectDestination(_dest(pki, recipient_cert=path))


def test_an_unlisted_recipient_key_type_is_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    public = x25519.X25519PrivateKey.generate().public_key()
    path = _recipient_file(pki, tmp_path, public, "x25519")
    with pytest.raises(ValueError, match="'recipient_cert' key type is X25519; S/MIME encryption"):
        DirectDestination(_dest(pki, recipient_cert=path))


def _unreadable_key_cert_pem(pki: dict[str, Any]) -> bytes:
    """A cert whose key algorithm OID ``cryptography`` does not know. Built by changing the last
    arc of rsaEncryption (1.2.840.113549.1.1.1) to 99, so ``public_key()`` raises
    ``UnsupportedAlgorithm``. The signature no longer verifies, which does not matter: the floor
    reads the key before any issuance check."""
    der = pki["ca_cert"].public_bytes(serialization.Encoding.DER)
    rsa_oid = bytes.fromhex("06092a864886f70d010101")
    assert der.count(rsa_oid) == 1
    odd = x509.load_der_x509_certificate(der.replace(rsa_oid, rsa_oid[:-1] + b"\x63"))
    with pytest.raises(UnsupportedAlgorithm):
        odd.public_key()  # the premise: unmapped, this is not a ValueError
    return odd.public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize("setting", ["signing_cert", "recipient_cert", "trust_anchor"])
def test_a_key_type_nobody_can_read_is_refused_as_a_value_error(
    pki: dict[str, Any], tmp_path: Path, setting: str
) -> None:
    odd = _unreadable_key_cert_pem(pki)
    path = tmp_path / f"unreadable_{setting}.pem"
    if setting == "trust_anchor":
        # Bundled beside the real anchor, so the refusal cannot be an issuance failure.
        path.write_bytes(Path(pki["trust_anchor"]).read_bytes() + odd)
    else:
        path.write_bytes(odd)
    with pytest.raises(ValueError, match=f"'{setting}' holds a key of a type this connector"):
        DirectDestination(_dest(pki, **{setting: str(path)}))


def test_a_dsa_trust_anchor_is_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    """The case that was live before the allow-list: ``verify_directly_issued_by`` checks a DSA
    CA's signature, so a DSA anchor issuing a valid RSA recipient constructed cleanly."""
    files = _anchor_issuing_an_rsa_recipient(tmp_path, _dsa_key(), "dsa")
    with pytest.raises(ValueError, match="'trust_anchor' key type is DSA, which is not on"):
        DirectDestination(_dest(pki, **files))


def test_an_unlisted_trust_anchor_type_is_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    # Bundled beside the real anchor, which issues the recipient. The floor checks every anchor in
    # the bundle before the issuance loop, so the unlisted one is refused though it issues nothing.
    public = x25519.X25519PrivateKey.generate().public_key()
    odd = _cert_for(public, "x25519 anchor", pki["ca_key"], pki["ca_cert"].subject)
    bundle = tmp_path / "bundle_x25519.pem"
    bundle.write_bytes(
        Path(pki["trust_anchor"]).read_bytes() + odd.public_bytes(serialization.Encoding.PEM)
    )
    with pytest.raises(ValueError, match="'trust_anchor' key type is X25519, which is not on"):
        DirectDestination(_dest(pki, trust_anchor=str(bundle)))


@pytest.mark.parametrize(
    "make",
    [ed25519.Ed25519PrivateKey.generate, ed448.Ed448PrivateKey.generate],
    ids=["ed25519", "ed448"],
)
def test_an_eddsa_trust_anchor_issuing_an_rsa_recipient_constructs(
    pki: dict[str, Any], tmp_path: Path, make: Callable[[], Any]
) -> None:
    # POSITIVE CONTROL for EdDSA being on the list: the trust anchor is the one surface Direct can
    # carry it on today, because verify_directly_issued_by checks an EdDSA CA's signature.
    DirectDestination(_dest(pki, **_anchor_issuing_an_rsa_recipient(tmp_path, make(), "eddsa")))


def test_the_partner_key_floor_matches_its_twin_in_xml_signature() -> None:
    """``parsing/`` may not import ``transports/``, so the XML-DSig key floor copies this curve set
    and RSA number rather than sharing them (BACKLOG #1166). This pins the copies, so the two cannot
    drift apart. It lives here, not beside the XML tests, because those skip without the ``[xml]``
    extra.

    It also pins the allowed key TYPES (BACKLOG #3384) by behaviour, not by a constant: each probe
    key goes to both floors, and both must give the same verdict. The probes cover every type either
    floor lists, a weak key of each sized type, and two types neither lists."""
    from messagefoundry.parsing.xml import signature
    from messagefoundry.transports import direct

    assert signature._APPROVED_EC_CURVES == direct._APPROVED_EC_CURVES
    assert signature._MIN_RSA_BITS == direct._MIN_RSA_BITS

    probes: dict[str, Any] = {
        "rsa-2048": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        # A negative control, minted only to be refused; see _weak_pki for the CodeQL note.
        "rsa-1024": rsa.generate_private_key(public_exponent=65537, key_size=1024),
        "p-256": ec.generate_private_key(ec.SECP256R1()),
        "p-192": ec.generate_private_key(ec.SECP192R1()),
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
        "ed448": ed448.Ed448PrivateKey.generate(),
        "dsa-2048": _dsa_key(),
        "x25519": x25519.X25519PrivateKey.generate(),
        "x448": x448.X448PrivateKey.generate(),
    }
    allowed = {"rsa-2048", "p-256", "ed25519", "ed448"}
    for label, key in probes.items():
        public = key.public_key()
        # A stand-in for signxml's VerifyResult: the XML floor reads only ``signature_key``.
        reported = types.SimpleNamespace(
            signature_key=public.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        xml_passes = signature._signing_key_refusal(reported) is None
        try:
            direct._require_key_strength(public, "probe")
            direct_passes = True
        except ValueError:
            direct_passes = False
        assert xml_passes == direct_passes, f"the two floors disagree on {label}"
        assert direct_passes == (label in allowed), f"both floors give the wrong verdict on {label}"


# --- recipient key type: RSA only, refused at construction (BACKLOG #1918) ---------------------------
#
# The pinned cryptography's PKCS7EnvelopeBuilder does RSA key transport and nothing else. An EC
# recipient cert used to pass construction (it clears the EC curve list) and then fail every send.
# The refusal is scoped to the recipient: the signer and the trust anchor take EC, and are pinned so
# below, because the library limit is on the ENVELOPE and not on the key type in general.


def _ec_recipient(pki: dict[str, Any], tmp_path: Path) -> str:
    _, cert = _mint_ec_leaf("ec-recipient@hisp.example", pki["ca_key"], pki["ca_cert"])
    path = tmp_path / "ec_recip.crt"
    _write_pem(path, cert)
    return str(path)


def test_an_ec_recipient_cert_is_refused_at_construction(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="recipient_cert.*RSA"):
        DirectDestination(_dest(pki, recipient_cert=_ec_recipient(pki, tmp_path)))


def test_a_non_ec_non_rsa_recipient_cert_is_refused_too(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    # The fallback label, on a key type the curve list never sees: Ed25519.
    key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ed25519-recip")]))
        .issuer_name(pki["ca_cert"].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    cert = _with_san(builder, "recipient@hisp.example").sign(pki["ca_key"], hashes.SHA256())
    path = tmp_path / "ed25519_recip.crt"
    _write_pem(path, cert)
    with pytest.raises(ValueError, match="recipient_cert' key type is Ed25519; S/MIME encryption"):
        DirectDestination(_dest(pki, recipient_cert=str(path)))


def test_pkcs7_envelope_builder_still_refuses_an_ec_recipient(pki: dict[str, Any]) -> None:
    """Library-drift tripwire for the refusal above. If a later cryptography envelopes to an EC
    recipient, this fails, and the construction refusal is refusing a partner the library could now
    serve -- re-read BACKLOG #1918 before widening it."""
    _, cert = _mint_ec_leaf("ec-recipient@hisp.example", pki["ca_key"], pki["ca_cert"])
    with pytest.raises(TypeError, match="Only RSA"):
        pkcs7.PKCS7EnvelopeBuilder().set_data(b"synthetic").add_recipient(cert)


def test_an_ec_trust_anchor_issuing_an_rsa_recipient_still_constructs(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    # POSITIVE CONTROL: the refusal is about the ENVELOPE target, not EC anywhere in the chain. An EC
    # CA signing an RSA recipient verifies with verify_directly_issued_by on the pinned library.
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EC Direct CA")])
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA384())
    )
    recip_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    recip_builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rsa-recip")]))
        .issuer_name(ca_name)
        .public_key(recip_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    recip_cert = _with_san(recip_builder, "recipient@hisp.example").sign(ca_key, hashes.SHA384())
    anchor_p = tmp_path / "ec_ca.crt"
    recip_p = tmp_path / "rsa_recip_of_ec_ca.crt"
    _write_pem(anchor_p, ca_cert)
    _write_pem(recip_p, recip_cert)
    DirectDestination(_dest(pki, recipient_cert=str(recip_p), trust_anchor=str(anchor_p)))


# --- library-capability tripwire for BACKLOG #1168 --------------------------------------------------

# ASVS 11.3.1 fails on this connector for a reason that lives OUTSIDE this repository, and #1168
# carries the measurement. In one sentence: `DirectDestination._build_smime` (direct.py) signs with a
# padding the pinned `cryptography` lets a caller choose, then wraps the content-encryption key with
# one it does not -- so the signer is a CODE CHOICE and the recipient is a LIBRARY LIMIT, and the two
# must never be reported as one defect. The evidence is in #1168 and is not restated here.
#
# The limit is a fact about an external library on a pin that moves, and nothing watched it. A release
# growing an RSA-OAEP seam would make #1168 actionable and would announce itself nowhere. These two
# tests are that alarm. Same class as the paramiko key-name pin in tests/test_remotefile_transport.py.
#
# SCOPE: a TRIPWIRE, not a fix. Nothing here asserts what the engine emits and nothing here moves the
# cell -- DIRECT still wraps its content-encryption key with RSAES-PKCS1-v1_5.


def test_pkcs7_envelope_builder_still_has_no_key_encryption_seam() -> None:
    # A seam can arrive in two shapes and `dir()` sees only the first: a new METHOD, or a new
    # PARAMETER on the method already there. Subset rather than equality, because the failure mode is
    # an ADDITION -- an upstream rename must not raise an alarm about a seam that did not appear.
    public = {n for n in dir(pkcs7.PKCS7EnvelopeBuilder) if not n.startswith("_")}
    assert public <= {"add_recipient", "encrypt", "set_content_encryption_algorithm", "set_data"}, (
        "PKCS7EnvelopeBuilder grew a public method. If it is a key-encryption or padding seam, the "
        "DIRECT key-transport limb of BACKLOG #1168 just became reachable -- re-read that item "
        "before widening this set."
    )
    params = list(inspect.signature(pkcs7.PKCS7EnvelopeBuilder.add_recipient).parameters)
    assert params == ["self", "certificate"], (
        "add_recipient grew a parameter -- same seam, see above."
    )


def test_pkcs7_add_signer_still_accepts_rsa_padding() -> None:
    # POSITIVE CONTROL on the test above: it proves the introspection CAN see a padding parameter
    # when the library exposes one, so "add_recipient takes none" is not green merely because the
    # probe is blind. Load-bearing on its own too -- lose this keyword and the DIRECT signer stops
    # being a code choice, both sites collapse into one library limit, and #1168 changes shape.
    param = inspect.signature(pkcs7.PKCS7SignatureBuilder.add_signer).parameters["rsa_padding"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
    assert param.default is None


# --- content cipher: AES-256-CBC, pinned in code (ASVS 11.3.1, BACKLOG #1168) -----------------------
#
# Why the cipher is pinned is recorded once, at `direct._CONTENT_CIPHER`. These tests read the OID
# out of the envelope's structure rather than scanning bytes, so they say WHICH field carries it.

#: DER content octets of the two content-encryption OIDs (NIST CSOR, RFC 3565).
_AES128_CBC_OID = bytes.fromhex("608648016503040102")  # 2.16.840.1.101.3.4.1.2
_AES256_CBC_OID = bytes.fromhex("60864801650304012a")  # 2.16.840.1.101.3.4.1.42
_ID_ENVELOPED_DATA_OID = bytes.fromhex("2a864886f70d010703")  # 1.2.840.113549.1.7.3


def _der_tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    """Read one definite-length DER TLV at `pos`. Returns (tag, content start, content end).
    Single-byte tags only, which is all CMS EnvelopedData uses on the path walked below."""
    tag = buf[pos]
    length = buf[pos + 1]
    start = pos + 2
    if length & 0x80:
        n = length & 0x7F
        assert 0 < n <= 4, "indefinite or oversized DER length -- not a DER envelope"
        length = int.from_bytes(buf[start : start + n], "big")
        start += n
    return tag, start, start + length


def _der_children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    pos = start
    while pos < end:
        tlv = _der_tlv(buf, pos)
        out.append(tlv)
        pos = tlv[2]
    assert pos == end, "DER children overran their parent"
    return out


def _content_encryption_oid(enveloped: bytes) -> bytes:
    """The OID in EnvelopedData.encryptedContentInfo.contentEncryptionAlgorithm (RFC 5652 s6.1),
    found by walking the structure, not by searching for bytes."""
    tag, s, e = _der_tlv(enveloped, 0)
    assert tag == 0x30  # ContentInfo SEQUENCE
    (oid_tag, oid_s, oid_e), (ctx_tag, ctx_s, ctx_e) = _der_children(enveloped, s, e)
    assert oid_tag == 0x06 and enveloped[oid_s:oid_e] == _ID_ENVELOPED_DATA_OID
    assert ctx_tag == 0xA0  # [0] EXPLICIT content
    [(env_tag, env_s, env_e)] = _der_children(enveloped, ctx_s, ctx_e)
    assert env_tag == 0x30  # EnvelopedData SEQUENCE
    # version INTEGER, [0] originatorInfo OPTIONAL, recipientInfos SET, encryptedContentInfo, ...
    fields = [f for f in _der_children(enveloped, env_s, env_e) if f[0] != 0xA0]
    assert fields[0][0] == 0x02 and fields[1][0] == 0x31, "unexpected EnvelopedData layout"
    eci_tag, eci_s, eci_e = fields[2]
    assert eci_tag == 0x30  # EncryptedContentInfo SEQUENCE
    alg_tag, alg_s, alg_e = _der_children(enveloped, eci_s, eci_e)[1]
    assert alg_tag == 0x30  # AlgorithmIdentifier SEQUENCE
    alg_oid_tag, alg_oid_s, alg_oid_e = _der_children(enveloped, alg_s, alg_e)[0]
    assert alg_oid_tag == 0x06
    return enveloped[alg_oid_s:alg_oid_e]


async def test_envelope_content_cipher_is_aes256_cbc(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    """The shipped envelope encrypts content under AES-256-CBC, the cipher the 2026-09-22 ruling
    accepts, and the recipient recovers the exact body from that same envelope."""
    _install_fake(monkeypatch)
    await DirectDestination(_dest(pki)).send(_SYNTHETIC_HL7)
    [smtp] = _FakeSMTP.instances
    enveloped = _sent_smime_bytes(smtp)

    oid = _content_encryption_oid(enveloped)
    assert oid == _AES256_CBC_OID, f"content cipher OID is {oid.hex()}, not AES-256-CBC"

    # Round trip on the SAME AES-256 envelope. The engine has no DIRECT receive path (ADR 0085 PR1 is
    # outbound only), so this is the receiver's side: the recipient key through the library's CMS
    # decrypt, which is what a HISP peer runs. The body comes back byte-exact.
    signed = pkcs7.pkcs7_decrypt_der(enveloped, pki["recip_cert"], pki["recip_key"], [])
    assert _SYNTHETIC_HL7.encode("utf-8") in signed
    assert any(c == pki["signer_cert"] for c in pkcs7.load_der_pkcs7_certificates(signed))


@pytest.mark.parametrize("signer", ["rsa-pkcs1v15", "rsa-pss", "ec"])
async def test_envelope_content_cipher_holds_under_every_signer_choice(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], tmp_path: Path, signer: str
) -> None:
    # The cipher is set on the envelope builder, and the signer choices touch only the signature
    # builder. Pinned so a later refactor that branches the builder chain per signer cannot drop the
    # cipher on one branch.
    overrides: dict[str, str] = {
        "rsa-pkcs1v15": {},
        "rsa-pss": {"signature_padding": "pss"},
        "ec": _ec_signer(pki, tmp_path),
    }[signer]
    _install_fake(monkeypatch)
    await DirectDestination(_dest(pki, **overrides)).send(_SYNTHETIC_HL7)
    [smtp] = _FakeSMTP.instances
    assert _content_encryption_oid(_sent_smime_bytes(smtp)) == _AES256_CBC_OID


def _library_envelope(
    recipient: x509.Certificate, *cipher: pkcs7.ContentEncryptionAlgorithm
) -> bytes:
    builder = pkcs7.PKCS7EnvelopeBuilder().set_data(b"synthetic")
    for c in cipher:
        builder = builder.set_content_encryption_algorithm(c)
    return builder.add_recipient(recipient).encrypt(
        serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]
    )


def test_content_encryption_oid_probe_can_read_both_ciphers(pki: dict[str, Any]) -> None:
    # POSITIVE CONTROL for the DER probe, independent of any library default: it must report AES-128
    # when AES-128 is asked for, so the AES-256 assertions above are not green on a probe that can
    # only ever return one value.
    cert = pki["recip_cert"]
    assert _content_encryption_oid(_library_envelope(cert, algorithms.AES128)) == _AES128_CBC_OID
    assert _content_encryption_oid(_library_envelope(cert, algorithms.AES256)) == _AES256_CBC_OID


def test_pkcs7_envelope_default_content_cipher_is_still_aes128(pki: dict[str, Any]) -> None:
    """Library-drift tripwire: the library default is still AES-128-CBC, which is why `direct.py`
    sets the cipher explicitly.

    If this fails, an upstream release changed the default, and what to do depends on what it moved
    to. If the new default is AES-256-CBC, the pin in `direct.py` is redundant but harmless. If it is
    anything else -- including something stronger, such as an authenticated mode -- the pin may now
    hold Direct BELOW the library default. Either way, re-read BACKLOG #1168 before changing the pin
    or this test.
    """
    assert _content_encryption_oid(_library_envelope(pki["recip_cert"])) == _AES128_CBC_OID


# --- recipient trust beyond issuance (BACKLOG #5631) --------------------------------------------------
#
# Issuance alone used to be the whole trust check. Each refusal below constructed before #5631: an
# expired or not-yet-valid recipient or anchor, a non-CA anchor, a keyUsage or extendedKeyUsage that
# rules encryption out, and a cert the same CA issued to another subscriber, so PHI would have been
# encrypted to it. Each refusal has a positive control.


_CA_CONSTRAINTS = x509.BasicConstraints(ca=True, path_length=None)


def _key_usage(*, key_encipherment: bool = False, key_cert_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=key_encipherment,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _issuer(
    *,
    key: rsa.RSAPrivateKey | None = None,
    constraints: x509.BasicConstraints | None = _CA_CONSTRAINTS,
    usage: x509.KeyUsage | None = None,
    valid_to: datetime.timedelta = datetime.timedelta(days=3650),
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """A self-signed issuing anchor, named like the ``pki`` CA so it can stand in for it."""
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Direct CA")])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now + valid_to)
    )
    if constraints is not None:
        builder = builder.add_extension(constraints, critical=True)
    if usage is not None:
        builder = builder.add_extension(usage, critical=True)
    return key, builder.sign(key, hashes.SHA256())


def _files(tmp_path: Path, tag: str, **certs: x509.Certificate) -> dict[str, str]:
    """Write each cert to a file and return ``{setting: path}`` overrides."""
    out: dict[str, str] = {}
    for setting, cert in certs.items():
        path = tmp_path / f"{tag}_{setting}.crt"
        _write_pem(path, cert)
        out[setting] = str(path)
    return out


def _recipient(pki: dict[str, Any], tmp_path: Path, tag: str, **mint: Any) -> str:
    """A recipient cert issued by the ``pki`` CA, minted with ``mint``, as a file path."""
    _, cert = _mint_leaf("recipient@hisp.example", pki["ca_key"], pki["ca_cert"], **mint)
    return _files(tmp_path, tag, recipient_cert=cert)["recipient_cert"]


def _refusal(pki: dict[str, Any], **overrides: Any) -> str:
    with pytest.raises(ValueError) as caught:
        DirectDestination(_dest(pki, **overrides))
    text = str(caught.value)
    # Never a subject or a SAN value: either may identify a patient's provider.
    assert "@" not in text and "Test Direct CA" not in text and "example" not in text
    return text


async def _warns_then_refuses_every_send(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    pki: dict[str, Any],
    expected: str,
    **overrides: Any,
) -> None:
    """Construction WARNS on the validity window and builds (a refusal there would fail the lane's
    build at start); the send then refuses before building or dialling. Either bound is a
    permanent configuration fault whose code names the setting and the bound, so a not-yet-valid
    cert never spends a row's attempts (no row dead-letters on it under the stop policy)."""
    _install_fake(monkeypatch)
    with caplog.at_level("WARNING", logger="messagefoundry.transports.direct"):
        d = DirectDestination(_dest(pki, **overrides))
    [warning] = [r.getMessage() for r in caplog.records if expected in r.getMessage()]
    assert "@" not in warning and "Test Direct CA" not in warning
    expired = "has expired" in expected
    assert "dead_letter" in warning
    assert ("rebuild the connector" in warning) is expired
    assert ("once notBefore has passed" in warning) is not expired
    with pytest.raises(NegativeAckError) as caught:
        await d.send(_SYNTHETIC_HL7)
    assert expected in str(caught.value)
    assert caught.value.permanent is True and caught.value.config_fault is True
    setting = expected.split("'")[1]
    bound = "expired" if expired else "not-yet-valid"
    assert caught.value.code == f"direct-cert-validity:{setting}:{bound}"
    assert _FakeSMTP.instances == []


@pytest.mark.parametrize(
    "valid_from, valid_to, expected",
    [
        (datetime.timedelta(days=-30), datetime.timedelta(days=-1), "'recipient_cert' has expired"),
        (
            datetime.timedelta(days=1),
            datetime.timedelta(days=30),
            "'recipient_cert' is not yet valid",
        ),
    ],
    ids=["expired", "not-yet-valid"],
)
async def test_a_recipient_cert_outside_its_validity_window_warns_and_refuses_every_send(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    pki: dict[str, Any],
    tmp_path: Path,
    valid_from: datetime.timedelta,
    valid_to: datetime.timedelta,
    expected: str,
) -> None:
    path = _recipient(pki, tmp_path, "window", valid_from=valid_from, valid_to=valid_to)
    await _warns_then_refuses_every_send(monkeypatch, caplog, pki, expected, recipient_cert=path)


async def test_an_expired_issuing_anchor_warns_and_refuses_every_send(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    pki: dict[str, Any],
    tmp_path: Path,
) -> None:
    ca_key, ca = _issuer(valid_to=datetime.timedelta(days=-1))
    _, recipient = _mint_leaf("recipient@hisp.example", ca_key, ca)
    files = _files(tmp_path, "old_ca", recipient_cert=recipient, trust_anchor=ca)
    await _warns_then_refuses_every_send(
        monkeypatch, caplog, pki, "'trust_anchor' has expired", **files
    )


def _renewed_bundle(
    tmp_path: Path, old_valid_to: datetime.timedelta
) -> tuple[dict[str, str], x509.Certificate, x509.Certificate]:
    """A CA renewed under the same name and key, the older copy first in the bundle, and a
    recipient both verify. Returns the overrides, the old copy and the renewed one."""
    ca_key, old = _issuer(valid_to=old_valid_to)
    _, renewed = _issuer(key=ca_key)
    _, recipient = _mint_leaf("recipient@hisp.example", ca_key, renewed)
    bundle = tmp_path / "renewed_bundle.pem"
    bundle.write_bytes(
        old.public_bytes(serialization.Encoding.PEM)
        + renewed.public_bytes(serialization.Encoding.PEM)
    )
    files = _files(tmp_path, "renewed", recipient_cert=recipient)
    return {"trust_anchor": str(bundle), **files}, old, renewed


def test_an_expired_anchor_beside_its_renewed_successor_constructs(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    # The search must not stop at the expired copy, which comes first.
    overrides, old, renewed = _renewed_bundle(tmp_path, datetime.timedelta(days=-1))
    d = DirectDestination(_dest(pki, **overrides))
    assert d._recipient_anchors == (old, renewed)


async def test_an_older_anchor_expiring_after_construction_leaves_its_successor_in_use(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], tmp_path: Path
) -> None:
    # Both copies are valid at construction; the older one then expires. The send goes ahead on
    # the renewed copy rather than stopping the lane.
    from messagefoundry.transports import direct

    _install_fake(monkeypatch)
    overrides, _, _ = _renewed_bundle(tmp_path, datetime.timedelta(days=10))
    d = DirectDestination(_dest(pki, **overrides))
    later = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=20)
    monkeypatch.setattr(direct, "_utcnow", lambda: later)
    await d.send(_SYNTHETIC_HL7)
    [smtp] = _FakeSMTP.instances
    assert len(smtp.sent) == 1


@pytest.mark.parametrize(
    "constraints",
    [None, x509.BasicConstraints(ca=False, path_length=None)],
    ids=["no-basic-constraints", "ca-false"],
)
def test_a_non_ca_issuing_anchor_is_refused(
    pki: dict[str, Any], tmp_path: Path, constraints: x509.BasicConstraints | None
) -> None:
    # An end-entity cert used as the anchor: it signed the recipient, but it is no CA.
    ca_key, ca = _issuer(constraints=constraints)
    _, recipient = _mint_leaf("recipient@hisp.example", ca_key, ca)
    files = _files(tmp_path, "leaf_anchor", recipient_cert=recipient, trust_anchor=ca)
    assert "'trust_anchor' that issues 'recipient_cert' is not a CA" in _refusal(pki, **files)


def test_an_anchor_whose_key_usage_forbids_cert_signing_is_refused(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    ca_key, ca = _issuer(usage=_key_usage(key_encipherment=True))
    _, recipient = _mint_leaf("recipient@hisp.example", ca_key, ca)
    files = _files(tmp_path, "ku_anchor", recipient_cert=recipient, trust_anchor=ca)
    assert "does not assert keyCertSign" in _refusal(pki, **files)


def test_an_anchor_whose_key_usage_allows_cert_signing_constructs(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    ca_key, ca = _issuer(usage=_key_usage(key_cert_sign=True))
    _, recipient = _mint_leaf("recipient@hisp.example", ca_key, ca)
    files = _files(tmp_path, "ku_ok", recipient_cert=recipient, trust_anchor=ca)
    DirectDestination(_dest(pki, **files))


def test_a_self_signed_recipient_pinned_as_its_own_anchor_is_exempt_from_the_ca_check(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    # The pinned-correspondent shape: no basicConstraints and no keyCertSign, since it issues nothing.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _cert_for(key.public_key(), "recipient@hisp.example", key)
    path = _files(tmp_path, "pinned", recipient_cert=cert)["recipient_cert"]
    d = DirectDestination(_dest(pki, recipient_cert=path, trust_anchor=path))
    assert d._recipient_anchors == (cert,)


def test_a_ca_certificate_as_the_recipient_is_refused(pki: dict[str, Any], tmp_path: Path) -> None:
    # A CA cert with no keyUsage and a SAN for the mailbox passes every other recipient check.
    ca = x509.BasicConstraints(ca=True, path_length=0)
    path = _recipient(pki, tmp_path, "ca_recipient", extensions=[ca])
    assert "'recipient_cert' is a CA certificate" in _refusal(pki, recipient_cert=path)


def test_a_renewed_pinned_self_signed_recipient_checked_against_its_old_copy_constructs(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    # The correspondent renewed its self-signed cert (same name and key, new serial, CA=true as
    # openssl req -x509 sets it) and only recipient_cert was updated. It is still the pinned
    # correspondent, not a CA certificate issued by another anchor.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    old = _cert_for(key.public_key(), "recipient@hisp.example", key, ca=True)
    renewed = _cert_for(key.public_key(), "recipient@hisp.example", key, ca=True)
    assert old != renewed
    files = _files(tmp_path, "renewed_pin", recipient_cert=renewed, trust_anchor=old)
    DirectDestination(_dest(pki, **files))


async def test_an_expired_old_pinned_copy_does_not_stop_a_valid_renewed_pin(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], tmp_path: Path
) -> None:
    # The old pinned copy, still the trust_anchor, has expired; the renewed recipient is valid.
    # A pinned correspondent's validity is the recipient cert's alone, so the send delivers.
    _install_fake(monkeypatch)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "recipient@hisp.example")])
    now = datetime.datetime.now(datetime.UTC)

    def self_signed(start: datetime.timedelta, end: datetime.timedelta) -> x509.Certificate:
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + start)
            .not_valid_after(now + end)
        )
        return _with_san(builder, "recipient@hisp.example").sign(key, hashes.SHA256())

    old = self_signed(datetime.timedelta(days=-400), datetime.timedelta(days=-1))
    renewed = self_signed(datetime.timedelta(days=-1), datetime.timedelta(days=365))
    files = _files(tmp_path, "expired_pin", recipient_cert=renewed, trust_anchor=old)
    d = DirectDestination(_dest(pki, **files))
    await d.send(_SYNTHETIC_HL7)
    [smtp] = _FakeSMTP.instances
    assert len(smtp.sent) == 1


def test_a_pinned_self_signed_recipient_asserting_ca_constructs(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    # openssl req -x509 sets CA=true by default, and a pinned correspondent issues nothing else.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _cert_for(key.public_key(), "recipient@hisp.example", key, ca=True)
    path = _files(tmp_path, "pinned_ca", recipient_cert=cert)["recipient_cert"]
    DirectDestination(_dest(pki, recipient_cert=path, trust_anchor=path))


def test_a_recipient_whose_key_usage_forbids_key_encipherment_is_refused(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    path = _recipient(pki, tmp_path, "ku_sign_only", extensions=[_key_usage()])
    assert "does not assert keyEncipherment" in _refusal(pki, recipient_cert=path)


def test_a_recipient_whose_eku_omits_email_protection_is_refused(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    path = _recipient(pki, tmp_path, "eku_tls", extensions=[eku])
    assert "lists neither emailProtection" in _refusal(pki, recipient_cert=path)


def test_a_recipient_whose_eku_is_any_extended_key_usage_constructs(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    # RFC 5280, the extended key usage section: anyExtendedKeyUsage stands for every purpose.
    eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
    DirectDestination(
        _dest(pki, recipient_cert=_recipient(pki, tmp_path, "eku_any", extensions=[eku]))
    )


@pytest.mark.parametrize(
    "raised",
    [
        x509.DuplicateExtension(
            "synthetic duplicate", x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ),
        x509.UnsupportedGeneralNameType("synthetic x400Address"),
        ValueError("synthetic malformed extension"),
        UserWarning("synthetic three-letter country"),
        CryptographyDeprecationWarning("synthetic deprecated encoding"),
    ],
    ids=["duplicate", "unsupported-general-name", "malformed", "user-warning", "deprecation"],
)
def test_an_extension_that_does_not_read_is_a_value_error_naming_the_setting(
    raised: Exception,
) -> None:
    # Two of these are not ValueError subclasses, so unmapped they escaped the construction
    # contract carrying the library's text. A stand-in cert, because the builder will not mint them.
    from messagefoundry.transports import direct

    class _Unreadable:
        @property
        def extensions(self) -> Any:
            raise raised

    stand_in: Any = _Unreadable()
    with pytest.raises(ValueError, match="'recipient_cert' carries an extension") as caught:
        direct._extension(stand_in, x509.KeyUsage, "recipient_cert")
    assert "synthetic" not in str(caught.value)


def test_a_recipient_whose_usages_allow_email_encryption_constructs(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    usages = [
        _key_usage(key_encipherment=True),
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
    ]
    path = _recipient(pki, tmp_path, "usages_ok", extensions=usages)
    DirectDestination(_dest(pki, recipient_cert=path))


@pytest.mark.parametrize(
    "addresses, dns_names",
    [
        (("other@hisp.example",), ()),
        ((), ()),
        (("recipient@other.example",), ("other.example",)),
        (("Recipient@hisp.example",), ()),
    ],
    ids=["another-subscriber", "no-san", "another-domain", "local-part-case"],
)
def test_a_cert_the_ca_issued_to_another_subscriber_is_refused(
    pki: dict[str, Any], tmp_path: Path, addresses: tuple[str, ...], dns_names: tuple[str, ...]
) -> None:
    # Issued by the trusted CA, in its window, with no usage objection: only the binding fails.
    path = _recipient(pki, tmp_path, "other", addresses=addresses, dns_names=dns_names)
    assert "does not name recipient address 1 of 1" in _refusal(pki, recipient_cert=path)


def test_every_recipient_must_be_named_and_the_refusal_gives_the_position(
    pki: dict[str, Any], tmp_path: Path
) -> None:
    path = _recipient(pki, tmp_path, "one_of_two")
    recipients = ["recipient@hisp.example", "second@hisp.example"]
    assert "address 2 of 2" in _refusal(pki, recipient_cert=path, recipients=recipients)
    # One entry holding two comma-joined addresses: the position counts addresses.
    joined = [", ".join(recipients)]
    assert "address 2 of 2" in _refusal(pki, recipient_cert=path, recipients=joined)


@pytest.mark.parametrize(
    "addresses, dns_names, recipient",
    [
        (("recipient@HISP.example",), (), "recipient@hisp.example"),
        ((), ("hisp.example",), "anyone@HISP.EXAMPLE"),
    ],
    ids=["rfc822-domain-case", "dns-name-organisation-cert"],
)
def test_a_cert_naming_the_recipient_constructs(
    pki: dict[str, Any],
    tmp_path: Path,
    addresses: tuple[str, ...],
    dns_names: tuple[str, ...],
    recipient: str,
) -> None:
    path = _recipient(pki, tmp_path, "named", addresses=addresses, dns_names=dns_names)
    DirectDestination(_dest(pki, recipient_cert=path, recipients=[recipient]))


@pytest.mark.parametrize("setting", ["recipient_cert", "trust_anchor"])
async def test_a_cert_that_expires_after_construction_holds_the_queue_at_send(
    monkeypatch: pytest.MonkeyPatch,
    pki: dict[str, Any],
    tmp_path: Path,
    setting: str,
) -> None:
    """Construction passed, then the clock moved past one cert's notAfter. The send must neither
    build nor dial, and must be a permanent configuration fault, which the delivery worker answers
    by stopping the lane and keeping the queue rather than dead-lettering each row."""
    from messagefoundry.transports import direct

    _install_fake(monkeypatch)
    builds: list[str] = []
    real_build = DirectDestination._build_smime

    def counted_build(self: DirectDestination, payload: str) -> EmailMessage:
        builds.append(payload)
        return real_build(self, payload)

    monkeypatch.setattr(DirectDestination, "_build_smime", counted_build)
    soon = datetime.timedelta(days=30)
    if setting == "recipient_cert":
        overrides = {"recipient_cert": _recipient(pki, tmp_path, "soon", valid_to=soon)}
    else:
        ca_key, ca = _issuer(valid_to=soon)
        _, recipient = _mint_leaf("recipient@hisp.example", ca_key, ca)
        overrides = _files(tmp_path, "soon_ca", recipient_cert=recipient, trust_anchor=ca)
    d = DirectDestination(_dest(pki, **overrides))
    later = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=60)
    monkeypatch.setattr(direct, "_utcnow", lambda: later)
    builds.clear()  # the construction probe built one
    with pytest.raises(NegativeAckError) as caught:
        await d.send(_SYNTHETIC_HL7)
    exc = caught.value
    assert exc.permanent is True and exc.config_fault is True
    assert exc.code == f"direct-cert-validity:{setting}:expired"
    assert f"'{setting}' has expired" in str(exc)
    assert builds == [] and _FakeSMTP.instances == []


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    from messagefoundry.store.store import MessageStore

    s = await MessageStore.open(tmp_path / "direct.db")
    yield s
    await s.close()


async def _deliver_one_through_the_worker(store: Any, connector: DirectDestination) -> Any:
    """Seed one outbound row and run one delivery of it through the real worker step, as
    tests/test_credential_fault_stop.py does for its stub connector. Returns the outcome."""
    from tests.test_credential_fault_stop import DEST, _RecordingSink, _runner, _seed_outbound

    await _seed_outbound(store)
    sink = _RecordingSink()
    runner = _runner(store, sink)
    runner._destinations[DEST] = connector
    item = await store.claim_next_fifo(DEST, now=1.0)
    assert item is not None
    outcome = await runner._process_delivery_item(DEST, item)
    return outcome, item, sink


async def _assert_stopped_and_kept(
    store: Any,
    outcome: Any,
    item: Any,
    sink: Any,
    *,
    code: str = "direct-cert-validity:recipient_cert:expired",
) -> None:
    from messagefoundry.pipeline.wiring_runner import _ItemOutcome
    from messagefoundry.store.store import OutboxStatus
    from tests.test_credential_fault_stop import DEST, _row_state

    assert outcome[0] is _ItemOutcome.STOPPED
    status, attempts, last_error = await _row_state(store, item.message_id)
    # Kept: pending, the claim's attempt given back, no error. Never dead-lettered.
    assert (status, attempts, last_error) == (OutboxStatus.PENDING.value, 0, None)
    assert [name for name, _ in sink.stopped] == [DEST]
    # The alert says which certificate and which bound failed, and nothing of the cert itself.
    detail = sink.stopped[0][1]
    assert f"configuration fault ({code})" in detail
    assert "@" not in detail


async def test_the_worker_stops_the_lane_and_keeps_the_queue_on_an_expiry_at_send(
    monkeypatch: pytest.MonkeyPatch,
    pki: dict[str, Any],
    tmp_path: Path,
    store: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # BACKLOG #5631, end to end through the delivery worker step: the cert expires after
    # construction, and the default credential_fault_policy stops the lane and keeps the row.
    from messagefoundry.transports import direct

    _install_fake(monkeypatch)
    path = _recipient(pki, tmp_path, "worker", valid_to=datetime.timedelta(days=30))
    d = DirectDestination(_dest(pki, recipient_cert=path))
    later = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=60)
    monkeypatch.setattr(direct, "_utcnow", lambda: later)
    with caplog.at_level("ERROR", logger="messagefoundry.pipeline.wiring_runner"):
        await _assert_stopped_and_kept(store, *await _deliver_one_through_the_worker(store, d))
    # The worker's lane-stop line carries the same code, so the log says which cert failed too.
    assert any(
        "direct-cert-validity:recipient_cert:expired" in r.getMessage() for r in caplog.records
    )
    assert _FakeSMTP.instances == []


async def test_a_not_yet_valid_cert_stops_the_lane_and_dead_letters_nothing(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], tmp_path: Path, store: Any
) -> None:
    """A cert installed before its notBefore: the lane stops and keeps the row, spending none of
    its attempts, so no row dead-letters while time cures the cert. Once notBefore has passed, the
    same connector delivers when an operator starts the lane again."""
    from messagefoundry.transports import direct

    _install_fake(monkeypatch)
    path = _recipient(
        pki,
        tmp_path,
        "early",
        valid_from=datetime.timedelta(minutes=10),
        valid_to=datetime.timedelta(days=30),
    )
    d = DirectDestination(_dest(pki, recipient_cert=path))
    await _assert_stopped_and_kept(
        store,
        *await _deliver_one_through_the_worker(store, d),
        code="direct-cert-validity:recipient_cert:not-yet-valid",
    )
    assert _FakeSMTP.instances == []
    # notBefore passes: the same connector now delivers.
    later = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    monkeypatch.setattr(direct, "_utcnow", lambda: later)
    await d.send(_SYNTHETIC_HL7)
    assert len(_FakeSMTP.instances) == 1


async def test_an_expired_anchor_wins_over_a_not_yet_valid_recipient(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], tmp_path: Path
) -> None:
    # Time cures the recipient's notBefore but never the anchor's notAfter, so the send must stop
    # the lane on the anchor rather than retry on the recipient.
    _install_fake(monkeypatch)
    ca_key, ca = _issuer(valid_to=datetime.timedelta(days=-1))
    _, recipient = _mint_leaf(
        "recipient@hisp.example", ca_key, ca, valid_from=datetime.timedelta(days=1)
    )
    d = DirectDestination(
        _dest(pki, **_files(tmp_path, "mixed", recipient_cert=recipient, trust_anchor=ca))
    )
    with pytest.raises(NegativeAckError) as caught:
        await d.send(_SYNTHETIC_HL7)
    assert caught.value.code == "direct-cert-validity:trust_anchor:expired"
    assert caught.value.config_fault is True


def test_the_construction_warning_is_not_logged_for_a_connector_that_is_then_refused(
    pki: dict[str, Any], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # An expired cert that ALSO names another mailbox: construction refuses on the binding, and
    # must not first have logged that sends will be refused for a connector that never existed.
    path = _recipient(
        pki,
        tmp_path,
        "expired_other",
        addresses=("other@hisp.example",),
        valid_from=datetime.timedelta(days=-30),
        valid_to=datetime.timedelta(days=-1),
    )
    with caplog.at_level("WARNING", logger="messagefoundry.transports.direct"):
        _refusal(pki, recipient_cert=path)
    assert not [r for r in caplog.records if "has expired" in r.getMessage()]


def test_in_window_material_logs_no_validity_warning(
    pki: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("WARNING", logger="messagefoundry.transports.direct"):
        DirectDestination(_dest(pki))
    assert not [r for r in caplog.records if "valid" in r.getMessage()]


async def test_a_restart_with_an_already_expired_cert_dead_letters_nothing(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any], tmp_path: Path, store: Any
) -> None:
    """A start or restart after the cert expired. The connector still BUILDS, through the same
    factory an engine start calls, so the lane is not recorded failed (whose worker would charge
    each queued row an attempt until it dead-lettered); its first send stops the lane instead."""
    from messagefoundry.transports.base import build_destination

    _install_fake(monkeypatch)
    path = _recipient(
        pki,
        tmp_path,
        "restart",
        valid_from=datetime.timedelta(days=-30),
        valid_to=datetime.timedelta(days=-1),
    )
    built = build_destination(
        _dest(pki, recipient_cert=path), egress=EgressSettings(deny_by_default=False)
    )
    assert isinstance(built, DirectDestination)
    await _assert_stopped_and_kept(store, *await _deliver_one_through_the_worker(store, built))
    assert _FakeSMTP.instances == []


async def test_a_cert_inside_its_window_at_send_still_delivers(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, Any]
) -> None:
    # POSITIVE CONTROL for the send-time check: the same clock seam, at a time inside both windows.
    from messagefoundry.transports import direct

    _install_fake(monkeypatch)
    d = DirectDestination(_dest(pki))
    later = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)
    monkeypatch.setattr(direct, "_utcnow", lambda: later)
    await d.send(_SYNTHETIC_HL7)
    [smtp] = _FakeSMTP.instances
    assert len(smtp.sent) == 1
