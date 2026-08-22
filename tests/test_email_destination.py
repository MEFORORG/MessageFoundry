# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SMTP-send outbound EMAIL destination (ADR 0029): message build, STARTTLS path, the cleartext
refusals, DeliveryError on failure, and the connect/EHLO/NOOP test_connection probe — all against an
in-process fake SMTP (no real server is ever contacted)."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import pytest

import messagefoundry.transports.email as email_mod
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, EgressSettings
from messagefoundry.config.tls_policy import (
    HopPosture,
    InsecureHopRefused,
    active_hop_posture,
)
from messagefoundry.pipeline.wiring_runner import check_egress_allowed
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.email import EmailDestination
from messagefoundry.transports.mllp import InsecureHopGuard


class _FakeSMTP:
    """A drop-in for ``smtplib.SMTP`` / ``SMTP_SSL`` that records the exchange instead of dialing a
    server. ``fail_at`` makes the named step raise so the DeliveryError mapping can be exercised."""

    instances: list[_FakeSMTP] = []

    #: What the fake relay advertises for AUTH. A CLASS attribute so a test can vary it --
    #: __init__ copies it per instance, and patching the instance is impossible from outside
    #: because the connector constructs the object itself.
    AUTH_ADVERTISED: dict[str, str] = {"auth": "CRAM-MD5 PLAIN LOGIN"}

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
        # #323: the context the connector handed us — on 465 via SMTP_SSL(context=), on 587 via
        # starttls(context=). Recorded (not ignored) so a test can assert it actually verifies:
        # smtplib's own default is ssl._create_unverified_context, so "a context was passed" is the
        # whole point and a fake that silently swallowed it would hide a regression.
        self.tls_context = context
        self.started_tls = False
        self.logged_in: tuple[str, str] | None = None
        self.auth_mechanism: str | None = None
        self.user = ""
        self.password = ""
        self.esmtp_features = dict(type(self).AUTH_ADVERTISED)
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

    monkeypatch.setattr(email_mod.smtplib, "SMTP", factory)
    monkeypatch.setattr(email_mod.smtplib, "SMTP_SSL", factory)
    return _FakeSMTP


def _dest(**settings: Any) -> Destination:
    base: dict[str, Any] = {
        "host": "smtp.partner.org",
        "sender": "engine@hospital.org",
        "recipients": ["clinician@partner.org"],
    }
    base.update(settings)
    return Destination(name="OB_EMAIL", type=ConnectorType.EMAIL, settings=base)


# --- construction / validation ----------------------------------------------------------------------


def test_requires_host_sender_recipients() -> None:
    with pytest.raises(ValueError, match="'host'"):
        EmailDestination(Destination(name="OB", type=ConnectorType.EMAIL, settings={}))
    with pytest.raises(ValueError, match="'sender'"):
        EmailDestination(Destination(name="OB", type=ConnectorType.EMAIL, settings={"host": "h"}))
    with pytest.raises(ValueError, match="recipients"):
        EmailDestination(
            Destination(name="OB", type=ConnectorType.EMAIL, settings={"host": "h", "sender": "s"})
        )


def test_recipients_accepts_a_lone_string() -> None:
    d = EmailDestination(_dest(recipients="solo@partner.org"))
    assert d.recipients == ["solo@partner.org"]


def test_defaults() -> None:
    d = EmailDestination(_dest())
    assert d.port == 587
    assert d.use_tls is True
    assert d.subject == ""


# --- message build + STARTTLS send path -------------------------------------------------------------


async def test_send_builds_message_and_starttls(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake(monkeypatch)
    d = EmailDestination(_dest(subject="Result ready", recipients=["a@p.org", "b@p.org"]))
    result = await d.send("PID|1|patient")
    assert result is None  # one-way delivery, no captured reply (like File)
    [smtp] = _FakeSMTP.instances
    assert smtp.started_tls is True  # STARTTLS issued before send (the default posture)
    assert smtp.logged_in is None  # no AUTH configured
    [msg] = smtp.sent
    assert msg["Subject"] == "Result ready"
    assert msg["From"] == "engine@hospital.org"
    assert msg["To"] == "a@p.org, b@p.org"
    assert msg.get_content().strip() == "PID|1|patient"


async def test_send_with_auth_logs_in(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake(monkeypatch)
    d = EmailDestination(_dest(username="svc", password="s3cret"))
    await d.send("body")
    [smtp] = _FakeSMTP.instances
    assert smtp.logged_in == ("svc", "s3cret")
    assert smtp.started_tls is True  # AUTH only over TLS


async def test_port_465_uses_implicit_tls_not_starttls(monkeypatch: pytest.MonkeyPatch) -> None:
    # On 465 the whole session is wrapped (SMTP_SSL), so no explicit STARTTLS is issued.
    captured: dict[str, str] = {}

    def ssl_factory(
        host: str, port: int, timeout: float = 0.0, context: ssl.SSLContext | None = None
    ) -> _FakeSMTP:
        captured["which"] = "SMTP_SSL"
        return _FakeSMTP(host, port, timeout, context=context)

    def plain_factory(
        host: str, port: int, timeout: float = 0.0, context: ssl.SSLContext | None = None
    ) -> _FakeSMTP:
        captured["which"] = "SMTP"
        return _FakeSMTP(host, port, timeout, context=context)

    _FakeSMTP.instances = []
    monkeypatch.setattr(email_mod.smtplib, "SMTP_SSL", ssl_factory)
    monkeypatch.setattr(email_mod.smtplib, "SMTP", plain_factory)
    d = EmailDestination(_dest(port=465))
    await d.send("body")
    assert captured["which"] == "SMTP_SSL"
    [smtp] = _FakeSMTP.instances
    assert smtp.started_tls is False  # implicit TLS — no explicit starttls() call


# --- cleartext / insecure_tls refusals --------------------------------------------------------------


def test_use_tls_false_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with pytest.raises(ValueError, match="cleartext"):
        EmailDestination(_dest(use_tls=False))


def test_use_tls_false_allowed_with_escape_but_no_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    d = EmailDestination(_dest(use_tls=False))  # no username → allowed (loud warning)
    assert d.use_tls is False


def test_credentials_over_cleartext_refused_even_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(ValueError, match="credentials"):
        EmailDestination(_dest(use_tls=False, username="svc", password="pw"))


async def test_cleartext_send_path_when_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    _install_fake(monkeypatch)
    d = EmailDestination(_dest(use_tls=False))
    await d.send("body")
    [smtp] = _FakeSMTP.instances
    assert smtp.started_tls is False  # no STARTTLS when use_tls=false


# --- #200 (ADR 0092): the PHI BODY over cleartext SMTP, on the shared posture gradient ---------------
#
# The credential got a hard refusal while the (PHI) message body got only a logger.warning, and the
# whole decision keyed on the RAW insecure_tls_allowed() while every sibling connector routes it
# through the CLAMPED weakened_tls_escape_permitted_here(). Both are fixed: the escape can no longer
# cross an ENFORCING production-PHI cleartext hop, and the body is decided by the same
# InsecureHopGuard gradient raw-TCP / X12 / plaintext-DIMSE / anonymous-FTP consume.

PROD_PHI = HopPosture(is_phi=True, enforcing=True)
STAGING_PHI = HopPosture(is_phi=True, enforcing=False)  # PHI, dial at warn
SYNTHETIC = HopPosture(is_phi=False, enforcing=True)  # not is_phi → always ALLOW


def _cleartext_dest(
    *,
    host: str = "smtp.partner.org",
    attested: bool = False,
    reason: str | None = None,
    accepted: bool = False,
    accept_reason: str | None = None,
) -> Destination:
    return Destination(
        name="OB_EMAIL",
        type=ConnectorType.EMAIL,
        settings={
            "host": host,
            "sender": "engine@hospital.org",
            "recipients": ["clinician@partner.org"],
            "use_tls": False,
        },
        tls_hop_attested=attested,
        tls_hop_attested_reason=reason,
        cleartext_accepted=accepted,
        cleartext_reason=accept_reason,
    )


def test_prod_phi_cleartext_smtp_refused_even_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # THE headline fix: before this, the escape silenced the refusal and the PHI body was sent with a
    # warning. The clamped escape is inert under ENFORCE, so the hop is refused.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with active_hop_posture(PROD_PHI), pytest.raises(ValueError, match="cleartext"):
        EmailDestination(_cleartext_dest())


def test_prod_phi_cleartext_smtp_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with active_hop_posture(PROD_PHI), pytest.raises(ValueError, match="cleartext"):
        EmailDestination(_cleartext_dest())


def test_prod_phi_cleartext_smtp_allowed_when_hop_attested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The acknowledged, reasoned, audited opt-out — the ONLY way across an enforcing PHI cleartext hop.
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with active_hop_posture(PROD_PHI):
        d = EmailDestination(_cleartext_dest(attested=True, reason="carrier-grade private circuit"))
    assert d.use_tls is False


def test_staging_phi_cleartext_smtp_warns_and_crosses(monkeypatch: pytest.MonkeyPatch) -> None:
    # Non-enforcing PHI: the gradient WARNs rather than refusing, so a lab lane still runs.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with active_hop_posture(STAGING_PHI):
        d = EmailDestination(_cleartext_dest())
    assert d._hop_guard is not None


def test_cleartext_smtp_crosses_on_a_declaration(monkeypatch: pytest.MonkeyPatch) -> None:
    """ADR 0153: the declaration crosses an ENFORCING cleartext SMTP hop; the data label no longer does.

    It also has to satisfy EmailDestination's own pre-gate, which fires BEFORE the shared authority — a
    declaration that passed the authority but not the pre-gate would be dead config on SMTP alone."""
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with active_hop_posture(PROD_PHI):
        d = EmailDestination(
            _cleartext_dest(accepted=True, accept_reason="legacy relay has no STARTTLS")
        )
    assert d.use_tls is False
    assert d._hop_guard is not None  # crossed under a WARN, still guarded at send


def test_synthetic_cleartext_smtp_now_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # SYNTHETIC here is ENFORCING. Pre-0153 the label alone allowed this hop; now only `enforcing`
    # reaches the authority, so it refuses — and the escape cannot rescue it either (decision 5).
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with active_hop_posture(SYNTHETIC), pytest.raises(ValueError, match="cleartext"):
        EmailDestination(_cleartext_dest())


def test_unstamped_posture_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    # Built outside the construction gate (a live serve build after the pre-flight, or an embedding):
    # the guard no-ops, so no existing lane that already carried the escape breaks.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    d = EmailDestination(_cleartext_dest())
    assert d.use_tls is False


def test_tls_enabled_captures_no_cleartext_guard() -> None:
    # The STARTTLS default is not a cleartext hop — no guard, so the gradient never fires on it.
    assert EmailDestination(_dest())._hop_guard is None


async def test_send_time_backstop_refuses_at_the_byte_crossing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Defense in depth: a reload that flips the instance to enforcing production-PHI must not put the
    # body on the wire just because construction happened under a laxer posture.
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    _install_fake(monkeypatch)
    # Constructed under a declaration (ADR 0153) rather than the retired synthetic carve-out.
    with active_hop_posture(SYNTHETIC):
        d = EmailDestination(
            _cleartext_dest(accepted=True, accept_reason="legacy relay has no STARTTLS")
        )
    assert d._hop_guard is not None
    d._hop_guard = InsecureHopGuard(
        host=d.host,
        port=d.port,
        cell="EMAIL outbound",
        description="cleartext SMTP egress (use_tls=false)",
        attested=False,
        attested_reason=None,
        posture=PROD_PHI,
    )
    with pytest.raises(InsecureHopRefused):
        await d.send("PID|1|patient")
    assert _FakeSMTP.instances == []  # never dialed — refused before any socket


# --- DeliveryError mapping (the staged queue retries) -----------------------------------------------


@pytest.mark.parametrize("fail_at", ["connect", "starttls", "login", "send"])
async def test_send_failure_raises_delivery_error(
    monkeypatch: pytest.MonkeyPatch, fail_at: str
) -> None:
    _install_fake(monkeypatch, fail_at=fail_at)
    d = EmailDestination(_dest(username="svc", password="pw"))
    with pytest.raises(DeliveryError):
        await d.send("body")


async def test_delivery_error_text_is_phi_and_secret_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake(monkeypatch, fail_at="send")
    d = EmailDestination(_dest(username="svc", password="s3cret"))
    with pytest.raises(DeliveryError) as ei:
        await d.send("PID|1|SENSITIVE-PHI-BODY")
    text = str(ei.value)
    assert "SENSITIVE-PHI-BODY" not in text  # never the body
    assert "s3cret" not in text  # never the password
    assert "clinician@partner.org" not in text  # never a recipient


# --- test_connection: connect + EHLO + NOOP only, no MAIL FROM / DATA --------------------------------


async def test_test_connection_probes_without_sending(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake(monkeypatch)
    d = EmailDestination(_dest(username="svc", password="pw"))
    await d.test_connection()
    [smtp] = _FakeSMTP.instances
    assert smtp.did_ehlo is True
    assert smtp.did_noop is True
    assert smtp.logged_in == ("svc", "pw")  # auth surfaced
    assert smtp.sent == []  # no MAIL FROM / DATA — no real email sent


async def test_test_connection_failure_raises_delivery_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake(monkeypatch, fail_at="connect")
    d = EmailDestination(_dest())
    with pytest.raises(DeliveryError):
        await d.test_connection()


# --- [egress].allowed_smtp deny-by-default / host gate ----------------------------------------------


def _email_dest(host: str, port: int = 587) -> Destination:
    return Destination(
        name="OB_EMAIL",
        type=ConnectorType.EMAIL,
        settings={"host": host, "sender": "s@x.org", "recipients": ["r@y.org"], "port": port},
    )


def test_allowed_smtp_empty_is_unrestricted() -> None:
    check_egress_allowed(_email_dest("any.smtp.example"), EgressSettings())  # no raise


def test_allowed_smtp_host_and_port_gate() -> None:
    e = EgressSettings(allowed_smtp=["smtp.partner.org:587", "10.0.0.9"])
    check_egress_allowed(_email_dest("smtp.partner.org", 587), e)  # exact host:port
    check_egress_allowed(_email_dest("10.0.0.9", 2525), e)  # host-only entry → any port
    with pytest.raises(Exception, match="allowed_smtp"):
        check_egress_allowed(_email_dest("evil.relay.example", 587), e)  # wrong host
    with pytest.raises(Exception, match="allowed_smtp"):
        check_egress_allowed(_email_dest("smtp.partner.org", 2525), e)  # wrong port


def test_allowed_smtp_deny_by_default_refuses_empty() -> None:
    # deny-by-default: an EMAIL destination with no allowed_smtp list is refused (fail-closed), exactly
    # like every other egress type.
    e = EgressSettings(deny_by_default=True)
    with pytest.raises(Exception, match="deny_by_default"):
        check_egress_allowed(_email_dest("smtp.partner.org"), e)


def test_allowed_smtp_deny_by_default_honours_set_list() -> None:
    e = EgressSettings(deny_by_default=True, allowed_smtp=["smtp.partner.org:587"])
    check_egress_allowed(_email_dest("smtp.partner.org", 587), e)  # listed → allowed
    with pytest.raises(Exception, match="allowed_smtp"):
        check_egress_allowed(_email_dest("evil.relay.example", 587), e)


# --- registry + factory surface ---------------------------------------------------------------------


def test_registered_in_destination_registry() -> None:
    from messagefoundry.transports.base import build_destination

    conn = build_destination(_dest())
    assert isinstance(conn, EmailDestination)


def test_email_and_smtp_factories_exported() -> None:
    import messagefoundry as mf
    from messagefoundry import SMTP, Email

    assert Email is SMTP  # the alias
    spec = mf.Email(host="smtp.partner.org", sender="s@x.org", recipients=["r@y.org"], subject="hi")
    assert spec.type is ConnectorType.EMAIL
    assert spec.settings["host"] == "smtp.partner.org"
    assert spec.settings["port"] == 587  # STARTTLS submission default
    assert "Email" in mf.__all__ and "SMTP" in mf.__all__


# --- #323: the TLS hop actually VERIFIES ------------------------------------------------------------
#
# These are the regression fence for #323. Before it, both arms called smtplib with NO context, and
# smtplib's fallback is ssl._create_stdlib_context — which IS ssl._create_unverified_context
# (CERT_NONE / check_hostname=False). So `use_tls=True` bought encryption without authentication and
# every certificate was accepted. Asserting "STARTTLS was issued" (the pre-existing tests) could never
# catch that: it was issued, over an unverified session. These assert the CONTEXT, which is the only
# thing that distinguishes the fixed state from the broken one. Run them against the pre-fix connector
# and they go red on `tls_context is None`.


async def test_starttls_gets_a_verifying_context(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake(monkeypatch)
    await EmailDestination(_dest()).send("body")
    [smtp] = _FakeSMTP.instances
    assert smtp.started_tls is True
    ctx = smtp.tls_context
    assert ctx is not None, "starttls() was called with no context — smtplib would not verify"
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version is ssl.TLSVersion.TLSv1_2


async def test_implicit_tls_465_gets_a_verifying_context(monkeypatch: pytest.MonkeyPatch) -> None:
    # The 465 arm builds SMTP_SSL, a different smtplib entry point with its own unverified default.
    _install_fake(monkeypatch)
    await EmailDestination(_dest(port=465)).send("body")
    [smtp] = _FakeSMTP.instances
    assert smtp.started_tls is False  # implicit TLS — no explicit STARTTLS
    ctx = smtp.tls_context
    assert ctx is not None, "SMTP_SSL was constructed with no context — it would not verify"
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_tls_verify_false_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    with pytest.raises(ValueError, match="tls_verify=false"):
        EmailDestination(_dest(tls_verify=False))


def test_tls_verify_false_refuses_credentials_even_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An unverified session is as bad as cleartext for an AUTH exchange: an on-path attacker
    # presenting any certificate captures it. Mirrors the use_tls=false credential refusal.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(ValueError, match="UNVERIFIED"):
        EmailDestination(_dest(tls_verify=False, username="svc", password="pw"))


async def test_tls_verify_false_with_escape_builds_an_unverified_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    _install_fake(monkeypatch)
    await EmailDestination(_dest(tls_verify=False)).send("body")
    [smtp] = _FakeSMTP.instances
    ctx = smtp.tls_context
    assert ctx is not None  # still a context — just a deliberately non-verifying one
    assert ctx.verify_mode is ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_tls_verify_false_refused_on_enforcing_phi_even_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The clamp (#200, ADR 0092 decision 2): the blunt process-wide escape must NOT silence a
    # verify-off PHI hop on an enforcing instance. This is why the arm reads
    # weakened_tls_escape_permitted_here() and not the raw insecure_tls_allowed().
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with (
        active_hop_posture(HopPosture(enforcing=True, is_phi=True)),
        pytest.raises(ValueError, match="tls_verify=false"),
    ):
        EmailDestination(_dest(tls_verify=False))


async def test_tls_ca_file_pins_that_ca_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    # A per-connection CA wins verbatim, and pins to ONLY that CA — no system bundle (ADR 0093
    # precedence #1). This is the supported route for a private-CA relay, and the reason
    # tls_verify=false should almost never be needed.
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Relay CA")])
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
    ca = tmp_path / "relay-ca.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    _install_fake(monkeypatch)
    await EmailDestination(_dest(tls_ca_file=str(ca))).send("body")
    [smtp] = _FakeSMTP.instances
    ctx = smtp.tls_context
    assert ctx is not None
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    loaded = ctx.get_ca_certs()
    assert len(loaded) == 1, (
        "a per-connection CA must pin to ONLY that CA, not augment system roots"
    )
    assert dict(x[0] for x in loaded[0]["subject"])["commonName"] == "Test Relay CA"


def test_tls_ca_file_that_does_not_exist_fails_loudly(tmp_path: Any) -> None:
    # Silently falling back to system roots on an unreadable CA would be the worst outcome: the
    # operator believes they pinned, and did not.
    with pytest.raises((FileNotFoundError, ssl.SSLError, OSError)):
        EmailDestination(_dest(tls_ca_file=str(tmp_path / "nope.pem")))


async def test_a_server_offering_no_approved_mechanism_is_a_delivery_error_not_our_bug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A POLICY refusal must reach the worker as DeliveryError (BACKLOG #1171).

    smtp_login_approved raises InsecureHopRefused, which subclasses ValueError and therefore escapes
    this connector's ``except smtplib.SMTPException`` arms. Unconverted it lands in the delivery
    worker's catch-all, which is documented as "Internal/code error (our bug, not the partner)" and
    dead-letters the row -- sending an operator to read our source over a relay that simply offers no
    approved AUTH mechanism.

    WITHOUT THE CONVERSION this raises InsecureHopRefused and the test fails on the raises() type.
    """
    _install_fake(monkeypatch)
    # The relay advertises ONLY the disallowed mechanism, which is the reachable real-world case:
    # an older server offering CRAM-MD5 alone.
    monkeypatch.setattr(_FakeSMTP, "AUTH_ADVERTISED", {"auth": "CRAM-MD5"})
    d = EmailDestination(_dest(username="svc", password="s3cret"))
    with pytest.raises(DeliveryError) as ei:
        await d.send("body")
    # The refusal text is carried whole, not reduced to a type name: it names the approved set, which
    # is the one thing that tells an operator what to change. It is config, never message content.
    assert "approved" in str(ei.value)
    [smtp] = _FakeSMTP.instances
    assert smtp.logged_in is None, (
        "a credential was sent to a server offering no approved mechanism"
    )


async def test_an_approved_mechanism_still_authenticates(monkeypatch: pytest.MonkeyPatch) -> None:
    """POSITIVE CONTROL for the test above: the refusal is about the OFFERED set, not about auth.

    A guard that refused every authenticated send would satisfy the previous test perfectly.
    """
    _install_fake(monkeypatch)
    monkeypatch.setattr(_FakeSMTP, "AUTH_ADVERTISED", {"auth": "CRAM-MD5 LOGIN"})
    d = EmailDestination(_dest(username="svc", password="s3cret"))
    await d.send("body")
    [smtp] = _FakeSMTP.instances
    assert smtp.auth_mechanism == "LOGIN", "should fall through CRAM-MD5 to the approved LOGIN"
