# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SMTP-send outbound EMAIL destination (ADR 0029): message build, STARTTLS path, the cleartext
refusals, DeliveryError on failure, and the connect/EHLO/NOOP test_connection probe — all against an
in-process fake SMTP (no real server is ever contacted)."""

from __future__ import annotations

import email.policy
import smtplib
import socket
import ssl
import threading
from collections.abc import Iterator
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, EgressSettings, load_settings
from messagefoundry.config.tls_policy import (
    HopPosture,
    InsecureHopRefused,
    active_hop_posture,
)
from messagefoundry.config.wiring import WiringError
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.egress import check_egress_allowed
from messagefoundry.transports.email import EmailDestination, envelope_address_problem
from messagefoundry.transports.mllp import InsecureHopGuard
from tests._egress_policy import permitting


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

    # smtplib is the module object email.py calls, so the patch lands where it is read.
    monkeypatch.setattr(smtplib, "SMTP", factory)
    monkeypatch.setattr(smtplib, "SMTP_SSL", factory)
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
    # The RCPT set is the list the [egress] recipient-domain check reads, passed explicitly, so a
    # header added later cannot widen it (vault BACKLOG #2616).
    assert smtp.to_addrs == ["a@p.org", "b@p.org"]


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
    monkeypatch.setattr(smtplib, "SMTP_SSL", ssl_factory)
    monkeypatch.setattr(smtplib, "SMTP", plain_factory)
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
    escape_at_warn: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    d = EmailDestination(_dest(use_tls=False))  # no username → allowed (loud warning)
    assert d.use_tls is False


def test_credentials_over_cleartext_refused_even_with_escape(escape_at_warn: None) -> None:
    # On a warn posture the escape passes the cleartext gate, so the credential arm is what refuses.
    with pytest.raises(ValueError, match="authentication credentials over cleartext"):
        EmailDestination(_dest(use_tls=False, username="svc", password="pw"))


async def test_cleartext_send_path_when_escaped(
    escape_at_warn: None, monkeypatch: pytest.MonkeyPatch
) -> None:
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

PROD_PHI = HopPosture(enforcing=True)
STAGING_PHI = HopPosture(enforcing=False)  # PHI, dial at warn
SYNTHETIC = HopPosture(enforcing=True)  # not is_phi → always ALLOW


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


def test_unstamped_posture_refuses_the_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    # Built outside the construction gate with no posture: the escape alone no longer crosses
    # (vault BACKLOG #2354). It used to, byte-identical to pre-#200. Live serve builds are stamped.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with active_hop_posture(None), pytest.raises(ValueError, match="cleartext SMTP"):
        EmailDestination(_cleartext_dest())


def test_warn_posture_still_honours_the_escape(escape_at_warn: None) -> None:
    # The control arm for the test above.
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


#: The recipient domain every host-gate test below lists, so those tests exercise the host arm alone.
_RCPT_DOMAINS = ["y.org"]


def _email_dest(
    host: str, port: int = 587, recipients: list[str] | str | None = None
) -> Destination:
    return Destination(
        name="OB_EMAIL",
        type=ConnectorType.EMAIL,
        settings={
            "host": host,
            "sender": "s@x.org",
            "recipients": ["r@y.org"] if recipients is None else recipients,
            "port": port,
        },
    )


def test_allowed_smtp_empty_leaves_the_relay_host_unrestricted() -> None:
    # Under the audited opt-out only: the model default denies an empty list (vault BACKLOG #2605).
    e = EgressSettings(deny_by_default=False, allowed_recipient_domains=_RCPT_DOMAINS)
    check_egress_allowed(_email_dest("any.smtp.example"), e)  # no raise


def test_allowed_smtp_host_and_port_gate() -> None:
    e = EgressSettings(
        allowed_smtp=["smtp.partner.org:587", "10.0.0.9"], allowed_recipient_domains=_RCPT_DOMAINS
    )
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
    with pytest.raises(Exception, match="block_unlisted_outbound"):
        check_egress_allowed(_email_dest("smtp.partner.org"), e)


def test_allowed_smtp_deny_by_default_honours_set_list() -> None:
    e = EgressSettings(
        deny_by_default=True,
        allowed_smtp=["smtp.partner.org:587"],
        allowed_recipient_domains=_RCPT_DOMAINS,
    )
    check_egress_allowed(_email_dest("smtp.partner.org", 587), e)  # listed → allowed
    with pytest.raises(Exception, match="allowed_smtp"):
        check_egress_allowed(_email_dest("evil.relay.example", 587), e)


# --- [egress].allowed_recipient_domains (vault BACKLOG #2616) ---------------------------------------


def _relay_listed(domains: list[str]) -> EgressSettings:
    """The relay host is listed, so only the recipient-domain arm can refuse."""
    return EgressSettings(allowed_smtp=["smtp.hospital.example"], allowed_recipient_domains=domains)


@pytest.mark.parametrize(
    "recipients",
    [
        ["a@hospital.example"],
        ["Ops <ops@HOSPITAL.example>"],  # display name, and the domain match ignores case
        ["a@hospital.example", "", "b@hospital.example"],  # a blank entry is not a recipient
    ],
)
def test_listed_recipient_domain_passes(recipients: list[str]) -> None:
    e = _relay_listed(["Hospital.Example"])
    check_egress_allowed(_email_dest("smtp.hospital.example", recipients=recipients), e)


@pytest.mark.parametrize(
    "recipients",
    [
        ["a@partner.example"],  # unlisted domain
        ["a@hospital.example", "b@partner.example"],  # every recipient must be listed
        # The transport joins the entries into one To: header, so every address inside one entry
        # is checked, whether the setting is a list or a lone string.
        ["a@hospital.example, b@partner.example"],
        "a@hospital.example, b@partner.example",
        ["a@mail.hospital.example"],  # a subdomain is a different domain
        ["a@nothospital.example"],  # a listed domain as a suffix does not match
        ["no-at-sign"],  # not a readable address
        ["a@"],
        ['""@hospital.example'],  # listed domain, empty local part
        # A routing character in the local part: the listed domain would not be the last hop.
        ["a%partner.example@hospital.example"],
        ["partner.example!a@hospital.example"],
        ['"a@partner.example"@hospital.example'],
        ["a@höspital.example"],  # non-ASCII domain: only the ASCII xn-- form can be listed
        ["a@Kospital.example"],  # a Unicode case fold must not reach an ASCII entry
        ["a|b@hospital.example"],  # a delivery-pipe character
        ["a/b@hospital.example"],  # a delivery-file character
        ["-a@hospital.example"],  # a leading hyphen reads as an option to some delivery programs
        ["a=b@hospital.example"],  # = and ? are refused, so no encoded word can form
        ["a?b@hospital.example"],
        [' :%.bK".b'],  # malformed enough that the stdlib header parser once raised on it
        ["x" * 65 + "@hospital.example"],  # longer than SMTP allows for a local part
    ],
)
def test_unlisted_or_unreadable_recipient_is_refused(recipients: list[str] | str) -> None:
    e = _relay_listed(["hospital.example"])
    with pytest.raises(WiringError, match="allowed_recipient_domains"):
        check_egress_allowed(_email_dest("smtp.hospital.example", recipients=recipients), e)


@pytest.mark.parametrize(
    "egress",
    [EgressSettings(deny_by_default=False), EgressSettings(allowed_smtp=["smtp.hospital.example"])],
    ids=["nothing-listed", "relay-listed"],
)
def test_recipient_domains_empty_refuses_every_email_destination(egress: EgressSettings) -> None:
    # Deny-by-default on its own terms: no list means no recipient is permitted, whatever the host
    # lists and whatever [security].block_unlisted_outbound says.
    with pytest.raises(WiringError, match="allowed_recipient_domains"):
        check_egress_allowed(
            _email_dest("smtp.hospital.example", recipients=["a@hospital.example"]), egress
        )


def _address_of_length(local_len: int, total_len: int) -> str:
    """A plain address with a local part of ``local_len`` octets and ``total_len`` overall, ending
    in ``hospital.example``. Long domains use three 63-octet labels plus one sized to fit."""
    tail = "hospital.example"
    if total_len == local_len + 1 + len(tail):
        address = "a" * local_len + "@" + tail
    else:
        fixed = ".".join(["x" * 63] * 3)
        last = total_len - local_len - 1 - len(fixed) - 1 - 1 - len(tail)
        address = "a" * local_len + "@" + fixed + "." + "x" * last + "." + tail
    assert len(address) == total_len, (len(address), total_len)
    return address


@pytest.mark.parametrize(
    ("local_len", "total_len", "allowed"),
    [
        (64, 64 + 1 + len("hospital.example"), True),
        (65, 65 + 1 + len("hospital.example"), False),
        (20, 254, True),
        (20, 255, False),
    ],
    ids=["local-64", "local-65", "address-254", "address-255"],
)
def test_the_rfc_5321_size_limits_are_the_boundary(
    local_len: int, total_len: int, allowed: bool
) -> None:
    address = _address_of_length(local_len, total_len)
    domain = address.rpartition("@")[2]
    e = EgressSettings(allowed_smtp=["smtp.hospital.example"], allowed_recipient_domains=[domain])
    dest = _email_dest("smtp.hospital.example", recipients=[address])
    if allowed:
        check_egress_allowed(dest, e)
    else:
        with pytest.raises(WiringError, match="longer than SMTP allows"):
            check_egress_allowed(dest, e)


class _WireCapture:
    """A loopback SMTP listener that records each ``MAIL`` and ``RCPT`` command line exactly as it
    arrives, so a test reads the envelope the relay would act on rather than a list handed to a fake
    client."""

    def __init__(self) -> None:
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._sock.getsockname()[1]
        self.mail_lines: list[bytes] = []
        self.rcpt_lines: list[bytes] = []
        self.data: list[bytes] = []
        self.connections = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.connections += 1
            with conn, conn.makefile("rb") as reader:
                conn.sendall(b"220 capture\r\n")
                for raw in reader:
                    line = raw.rstrip(b"\r\n")
                    verb = line[:4].upper()
                    if verb == b"MAIL":
                        self.mail_lines.append(line)
                    if verb == b"RCPT":
                        self.rcpt_lines.append(line)
                    if verb == b"DATA":
                        conn.sendall(b"354 go\r\n")
                        for body in reader:
                            if body.rstrip(b"\r\n") == b".":
                                break
                            self.data.append(body)
                    elif verb == b"QUIT":
                        conn.sendall(b"221 bye\r\n")
                        break
                    conn.sendall(b"250 ok\r\n")

    def close(self) -> None:
        self._sock.close()


@pytest.fixture
def wire() -> Iterator[_WireCapture]:
    capture = _WireCapture()
    try:
        yield capture
    finally:
        capture.close()


def _wire_dest(
    port: int, recipients: list[str], sender: str = "engine@hospital.example"
) -> Destination:
    return Destination(
        name="OB_EMAIL",
        type=ConnectorType.EMAIL,
        settings={
            "host": "127.0.0.1",
            "port": port,
            "sender": sender,
            "recipients": recipients,
            "use_tls": False,
            "timeout_seconds": 5.0,
        },
        cleartext_accepted=True,
        cleartext_reason="loopback capture listener in a unit test",
    )


def _wire_egress(port: int) -> EgressSettings:
    return EgressSettings(
        allowed_smtp=[f"127.0.0.1:{port}"], allowed_recipient_domains=["hospital.example"]
    )


async def test_the_rcpt_line_on_the_wire_names_exactly_the_checked_address(
    wire: _WireCapture,
) -> None:
    dest = _wire_dest(wire.port, ["Ops <a@hospital.example>", "b.c+d@HOSPITAL.example"])
    check_egress_allowed(dest, _wire_egress(wire.port))
    await EmailDestination(dest).send("PID|1|synthetic")
    assert [line.upper() for line in wire.rcpt_lines] == [
        b"RCPT TO:<A@HOSPITAL.EXAMPLE>",
        b"RCPT TO:<B.C+D@HOSPITAL.EXAMPLE>",
    ]
    # The To: header is built from the same checked list, so the display name does not reach it.
    [to_line] = [line for line in wire.data if line.lower().startswith(b"to:")]
    assert to_line.rstrip(b"\r\n") == b"To: a@hospital.example, b.c+d@HOSPITAL.example"


def _quote() -> str:
    return chr(34)


#: Recipient values whose parse does not read back as the plain address it seems to name. Built from
#: parts so no single literal reads as a recipe.
_NON_ROUND_TRIP = [
    _quote() + "<" + "relaylocal" + ">" + " " + "ORCPT" + "=" + "rfc822;x" + "@hospital.example",
    _quote() + "relaylocal" + ">" + "@hospital.example",
]


def _encoded_word(charset: str, kind: str, text: str) -> str:
    return "=" + "?" + charset + "?" + kind + "?" + text + "?" + "="


def _b64_word(text: str) -> str:
    import base64

    return _encoded_word("utf-8", "b", base64.b64encode(text.encode()).decode())


#: Local parts that a decoding parse would turn into something other than what was checked: an
#: encoded word nested in an encoded word that decodes to an address list, and one that decodes to a
#: line break. Built from parts.
_INNER_LIST = _encoded_word("utf-8", "q", "other=40partner.example=2C_x")
_ENCODED_LOCAL = [
    _b64_word(_INNER_LIST) + "@hospital.example",
    _b64_word("a" + chr(13) + chr(10) + "b") + "@hospital.example",
]


@pytest.mark.parametrize("value", _ENCODED_LOCAL, ids=["nested-encoded-list", "encoded-line-break"])
async def test_an_encoded_word_local_part_is_refused_at_the_gate(
    wire: _WireCapture, value: str
) -> None:
    dest = _wire_dest(wire.port, [value])
    with pytest.raises(WiringError, match="allowed_recipient_domains"):
        check_egress_allowed(dest, _wire_egress(wire.port))
    with pytest.raises(ValueError, match="recipient"):
        EmailDestination(dest)
    assert wire.connections == 0
    assert wire.rcpt_lines == []


async def test_the_to_line_names_exactly_the_checked_addresses(wire: _WireCapture) -> None:
    # Every character the allowlist admits, so a decoding or quoting step would show here.
    local = "a#b$c&d'e*f+g-h^i_j`k{l}m~n.o"
    dest = _wire_dest(wire.port, [local + "@hospital.example", "plain@hospital.example"])
    check_egress_allowed(dest, _wire_egress(wire.port))
    await EmailDestination(dest).send("PID|1|synthetic")
    assert [line.upper() for line in wire.rcpt_lines] == [
        ("RCPT TO:<" + local + "@hospital.example>").upper().encode(),
        b"RCPT TO:<PLAIN@HOSPITAL.EXAMPLE>",
    ]
    [to_line] = [line for line in wire.data if line.lower().startswith(b"to:")]
    expected = "To: " + local + "@hospital.example, plain@hospital.example"
    assert to_line.rstrip(b"\r\n") == expected.encode()


@pytest.mark.parametrize("field", ["recipients", "sender"])
def test_a_header_that_parses_differently_is_refused_at_construction(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    # Simulates a later widening of the local-part allowlist: with the address rule switched off,
    # an encoded-word local part reaches the To: or From: header, whose parse would decode it. The
    # construction-time comparison must refuse it, so the allowlist is not the only control.
    import messagefoundry.transports.email as email_mod

    monkeypatch.setattr(email_mod, "envelope_address_problem", lambda _address: None)
    dest = _wire_dest(2525, ["a@hospital.example"])
    dest.settings[field] = [_ENCODED_LOCAL[0]] if field == "recipients" else _ENCODED_LOCAL[0]
    with pytest.raises(ValueError, match="does not match the checked " + field):
        EmailDestination(dest)


@pytest.mark.parametrize("field", ["subject", "sender"])
@pytest.mark.parametrize("separator", [13, 10, 0, 0x7F, 0x85, 0x2028, 0x2029])
def test_a_control_character_in_a_header_setting_is_refused_at_load(
    field: str, separator: int
) -> None:
    # Refused at construction, not dead-lettered as an internal error at every send. Covers every
    # line separator policy.default refuses, the Unicode ones included.
    dest = _wire_dest(2525, ["a@hospital.example"])
    dest.settings[field] = "e" + chr(separator) + "x@hospital.example"
    with pytest.raises(ValueError, match="control character"):
        EmailDestination(dest)


@pytest.mark.parametrize("code", [0xD800, 0xDC80])
def test_a_lone_surrogate_in_the_subject_is_refused_at_load(code: int) -> None:
    # It passes the control-character check. Before vault BACKLOG #2842 a U+D800 subject then raised
    # UnicodeEncodeError in _build_message at every send, which _send does not convert, and a U+DC80
    # one went out garbled. The refusal names the setting and never quotes its value.
    dest = _wire_dest(2525, ["a@hospital.example"])
    subject = f"Referral {chr(code)} note"
    dest.settings["subject"] = subject
    with pytest.raises(ValueError, match="'subject' holds a lone surrogate") as caught:
        EmailDestination(dest)
    assert subject not in str(caught.value)


def test_a_non_ascii_subject_that_can_be_encoded_is_written_as_utf8() -> None:
    # The control for the test above: only the unencodable shape is refused. Serialized, because a
    # U+DC80 subject also builds and reads back equal, and goes wrong only when written.
    dest = _wire_dest(2525, ["a@hospital.example"])
    dest.settings["subject"] = "Référence – 患者"
    msg = EmailDestination(dest)._build_message("PID|1|synthetic")
    wire = msg.as_bytes(policy=email.policy.SMTP)
    assert b"Subject: =?utf-8?" in wire
    assert b"unknown-8bit" not in wire


@pytest.mark.parametrize("value", _NON_ROUND_TRIP, ids=["parameter-after-mailbox", "stray-angle"])
async def test_a_value_that_does_not_read_back_is_refused_before_any_rcpt(
    wire: _WireCapture, value: str
) -> None:
    dest = _wire_dest(wire.port, [value])
    with pytest.raises(WiringError, match="allowed_recipient_domains"):
        check_egress_allowed(dest, _wire_egress(wire.port))
    # Construction holds the same rule, so a build path that skipped the check sends nothing either.
    with pytest.raises(ValueError, match="recipient"):
        EmailDestination(dest)
    assert wire.connections == 0
    assert wire.rcpt_lines == []


async def test_the_mail_from_line_and_from_header_name_exactly_the_checked_sender(
    wire: _WireCapture,
) -> None:
    # Every character the allowlist admits, so a decoding or quoting step would show here.
    sender = _ALL_ATEXT_SENDER
    dest = _wire_dest(wire.port, ["a@hospital.example"], sender=sender)
    check_egress_allowed(dest, _wire_egress(wire.port))
    await EmailDestination(dest).send("PID|1|synthetic")
    assert wire.mail_lines == [("mail from:<" + sender + ">").encode()]
    [from_line] = [line for line in wire.data if line.lower().startswith(b"from:")]
    assert from_line.rstrip(b"\r\n") == ("From: " + sender).encode()


async def test_send_passes_the_checked_sender_as_the_envelope_sender(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # MAIL FROM comes from the checked setting, never from a parse of the From header, so a header
    # changed later cannot move it (vault BACKLOG #2841).
    _install_fake(monkeypatch)
    await EmailDestination(_dest()).send("PID|1|synthetic")
    [smtp] = _FakeSMTP.instances
    assert smtp.from_addr == "engine@hospital.org"


async def test_the_mail_from_line_does_not_follow_the_from_header(
    wire: _WireCapture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A plain sender reads the same either way, so change the header after it is built: MAIL FROM
    # must still be the checked setting, which it is only when passed explicitly.
    build = EmailDestination._build_message

    def changed_from(self: EmailDestination, payload: str) -> EmailMessage:
        msg = build(self, payload)
        msg.replace_header("From", "another@hospital.example")
        return msg

    monkeypatch.setattr(EmailDestination, "_build_message", changed_from)
    dest = _wire_dest(wire.port, ["a@hospital.example"])
    await EmailDestination(dest).send("PID|1|synthetic")
    assert wire.mail_lines == [b"mail from:<engine@hospital.example>"]


def _sender_shapes() -> dict[str, str]:
    """Sender values that are not one plain, checked address. Built from parts, so no literal reads
    as a recipe; the ids are neutral."""
    other = "other" + "@" + "partner.example"
    own = "engine" + "@" + "hospital.example"
    shapes = {
        "shape-a": _b64_word(other),
        "shape-b": _ENCODED_LOCAL[0],
        "shape-c": _b64_word("Ops") + " <" + own + ">",
        "shape-d": "grp" + ":" + " " + other + ";",
        "shape-e": "grp" + ":" + " " + own + ";",
        "shape-f": _quote() + own,
        "shape-g": _quote() + "engine" + "@" + _quote() + "@" + "hospital.example",
        "shape-h": own + ", " + other,
        "shape-i": "Ops <" + own + ">",
        # A non-ASCII sender would fail every send on a relay without SMTPUTF8 (vault BACKLOG #2842).
        "non-ascii-local": "zoë" + "@" + "hospital.example",
        "non-ascii-domain": "engine" + "@" + "höspital.example",
    }
    # Every line break policy.default refuses, the three Unicode ones included.
    for code in (13, 10, 0x85, 0x2028, 0x2029):
        shapes[f"break-{code:04x}"] = "engine" + chr(code) + "x@hospital.example"
    return shapes


#: Domains of hostname characters in a shape no mail domain takes, mapped to the words of the refusal.
#: Each passed the address rule before vault BACKLOG #2911, which tested the domain's characters
#: alone. The unit test below takes every shape; the shared tables take a few (_DOMAIN_ON_THE_WIRE).
_DOMAIN_SHAPES = {
    "domain-trailing-dot": ("a@example.org.", "empty label"),
    "domain-double-dot": ("a@example..org", "empty label"),
    "domain-leading-dot": ("a@.example.org", "empty label"),
    "domain-leading-hyphen": ("a@-mx.example.org", "hyphen"),
    "domain-trailing-hyphen": ("a@mx-.example.org", "hyphen"),
    "domain-long-label": ("a@" + "x" * 64 + ".example.org", "longer than 63"),
    "domain-dotted-quad": ("a@10.0.0.1", "start with a letter"),
    "domain-numeric-last-label": ("a@example.123", "start with a letter"),
    # inet_aton reads both as IPv4 addresses, so an all-digits test alone would pass them.
    "domain-hex-last-part": ("a@10.0.0.0x1", "start with a letter"),
    "domain-hex-whole": ("a@0x7f000001", "start with a letter"),
}

#: Plain addresses the domain rule must still pass: a hyphen inside a label, digits in a label that
#: is not the last, a 63-character label, and an xn-- label, whose hyphens sit inside it.
_DOMAIN_CONTROLS = [
    "a@example.org",
    "a@mail-relay.example.net",
    "a@mx1.example.org",
    "a@10.mail.example.com",
    "a@" + "x" * 63 + ".example.org",
    "a@xn--bcher-kva.example.com",
]

#: The domain shapes the shared tables carry, so every cell that reads them (Email, Direct, alert
#: mail) is shown to refuse one before any connection. Every cell calls the same rule, so these
#: three show the call; the unit test proves each shape. The dotted quad is the decided one, and
#: the hex form is the one an all-digits test would have missed.
_DOMAIN_ON_THE_WIRE = {
    k: _DOMAIN_SHAPES[k][0]
    for k in ("domain-trailing-dot", "domain-dotted-quad", "domain-hex-last-part")
}

_SENDER_SHAPES = _sender_shapes() | _DOMAIN_ON_THE_WIRE


def _recipient_shapes() -> dict[str, str]:
    """Recipient values that are not one plain address, even with a display name or group dropped.
    The Direct and alert-mail tests share them (vault BACKLOG #2870). Built from parts; the ids are
    neutral."""
    other = "other" + "@" + "partner.example"
    shapes = {
        "shape-a": _b64_word(other),
        "shape-b": _ENCODED_LOCAL[0],
        "shape-c": _ENCODED_LOCAL[1],
        "shape-d": "undisclosed" + ":" + ";",
        "shape-e": other + " <" + "ok" + "@" + "hospital.example" + ">",
        "shape-f": _NON_ROUND_TRIP[0],
        "shape-g": _NON_ROUND_TRIP[1],
    }
    for code in (13, 10, 0x85, 0x2028, 0x2029):
        shapes[f"break-{code:04x}"] = "ok" + chr(code) + "x@hospital.example"
    return shapes


_RECIPIENT_SHAPES = _recipient_shapes() | _DOMAIN_ON_THE_WIRE

#: Both tables as (setting, value) pairs, for a test that refuses either half of the envelope.
_REFUSED_ADDRESSES = [("sender", v) for v in _SENDER_SHAPES.values()] + [
    ("recipients", v) for v in _RECIPIENT_SHAPES.values()
]
_REFUSED_ADDRESS_IDS = [f"sender-{k}" for k in _SENDER_SHAPES] + [
    f"recipient-{k}" for k in _RECIPIENT_SHAPES
]

#: Every character the local-part allowlist admits, so a decoding or quoting step would show.
_ALL_ATEXT_SENDER = "a#b$c&d'e*f+g-h^i_j`k{l}m~n.o@Hospital.example"

#: Recipient values that read as one plain address once a display name or group is dropped, mapped
#: to the one address RCPT TO and To: must carry. Shared like the shapes above; the ids are neutral.
_NORMALISED_RECIPIENTS = {
    "plain": ("b.c+d@HOSPITAL.example", "b.c+d@HOSPITAL.example"),
    "display-comma": (
        _quote() + "other@partner.example, x" + _quote() + " <ok@hospital.example>",
        "ok@hospital.example",
    ),
    "display-encoded": (
        _b64_word("other@partner.example, x") + " <ok@hospital.example>",
        "ok@hospital.example",
    ),
    "group-member": ("grp: ok@hospital.example;", "ok@hospital.example"),
}


@pytest.mark.parametrize("value", list(_RECIPIENT_SHAPES.values()), ids=list(_RECIPIENT_SHAPES))
async def test_a_recipient_that_is_not_one_plain_address_is_refused_before_any_connection(
    wire: _WireCapture, value: str
) -> None:
    # The line-break ids were accepted before vault BACKLOG #2870: the address parser drops a bare
    # CR or LF, so the RCPT line named an address with the break removed. The gate and construction
    # read the same list, so both refuse, and the gate names the control character.
    dest = _wire_dest(wire.port, [value])
    gate = "allowed_recipient_domains" if value.isprintable() else "a recipient holds a control"
    with pytest.raises(WiringError, match=gate):
        check_egress_allowed(dest, _wire_egress(wire.port))
    with pytest.raises(ValueError, match="recipient"):
        EmailDestination(dest)
    assert wire.connections == 0
    assert wire.rcpt_lines == []


@pytest.mark.parametrize("value", list(_SENDER_SHAPES.values()), ids=list(_SENDER_SHAPES))
async def test_a_sender_that_is_not_one_plain_address_is_refused_before_any_connection(
    wire: _WireCapture, value: str
) -> None:
    dest = _wire_dest(wire.port, ["a@hospital.example"], sender=value)
    with pytest.raises(ValueError, match="sender"):
        EmailDestination(dest)
    assert wire.connections == 0
    assert wire.mail_lines == []


# --- the domain's shape (vault BACKLOG #2911) --------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "why"), list(_DOMAIN_SHAPES.values()), ids=list(_DOMAIN_SHAPES)
)
def test_a_domain_of_host_characters_in_the_wrong_shape_is_refused(address: str, why: str) -> None:
    problem = envelope_address_problem(address)
    assert problem is not None and why in problem
    # The reason never quotes the address or its domain.
    assert address.rpartition("@")[2] not in problem


@pytest.mark.parametrize("address", _DOMAIN_CONTROLS)
def test_a_plain_domain_still_passes_the_address_rule(address: str) -> None:
    assert envelope_address_problem(address) is None


@pytest.mark.parametrize(
    ("key", "why"),
    [
        ("non-ascii-local", "the sender has a local part outside plain mailbox characters"),
        ("non-ascii-domain", "the sender has a non-ASCII domain"),
    ],
)
def test_a_non_ascii_sender_is_refused_at_construction_by_the_address_rule(
    key: str, why: str
) -> None:
    # vault BACKLOG #2842: pins WHICH rule refuses, the address rule applied to the sender in
    # 07e87db5e6 (PR 1978, #2841). The shared table carries both shapes to Direct and alert mail.
    dest = _wire_dest(2525, ["a@hospital.example"], sender=_SENDER_SHAPES[key])
    with pytest.raises(ValueError, match=why):
        EmailDestination(dest)


def test_a_trailing_dot_recipient_never_matched_the_recipient_domain_list() -> None:
    # The list drops a trailing dot from each entry at load, and the gate compares the recipient's
    # domain as written. So "example.org." never matched "example.org", and the gate refused it
    # before vault BACKLOG #2911 too, naming the domain as unlisted. It now refuses the shape first.
    e = _relay_listed(["example.org."])
    assert e.allowed_recipient_domains == ["example.org"]
    dest = _email_dest("smtp.hospital.example", recipients=["a@example.org."])
    with pytest.raises(WiringError, match="empty label") as refused:
        check_egress_allowed(dest, e)
    assert "allowed_recipient_domains" in str(refused.value)
    # Control: the same domain without the dot passes, so the refusal above is the dot.
    check_egress_allowed(_email_dest("smtp.hospital.example", recipients=["a@example.org"]), e)


def test_a_listed_hex_ip_domain_is_refused_by_the_shape_rule_at_the_gate() -> None:
    # The list's own validator accepts this entry, so before vault BACKLOG #2911 the recipient
    # matched it and passed the gate. Only the shape rule refuses it, which the reason pins.
    address = _DOMAIN_SHAPES["domain-hex-last-part"][0]
    e = _relay_listed([address.rpartition("@")[2]])
    dest = _email_dest("smtp.hospital.example", recipients=[address])
    with pytest.raises(WiringError, match="start with a letter"):
        check_egress_allowed(dest, e)


def test_recipient_domains_do_not_gate_direct() -> None:
    # DIRECT encrypts to one partner certificate, so the row scopes this list to EMAIL only.
    d = Destination(
        name="OB_DIRECT",
        type=ConnectorType.DIRECT,
        settings={"host": "hisp.example", "recipients": ["a@partner.example"], "port": 587},
    )
    check_egress_allowed(d, EgressSettings(deny_by_default=False))  # no raise


def test_recipient_domains_load_from_the_environment(tmp_path: Path) -> None:
    empty = tmp_path / "settings.toml"
    empty.write_text("", encoding="utf-8")
    environ = {"MEFOR_EGRESS_ALLOWED_RECIPIENT_DOMAINS": "Hospital.Example., lab.example"}
    loaded = load_settings(config_path=empty, environ=environ).egress
    assert loaded.allowed_recipient_domains == ["hospital.example", "lab.example"]


def test_a_gate_that_read_no_address_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    # The stdlib parser never yields an empty list today; the gate must not depend on that.
    import messagefoundry.transports.egress as egress_mod

    monkeypatch.setattr(egress_mod, "envelope_recipients", lambda _value: [])
    e = _relay_listed(["hospital.example"])
    with pytest.raises(WiringError, match="no recipient address"):
        check_egress_allowed(_email_dest("smtp.hospital.example"), e)


@pytest.mark.parametrize(
    "recipients",
    [[""], []],
)
def test_empty_recipients_are_refused_with_the_construction_message(
    recipients: list[str],
) -> None:
    # The operator is told to fix the connection, not the allowlist.
    e = _relay_listed(["hospital.example"])
    with pytest.raises(WiringError, match="Email destination.*'recipients'"):
        check_egress_allowed(_email_dest("smtp.hospital.example", recipients=recipients), e)


@pytest.mark.parametrize(
    "entry",
    [
        "a@hospital.example",
        "https://hospital.example",
        "hospital.example:25",
        "*.example",
        ".hospital.example",
        "[10.0.0.1]",
        "a.example,b.example",
        "hospital..example",
        "10.0.0.1",
        "-a-.example",
        "x" * 64 + ".example",
        ".",
    ],
)
def test_a_recipient_domain_that_can_never_match_is_refused_at_load(entry: str) -> None:
    with pytest.raises(ValidationError, match="bare domain"):
        EgressSettings(allowed_recipient_domains=[entry])


# --- registry + factory surface ---------------------------------------------------------------------


def test_registered_in_destination_registry() -> None:
    from messagefoundry.transports.base import build_destination

    conn = build_destination(_dest(), egress=permitting(_dest().settings))
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
    escape_at_warn: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An unverified session is as bad as cleartext for an AUTH exchange: an on-path attacker
    # presenting any certificate captures it. Mirrors the use_tls=false credential refusal.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with pytest.raises(ValueError, match="unverified TLS"):
        EmailDestination(_dest(tls_verify=False, username="svc", password="pw"))


def test_check_hostname_false_refuses_credentials() -> None:
    # BACKLOG #1314, the THIRD weakening axis. TLS is on and the chain IS verified, but the peer
    # NAME is not checked, so any certificate chaining to the configured anchor is accepted
    # regardless of who it was issued to. An AUTH exchange on that hop hands the credential to a
    # peer whose identity was never established -- the same loss the two arms above refuse.
    #
    # ABSOLUTE, and deliberately not keyed on any escape: in both existing arms the escape governs
    # the BODY posture and never the credential. A third arm keeps that split.
    with pytest.raises(ValueError, match="tls_check_hostname=false"):
        EmailDestination(_dest(tls_check_hostname=False, username="svc", password="pw"))


def test_check_hostname_false_without_credentials_still_constructs() -> None:
    # NEGATIVE CONTROL. The refusal must be keyed on the CREDENTIAL, not on the posture. A
    # name-unchecked hop carrying no username is this item's out of scope -- widening to it would
    # be the "must not widen the existing arms" failure the item names.
    EmailDestination(_dest(tls_check_hostname=False))


def test_credentials_over_a_fully_verified_hop_still_construct() -> None:
    # POSITIVE CONTROL. Proves the new gate can be PASSED, so the test above is not green merely
    # because EmailDestination refuses every credentialed construction.
    EmailDestination(_dest(username="svc", password="pw"))


async def test_tls_verify_false_with_escape_builds_an_unverified_context(
    escape_at_warn: None,
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
        active_hop_posture(HopPosture(enforcing=True)),
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
    subject = loaded[0]["subject"]
    assert isinstance(subject, tuple)
    assert {rdn[0][0]: rdn[0][1] for rdn in subject}["commonName"] == "Test Relay CA"


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
