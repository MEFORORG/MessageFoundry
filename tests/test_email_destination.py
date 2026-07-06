# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SMTP-send outbound EMAIL destination (ADR 0029): message build, STARTTLS path, the cleartext
refusals, DeliveryError on failure, and the connect/EHLO/NOOP test_connection probe — all against an
in-process fake SMTP (no real server is ever contacted)."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Any

import pytest

import messagefoundry.transports.email as email_mod
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings, INSECURE_TLS_ESCAPE_ENV
from messagefoundry.pipeline.wiring_runner import check_egress_allowed
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.email import EmailDestination


class _FakeSMTP:
    """A drop-in for ``smtplib.SMTP`` / ``SMTP_SSL`` that records the exchange instead of dialing a
    server. ``fail_at`` makes the named step raise so the DeliveryError mapping can be exercised."""

    instances: list["_FakeSMTP"] = []

    def __init__(
        self, host: str, port: int, timeout: float = 0.0, fail_at: str | None = None
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.fail_at = fail_at
        self.started_tls = False
        self.logged_in: tuple[str, str] | None = None
        self.sent: list[EmailMessage] = []
        self.did_ehlo = False
        self.did_noop = False
        _FakeSMTP.instances.append(self)
        if fail_at == "connect":
            raise OSError("connection refused")

    def __enter__(self) -> "_FakeSMTP":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def starttls(self) -> None:
        if self.fail_at == "starttls":
            raise smtplib.SMTPException("STARTTLS not supported")
        self.started_tls = True

    def ehlo_or_helo_if_needed(self) -> None:
        self.did_ehlo = True

    def login(self, user: str, password: str) -> None:
        if self.fail_at == "login":
            raise smtplib.SMTPAuthenticationError(535, b"bad creds")
        self.logged_in = (user, password)

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

    def factory(host: str, port: int, timeout: float = 0.0) -> _FakeSMTP:
        return _FakeSMTP(host, port, timeout, fail_at=fail_at)

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

    def ssl_factory(host: str, port: int, timeout: float = 0.0) -> _FakeSMTP:
        captured["which"] = "SMTP_SSL"
        return _FakeSMTP(host, port, timeout)

    def plain_factory(host: str, port: int, timeout: float = 0.0) -> _FakeSMTP:
        captured["which"] = "SMTP"
        return _FakeSMTP(host, port, timeout)

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
    from messagefoundry import Email, SMTP

    assert Email is SMTP  # the alias
    spec = mf.Email(host="smtp.partner.org", sender="s@x.org", recipients=["r@y.org"], subject="hi")
    assert spec.type is ConnectorType.EMAIL
    assert spec.settings["host"] == "smtp.partner.org"
    assert spec.settings["port"] == 587  # STARTTLS submission default
    assert "Email" in mf.__all__ and "SMTP" in mf.__all__
