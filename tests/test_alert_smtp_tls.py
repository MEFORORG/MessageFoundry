# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #323 layer 3 — the ``[alerts]`` SMTP hop AUTHENTICATES the relay.

``smtplib.starttls()`` takes no context by default and falls back to ``ssl._create_stdlib_context``,
which **is** ``ssl._create_unverified_context`` (``CERT_NONE``, ``check_hostname=False`` — measured on
CPython 3.14.6). So this hop was encrypted but unauthenticated: an on-path attacker presenting any
certificate read the alert bodies, every per-user security-event email, and the SMTP AUTH password.
Layers 1–2 (PR #132) fixed the EMAIL and DIRECT *connectors*; this is the third and last cell.

**Every assertion here is a NEGATIVE CONTROL.** Stash the production change and each one goes red — the
failure mode is named in each test's comment. That discipline is the point: the pre-existing
``sent["tls"] is True`` assertion in ``test_alert_sinks.py`` stayed green throughout the insecure
period, and the fake had *already* been widened to accept ``context=`` by PR #132 without the
production code passing one. A test that passes both ways proves nothing.
"""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.notifications import ACCOUNT_LOCKED, SecurityEvent
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AlertsSettings,
    AuthSettings,
    SecretRotationSettings,
    SecuritySettings,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.pipeline.alert_sinks import EmailTransport
from messagefoundry.pipeline.security_notify import SecurityEventNotifier


class _RecordingSMTP:
    """An SMTP fake that RECORDS the TLS context instead of discarding it."""

    captured: dict[str, Any] = {}

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        _RecordingSMTP.captured = {"host": host, "port": port, "context": None, "tls": False}

    def __enter__(self) -> _RecordingSMTP:
        return self

    def __exit__(self, *a: object) -> None:
        return None

    def starttls(self, context: ssl.SSLContext | None = None) -> None:
        _RecordingSMTP.captured["tls"] = True
        _RecordingSMTP.captured["context"] = context

    # BACKLOG #1171: production drives auth() directly, never login(). CRAM-MD5 is advertised
    # DELIBERATELY -- it is what a regression to login() would select, so a fake offering only
    # PLAIN/LOGIN could not tell a fixed cell from a broken one.
    esmtp_features = {"auth": "CRAM-MD5 PLAIN LOGIN"}
    user = ""
    password = ""

    def ehlo_or_helo_if_needed(self) -> None:
        return None

    def has_extn(self, name: str) -> bool:
        return name.lower() == "auth"

    def auth(self, mechanism: str, authobject: Any, *, initial_response_ok: bool = True) -> None:
        _RecordingSMTP.captured["auth_mechanism"] = mechanism
        _RecordingSMTP.captured["login"] = (self.user, self.password)

    def auth_plain(self, challenge: bytes | None = None) -> str:
        return ""

    def auth_login(self, challenge: bytes | None = None) -> str:
        return ""

    def send_message(self, msg: Any) -> None:
        _RecordingSMTP.captured["subject"] = msg["Subject"]


@pytest.fixture
def smtp(monkeypatch: pytest.MonkeyPatch) -> type[_RecordingSMTP]:
    # RESET THE SHARED DICT PER TEST. `captured` is CLASS state and was previously only cleared in
    # __init__, i.e. only when a connection was actually opened. Every test that asserts something did
    # NOT happen — a refusal firing before smtplib.SMTP is ever constructed (BACKLOG #1171) — was
    # therefore reading the PREVIOUS test's dict. MEASURED: the security-event refusal test passed
    # alone and failed after the one that logs in successfully, because it inherited that login. Three
    # sibling refusal tests passed only because of the order they happened to run in.
    _RecordingSMTP.captured = {}
    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.smtplib.SMTP", _RecordingSMTP)
    return _RecordingSMTP


# --------------------------------------------------------------------------------------------------
# The two production call sites. These are SEPARATE code paths (alert_sinks.EmailTransport and
# security_notify.SecurityEventNotifier), so one passing does not imply the other.
# --------------------------------------------------------------------------------------------------


def test_the_ops_alert_hop_verifies_the_relay_certificate(smtp: type[_RecordingSMTP]) -> None:
    # WITHOUT THE FIX: context is None → red on the first assert. That is the whole defect.
    t = EmailTransport(host="smtp.example", port=587, sender="mf@example", recipients=["ops@x"])
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "boom"}))
    ctx = smtp.captured["context"]
    assert ctx is not None, "starttls() was called with NO context — the hop verifies nothing"
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_the_security_event_hop_verifies_the_relay_certificate(smtp: type[_RecordingSMTP]) -> None:
    # A DISTINCT call site from the one above — pipeline/security_notify.py builds its own transport,
    # so the ops-alert test passing tells us nothing about this one. WITHOUT THE FIX: context is None.
    n = SecurityEventNotifier(host="smtp.example", port=587, sender="mf@example")
    n._send(SecurityEvent(event_type=ACCOUNT_LOCKED, username="dr.who", email="dr.who@example"))
    ctx = smtp.captured["context"]
    assert ctx is not None, "the security-event hop verifies nothing"
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_strict_x509_is_on_so_a_malformed_chain_is_rejected(smtp: type[_RecordingSMTP]) -> None:
    # ASVS 12.1.4: harden_verify_flags ORs VERIFY_X509_STRICT into the context, so a presented chain
    # must be RFC 5280-conformant. WITHOUT THE FIX there is no context to carry the flag.
    t = EmailTransport(host="smtp.example", port=587, sender="mf@example", recipients=["ops@x"])
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "boom"}))
    ctx = smtp.captured["context"]
    assert ctx is not None
    assert ctx.verify_flags & ssl.VERIFY_X509_STRICT


def test_tls_1_2_is_the_negotiated_floor(smtp: type[_RecordingSMTP]) -> None:
    # NIST SP 800-52r2. WITHOUT THE FIX: no context, so no floor is asserted at all.
    t = EmailTransport(host="smtp.example", port=587, sender="mf@example", recipients=["ops@x"])
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "boom"}))
    assert smtp.captured["context"].minimum_version is ssl.TLSVersion.TLSv1_2


# --------------------------------------------------------------------------------------------------
# The audited escape still works, and is visibly different from the secure default.
# --------------------------------------------------------------------------------------------------


def test_tls_verify_false_produces_an_unverified_context(smtp: type[_RecordingSMTP]) -> None:
    # The escape is REAL — it must actually turn verification off, or an operator who set it would be
    # running a posture nobody described. It is gated at the SERVE gate, not here (this cell is built
    # outside the connectors' active_hop_posture scope, so their clamp is inert on it).
    t = EmailTransport(
        host="smtp.example", port=587, sender="mf@example", recipients=["ops@x"], tls_verify=False
    )
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "boom"}))
    ctx = smtp.captured["context"]
    assert ctx is not None
    assert ctx.verify_mode is ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_use_tls_false_passes_no_context_because_there_is_no_tls(
    smtp: type[_RecordingSMTP],
) -> None:
    t = EmailTransport(
        host="smtp.example", port=587, sender="mf@example", recipients=["ops@x"], use_tls=False
    )
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "boom"}))
    assert smtp.captured["tls"] is False
    assert smtp.captured["context"] is None


def test_a_connection_ca_file_is_loaded_as_the_only_anchor(
    smtp: type[_RecordingSMTP], tmp_path: Path
) -> None:
    # [alerts].email_tls_ca_file pins the relay's own CA. Assert it LOADED it: an empty cert store
    # would mean the path was accepted and ignored, which looks identical from the outside.
    ca = tmp_path / "relay-ca.pem"
    ca.write_bytes(_self_signed_ca_pem())
    t = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@example",
        recipients=["ops@x"],
        tls_ca_file=str(ca),
    )
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "boom"}))
    ctx = smtp.captured["context"]
    assert ctx is not None
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert len(ctx.get_ca_certs()) == 1, "the CA file was accepted but no anchor was loaded"


# --------------------------------------------------------------------------------------------------
# The loosening registry SEES the deviation. Without this the weakening is invisible to every operator
# surface — which is exactly how the original defect survived.
# --------------------------------------------------------------------------------------------------


def _names(**kw: Any) -> list[str]:
    alerts = AlertsSettings(
        email_smtp_host="smtp.example", email_from="mf@example", **kw.pop("alerts", {})
    )
    sec = SecuritySettings(**kw.pop("security", {}))
    return [
        n
        for n, _ in security_loosenings(
            sec, StoreSettings(), AuthSettings(), alerts, SecretRotationSettings(), (), (), ()
        )
    ]


def test_the_shipped_alert_defaults_are_not_a_loosening() -> None:
    assert "email_tls_verify" not in _names()
    assert "email_use_tls" not in _names()
    assert "allow_unverified_alert_smtp_tls" not in _names()


def test_verification_off_is_reported_even_without_the_acknowledgment() -> None:
    # THE POINT OF A SEPARATE ENTRY: under enforcement=warn an operator can run verify-off with no
    # acknowledgment at all. Keying the report on the ack switch alone would leave the actual
    # weakening invisible. WITHOUT THE FIX: security_loosenings() cannot even see AlertsSettings.
    assert "email_tls_verify" in _names(alerts={"email_tls_verify": False})


def test_cleartext_alert_smtp_is_reported() -> None:
    assert "email_use_tls" in _names(alerts={"email_use_tls": False})


def test_the_acknowledgment_switch_is_itself_reported() -> None:
    # Armed by the completeness floor in tests/test_security_posture_defaults.py, which iterates
    # SecuritySettings.model_fields — this asserts the entry it demands actually exists.
    assert "allow_unverified_alert_smtp_tls" in _names(
        security={"allow_unverified_alert_smtp_tls": True}
    )


def test_an_unconfigured_alert_transport_reports_no_hop_deviation() -> None:
    # No SMTP host/sender = no hop to weaken. Reporting one would be a false positive an operator
    # cannot act on.
    bare = AlertsSettings(email_use_tls=False, email_tls_verify=False)
    names = [
        n
        for n, _ in security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            bare,
            SecretRotationSettings(),
            (),
            (),
            (),
        )
    ]
    assert "email_use_tls" not in names
    assert "email_tls_verify" not in names


def _self_signed_ca_pem() -> bytes:
    """A throwaway self-signed CA, generated fresh in-process for the anchor-loading test.

    Generated rather than embedded so the file carries no certificate blob a reader has to trust, and
    so it can never expire and turn this into a time-bomb failure. The private key is discarded when
    this function returns — nothing can be signed with it. ``cryptography`` is a base dependency
    (``transports/direct.py`` S/MIME), so this needs no extra."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mf-test-relay-ca")])
    not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


# --------------------------------------------------------------------------------------------------
# The serve gate. An ACKNOWLEDGMENT switch, not the connectors' clamp — the contextvar hop posture is
# never stamped for this cell, so weakened_tls_escape_permitted_here() would be inert here.
# --------------------------------------------------------------------------------------------------

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


def _prod_phi_toml(*, alerts_lines: str = "", security_lines: str = "") -> str:
    """A production-PHI service config that clears every gate AHEAD of the #323 one.

    Loopback bind, so the exposure-keyed ladder (Posture-B, MFA-at-exposure, /ui) never fires and a
    refusal here can only be the alerts-SMTP gate. `[alerts]` is configured because the #188 gate
    refuses a PHI instance with no notification channel at all — which would make a refusal test pass
    for the wrong reason. Extra `[security]` lines are spliced in as dotted keys BEFORE the first table
    header: appended after `[alerts]` they would land IN `[alerts]`, load clean, and silently do
    nothing."""
    return (
        "security.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n"
        + security_lines
        + "[retention]\ndead_letter_days = 30\n"
        + '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'
        + alerts_lines
    )


def _serve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str, *, env: str = "prod") -> int:
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", env])


def test_the_shipped_alert_defaults_start_a_production_phi_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The gate must be BYTE-IDENTICAL on the secure defaults. A gate that refuses a stock config is a
    # gate that gets disabled.
    assert _serve(tmp_path, monkeypatch, _prod_phi_toml()) == 0


def test_verification_off_refuses_a_production_phi_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # WITHOUT THE GATE: returns 0 and the instance starts with an unauthenticated alert hop.
    rc = _serve(tmp_path, monkeypatch, _prod_phi_toml(alerts_lines="email_tls_verify = false\n"))
    assert rc == 2
    err = capsys.readouterr().err
    assert "email_tls_verify=false" in err
    assert "refusing to start" in err
    # It must name the way OUT, not just the problem — an operator reading this gets nothing else.
    assert "allow_unverified_alert_smtp_tls" in err


def test_cleartext_alert_smtp_refuses_a_production_phi_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The BYPASS this gate exists to close: refusing verify-off while permitting use_tls=false would
    # push an operator onto the STRICTLY WORSE posture to escape the refusal.
    rc = _serve(tmp_path, monkeypatch, _prod_phi_toml(alerts_lines="email_use_tls = false\n"))
    assert rc == 2
    assert "CLEARTEXT" in capsys.readouterr().err


def test_the_acknowledgment_permits_the_start_and_audits_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _serve(
        tmp_path,
        monkeypatch,
        _prod_phi_toml(
            alerts_lines="email_tls_verify = false\n",
            security_lines="security.allow_unverified_alert_smtp_tls = true\n",
        ),
    )
    assert rc == 0
    # Permitted is not the same as silent: the deliberate weakening must leave a durable record.
    assert "warning:" in capsys.readouterr().err


def test_a_synthetic_instance_is_not_gated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # No PHI, no refusal — the gate is keyed on data_class, like every sibling in the ladder.
    #
    # The posture is declared EXPLICITLY rather than inferred from `--env dev`. Measured: the samples
    # config resolves `dev` to data_class=phi, so an env-name-based version of this test failed with
    # rc=2 — and had the gate been (wrongly) keyed on the env NAME instead of the derived data_class,
    # that version would have passed while proving nothing.
    rc = _serve(
        tmp_path,
        monkeypatch,
        _prod_phi_toml(
            alerts_lines="email_tls_verify = false\n",
            security_lines="security.handles_real_patient_data = false\n",
        ),
        env="dev",
    )
    assert rc == 0


# --------------------------------------------------------------------------------------------------
# The `messagefoundry check` advisory — the review surface. The defect was invisible for exactly as
# long as nothing reported it.
# --------------------------------------------------------------------------------------------------


def _advisory(tmp_path: Path, toml: str) -> Any:
    from messagefoundry.checks import _check_alert_smtp_tls

    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    return _check_alert_smtp_tls(tmp_path, service_config=tmp_path / "messagefoundry.toml")


def test_the_advisory_states_the_secure_case_out_loud(tmp_path: Path) -> None:
    # An absent line is indistinguishable from a check that did not run, so the PASSING case must say
    # something. This is the leak-gate-blindness rule applied to the report itself.
    r = _advisory(tmp_path, _prod_phi_toml())
    assert r.ok and not r.required and not r.skipped
    assert "verifies" in r.detail and "OS trust store" in r.detail


def test_the_advisory_names_an_unacknowledged_deviation(tmp_path: Path) -> None:
    r = _advisory(tmp_path, _prod_phi_toml(alerts_lines="email_tls_verify = false\n"))
    assert r.ok and not r.required  # advisory: the serve gate refuses, this only reports
    assert "ANY certificate" in r.detail
    assert "NOT acknowledged" in r.detail


def test_the_advisory_reports_the_acknowledgment_when_it_is_set(tmp_path: Path) -> None:
    r = _advisory(
        tmp_path,
        _prod_phi_toml(
            alerts_lines="email_tls_verify = false\n",
            security_lines="security.allow_unverified_alert_smtp_tls = true\n",
        ),
    )
    assert "acknowledged by [security].allow_unverified_alert_smtp_tls" in r.detail


def test_the_advisory_skips_rather_than_inventing_a_result(tmp_path: Path) -> None:
    from messagefoundry.checks import _check_alert_smtp_tls

    r = _check_alert_smtp_tls(tmp_path)
    assert r.skipped and r.ok


# --------------------------------------------------------------------------------------------------
# BACKLOG #1171 / ASVS 11.4.1 — SMTP AUTH over an un-encrypted channel.
#
# The connectors (transports/email.py, transports/direct.py) already refused this at construction,
# with tests that SET the escape env var and still assert the raise. This cell did not: STARTTLS ran
# only when use_tls, and the login ran whenever a username was set. So `[alerts].email_use_tls=false`
# beside `email_username` put the password on the wire.
#
# Every test below asserts the fake recorded NO login, not merely that something raised. A refusal
# that fires after the credential reaches the transport is not a refusal.
# --------------------------------------------------------------------------------------------------


def test_cleartext_alerts_smtp_with_a_credential_is_refused(smtp: type[_RecordingSMTP]) -> None:
    # WITHOUT THE FIX: no raise, and captured["login"] holds ("svc", "pw") in the clear.
    t = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@example",
        recipients=["ops@x"],
        use_tls=False,
        username="svc",
        password="pw",
    )
    with pytest.raises(ValueError, match="credentials"):
        asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "b"}))
    assert "login" not in smtp.captured, "the credential reached the transport before the refusal"


def test_the_escape_does_not_re_permit_a_cleartext_credential(
    smtp: type[_RecordingSMTP], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The escape buys a cleartext BODY, never a cleartext CREDENTIAL.

    This mirrors tests/test_email_destination.py and tests/test_direct_transport.py, which set the
    same env var and still assert the raise. Without this test the refusal could be quietly softened
    into an escapable one and the suite would stay green.
    """
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    t = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@example",
        recipients=["ops@x"],
        use_tls=False,
        username="svc",
        password="pw",
    )
    with pytest.raises(ValueError, match="credentials"):
        asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "b"}))
    assert "login" not in smtp.captured


def test_cleartext_without_a_credential_still_sends(smtp: type[_RecordingSMTP]) -> None:
    """POSITIVE CONTROL. A guard that refused every cleartext send would satisfy both tests above.

    Nothing on this path is a credential, so the pre-existing behaviour is unchanged: no TLS, no
    context, no login, and the message goes.
    """
    t = EmailTransport(
        host="smtp.example", port=587, sender="mf@example", recipients=["ops@x"], use_tls=False
    )
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "b"}))
    assert smtp.captured["tls"] is False
    assert "login" not in smtp.captured


def test_a_credential_over_starttls_still_logs_in(smtp: type[_RecordingSMTP]) -> None:
    """POSITIVE CONTROL for the other half: the refusal must not break authenticated SMTP.

    A guard keyed on `username is not None` alone — dropping the `not use_tls` half — would refuse
    this, which is the ordinary production configuration.
    """
    t = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@example",
        recipients=["ops@x"],
        username="svc",
        password="pw",
    )
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "b"}))
    assert smtp.captured["tls"] is True
    assert smtp.captured["login"] == ("svc", "pw")


def test_the_security_event_hop_refuses_a_cleartext_credential(smtp: type[_RecordingSMTP]) -> None:
    """A DISTINCT call site, per this file's own rule that one passing does not imply the other.

    security_notify builds its own transport and passes the SAME `[alerts].email_use_tls` knob, so
    the gap was reachable twice. Both callers funnel through send_plain_email, which is why one
    refusal covers both — but that is a claim about the code, and this is the measurement of it.
    """
    n = SecurityEventNotifier(
        host="smtp.example",
        port=587,
        sender="mf@example",
        use_tls=False,
        username="svc",
        password="pw",
    )
    with pytest.raises(ValueError, match="credentials"):
        n._send(SecurityEvent(event_type=ACCOUNT_LOCKED, username="dr.who", email="dr.who@x"))
    assert "login" not in smtp.captured


def test_cram_md5_is_never_selected_even_when_the_server_offers_it(
    smtp: type[_RecordingSMTP],
) -> None:
    """THE CONFORMANCE ASSERTION. ASVS 11.4.1 disallows MD5 for any cryptographic purpose.

    The fake advertises ``CRAM-MD5 PLAIN LOGIN``. smtplib's own ``login()`` builds its preference
    list as ``['CRAM-MD5', 'PLAIN', 'LOGIN']`` and picks the first the server advertises — so the
    unfixed code selects an HMAC over MD5 here. Restoring ``smtp.login()`` in place of
    ``smtp_login_approved`` turns this red.
    """
    t = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@example",
        recipients=["ops@x"],
        username="svc",
        password="pw",
    )
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "b"}))
    assert smtp.captured["auth_mechanism"] == "PLAIN"
    assert "MD5" not in smtp.captured["auth_mechanism"].upper()
    # POSITIVE CONTROL on the fake itself: it really did offer the disallowed mechanism, so the
    # assertion above is a choice the code made and not an option it never had.
    assert "CRAM-MD5" in _RecordingSMTP.esmtp_features["auth"]
