# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The revocation-hop guard on the ``[alerts]`` SMTP login and the alert webhook (BACKLOG #2193
slices (c) and (d), ADR 0173).

Both hops verify a peer certificate and, before this, ran no guard: under an enforcing posture a
revoked but unexpired certificate was accepted with no refusal and no record. The owner ruling of
2026-10-27 guards both:

* **(c) the SMTP hop, when it carries a login** (``[alerts].email_username``). The levers are a
  ``[tls].crl_file`` that reaches the hop's context, or the ``[alerts].email_tls_revocation_attested``
  pair. A hop with no login takes no guard, a decline recorded in ADR 0173. The security notifier
  rides the same hop and takes the same guard.
* **(d) the https webhook**, with the ``[alerts].webhook_tls_revocation_attested`` pair as its only
  lever, on the pattern of ADR 0173 section 12: its opener is built at import and no CRL reaches it.

The arms follow ``tests/test_revocation_guard_remaining_hops.py``: refused under an enforcing posture
with no lever (the control), admitted with a CRL read off the hop's OWN context, and still refused
where the CRL is configured but does not reach that context. Nothing here dials. Every certificate,
CRL and address is synthetic.
"""

from __future__ import annotations

import ast
import asyncio
import datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.settings import (
    AiSettings,
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    SecretRotationSettings,
    SecretsSettings,
    SecuritySettings,
    StoreSettings,
    alert_revocation_attestations,
    security_loosenings,
)
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopPosture,
    InsecureHopRefused,
    TrustAnchorPolicy,
    active_hop_posture,
    build_smtp_tls_context,
    context_checks_revocation,
    current_hop_posture,
)
from messagefoundry.pipeline import alert_sinks
from messagefoundry.pipeline.alert_sinks import (
    EmailTransport,
    WebhookTransport,
    notifier_from_settings,
)
from messagefoundry.pipeline.security_notify import (
    SecurityEventNotifier,
    security_notifier_from_settings,
)
from tests._ast_sites import call_sites, parse_source
from tests.test_revocation_guard_remaining_hops import _guard_log

ENFORCING = HopPosture(enforcing=True)
NOT_ENFORCING = HopPosture(enforcing=False)

RELAY = "smtp.example.test"  # off the box, never dialled: construction reads settings only
WEBHOOK = "https://hooks.example.test/services/T000/B000/synthetic"
LOOPBACK_WEBHOOK = "https://127.0.0.1:8443/hook"
REASON = "the relay certificate lives 24 hours"

_SMTP_CELL = "[alerts] SMTP login to the relay"
_WEBHOOK_CELL = "[alerts] webhook POST"
_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _no_blanket_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The blanket attestation and the weakened-TLS escape must not stand in for the hop's facts."""
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)


@pytest.fixture(scope="module")
def bare_crl(tmp_path_factory: pytest.TempPathFactory) -> str:
    """A CRL with no CA beside it, the shape a system-trust-store hop loads. Synthetic."""
    now = datetime.datetime.now(datetime.UTC)
    day = datetime.timedelta(days=1)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-2193-alerts-ca")])
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - 2 * day)
        .next_update(now + 30 * day)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path_factory.mktemp("crl2193alerts") / "crl_only.pem"
    path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return str(path)


def _email(posture: HopPosture | None, **over: Any) -> EmailTransport:
    fields: dict[str, Any] = {
        "host": RELAY,
        "port": 587,
        "sender": "alerts@example.test",
        "recipients": ["ops@example.test"],
        "username": "alerts-relay",
        "password": "synthetic-not-a-secret",
        "posture": posture,
        **over,
    }
    return EmailTransport(**fields)


def _notifier(posture: HopPosture | None, **over: Any) -> SecurityEventNotifier:
    fields: dict[str, Any] = {
        "host": RELAY,
        "port": 587,
        "sender": "alerts@example.test",
        "username": "alerts-relay",
        "password": "synthetic-not-a-secret",
        "posture": posture,
        **over,
    }
    return SecurityEventNotifier(**fields)


# --- (c) the SMTP login ---------------------------------------------------------------------------


def test_an_off_box_smtp_login_is_refused_when_it_checks_no_revocation() -> None:
    # THE CONTROL. Before BACKLOG #2193 slice (c) this constructed: the hop took no guard at all.
    with pytest.raises(InsecureHopRefused, match="revocation") as exc:
        _email(ENFORCING)
    text = str(exc.value)
    assert _SMTP_CELL in text
    # This hop's own levers, not the connection-shaped one it cannot use.
    assert "[tls].crl_file" in text
    assert "[alerts].email_tls_revocation_attested" in text
    assert "tls_revocation_attested=true" not in text
    # The login password never reaches the refusal.
    assert "synthetic-not-a-secret" not in text


def test_the_security_notifier_takes_the_same_guard() -> None:
    with pytest.raises(InsecureHopRefused, match="revocation") as exc:
        _notifier(ENFORCING)
    assert _SMTP_CELL in str(exc.value)


def test_an_smtp_login_is_admitted_when_its_crl_reaches_the_send_context(bare_crl: str) -> None:
    policy = TrustAnchorPolicy(crl_file=bare_crl)
    _email(ENFORCING, trust_anchor_policy=policy)
    _notifier(ENFORCING, trust_anchor_policy=policy)
    # Read off the context send_plain_email builds for a send, from the same arguments.
    ctx = build_smtp_tls_context(
        host=RELAY,
        cell=alert_sinks.ALERTS_SMTP_CELL,
        trust_anchor_policy=policy,
        ca_setting="[alerts].email_tls_ca_file",
    )
    assert context_checks_revocation(ctx) is True


def test_a_configured_crl_does_not_admit_a_login_whose_context_lacks_it(
    bare_crl: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard reads the context, never the setting."""
    original = build_smtp_tls_context  # the function alert_sinks binds

    def _drop_the_crl(**kwargs: Any) -> Any:
        kwargs["trust_anchor_policy"] = None
        return original(**kwargs)

    monkeypatch.setattr(alert_sinks, "build_smtp_tls_context", _drop_the_crl)
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _email(ENFORCING, trust_anchor_policy=TrustAnchorPolicy(crl_file=bare_crl))


def test_a_configured_crl_that_cannot_be_loaded_refuses_the_build(tmp_path: Path) -> None:
    missing = str(tmp_path / "gone.crl.pem")
    with pytest.raises((OSError, ValueError)):
        _email(ENFORCING, trust_anchor_policy=TrustAnchorPolicy(crl_file=missing))


def test_an_attested_smtp_login_crosses_and_is_recorded() -> None:
    with _guard_log() as log:
        _email(ENFORCING, revocation_attested=True, revocation_attested_reason=REASON)
        _notifier(ENFORCING, revocation_attested=True, revocation_attested_reason=REASON)
    assert log.audit.count(REASON) == 2, log.state()
    assert _SMTP_CELL in log.audit, log.state()


def test_an_smtp_hop_with_no_login_takes_no_guard() -> None:
    # The decline recorded in ADR 0173: no credential crosses, and an alert body carries no PHI.
    with _guard_log() as log:
        _email(ENFORCING, username=None, password=None)
        _notifier(ENFORCING, username=None, password=None)
    assert not log.has(_SMTP_CELL), log.state()


def test_a_relay_outside_the_allowlist_is_left_to_the_send_refusal() -> None:
    """The egress allowlist refuses the host at every send, before any other work, so the guard
    does not send the operator to fix revocation on a hop the policy forbids."""
    transport = _email(ENFORCING, allowed_hosts=("other.example.test",))
    with pytest.raises(ValueError, match="allowlist"):
        asyncio.run(transport.send({"type": "connection_stopped", "connection": "OB_X"}))


def test_an_smtp_login_on_loopback_still_crosses() -> None:
    _email(ENFORCING, host="127.0.0.1")
    _notifier(ENFORCING, host="localhost")


def test_an_smtp_login_warns_but_builds_when_not_enforcing() -> None:
    with _guard_log() as log:
        _email(NOT_ENFORCING)
    assert log.has("revocation") and log.has(_SMTP_CELL), log.state()


def test_an_smtp_login_built_with_no_posture_is_refused() -> None:
    """No posture passed and none stamped counts as enforcing (ADR 0173 section 12), as on the AI
    broker. It was the unstamped no-op until the batch 453 wave 3 alignment."""
    assert current_hop_posture() is None
    with pytest.raises(InsecureHopRefused, match="revocation") as exc:
        _email(None)
    assert _SMTP_CELL in str(exc.value)
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _notifier(None)


def test_an_smtp_login_with_no_posture_passed_reads_the_stamped_one() -> None:
    """The enforcing default is only for no posture at all: a stamped warn posture still warns."""
    with _guard_log() as log, active_hop_posture(NOT_ENFORCING):
        _email(None)
    assert log.has("revocation") and log.has(_SMTP_CELL), log.state()


def test_the_alerts_settings_pair_reaches_both_smtp_builds() -> None:
    settings = AlertsSettings(
        email_smtp_host=RELAY,
        email_from="alerts@example.test",
        email_to=["ops@example.test"],
        email_username="alerts-relay",
        email_password="synthetic-not-a-secret",
    )
    with pytest.raises(InsecureHopRefused, match="revocation"):
        notifier_from_settings(settings, posture=ENFORCING)
    with pytest.raises(InsecureHopRefused, match="revocation"):
        security_notifier_from_settings(settings, posture=ENFORCING)
    attested = settings.model_copy(
        update={
            "email_tls_revocation_attested": True,
            "email_tls_revocation_attested_reason": REASON,
        }
    )
    assert notifier_from_settings(attested, posture=ENFORCING) is not None
    assert security_notifier_from_settings(attested, posture=ENFORCING) is not None


# --- (d) the webhook ------------------------------------------------------------------------------


def test_an_off_box_https_webhook_is_refused_when_it_checks_no_revocation() -> None:
    # THE CONTROL. Before BACKLOG #2193 slice (d) this constructed: the hop took no guard at all.
    with pytest.raises(InsecureHopRefused, match="revocation") as exc:
        WebhookTransport(WEBHOOK, posture=ENFORCING)
    text = str(exc.value)
    assert _WEBHOOK_CELL in text
    # The attestation is the only lever: no CRL reaches the import-time opener.
    assert "[alerts].webhook_tls_revocation_attested" in text
    assert "Configure [tls].crl_file" not in text
    # The path token, the webhook's credential, never reaches the refusal.
    assert "/services/" not in text and "synthetic" not in text


def test_an_attested_webhook_crosses_and_is_recorded() -> None:
    with _guard_log() as log:
        WebhookTransport(
            WEBHOOK,
            posture=ENFORCING,
            revocation_attested=True,
            revocation_attested_reason=REASON,
        )
    assert REASON in log.audit and _WEBHOOK_CELL in log.audit, log.state()


@pytest.mark.parametrize("reason", [None, "   ", "covered\nFORGED LINE"])
def test_a_direct_build_cannot_attest_without_a_recordable_reason(reason: str | None) -> None:
    """The settings load refuses these; a transport built directly is refused at its guard too,
    as the AI broker is, so no crossing is recorded with no reason or a forged line."""
    with pytest.raises(ValueError, match="webhook_tls_revocation_attested") as exc:
        WebhookTransport(
            WEBHOOK, posture=ENFORCING, revocation_attested=True, revocation_attested_reason=reason
        )
    assert not isinstance(exc.value, InsecureHopRefused)
    with pytest.raises(ValueError, match="email_tls_revocation_attested") as exc:
        _email(ENFORCING, revocation_attested=True, revocation_attested_reason=reason)
    assert not isinstance(exc.value, InsecureHopRefused)


def test_a_truthy_non_bool_attestation_does_not_cross() -> None:
    with pytest.raises(InsecureHopRefused, match="revocation"):
        WebhookTransport(
            WEBHOOK,
            posture=ENFORCING,
            revocation_attested="yes",  # type: ignore[arg-type]  # a direct build's wrong type
            revocation_attested_reason=REASON,
        )


def test_a_reason_without_the_flag_does_not_cross() -> None:
    with pytest.raises(InsecureHopRefused, match="revocation"):
        WebhookTransport(WEBHOOK, posture=ENFORCING, revocation_attested_reason=REASON)


def test_a_loopback_https_webhook_still_crosses() -> None:
    WebhookTransport(LOOPBACK_WEBHOOK, posture=ENFORCING)


def test_an_https_webhook_warns_but_builds_when_not_enforcing() -> None:
    with _guard_log() as log:
        WebhookTransport(WEBHOOK, posture=NOT_ENFORCING)
    assert log.has("revocation") and log.has(_WEBHOOK_CELL), log.state()


def test_an_https_webhook_built_with_no_posture_is_refused() -> None:
    """No posture passed and none stamped counts as enforcing (ADR 0173 section 12), as on the AI
    broker. It was the unstamped no-op until the batch 453 wave 3 alignment."""
    assert current_hop_posture() is None
    with pytest.raises(InsecureHopRefused, match="revocation") as exc:
        WebhookTransport(WEBHOOK)
    assert _WEBHOOK_CELL in str(exc.value)
    with _guard_log() as log, active_hop_posture(NOT_ENFORCING):
        WebhookTransport(WEBHOOK)
    assert sum(_WEBHOOK_CELL in m for m in log.messages) == 1, log.state()


def test_a_cleartext_webhook_takes_no_revocation_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    # No certificate, so nothing to revoke; the cleartext refusal owns that hop. The escape lets an
    # http URL build on a warn instance, which is the only place one builds.
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with _guard_log() as log:
        WebhookTransport("http://hooks.example.test/hook", posture=NOT_ENFORCING)
    assert not log.has(_WEBHOOK_CELL), log.state()


def test_the_alerts_settings_pair_reaches_the_webhook_build() -> None:
    settings = AlertsSettings(webhook_url=WEBHOOK)
    with pytest.raises(InsecureHopRefused, match="revocation"):
        notifier_from_settings(settings, posture=ENFORCING)
    attested = settings.model_copy(
        update={
            "webhook_tls_revocation_attested": True,
            "webhook_tls_revocation_attested_reason": REASON,
        }
    )
    assert notifier_from_settings(attested, posture=ENFORCING) is not None


# --- the settings pairs ---------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", ["email", "webhook"])
def test_a_flag_without_a_reason_is_refused_at_load(prefix: str) -> None:
    with pytest.raises(ValueError, match=f"{prefix}_tls_revocation_attested_reason"):
        AlertsSettings.model_validate({f"{prefix}_tls_revocation_attested": True})


@pytest.mark.parametrize("prefix", ["email", "webhook"])
def test_a_reason_without_the_flag_is_refused_at_load(prefix: str) -> None:
    with pytest.raises(ValueError, match=f"{prefix}_tls_revocation_attested"):
        AlertsSettings.model_validate({f"{prefix}_tls_revocation_attested_reason": REASON})


@pytest.mark.parametrize("prefix", ["email", "webhook"])
@pytest.mark.parametrize("reason", ["   ", "covered\nFORGED LINE", "lone \ud800 surrogate"])
def test_a_blank_or_unprintable_reason_is_refused_at_load(prefix: str, reason: str) -> None:
    with pytest.raises(ValueError, match=f"{prefix}_tls_revocation_attested"):
        AlertsSettings.model_validate(
            {
                f"{prefix}_tls_revocation_attested": True,
                f"{prefix}_tls_revocation_attested_reason": reason,
            }
        )


def _loosenings(alerts: AlertsSettings) -> dict[str, str]:
    return dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            alerts,
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            path_form_fhir_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            cert_monitor=CertMonitorSettings(),
            backup=BackupSettings(),
            secrets=SecretsSettings(),
            ai=AiSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
            service_env=None,
        )
    )


def test_each_set_pair_is_named_as_a_loosening() -> None:
    alerts = AlertsSettings(
        email_tls_revocation_attested=True,
        email_tls_revocation_attested_reason=REASON,
        webhook_tls_revocation_attested=True,
        webhook_tls_revocation_attested_reason="the hook host certificate lives 7 days",
    )
    named = _loosenings(alerts)
    assert REASON in named["alerts.email_tls_revocation_attested"]
    assert "7 days" in named["alerts.webhook_tls_revocation_attested"]
    assert alert_revocation_attestations(AlertsSettings()) == []
    shipped = _loosenings(AlertsSettings())
    assert not any(s.startswith("alerts.") for s in shipped), shipped


# --- the posture reaches every engine build ------------------------------------------------------


#: The builds whose guard reads a ``posture`` keyword, and the engine files that must make them.
_POSTURE_BUILDS = {
    "EmailTransport": {"messagefoundry/pipeline/alert_sinks.py", "messagefoundry/api/app.py"},
    "WebhookTransport": {"messagefoundry/pipeline/alert_sinks.py"},
    "SecurityEventNotifier": {"messagefoundry/pipeline/security_notify.py"},
    "security_notifier_from_settings": {
        "messagefoundry/api/app.py",
        "messagefoundry/__main__.py",
    },
    "notifier_from_settings": {"messagefoundry/api/app.py"},
}


def _engine_builds(name: str) -> list[tuple[str, ast.Call]]:
    found: list[tuple[str, ast.Call]] = []
    for path in sorted((_ROOT / "messagefoundry").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if name not in source:
            continue
        rel = path.relative_to(_ROOT).as_posix()
        tree = parse_source(source)
        found.extend((rel, call) for call in call_sites(tree, name))
        # A build handed to a worker thread, as the alerts test send does: to_thread(name, ...).
        found.extend(
            (rel, call)
            for call in call_sites(tree, "to_thread")
            if call.args and isinstance(call.args[0], ast.Name) and call.args[0].id == name
        )
    return found


@pytest.mark.parametrize("name", sorted(_POSTURE_BUILDS))
def test_every_engine_build_passes_a_posture(name: str) -> None:
    """A CENSUS PIN on the posture, as for the LDAPS bind. The census entry proves the guard is
    called; it cannot see a caller that stops passing ``posture``, which would leave the guard on
    its enforcing default for no posture, so a warn instance would refuse rather than warn. A name
    that is always ``None`` still passes this."""
    builds = _engine_builds(name)
    assert {rel for rel, _ in builds} >= _POSTURE_BUILDS[name], builds
    missing = []
    for rel, call in builds:
        value = {kw.arg: kw.value for kw in call.keywords}.get("posture")
        if value is None or (isinstance(value, ast.Constant) and value.value is None):
            missing.append(f"{rel}: {ast.unparse(call)}")
    assert not missing, f"{name} built with no posture: {missing}"


def test_the_lifespan_hands_the_test_send_its_posture() -> None:
    """The lifespan stores the posture it hands the live notifier where the test-email route
    reads it. Read from source: building the managed lifespan here would start an engine. The
    route's own behaviour is the test below."""
    source = (_ROOT / "messagefoundry" / "api" / "app.py").read_text(encoding="utf-8")
    assert "app.state.alert_hop_posture = _hop_posture" in source


async def test_the_alerts_test_send_reports_the_refusal_a_live_alert_would_meet(
    tmp_path: Path,
) -> None:
    """On the posture a live alert reads, the test send meets the same refusal and reports it as a
    failed test, not a 500, so it cannot pass a relay the live sink refuses."""
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline import Engine

    engine = await Engine.create(
        tmp_path / "alerts.db", egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        alerts = AlertsSettings(
            email_smtp_host=RELAY,
            email_from="alerts@example.test",
            email_to=["ops@example.test"],
            email_username="alerts-relay",
            email_password="synthetic-not-a-secret",
        )
        app = create_app(engine, allow_no_auth=True, alerts_settings=alerts)
        app.state.alert_hop_posture = ENFORCING
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as client:
            reply = await client.post("/alerts/test-email")
        assert reply.status_code == 200
        body = reply.json()
        assert body["success"] is False
        assert "revocation" in (body["detail"] or ""), body
        assert "synthetic-not-a-secret" not in reply.text
    finally:
        await engine.stop()


def test_an_offline_notifier_with_no_posture_reads_the_instance_posture(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``admin reset-totp`` passes no posture. The offline notifier then derives the instance's
    own: an enforcing instance refuses (and the notice is dropped with a WARNING), and a warn
    instance builds with a WARNING, where the guard's own default for no posture would refuse."""
    from messagefoundry.__main__ import _offline_security_notifier
    from messagefoundry.config.settings import SecurityEnforcement, ServiceSettings

    alerts = AlertsSettings(
        email_smtp_host=RELAY,
        email_from="alerts@example.test",
        email_username="alerts-relay",
        email_password="synthetic-not-a-secret",
    )
    assert _offline_security_notifier(ServiceSettings(alerts=alerts)) is None
    assert "revocation" in capsys.readouterr().err
    warn = SecuritySettings(enforcement=SecurityEnforcement.WARN)
    assert _offline_security_notifier(ServiceSettings(alerts=alerts, security=warn)) is not None
    attested = alerts.model_copy(
        update={
            "email_tls_revocation_attested": True,
            "email_tls_revocation_attested_reason": REASON,
        }
    )
    assert _offline_security_notifier(ServiceSettings(alerts=attested)) is not None


def test_the_guarded_send_still_sends(monkeypatch: pytest.MonkeyPatch) -> None:
    """An admitted login is not otherwise changed: the send still runs STARTTLS then AUTH."""
    from tests.test_alert_smtp_tls import _RecordingSMTP

    # Class state shared with tests/test_alert_smtp_tls.py: reset here, restored after.
    monkeypatch.setattr(_RecordingSMTP, "captured", {})
    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.smtplib.SMTP", _RecordingSMTP)
    transport = _email(ENFORCING, revocation_attested=True, revocation_attested_reason=REASON)
    asyncio.run(transport.send({"type": "connection_stopped", "connection": "OB_X"}))
    assert _RecordingSMTP.captured["tls"] is True
    assert _RecordingSMTP.captured["login"] == ("alerts-relay", "synthetic-not-a-secret")
