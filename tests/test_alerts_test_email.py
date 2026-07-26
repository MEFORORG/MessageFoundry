# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``POST /alerts/test-email`` — operator-triggered alert-mail-server connectivity test (BACKLOG #118).

The endpoint sends a synthetic, PHI-free event through the **real** ``[alerts]`` email transport
(``EmailTransport.send`` → ``send_plain_email``) and reports a synchronous pass/fail — the operator's
"test the alert mail server" button. These tests never open a real SMTP socket: the module-level
``send_plain_email`` is monkeypatched for the success/failure paths, and the *real* allowlist guard is
exercised (it raises before any socket) for the egress-allowlist case.

Invariants asserted:
* the synthetic event is PHI-free (no message body) and the result carries NO email addresses;
* a raised SMTP error becomes ``success=False`` with a scrubbed detail — never a 500;
* an unconfigured transport returns a clean ``configured=False`` (not an error) and never sends;
* the route is admin-gated (``service:configure``) and fails closed for unauthenticated callers;
* exactly one metadata-only ``alert_test_email`` audit row is written (no addresses / bodies).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AlertsSettings, AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)

# A sentinel planted in the SMTP password. It must never surface in a response or an audit row.
SMTP_PASSWORD_SECRET = "ZZSMTPPASSWORD9999"


def _email_alerts(**overrides: object) -> AlertsSettings:
    """An [alerts] config with the email transport configured (secret embedded)."""
    base: dict[str, object] = {
        "email_smtp_host": "smtp.example.com",
        "email_smtp_port": 2525,
        "email_from": "alerts@example.com",
        "email_to": ["oncall@example.com", "ops@example.com"],
        "email_use_tls": True,
        "email_username": "smtp-user",
        "email_password": SMTP_PASSWORD_SECRET,
    }
    base.update(overrides)
    return AlertsSettings(**base)  # type: ignore[arg-type]


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "alerts.db", poll_interval=0.02)
    eng.started_at = 1.0
    yield eng
    await eng.stop()


# --- 1. CONFIGURED + SEND SUCCEEDS -------------------------------------------


async def test_test_email_success_is_phi_free(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[dict[str, object]] = []

    def _fake_send(**kwargs: object) -> None:
        # Record the whole call so we can prove the event/subject/body carry no PHI.
        sent.append(dict(kwargs))

    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.send_plain_email", _fake_send)
    alerts = _email_alerts()
    transport = httpx.ASGITransport(
        app=create_app(engine, allow_no_auth=True, alerts_settings=alerts)
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/alerts/test-email")
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is True
    assert body["success"] is True
    assert body["recipient_count"] == 2
    assert body["detail"] is None
    assert body["duration_ms"] >= 0.0

    # The response carries NO email addresses and no password.
    assert SMTP_PASSWORD_SECRET not in r.text
    for addr in ("oncall@example.com", "ops@example.com", "alerts@example.com"):
        assert addr not in r.text

    # Exactly one send, to the configured recipients, and the payload is PHI-free (a fixed
    # type/severity label + a static detail string — no message body).
    assert len(sent) == 1
    call = sent[0]
    assert call["recipients"] == ["oncall@example.com", "ops@example.com"]
    assert "connectivity test" in str(call["subject"]) or "test_email" in str(call["subject"])
    assert "test_email" in str(call["body"])
    # No stored-message content ever appears in a test email.
    assert "PID" not in str(call["body"]) and "MSH" not in str(call["body"])


# --- 2. SEND RAISES → success=False, scrubbed detail, NO 500 -----------------


async def test_test_email_failure_is_scrubbed_not_500(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    import smtplib

    # An adversarial exception message carrying HL7-shaped PHI (a PID segment with a name + MRN). The
    # route renders failures via safe_exc, so this content must be scrubbed before it reaches the caller
    # — the point of the PHI guard. (Ordinary SMTP banner text is deliberately surfaced; PHI is not.)
    def _boom(**kwargs: object) -> None:
        raise smtplib.SMTPException("PID|1||900123^^^H^MR||DOE^JANE^M sending failed")

    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.send_plain_email", _boom)
    transport = httpx.ASGITransport(
        app=create_app(engine, allow_no_auth=True, alerts_settings=_email_alerts())
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/alerts/test-email")
    # A send failure is a TEST failure, not a server error.
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is True
    assert body["success"] is False
    detail = body["detail"]
    assert detail  # present
    # The exception TYPE is kept (safe + useful), but the HL7 PHI field data is redacted out.
    assert "SMTPException" in detail
    assert "900123" not in detail  # MRN scrubbed
    assert "DOE" not in detail  # name scrubbed
    assert "[redacted]" in detail


# --- 3. NO EMAIL TRANSPORT CONFIGURED → configured=False, no send ------------


async def test_test_email_not_configured(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        "messagefoundry.pipeline.alert_sinks.send_plain_email",
        lambda **kw: calls.append(kw),
    )
    # Webhook-only alerts (no email triple) — email is not configured.
    alerts = AlertsSettings(webhook_url="https://hooks.example.com/x")
    transport = httpx.ASGITransport(
        app=create_app(engine, allow_no_auth=True, alerts_settings=alerts)
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/alerts/test-email")
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is False
    assert body["success"] is False
    assert body["recipient_count"] == 0
    assert body["detail"]  # a clear "not configured" reason
    assert calls == []  # never attempted a send


async def test_test_email_no_alerts_settings_at_all(engine: Engine) -> None:
    # No alerts_settings passed → all-off defaults → not configured, no 500.
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/alerts/test-email")
    assert r.status_code == 200
    assert r.json()["configured"] is False


# --- 4. EGRESS ALLOWLIST (the real sink guard is exercised) ------------------


async def test_test_email_host_outside_allowlist_fails_cleanly(engine: Engine) -> None:
    # NB: no send_plain_email monkeypatch — the REAL function runs its allowlist check and raises
    # ValueError before opening any socket, proving the sink's egress allowlist is enforced.
    alerts = _email_alerts(smtp_allowed_hosts=["other.example.com"])  # excludes smtp.example.com
    transport = httpx.ASGITransport(
        app=create_app(engine, allow_no_auth=True, alerts_settings=alerts)
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/alerts/test-email")
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is True
    assert body["success"] is False
    assert body["detail"]


# --- 5. RECIPIENT OVERRIDE ----------------------------------------------------


async def test_test_email_recipient_override(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(
        "messagefoundry.pipeline.alert_sinks.send_plain_email",
        lambda **kw: sent.append(dict(kw)),
    )
    transport = httpx.ASGITransport(
        app=create_app(engine, allow_no_auth=True, alerts_settings=_email_alerts())
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/alerts/test-email", json={"recipient_override": "smoke@example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["recipient_count"] == 1
    # The override address is used for the send but never echoed in the response.
    assert "smoke@example.com" not in r.text
    assert sent[0]["recipients"] == ["smoke@example.com"]


# --- 6. RBAC (service:configure, admin-gated) --------------------------------


async def _auth_service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login_token(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return str(r.json()["token"])


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_test_email_gated_by_service_configure(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.send_plain_email", lambda **kw: None)
    service = await _auth_service(engine)
    await _add(service, "admin1", Role.ADMINISTRATOR)  # holds service:configure
    await _add(service, "op1", Role.OPERATOR)  # does NOT hold service:configure
    await _add(service, "vw", Role.VIEWER)
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, alerts_settings=_email_alerts())
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        # No token under enabled auth → fail closed (401), not an open send.
        assert (await c.post("/alerts/test-email")).status_code == 401
        # An operator lacks service:configure → 403.
        op = _bearer(await _login_token(c, "op1"))
        assert (await c.post("/alerts/test-email", headers=op)).status_code == 403
        # A viewer lacks it too → 403.
        vw = _bearer(await _login_token(c, "vw"))
        assert (await c.post("/alerts/test-email", headers=vw)).status_code == 403
        # An administrator holds it → 200.
        ad = _bearer(await _login_token(c, "admin1"))
        r = await c.post("/alerts/test-email", headers=ad)
        assert r.status_code == 200
        assert r.json()["success"] is True


# --- 7. AUDIT (metadata only) ------------------------------------------------


async def test_test_email_writes_metadata_only_audit(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.send_plain_email", lambda **kw: None)
    service = await _auth_service(engine)
    await _add(service, "admin1", Role.ADMINISTRATOR)
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, alerts_settings=_email_alerts())
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        ad = _bearer(await _login_token(c, "admin1"))
        assert (await c.post("/alerts/test-email", headers=ad)).status_code == 200

    rows = [a for a in await engine.store.list_audit(limit=50) if a["action"] == "alert_test_email"]
    assert len(rows) == 1
    detail = rows[0]["detail"] or ""
    # Metadata only: outcome + count, and NEVER an address or the password.
    assert '"success": true' in detail
    assert '"recipient_count": 2' in detail
    assert SMTP_PASSWORD_SECRET not in detail
    for addr in ("oncall@example.com", "ops@example.com", "alerts@example.com"):
        assert addr not in detail
