# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Read-only ``GET /alerts/rules`` endpoint (BACKLOG #22b, ADR 0014).

The headline test is the **secret guard**: the loaded ``[alerts]`` config carries
credential-bearing fields (a webhook URL that may embed a Slack/Teams/PagerDuty token, the
SMTP password/username, recipient addresses). The endpoint exposes an allowlist model only —
transports are reported present-or-not — so none of those secrets may surface in the response.

REST is exercised with httpx's ASGI transport (async, shares this test's loop, so the real
async engine/store run). The lifespan-plumbing test uses starlette's sync TestClient against a
``create_managed_app`` app, proving the lifespan sets ``app.state.alerts_settings``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

from messagefoundry.api import create_app, create_managed_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    AlertRule,
    AlertSeverity,
    AlertsSettings,
    AuthSettings,
)
from messagefoundry.pipeline import Engine

# Sentinels planted in the two secret fields. If either ever appears in the response the endpoint
# has leaked a credential — the one thing #22b forbids.
WEBHOOK_SECRET = "ZZWEBHOOKSECRET9999"
SMTP_PASSWORD_SECRET = "ZZSMTPPASSWORD9999"

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)


def _alerts_with_secrets() -> AlertsSettings:
    """An [alerts] config with both transports configured (secrets embedded) + two rules."""
    return AlertsSettings(
        webhook_url=f"https://hooks.example.com/services/{WEBHOOK_SECRET}",
        webhook_timeout=7.5,
        webhook_allowed_hosts=["hooks.example.com"],
        email_smtp_host="smtp.example.com",
        email_smtp_port=2525,
        email_from="alerts@example.com",
        email_to=["oncall@example.com", "ops@example.com"],
        email_use_tls=True,
        email_username="smtp-user",
        email_password=SMTP_PASSWORD_SECRET,
        smtp_allowed_hosts=["smtp.example.com"],
        realert_seconds=120.0,
        rules=[
            AlertRule(
                event_type="connection_stopped",
                connection="IB_ACME_ADT",
                severity=AlertSeverity.CRITICAL,
                transports=["webhook", "email"],
                cooldown_seconds=60.0,
            ),
            AlertRule(
                event_type="queue_buildup",
                connection="OB_*",
                min_depth=500,
                min_oldest_seconds=90.0,
                severity=AlertSeverity.WARNING,
            ),
        ],
    )


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "alerts.db", poll_interval=0.02)
    eng.started_at = 1.0
    yield eng
    await eng.stop()


# --- 1. DATA: configured transports + rules round-trip -----------------------


async def test_alerts_rules_returns_configured_view(engine: Engine) -> None:
    alerts = _alerts_with_secrets()
    transport = httpx.ASGITransport(
        app=create_app(engine, allow_no_auth=True, alerts_settings=alerts)
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/alerts/rules")
    assert r.status_code == 200
    body = r.json()

    assert body["webhook_configured"] is True
    assert body["webhook_timeout"] == 7.5
    assert body["webhook_allowed_hosts"] == ["hooks.example.com"]
    assert body["email_configured"] is True
    assert body["email_smtp_port"] == 2525
    assert body["email_use_tls"] is True
    assert body["email_recipient_count"] == len(alerts.email_to) == 2
    assert body["smtp_allowed_hosts"] == ["smtp.example.com"]
    assert body["realert_seconds"] == 120.0

    rules = body["rules"]
    assert len(rules) == 2
    first = rules[0]
    assert first["event_type"] == "connection_stopped"
    assert first["connection"] == "IB_ACME_ADT"
    assert first["severity"] == "critical"  # AlertSeverity.value, a plain str
    assert first["transports"] == ["webhook", "email"]
    assert first["cooldown_seconds"] == 60.0
    second = rules[1]
    assert second["event_type"] == "queue_buildup"
    assert second["min_depth"] == 500
    assert second["min_oldest_seconds"] == 90.0
    assert second["severity"] == "warning"
    assert second["transports"] is None  # None = every configured transport


# --- 2. SECRET GUARD (the headline test) -------------------------------------


async def test_alerts_rules_never_leak_secrets(engine: Engine) -> None:
    alerts = _alerts_with_secrets()
    transport = httpx.ASGITransport(
        app=create_app(engine, allow_no_auth=True, alerts_settings=alerts)
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/alerts/rules")
    assert r.status_code == 200

    # Neither secret sentinel may appear anywhere in the serialized response.
    assert WEBHOOK_SECRET not in r.text
    assert SMTP_PASSWORD_SECRET not in r.text

    # The allowlist model cannot carry these keys — assert it explicitly so the contract is
    # regression-proof if the model ever changes.
    body = r.json()
    for forbidden in (
        "webhook_url",
        "email_password",
        "email_username",
        "email_to",
        "email_from",
        "email_smtp_host",
    ):
        assert forbidden not in body, f"response leaked forbidden key {forbidden!r}"

    # The transports are still reported present (booleans), proving we're not trivially passing
    # on an empty/scrubbed response.
    assert body["webhook_configured"] is True
    assert body["email_configured"] is True


# --- 3. DEFAULT/EMPTY: no alerts_settings → all-off ---------------------------


async def test_alerts_rules_defaults_when_unset(engine: Engine) -> None:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/alerts/rules")
    assert r.status_code == 200
    body = r.json()
    assert body["webhook_configured"] is False
    assert body["email_configured"] is False
    assert body["email_recipient_count"] == 0
    assert body["rules"] == []


# --- 4. AUTH: gated by monitoring:read ---------------------------------------


async def _auth_service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
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


async def test_alerts_rules_gated_by_monitoring_read(engine: Engine) -> None:
    # Mirror test_metrics_gated_by_monitoring_read: VIEWER holds monitoring:read (200); a role-less
    # user lacks it (403); no/invalid token fails closed (401).
    service = await _auth_service(engine)
    await _add(service, "vw", Role.VIEWER)
    await _add(service, "norole")  # empty roles list → no permissions
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, alerts_settings=_alerts_with_secrets())
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        # No token under enabled auth → fail closed (401), not an open read.
        assert (await c.get("/alerts/rules")).status_code == 401
        # An invalid token is equally rejected.
        bad = _bearer("not-a-real-token")
        assert (await c.get("/alerts/rules", headers=bad)).status_code == 401
        # VIEWER (has monitoring:read) → 200.
        vw = _bearer(await _login_token(c, "vw"))
        assert (await c.get("/alerts/rules", headers=vw)).status_code == 200
        # A role-less user lacks monitoring:read → 403.
        nr = _bearer(await _login_token(c, "norole"))
        assert (await c.get("/alerts/rules", headers=nr)).status_code == 403


# --- 5. LIFESPAN PLUMBING: create_managed_app sets app.state.alerts_settings --


def test_alerts_rules_lifespan_plumbs_alerts_settings(tmp_path: Path) -> None:
    # TestClient drives the lifespan, which creates/starts the engine on its own loop and sets
    # app.state.alerts_settings. Proving the rule shows up proves the plumbing.
    alerts = AlertsSettings(
        rules=[
            AlertRule(
                event_type="storage_threshold",
                connection="*",
                severity=AlertSeverity.INFO,
            )
        ]
    )
    app = create_managed_app(db_path=tmp_path / "managed.db", alerts_settings=alerts)
    with TestClient(app) as tc:
        r = tc.get("/alerts/rules")
        assert r.status_code == 200
        body = r.json()
        assert len(body["rules"]) == 1
        assert body["rules"][0]["event_type"] == "storage_threshold"
        assert body["rules"][0]["severity"] == "info"
