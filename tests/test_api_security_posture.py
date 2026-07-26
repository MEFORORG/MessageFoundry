# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0118 AC-5 — the read-only ``GET /security/posture`` view.

The web console shows the EFFECTIVE ``[security]`` posture (the switch values, any active loosenings, and
the synthetic-relaxation notice) through this authenticated, permission-gated route — and there is NO
endpoint that WRITES a security setting (the IDE is the sole authoring surface)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    AiSettings,
    AuthSettings,
    DataClass,
    SecuritySettings,
    StoreSettings,
)
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "posture_api.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _add_viewer(service: AuthService, username: str) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


def _app_and_client(
    engine: Engine,
    service: AuthService,
    *,
    ai_settings: AiSettings,
    security_settings: SecuritySettings,
    store_settings: StoreSettings | None = None,
) -> tuple[object, httpx.AsyncClient]:
    app = create_app(
        engine,
        auth=service,
        ai_settings=ai_settings,
        store_settings=store_settings or StoreSettings(allow_unencrypted_phi=True),
        security_settings=security_settings,
    )
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    return app, client


async def _token(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    resp = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return {"Authorization": f"Bearer {resp.json()['token']}"}


async def test_posture_reports_security_and_has_no_write_route(engine: Engine) -> None:
    service = await _service(engine)
    await _add_viewer(service, "vw")
    # A synthetic instance with two protections deliberately loosened. GIVEN 1 (ADR 0148): dev now
    # derives PHI, so a synthetic instance declares the opt-out explicitly (handles_real_patient_data
    # =False, which desugars to [ai].data_class=synthetic) — this is the path that reports the synthetic
    # relaxation + loosenings. This test builds the app directly (no _desugar_security), so the synthetic
    # posture is set on BOTH the AiSettings (drives the relaxation notice) and the SecuritySettings
    # (reported in the posture's security dict).
    ai = AiSettings(environment="dev", data_class=DataClass.SYNTHETIC)
    security = SecuritySettings(
        require_mfa=False, block_unlisted_outbound=False, handles_real_patient_data=False
    )
    app, client = _app_and_client(engine, service, ai_settings=ai, security_settings=security)

    async with client as c:
        body = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()

    # AC-5: the effective [security] switch values are reported (read-only, booleans/ints only).
    sec = body["security"]
    assert sec["require_mfa"] is False and sec["block_unlisted_outbound"] is False
    assert (
        sec["require_sign_in"] is True and sec["local_access_only"] is True
    )  # secure defaults kept
    assert sec["handles_real_patient_data"] is False  # explicit synthetic opt-out (GIVEN 1)

    # ...the active loosenings each name the risk (AC-4/AC-5)...
    loosen = {row["switch"]: row["risk"] for row in body["loosenings"]}
    assert "require_mfa" in loosen and "single-factor" in loosen["require_mfa"]
    assert (
        "block_unlisted_outbound" in loosen
        and "any destination" in loosen["block_unlisted_outbound"]
    )

    # ...and the synthetic-relaxation notice is stated (AC-6): the PHI-only gates are relaxed on synthetic.
    assert body["synthetic_relaxation"] is not None
    assert "synthetic" in body["synthetic_relaxation"] and "relaxed" in body["synthetic_relaxation"]

    # AC-5: NO endpoint writes a security setting — every /security route is read-only (GET/HEAD/OPTIONS).
    write_methods = {"POST", "PUT", "PATCH", "DELETE"}
    for route in app.routes:  # type: ignore[attr-defined]
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        if path.startswith("/security"):
            assert not (methods & write_methods), (
                f"{path} exposes a security write method: {methods}"
            )


async def test_posture_phi_instance_has_no_relaxation_and_no_loosenings(engine: Engine) -> None:
    # A PHI instance with all-secure defaults: no synthetic relaxation, no loosenings reported.
    service = await _service(engine)
    await _add_viewer(service, "vw")
    ai = AiSettings(environment="prod")  # prod → phi
    _app, client = _app_and_client(
        engine, service, ai_settings=ai, security_settings=SecuritySettings()
    )
    async with client as c:
        body = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()
    assert body["synthetic_relaxation"] is None
    assert body["loosenings"] == []


async def test_posture_reports_production_ack_switches(engine: Engine) -> None:
    # ADR 0140: a production (phi) instance with both production-PHI acks set — the read-only posture view
    # reports the switch values (booleans in the nested security dict, via model_dump) and names each as an
    # active loosening (via security_loosenings). No new top-level SecurityPosture field is needed.
    service = await _service(engine)
    await _add_viewer(service, "vw")
    ai = AiSettings(environment="prod")  # prod → phi
    security = SecuritySettings(
        allow_single_factor_admin_when_exposed=True,
        allow_unencrypted_phi_under_strict_enforcement=True,
    )
    _app, client = _app_and_client(engine, service, ai_settings=ai, security_settings=security)
    async with client as c:
        body = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()
    sec = body["security"]
    assert sec["allow_single_factor_admin_when_exposed"] is True
    assert sec["allow_unencrypted_phi_under_strict_enforcement"] is True
    loosen = {row["switch"] for row in body["loosenings"]}
    assert "allow_single_factor_admin_when_exposed" in loosen
    assert "allow_unencrypted_phi_under_strict_enforcement" in loosen
    assert body["data_class"] == "phi" and body["production"] is True


async def test_posture_surfaces_enforcement_level(engine: Engine) -> None:
    # This refactor: the security REFUSE/WARN dial is surfaced as a distinct top-level field AND in the
    # nested security dict; enforcement=warn is named as an active loosening (decoupled from the tier).
    service = await _service(engine)
    await _add_viewer(service, "vw")
    ai = AiSettings(environment="prod")  # prod → phi
    # Default (enforce) surfaces, is not a loosening.
    _app, client = _app_and_client(
        engine, service, ai_settings=ai, security_settings=SecuritySettings()
    )
    async with client as c:
        body = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()
    assert body["enforcement"] == "enforce"
    assert body["security"]["enforcement"] == "enforce"
    assert "enforcement" not in {row["switch"] for row in body["loosenings"]}
    # warn surfaces and is named as a loosening.
    from messagefoundry.config.ai_policy import SecurityEnforcement

    _app2, client2 = _app_and_client(
        engine,
        service,
        ai_settings=ai,
        security_settings=SecuritySettings(enforcement=SecurityEnforcement.WARN),
    )
    async with client2 as c:
        body2 = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()
    assert body2["enforcement"] == "warn"
    assert "enforcement" in {row["switch"] for row in body2["loosenings"]}


async def test_posture_surfaces_the_memory_encryption_readout_report_only(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR 0152 rungs 1+2 on the posture surface: a platform SELF-REPORT plus the operator's claim.

    Report-only in the ADR 0120 shape — additive, ``None`` = undeterminable, and no route behaviour
    keys on any of it. Capability and activation stay separate fields: a CPU flag ("this silicon
    can") and a guest device ("this guest is") are different facts, and fusing them is how a
    read-out becomes a false compliance claim."""
    from messagefoundry.config.memory_encryption import MemoryEncryptionReadout

    service = await _service(engine)
    await _add_viewer(service, "vw")
    ai = AiSettings(environment="prod")  # prod → phi

    # SEV-SNP-capable silicon, INACTIVE guest, operator declared → the contradiction is reported as a
    # field, not only as a startup line an operator may never see. SEV-SNP is what makes it a
    # contradiction: it is a mechanism that WOULD have a guest device node.
    monkeypatch.setattr(
        "messagefoundry.api.app.platform_memory_encryption_readout",
        lambda: MemoryEncryptionReadout(
            capability=True, active=False, mechanism="amd-sev-snp", source="test:capable-inactive"
        ),
    )
    _app, client = _app_and_client(
        engine,
        service,
        ai_settings=ai,
        security_settings=SecuritySettings(memory_encryption_operator_declared=True),
    )
    async with client as c:
        body = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()
    assert body["memory_encryption_self_reported_capability"] is True
    assert body["memory_encryption_self_reported_active"] is False
    assert body["memory_encryption_self_reported_mechanism"] == "amd-sev-snp"
    assert body["memory_encryption_readout_source"] == "test:capable-inactive"
    assert body["memory_encryption_operator_declared"] is True
    assert body["memory_encryption_readout_contradicts_declaration"] is True
    # The DISCLAIMER TRAVELS WITH THE ARTIFACT. ADR 0152 designates this endpoint the evidence
    # artifact for 11.7.1; a disclaimer that lives only in a docstring reaches nobody who reads the
    # response. Always populated, on every posture.
    assert body["memory_encryption_note"] is not None
    assert "11.7.1" in body["memory_encryption_note"]

    # An SME/TME host is memory-controller-wide encryption with NO guest interface to find, so a
    # missing device node there says nothing at all — reported as None, never as a contradiction.
    monkeypatch.setattr(
        "messagefoundry.api.app.platform_memory_encryption_readout",
        lambda: MemoryEncryptionReadout(
            capability=True, active=False, mechanism="amd-sme", source="test:sme-host"
        ),
    )
    _app_sme, client_sme = _app_and_client(
        engine,
        service,
        ai_settings=ai,
        security_settings=SecuritySettings(memory_encryption_operator_declared=True),
    )
    async with client_sme as c:
        body_sme = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()
    assert body_sme["memory_encryption_self_reported_active"] is False
    assert body_sme["memory_encryption_readout_contradicts_declaration"] is None

    # Undeterminable (the honest Windows answer) → nulls, and NOT a contradiction: "we cannot tell"
    # and "it is not there" are different answers.
    monkeypatch.setattr(
        "messagefoundry.api.app.platform_memory_encryption_readout",
        lambda: MemoryEncryptionReadout(
            capability=None, active=None, mechanism=None, source="unsupported-platform:win32"
        ),
    )
    _app2, client2 = _app_and_client(
        engine,
        service,
        ai_settings=ai,
        security_settings=SecuritySettings(memory_encryption_operator_declared=True),
    )
    async with client2 as c:
        body2 = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()
    assert body2["memory_encryption_self_reported_capability"] is None
    assert body2["memory_encryption_self_reported_active"] is None
    # NOT False. On Windows nothing is ever measured, and a `false` here beside a `true` declaration
    # is the exact artifact a compliance questionnaire quotes as corroboration.
    assert body2["memory_encryption_readout_contradicts_declaration"] is None

    # An all-defaults instance reports "nobody claimed anything", and the read-out is never a
    # loosening (it asserts a protection rather than giving one up). Nobody declared → nothing to
    # contradict → None, not a reassuring False.
    _app3, client3 = _app_and_client(
        engine, service, ai_settings=ai, security_settings=SecuritySettings()
    )
    async with client3 as c:
        body3 = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()
    assert body3["memory_encryption_operator_declared"] is False
    assert body3["memory_encryption_readout_contradicts_declaration"] is None
    assert body3["memory_encryption_note"] is not None
    assert "memory_encryption_operator_declared" not in {
        row["switch"] for row in body3["loosenings"]
    }
