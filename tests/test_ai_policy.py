# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The AI-assistance policy model: the clamping algorithm, [ai] settings, and the /ai/policy endpoint.

``resolve_effective_policy`` is pure, so the bulk here is a direct truth-table + an exhaustive sweep
over every (mode x scope x production) asserting the invariants. The posture (``production`` /
``data_class``) is **decoupled from the environment name** (ADR 0017), so the settings tests also cover
free-form names, known-name posture derivation, and the fail-closed custom-name path. The endpoint test
mirrors the existing API patterns (httpx ASGI transport, ``allow_no_auth`` for the system identity, an
``AuthService`` + login for the token-bearing / tokenless cases)."""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.ai_policy import (
    AiDataScope,
    AiMode,
    DataClass,
    EffectivePolicy,
    resolve_effective_policy,
)
from messagefoundry.config.settings import AiSettings, AuthSettings, load_settings
from messagefoundry.pipeline import Engine

# Scope ordering least->most sensitive, used to assert "never exceeds the ceiling".
_SCOPE_ORDER = {
    AiDataScope.CODE_ONLY: 0,
    AiDataScope.SYNTHETIC: 1,
    AiDataScope.DEIDENTIFIED: 2,
    AiDataScope.PHI: 3,
}


def _resolve(mode: AiMode, scope: AiDataScope, production: bool) -> EffectivePolicy:
    return resolve_effective_policy(mode=mode, data_scope=scope, production=production)


# --- the required truth-table cases (CONTRACT) -------------------------------


def test_byo_code_only_production_passes_through() -> None:
    eff = _resolve(AiMode.BYO, AiDataScope.CODE_ONLY, production=True)
    assert eff.data_scope is AiDataScope.CODE_ONLY
    assert eff.mode is AiMode.BYO
    assert eff.reason is None  # no clamp


def test_byo_phi_production_capped_to_code_only() -> None:
    # Non-BAA mode on a production instance floors at code_only (the posture ceiling does the capping).
    eff = _resolve(AiMode.BYO, AiDataScope.PHI, production=True)
    assert eff.data_scope is AiDataScope.CODE_ONLY
    assert eff.reason is not None


def test_managed_baa_phi_production_is_the_phi_safe_end() -> None:
    # The full PHI-safe end of the spectrum: BAA-managed + production reaches phi with no clamp.
    eff = _resolve(AiMode.MANAGED_CLAUDE_BAA, AiDataScope.PHI, production=True)
    assert eff.data_scope is AiDataScope.PHI
    assert eff.mode is AiMode.MANAGED_CLAUDE_BAA
    assert eff.reason is None


def test_managed_baa_deidentified_production_blocked() -> None:
    # deidentified needs the unbuilt de-id framework -> always falls back to code_only.
    eff = _resolve(AiMode.MANAGED_CLAUDE_BAA, AiDataScope.DEIDENTIFIED, production=True)
    assert eff.data_scope is AiDataScope.CODE_ONLY
    assert "deidentified" in (eff.reason or "")


def test_byo_phi_nonproduction_capped_to_synthetic() -> None:
    eff = _resolve(AiMode.BYO, AiDataScope.PHI, production=False)
    assert eff.data_scope is AiDataScope.SYNTHETIC  # non-production ceiling
    assert eff.reason is not None


def test_byo_deidentified_nonproduction_capped_to_synthetic() -> None:
    # The non-production ceiling (synthetic) is reached before the deidentified rule, so synthetic.
    eff = _resolve(AiMode.BYO, AiDataScope.DEIDENTIFIED, production=False)
    assert eff.data_scope is AiDataScope.SYNTHETIC
    assert eff.reason is not None


def test_managed_baa_synthetic_production_passes_through() -> None:
    eff = _resolve(AiMode.MANAGED_CLAUDE_BAA, AiDataScope.SYNTHETIC, production=True)
    assert eff.data_scope is AiDataScope.SYNTHETIC
    assert eff.reason is None  # synthetic <= phi ceiling, no clamp


def test_off_phi_production_normalizes_to_code_only() -> None:
    eff = _resolve(AiMode.OFF, AiDataScope.PHI, production=True)
    assert eff.mode is AiMode.OFF  # mode is never clamped
    assert eff.data_scope is AiDataScope.CODE_ONLY


def test_defaults_byo_code_only_production() -> None:
    # byo + code_only resolves cleanly with no clamp at the strictest (production) posture.
    eff = _resolve(AiMode.BYO, AiDataScope.CODE_ONLY, production=True)
    assert eff.data_scope is AiDataScope.CODE_ONLY
    assert eff.reason is None


# --- a non-production instance has a synthetic ceiling (was: dev/staging) -----


def test_nonproduction_ceiling_is_synthetic() -> None:
    assert _resolve(AiMode.BYO, AiDataScope.PHI, production=False).data_scope is (
        AiDataScope.SYNTHETIC
    )
    # Even a BAA-managed mode cannot exceed synthetic on a non-production instance.
    assert (
        _resolve(AiMode.MANAGED_CLAUDE_BAA, AiDataScope.PHI, production=False).data_scope
        is AiDataScope.SYNTHETIC
    )


# --- exhaustive sweep over every combination, asserting the invariants --------


def _ceiling(mode: AiMode, production: bool) -> AiDataScope:
    if production:
        return AiDataScope.PHI if mode is AiMode.MANAGED_CLAUDE_BAA else AiDataScope.CODE_ONLY
    return AiDataScope.SYNTHETIC


@pytest.mark.parametrize(
    ("mode", "scope", "production"),
    list(itertools.product(AiMode, AiDataScope, (True, False))),
)
def test_invariants_over_all_combinations(
    mode: AiMode, scope: AiDataScope, production: bool
) -> None:
    eff = _resolve(mode, scope, production)

    # mode is NEVER clamped by posture.
    assert eff.mode is mode

    # 1. effective scope never exceeds the posture ceiling.
    assert _SCOPE_ORDER[eff.data_scope] <= _SCOPE_ORDER[_ceiling(mode, production)]

    # 2. deidentified is never an effective output (the de-id framework is unbuilt).
    assert eff.data_scope is not AiDataScope.DEIDENTIFIED

    # 3. phi is an effective output ONLY when mode == managed_claude_baa.
    if eff.data_scope is AiDataScope.PHI:
        assert mode is AiMode.MANAGED_CLAUDE_BAA

    # 4. mode == off yields code_only regardless of requested scope.
    if mode is AiMode.OFF:
        assert eff.data_scope is AiDataScope.CODE_ONLY

    # reason is None exactly when none of the *reason-producing* rules fired. Per the CONTRACT only
    # the ceiling cap (1), the phi rule (2), and the deid rule (3) record a reason — the off
    # normalization (4) silently pins scope to the floor without a note ("scope is irrelevant when
    # AI is off"). So model the reason on the pre-off scope: a reason is expected iff the requested
    # scope would have been clamped before the off step.
    pre_off = scope
    if _SCOPE_ORDER[_ceiling(mode, production)] < _SCOPE_ORDER[pre_off]:  # rule 1
        pre_off = _ceiling(mode, production)
    if pre_off is AiDataScope.PHI and mode is not AiMode.MANAGED_CLAUDE_BAA:  # rule 2
        pre_off = AiDataScope.CODE_ONLY
    expect_reason = pre_off is not scope or scope is AiDataScope.DEIDENTIFIED  # rule 3 always notes
    assert (eff.reason is not None) == expect_reason


def test_managed_claude_non_baa_phi_production_capped() -> None:
    # managed_claude (NOT the BAA variant) is treated like any non-BAA mode by the production ceiling:
    # it floors at code_only. The ceiling subsumes the phi rule, so only one clamp reason is recorded.
    eff = _resolve(AiMode.MANAGED_CLAUDE, AiDataScope.PHI, production=True)
    assert eff.data_scope is AiDataScope.CODE_ONLY
    assert eff.reason is not None
    assert "; " not in eff.reason  # a single clamp note, not a join of several


def test_effective_policy_is_frozen() -> None:
    eff = _resolve(AiMode.BYO, AiDataScope.CODE_ONLY, production=True)
    with pytest.raises(Exception):  # frozen dataclass -> FrozenInstanceError
        eff.mode = AiMode.OFF  # type: ignore[misc]


# --- AiSettings: free-form name, posture, and derivation (ADR 0017) ----------


def test_ai_settings_defaults() -> None:
    ai = AiSettings()
    assert ai.mode is AiMode.BYO
    assert ai.data_scope is AiDataScope.CODE_ONLY
    assert ai.environment is None  # no default — serve requires it (no silent PROD)
    assert ai.data_class is None
    assert ai.production is None
    # forward-compat fields are accepted-but-unused in the MVP.
    assert ai.provider == "claude"
    assert ai.model == "claude-opus-4-8"
    assert ai.baa_attested is False
    assert ai.endpoint is None


def test_ai_settings_default_on_service_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)  # no ./messagefoundry.toml
    s = load_settings(environ={})
    assert s.ai.mode is AiMode.BYO
    assert s.ai.data_scope is AiDataScope.CODE_ONLY
    assert s.ai.environment is None  # unset — no silent default


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("dev", (DataClass.SYNTHETIC, False)),
        ("staging", (DataClass.PHI, False)),
        ("prod", (DataClass.PHI, True)),
    ],
)
def test_known_name_posture_derived(name: str, expected: tuple[DataClass, bool]) -> None:
    # The built-in names keep their original posture tiers when data_class/production are unset.
    ai = AiSettings(environment=name)
    assert ai.derived_posture() == expected
    assert ai.require_posture() == expected


def test_custom_name_requires_explicit_posture() -> None:
    # A custom env name has no built-in posture: derived_posture leaves it unresolved, and the
    # fail-closed require_posture raises so a custom instance never defaults permissive (ADR 0017).
    ai = AiSettings(environment="poc")
    assert ai.derived_posture() == (None, None)
    with pytest.raises(ValueError, match="no built-in security posture"):
        ai.require_posture()


def test_custom_name_with_explicit_posture_resolves() -> None:
    ai = AiSettings(environment="poc", data_class=DataClass.PHI, production=False)
    assert ai.require_posture() == (DataClass.PHI, False)


def test_explicit_posture_overrides_known_name() -> None:
    # Explicit fields win over the built-in derivation (a 'prod'-named but synthetic/non-prod box).
    ai = AiSettings(environment="prod", data_class=DataClass.SYNTHETIC, production=False)
    assert ai.require_posture() == (DataClass.SYNTHETIC, False)


def test_environment_name_must_be_a_safe_token() -> None:
    AiSettings(environment="poc_1")  # ok: letters/digits/._-
    with pytest.raises(ValueError, match="environments/<name>.toml"):
        AiSettings(environment="bad/name")  # a path separator is rejected
    with pytest.raises(ValueError):
        AiSettings(environment="")  # empty is rejected


def test_ai_env_vars_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    s = load_settings(
        environ={
            "MEFOR_AI_MODE": "managed_claude_baa",
            "MEFOR_AI_DATA_SCOPE": "phi",
            "MEFOR_AI_ENVIRONMENT": "test",  # a custom name parses fine
            "MEFOR_AI_DATA_CLASS": "phi",
            "MEFOR_AI_PRODUCTION": "true",
            "MEFOR_AI_BAA_ATTESTED": "true",
            "MEFOR_AI_ENDPOINT": "https://broker.example/internal",
        }
    )
    assert s.ai.mode is AiMode.MANAGED_CLAUDE_BAA
    assert s.ai.data_scope is AiDataScope.PHI
    assert s.ai.environment == "test"
    assert s.ai.data_class is DataClass.PHI  # str -> enum coercion
    assert s.ai.production is True  # str -> bool coercion
    assert s.ai.require_posture() == (DataClass.PHI, True)
    assert s.ai.baa_attested is True
    assert s.ai.endpoint == "https://broker.example/internal"


def test_ai_settings_from_toml(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        '[ai]\nmode = "off"\ndata_scope = "synthetic"\nenvironment = "staging"\n',
        encoding="utf-8",
    )
    s = load_settings(config_path=cfg, environ={})
    assert s.ai.mode is AiMode.OFF
    assert s.ai.data_scope is AiDataScope.SYNTHETIC
    assert s.ai.environment == "staging"  # a free-form string, not an enum
    assert s.ai.require_posture() == (DataClass.PHI, False)  # derived from the built-in name


# --- GET /ai/policy endpoint -------------------------------------------------

PW = "Sup3rSecret!!"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "ai_policy.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _client(app: object) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def test_ai_policy_open_app_reflects_settings_and_grants_assist(engine: Engine) -> None:
    # allow_no_auth -> the system identity holds every permission, so assist_permitted is True, and
    # the policy reflects the attached [ai] settings (a non-production 'dev' instance).
    ai = AiSettings(mode=AiMode.BYO, data_scope=AiDataScope.SYNTHETIC, environment="dev")
    app = create_app(engine, ai_settings=ai, allow_no_auth=True)
    async with _client(app) as c:
        body = (await c.get("/ai/policy")).json()
    assert body["mode"] == "byo"
    assert body["data_scope"] == "synthetic"
    assert body["environment"] == "dev"
    assert body["data_class"] == "synthetic"
    assert body["production"] is False
    assert body["assist_permitted"] is True
    assert body["reason"] is None


async def test_ai_policy_default_settings_when_none_attached(engine: Engine) -> None:
    # No ai_settings attached -> AiSettings() defaults: env unset (None) and the policy falls back to
    # the STRICTEST ceiling (production) so a misconfigured instance never under-clamps.
    app = create_app(engine, allow_no_auth=True)
    async with _client(app) as c:
        body = (await c.get("/ai/policy")).json()
    assert body["mode"] == "byo"
    assert body["data_scope"] == "code_only"
    assert body["environment"] is None
    assert body["production"] is True  # unresolved posture -> strictest
    assert body["assist_permitted"] is True


async def test_ai_policy_baa_phi_production_resolves_to_phi(engine: Engine) -> None:
    ai = AiSettings(mode=AiMode.MANAGED_CLAUDE_BAA, data_scope=AiDataScope.PHI, environment="prod")
    app = create_app(engine, ai_settings=ai, allow_no_auth=True)
    async with _client(app) as c:
        body = (await c.get("/ai/policy")).json()
    assert body["data_scope"] == "phi"  # the full PHI-safe end, no clamp
    assert body["production"] is True
    assert body["reason"] is None


async def test_ai_policy_byo_phi_production_clamped_to_code_only(engine: Engine) -> None:
    ai = AiSettings(mode=AiMode.BYO, data_scope=AiDataScope.PHI, environment="prod")
    app = create_app(engine, ai_settings=ai, allow_no_auth=True)
    async with _client(app) as c:
        body = (await c.get("/ai/policy")).json()
    assert body["mode"] == "byo"
    assert body["data_scope"] == "code_only"  # capped by the production ceiling for a non-BAA mode
    assert body["reason"] is not None


async def test_ai_policy_tokenless_under_enabled_auth_is_null(engine: Engine) -> None:
    # With auth enabled but NO token, optional_identity returns None -> assist_permitted is null
    # (unknown), while mode/scope are still served so a central 'off' is honored by a tokenless IDE.
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    ai = AiSettings(mode=AiMode.OFF, data_scope=AiDataScope.CODE_ONLY, environment="prod")
    app = create_app(engine, auth=service, ai_settings=ai)
    async with _client(app) as c:
        r = await c.get("/ai/policy")  # no Authorization header
    assert r.status_code == 200  # read-only policy is never gated by require()
    body = r.json()
    assert body["assist_permitted"] is None
    assert body["mode"] == "off"  # the central off is visible without a token


async def test_ai_policy_assist_permitted_reflects_role(engine: Engine) -> None:
    # A coding-role token holds ai:assist (True); a viewer-role token does not (False).
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    for username, role in (("coder", Role.CODING), ("vw", Role.VIEWER)):
        await service.create_local_user(
            username=username,
            password=PW,
            display_name=None,
            email=None,
            roles=[role.value],
            actor="test",
        )
    app = create_app(engine, auth=service)
    async with _client(app) as c:
        coder_tok = (
            await c.post("/auth/login", json={"username": "coder", "password": PW})
        ).json()["token"]
        vw_tok = (await c.post("/auth/login", json={"username": "vw", "password": PW})).json()[
            "token"
        ]
        coder = (await c.get("/ai/policy", headers={"Authorization": f"Bearer {coder_tok}"})).json()
        viewer = (await c.get("/ai/policy", headers={"Authorization": f"Bearer {vw_tok}"})).json()
    assert coder["assist_permitted"] is True  # coding role grants ai:assist
    assert viewer["assist_permitted"] is False  # viewer role does not
