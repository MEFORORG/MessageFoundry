"""The AI-assistance policy model: the clamping algorithm, [ai] settings, and the /ai/policy endpoint.

``resolve_effective_policy`` is pure, so the bulk here is a direct truth-table + an exhaustive sweep
over every (mode x scope x environment) asserting the invariants. The endpoint test mirrors the
existing API patterns (httpx ASGI transport, ``allow_no_auth`` for the system identity, an
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
    AiEnvironment,
    AiMode,
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


def _resolve(mode: AiMode, scope: AiDataScope, env: AiEnvironment) -> EffectivePolicy:
    return resolve_effective_policy(mode=mode, data_scope=scope, environment=env)


# --- the required truth-table cases (CONTRACT) -------------------------------


def test_byo_code_only_prod_passes_through() -> None:
    eff = _resolve(AiMode.BYO, AiDataScope.CODE_ONLY, AiEnvironment.PROD)
    assert eff.data_scope is AiDataScope.CODE_ONLY
    assert eff.mode is AiMode.BYO
    assert eff.environment is AiEnvironment.PROD
    assert eff.reason is None  # no clamp


def test_byo_phi_prod_capped_to_code_only() -> None:
    # Non-BAA mode in prod floors at code_only (the environment ceiling does the capping).
    eff = _resolve(AiMode.BYO, AiDataScope.PHI, AiEnvironment.PROD)
    assert eff.data_scope is AiDataScope.CODE_ONLY
    assert eff.reason is not None


def test_managed_baa_phi_prod_is_the_phi_safe_end() -> None:
    # The full PHI-safe end of the spectrum: BAA-managed + prod reaches phi with no clamp.
    eff = _resolve(AiMode.MANAGED_CLAUDE_BAA, AiDataScope.PHI, AiEnvironment.PROD)
    assert eff.data_scope is AiDataScope.PHI
    assert eff.mode is AiMode.MANAGED_CLAUDE_BAA
    assert eff.reason is None


def test_managed_baa_deidentified_prod_blocked() -> None:
    # deidentified needs the unbuilt de-id framework -> always falls back to code_only.
    eff = _resolve(AiMode.MANAGED_CLAUDE_BAA, AiDataScope.DEIDENTIFIED, AiEnvironment.PROD)
    assert eff.data_scope is AiDataScope.CODE_ONLY
    assert "deidentified" in (eff.reason or "")


def test_byo_phi_dev_capped_to_synthetic() -> None:
    eff = _resolve(AiMode.BYO, AiDataScope.PHI, AiEnvironment.DEV)
    assert eff.data_scope is AiDataScope.SYNTHETIC  # dev ceiling
    assert eff.reason is not None


def test_byo_deidentified_dev_capped_to_synthetic() -> None:
    # The dev ceiling (synthetic) is reached before the deidentified rule, so the result is synthetic.
    eff = _resolve(AiMode.BYO, AiDataScope.DEIDENTIFIED, AiEnvironment.DEV)
    assert eff.data_scope is AiDataScope.SYNTHETIC
    assert eff.reason is not None


def test_managed_baa_synthetic_prod_passes_through() -> None:
    eff = _resolve(AiMode.MANAGED_CLAUDE_BAA, AiDataScope.SYNTHETIC, AiEnvironment.PROD)
    assert eff.data_scope is AiDataScope.SYNTHETIC
    assert eff.reason is None  # synthetic <= phi ceiling, no clamp


def test_off_phi_prod_normalizes_to_code_only() -> None:
    eff = _resolve(AiMode.OFF, AiDataScope.PHI, AiEnvironment.PROD)
    assert eff.mode is AiMode.OFF  # mode is never clamped
    assert eff.data_scope is AiDataScope.CODE_ONLY


def test_defaults_byo_code_only_prod() -> None:
    # The AiSettings default triple resolves cleanly with no clamp.
    eff = _resolve(AiMode.BYO, AiDataScope.CODE_ONLY, AiEnvironment.PROD)
    assert eff.data_scope is AiDataScope.CODE_ONLY
    assert eff.reason is None


# --- staging behaves like dev (synthetic ceiling) ----------------------------


def test_staging_ceiling_is_synthetic() -> None:
    assert _resolve(AiMode.BYO, AiDataScope.PHI, AiEnvironment.STAGING).data_scope is (
        AiDataScope.SYNTHETIC
    )
    # Even a BAA-managed mode cannot exceed synthetic outside prod.
    assert (
        _resolve(AiMode.MANAGED_CLAUDE_BAA, AiDataScope.PHI, AiEnvironment.STAGING).data_scope
        is AiDataScope.SYNTHETIC
    )


# --- exhaustive sweep over every combination, asserting the invariants --------


def _ceiling(mode: AiMode, env: AiEnvironment) -> AiDataScope:
    if env is AiEnvironment.PROD:
        return AiDataScope.PHI if mode is AiMode.MANAGED_CLAUDE_BAA else AiDataScope.CODE_ONLY
    return AiDataScope.SYNTHETIC


@pytest.mark.parametrize(
    ("mode", "scope", "env"),
    list(itertools.product(AiMode, AiDataScope, AiEnvironment)),
)
def test_invariants_over_all_combinations(
    mode: AiMode, scope: AiDataScope, env: AiEnvironment
) -> None:
    eff = _resolve(mode, scope, env)

    # mode is NEVER clamped by environment.
    assert eff.mode is mode
    assert eff.environment is env

    # 1. effective scope never exceeds the environment ceiling.
    assert _SCOPE_ORDER[eff.data_scope] <= _SCOPE_ORDER[_ceiling(mode, env)]

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
    if _SCOPE_ORDER[_ceiling(mode, env)] < _SCOPE_ORDER[pre_off]:  # rule 1
        pre_off = _ceiling(mode, env)
    if pre_off is AiDataScope.PHI and mode is not AiMode.MANAGED_CLAUDE_BAA:  # rule 2
        pre_off = AiDataScope.CODE_ONLY
    expect_reason = pre_off is not scope or scope is AiDataScope.DEIDENTIFIED  # rule 3 always notes
    assert (eff.reason is not None) == expect_reason


def test_managed_claude_non_baa_phi_prod_capped() -> None:
    # managed_claude (NOT the BAA variant) is treated like any non-BAA mode by the prod ceiling:
    # it floors at code_only. The ceiling subsumes the phi rule, so only one clamp reason is recorded.
    eff = _resolve(AiMode.MANAGED_CLAUDE, AiDataScope.PHI, AiEnvironment.PROD)
    assert eff.data_scope is AiDataScope.CODE_ONLY
    assert eff.reason is not None
    assert "; " not in eff.reason  # a single clamp note, not a join of several


def test_effective_policy_is_frozen() -> None:
    eff = _resolve(AiMode.BYO, AiDataScope.CODE_ONLY, AiEnvironment.PROD)
    with pytest.raises(Exception):  # frozen dataclass -> FrozenInstanceError
        eff.mode = AiMode.OFF  # type: ignore[misc]


# --- AiSettings defaults + MEFOR_AI_* env loading ----------------------------


def test_ai_settings_defaults() -> None:
    ai = AiSettings()
    assert ai.mode is AiMode.BYO
    assert ai.data_scope is AiDataScope.CODE_ONLY
    assert ai.environment is AiEnvironment.PROD  # unset resolves to the safest prod ceiling
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
    assert s.ai.environment is AiEnvironment.PROD


def test_ai_env_vars_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    s = load_settings(
        environ={
            "MEFOR_AI_MODE": "managed_claude_baa",
            "MEFOR_AI_DATA_SCOPE": "phi",
            "MEFOR_AI_ENVIRONMENT": "dev",
            "MEFOR_AI_BAA_ATTESTED": "true",
            "MEFOR_AI_ENDPOINT": "https://broker.example/internal",
        }
    )
    assert s.ai.mode is AiMode.MANAGED_CLAUDE_BAA
    assert s.ai.data_scope is AiDataScope.PHI
    assert s.ai.environment is AiEnvironment.DEV
    assert s.ai.baa_attested is True  # str -> bool coercion
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
    assert s.ai.environment is AiEnvironment.STAGING


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
    # the policy reflects the attached [ai] settings.
    ai = AiSettings(
        mode=AiMode.BYO, data_scope=AiDataScope.SYNTHETIC, environment=AiEnvironment.DEV
    )
    app = create_app(engine, ai_settings=ai, allow_no_auth=True)
    async with _client(app) as c:
        body = (await c.get("/ai/policy")).json()
    assert body["mode"] == "byo"
    assert body["data_scope"] == "synthetic"
    assert body["environment"] == "dev"
    assert body["assist_permitted"] is True
    assert body["reason"] is None


async def test_ai_policy_default_settings_when_none_attached(engine: Engine) -> None:
    # No ai_settings attached -> the endpoint falls back to AiSettings() defaults (byo/code_only/prod).
    app = create_app(engine, allow_no_auth=True)
    async with _client(app) as c:
        body = (await c.get("/ai/policy")).json()
    assert body["mode"] == "byo"
    assert body["data_scope"] == "code_only"
    assert body["environment"] == "prod"
    assert body["assist_permitted"] is True


async def test_ai_policy_baa_phi_prod_resolves_to_phi(engine: Engine) -> None:
    ai = AiSettings(
        mode=AiMode.MANAGED_CLAUDE_BAA, data_scope=AiDataScope.PHI, environment=AiEnvironment.PROD
    )
    app = create_app(engine, ai_settings=ai, allow_no_auth=True)
    async with _client(app) as c:
        body = (await c.get("/ai/policy")).json()
    assert body["data_scope"] == "phi"  # the full PHI-safe end, no clamp
    assert body["reason"] is None


async def test_ai_policy_byo_phi_prod_clamped_to_code_only(engine: Engine) -> None:
    ai = AiSettings(mode=AiMode.BYO, data_scope=AiDataScope.PHI, environment=AiEnvironment.PROD)
    app = create_app(engine, ai_settings=ai, allow_no_auth=True)
    async with _client(app) as c:
        body = (await c.get("/ai/policy")).json()
    assert body["mode"] == "byo"
    assert body["data_scope"] == "code_only"  # capped by the prod ceiling for a non-BAA mode
    assert body["reason"] is not None


async def test_ai_policy_tokenless_under_enabled_auth_is_null(engine: Engine) -> None:
    # With auth enabled but NO token, optional_identity returns None -> assist_permitted is null
    # (unknown), while mode/scope are still served so a central 'off' is honored by a tokenless IDE.
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    ai = AiSettings(
        mode=AiMode.OFF, data_scope=AiDataScope.CODE_ONLY, environment=AiEnvironment.PROD
    )
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
