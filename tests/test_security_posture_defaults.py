# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The shipped-default posture lane: ONE posture, and operators may only LOOSEN from it.

Two defaults moved to the hardened value (ADR 0148 GIVEN 1 — the hardened path is the shipped path, so it
is the path every test, CI leg and dogfood instance exercises, not one first met in production):

* ``[store].aad_bind`` ``false`` → **``true``** (ADR 0019, 2026-07-28 amendment) — at-rest values are
  cell-bound (``mfenc:v2``) by default;
* ``[auth].ad_session_recheck_seconds`` ``0`` → **``300``** (ADR 0079, 2026-07-28 amendment) — directory
  revocation propagates by default.

The governing rule is that every deviation from that one posture is VISIBLE: ``security_loosenings()`` +
``GET /security/posture`` + ``docs/SECURITY-LOOSENING.md``. A deviation the registry cannot see is a
second posture by the back door, so these tests are as much about the REGISTRY as about the defaults —
including a completeness floor, because a registry with no floor is exactly the shape that lets a later
switch be added at an insecure value with nothing reporting it.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.settings import (
    AuthSettings,
    SecuritySettings,
    ServiceSettings,
    StoreSettings,
    load_settings,
    security_loosenings,
)
from messagefoundry.pipeline import Engine


def _ad(**over: object) -> AuthSettings:
    """AD-enabled auth settings with the connection essentials the model requires."""
    base: dict[str, object] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.test.invalid",
        "ad_user_search_base": "OU=Staff,DC=test,DC=invalid",
        "ad_bind_dn": "CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        "ad_bind_password": "synthetic",
    }
    base.update(over)
    return AuthSettings(**base)  # type: ignore[arg-type]


def _names(
    sec: SecuritySettings | None = None,
    store: StoreSettings | None = None,
    auth: AuthSettings | None = None,
    cleartext_hops: tuple[str, ...] = (),
) -> list[str]:
    """The loosening SWITCH NAMES for a settings combination (defaults where not overridden)."""
    return [
        name
        for name, _ in security_loosenings(
            sec or SecuritySettings(),
            store or StoreSettings(),
            auth or AuthSettings(),
            cleartext_hops,
        )
    ]


# --- the shipped defaults themselves ---------------------------------------------------------


def test_shipped_defaults_are_the_hardened_values() -> None:
    """Both flips, pinned at the model. A default that moves back reds here first."""
    settings = ServiceSettings()
    assert settings.store.aad_bind is True
    assert settings.auth.ad_session_recheck_seconds == 300


def test_the_shipped_defaults_are_not_themselves_loosenings() -> None:
    """The whole point: at the shipped defaults the registry reports NOTHING. If a hardened default
    were reported as a deviation, the list would be noise and operators would stop reading it."""
    assert _names() == []


# --- [store].aad_bind ------------------------------------------------------------------------


def test_aad_bind_off_is_a_named_loosening() -> None:
    named = dict(
        security_loosenings(SecuritySettings(), StoreSettings(aad_bind=False), AuthSettings(), ())
    )
    assert "aad_bind" in named
    # The risk text must say what is actually lost — cell binding, i.e. at-rest INTEGRITY binding — not
    # merely that a switch is off. An operator reading the serve warning gets this sentence and nothing
    # else; "aad_bind is false" would tell them nothing they did not already know.
    assert "cell" in named["aad_bind"]


def test_aad_bind_loosening_names_its_no_op_caveat() -> None:
    """It is a genuine no-op without a store key (the identity cipher has no tag to bind), and the risk
    text says so. Reporting it as a live weakness on a keyless dev box would train operators to ignore
    the list — the failure mode a loosening registry can least afford."""
    named = dict(
        security_loosenings(SecuritySettings(), StoreSettings(aad_bind=False), AuthSettings(), ())
    )
    assert "no effect without a store key" in named["aad_bind"]


# --- [auth].ad_session_recheck_seconds -------------------------------------------------------


def test_recheck_zero_with_ad_enabled_is_a_named_loosening() -> None:
    auth = _ad(ad_session_recheck_seconds=0)
    named = dict(security_loosenings(SecuritySettings(), StoreSettings(), auth, ()))
    assert "ad_session_recheck_seconds" in named
    assert "revocation" in named["ad_session_recheck_seconds"]


def test_recheck_zero_without_ad_is_NOT_a_loosening() -> None:
    """CONDITIONAL, like allowed_client_networks. With no directory to reconcile against, 0 is not a
    weaker choice — it is the only meaningful one.

    This is the detector-can-fire half of the guard: a rule that fired on every non-AD deployment would
    be a permanent false positive, and a permanently-true warning is read as noise, not as signal."""
    assert "ad_session_recheck_seconds" not in _names(
        auth=AuthSettings(ad_session_recheck_seconds=0)
    )


def test_recheck_at_the_default_with_ad_enabled_is_not_a_loosening() -> None:
    assert "ad_session_recheck_seconds" not in _names(auth=_ad())


# --- the cross-field refusal, keyed on model_fields_set ---------------------------------------
#
# These go through load_settings, NOT the constructor. Constructing AuthSettings(...) in Python marks
# every passed field as "set", so a constructor-only test cannot distinguish the shipped default from an
# explicitly-typed 300 — which is the entire distinction the guard turns on. It would pass while proving
# nothing.


def _load(tmp_path: Path, toml: str) -> ServiceSettings:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(toml, encoding="utf-8")
    return load_settings(config_path=path)


def test_shipped_default_does_not_break_a_non_ad_deployment(tmp_path: Path) -> None:
    """The reason the refusal had to be re-keyed: with a non-zero SHIPPED default, an unconditional
    'requires ad_enabled' rule would fail startup on every deployment that does not use AD."""
    settings = _load(tmp_path, "[auth]\nlocal_users = true\n")
    assert settings.auth.ad_session_recheck_seconds == 300
    assert settings.auth.ad_enabled is False


def test_explicit_value_without_ad_still_refuses(tmp_path: Path) -> None:
    """THE test that proves the guard still bites. An operator who typed a value believes directory
    revocation now propagates; a silently-dead security control is worse than one never enabled.

    Note the value is the SAME as the shipped default — so this can only pass if the check keys on
    `model_fields_set` rather than on the value."""
    with pytest.raises(ValueError, match="ad_session_recheck_seconds requires ad_enabled"):
        _load(tmp_path, "[auth]\nad_session_recheck_seconds = 300\n")


def test_explicit_zero_without_ad_loads(tmp_path: Path) -> None:
    """Explicitly disabling the loop on a non-AD box is coherent, not an error — there is nothing to
    reconcile, and the operator has asserted no belief the refusal needs to falsify."""
    settings = _load(tmp_path, "[auth]\nad_session_recheck_seconds = 0\n")
    assert settings.auth.ad_session_recheck_seconds == 0


# --- registry completeness --------------------------------------------------------------------


def test_every_security_bool_at_its_insecure_value_is_reported() -> None:
    """A COMPLETENESS FLOOR for the registry, which otherwise has none.

    Nothing else asserts that `security_loosenings()` can SEE every switch. Under "one posture, loosen
    only", a registry with no floor is the leak-gate-blindness shape: a switch added later at an insecure
    value would simply never be reported, and the green list would keep saying "no deviations".

    Scope, stated honestly: this covers the BOOLEAN `[security]` switches whose insecure value is the
    negation of their default — the mechanical majority. Non-boolean knobs (timeouts, day counts) and the
    deliberately-conditional entries have their own targeted tests above and below; they are listed here
    as exemptions so the exemption itself is visible rather than an accident of the loop."""
    #: Bools this floor deliberately does NOT require, each with the reason it is exempt.
    exempt = {
        # Owner-confirmed secure-and-usable default; turning it ON is the hardening move, not the
        # loosening (ADR 0118 §5) — it is documented as "not a loosening" in SECURITY-LOOSENING.md.
        "audit_all_authorization_decisions",
        # ADR 0152: these ASSERT / REQUIRE a host property rather than giving one up. Neither is a
        # loosening at either value; both are documented as such.
        "memory_encryption_operator_declared",
        "require_memory_encryption_declaration",
        # ADR 0143: disabling the console SHRINKS attack surface — the opposite of a loosening.
        "serve_web_console",
        # The data-class lever has its own entry keyed on the derived posture, not a plain negation.
        "handles_real_patient_data",
        "production_instance",
    }
    for field, info in SecuritySettings.model_fields.items():
        if field in exempt or not isinstance(info.default, bool):
            continue
        flipped = SecuritySettings(**{field: not info.default})
        assert field in _names(sec=flipped), (
            f"[security].{field} at its insecure value ({not info.default}) is NOT named by "
            "security_loosenings(). Add it to the registry, or add it to this test's `exempt` set "
            "with the reason it is not a loosening — silence is not an option."
        )


# --- the API surface: GET /security/posture reports store + auth deviations --------------------


async def _posture_body(engine: Engine, **state: object) -> dict[str, object]:
    app = create_app(engine, allow_no_auth=True)
    for key, value in state.items():
        setattr(app.state, key, value)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        resp = await client.get("/security/posture")
    assert resp.status_code == 200
    body: dict[str, object] = resp.json()
    return body


@pytest.fixture
async def engine(tmp_path: Path):  # type: ignore[no-untyped-def]
    eng = await Engine.create(tmp_path / "posture.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def test_posture_route_reports_the_store_deviation(engine: Engine) -> None:
    body = await _posture_body(engine, store_settings=StoreSettings(aad_bind=False))
    switches = [entry["switch"] for entry in body["loosenings"]]  # type: ignore[index,union-attr]
    assert "aad_bind" in switches


async def test_posture_route_reports_the_auth_deviation(engine: Engine) -> None:
    body = await _posture_body(engine, auth_settings=_ad(ad_session_recheck_seconds=0))
    switches = [entry["switch"] for entry in body["loosenings"]]  # type: ignore[index,union-attr]
    assert "ad_session_recheck_seconds" in switches


async def test_posture_route_reports_nothing_at_the_shipped_defaults(engine: Engine) -> None:
    """The route must be quiet on a default instance, or its signal is worthless."""
    body = await _posture_body(engine)
    assert body["loosenings"] == []


# --- the ONE connection-scoped deviation (ADR 0153) --------------------------------------------


def test_cleartext_accepted_is_a_named_loosening() -> None:
    """ADR 0153's per-connection declaration MUST surface in the same registry as the settings
    switches. It is a deviation from the one shipped posture, and a deviation the registry cannot see is
    a second posture by the back door."""
    named = dict(
        security_loosenings(
            SecuritySettings(), StoreSettings(), AuthSettings(), ("OB_LEGACY", "OB_LAB")
        )
    )
    assert "cleartext_accepted" in named
    risk = named["cleartext_accepted"]
    # It must NAME the connections. "some connections cross a cleartext hop" is not actionable — an
    # operator has to know WHICH, because the remedy is per-connection.
    assert "OB_LEGACY" in risk and "OB_LAB" in risk
    assert "2 outbound connection(s)" in risk


def test_no_declared_hops_is_not_a_loosening() -> None:
    assert "cleartext_accepted" not in _names(cleartext_hops=())


def test_accepted_cleartext_hops_reads_the_graph() -> None:
    """The single shared reader — `messagefoundry check` and the API posture route both use it, so the
    two can never report different accepted sets."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        accepted_cleartext_hops,
        build_outbound_connection,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_PLAIN", ConnectionSpec(type=ConnectorType.TCP, settings={"host": "x", "port": 1})
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_LEGACY",
            ConnectionSpec(type=ConnectorType.TCP, settings={"host": "y", "port": 2}),
            cleartext_accepted=True,
            cleartext_reason="vendor firmware predates TLS",
        )
    )
    assert accepted_cleartext_hops(reg) == [("OB_LEGACY", "vendor firmware predates TLS")]


async def test_posture_route_reports_declared_cleartext_hops(engine: Engine) -> None:
    """The surface the owner named explicitly. The route reads the LIVE graph off the engine's registry
    runner, so a reload is reflected rather than a startup snapshot going stale."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import ConnectionSpec, Registry, build_outbound_connection

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_LEGACY",
            ConnectionSpec(type=ConnectorType.TCP, settings={"host": "127.0.0.1", "port": 5099}),
            cleartext_accepted=True,
            cleartext_reason="vendor firmware predates TLS",
        )
    )
    engine.add_registry(reg)
    body = await _posture_body(engine)
    entry = next(
        e
        for e in body["loosenings"]  # type: ignore[union-attr]
        if e["switch"] == "cleartext_accepted"  # type: ignore[index]
    )
    assert "OB_LEGACY" in entry["risk"]  # type: ignore[index]
