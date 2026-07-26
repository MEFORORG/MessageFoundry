# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Posture-keyed transport-hop refusal — the escape clamp, the per-hop attestation model field, the
[ai]->posture mapping, and the construction-time posture stamping (#200, ADR 0092)."""

from __future__ import annotations

import pytest

from messagefoundry.config.ai_policy import AiMode, DataClass, SecurityEnforcement
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import (
    AiSettings,
    EgressSettings,
    hop_insecure_escape_downgrades,
    hop_posture_from_ai,
    insecure_tls_allowed,
)
from messagefoundry.config.tls_policy import HopPosture, current_hop_posture
from messagefoundry.config.wiring import (
    File,
    Registry,
    build_outbound_connection,
)


# --- decision 2: the escape clamp (MEFOR_ALLOW_INSECURE_TLS downgrades REFUSE->WARN, non-enforcing) ---
def test_escape_clamp_non_enforcing_downgrades_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    assert insecure_tls_allowed() is True
    assert hop_insecure_escape_downgrades(enforcing=False) is True  # warn dial: may downgrade


def test_escape_clamp_is_inert_under_enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    # The behaviour change: under ENFORCE the escape can NEVER satisfy an enforcing PHI hop.
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    assert insecure_tls_allowed() is True
    assert hop_insecure_escape_downgrades(enforcing=True) is False


def test_escape_clamp_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    assert hop_insecure_escape_downgrades(enforcing=False) is False
    assert hop_insecure_escape_downgrades(enforcing=True) is False


# --- decision 3: the per-connection attestation model field, load-validated --------------------
def test_destination_attestation_defaults_off() -> None:
    d = Destination(name="OB", type=ConnectorType.REST, settings={"url": "https://x"})
    assert d.tls_hop_attested is False
    assert d.tls_hop_attested_reason is None


def test_destination_attestation_with_reason_ok() -> None:
    d = Destination(
        name="OB",
        type=ConnectorType.REST,
        settings={"url": "http://seg.internal"},
        tls_hop_attested=True,
        tls_hop_attested_reason="terminated at the mesh sidecar",
    )
    assert d.tls_hop_attested is True
    assert d.tls_hop_attested_reason == "terminated at the mesh sidecar"


def test_destination_reason_without_flag_rejected() -> None:
    with pytest.raises(ValueError, match="tls_hop_attested_reason is set without"):
        Destination(
            name="OB",
            type=ConnectorType.REST,
            settings={"url": "http://x"},
            tls_hop_attested_reason="oops no flag",
        )


def test_destination_blank_reason_rejected() -> None:
    with pytest.raises(ValueError, match="must be non-empty"):
        Destination(
            name="OB",
            type=ConnectorType.REST,
            settings={"url": "http://x"},
            tls_hop_attested=True,
            tls_hop_attested_reason="   ",
        )


def test_source_attestation_field() -> None:
    s = Source(type=ConnectorType.REMOTEFILE, settings={}, tls_hop_attested=True)
    assert s.tls_hop_attested is True
    with pytest.raises(ValueError, match="without"):
        Source(type=ConnectorType.REMOTEFILE, settings={}, tls_hop_attested_reason="x")


# --- decision 7: the [ai]->HopPosture mapping (is_phi from data_class; enforcing from [security]) --
_ENFORCE = SecurityEnforcement.ENFORCE
_WARN = SecurityEnforcement.WARN


def test_hop_posture_from_ai_builtin_names_is_phi_mapping() -> None:
    # is_phi keys on data_class (GIVEN 1, ADR 0148: dev/staging/prod all derive phi now); enforcing
    # keys on the enforcement level, DECOUPLED from the tier — at the ENFORCE default all carry
    # enforcing=True.
    dev = AiSettings(mode=AiMode.BYO, environment="dev")
    assert hop_posture_from_ai(dev, enforcement=_ENFORCE) == HopPosture(is_phi=True, enforcing=True)
    staging = AiSettings(mode=AiMode.BYO, environment="staging")
    assert hop_posture_from_ai(staging, enforcement=_ENFORCE) == HopPosture(
        is_phi=True, enforcing=True
    )
    prod = AiSettings(mode=AiMode.BYO, environment="prod")
    assert hop_posture_from_ai(prod, enforcement=_ENFORCE) == HopPosture(
        is_phi=True, enforcing=True
    )


def test_hop_posture_from_ai_enforcement_drives_enforcing() -> None:
    # enforcement=warn reproduces the historical non-production dial (enforcing=False) on every tier;
    # is_phi is unchanged. This is the dial DECOUPLING: the tier no longer sets the refuse/warn bit.
    for env, is_phi in (("dev", True), ("staging", True), ("prod", True)):
        ai = AiSettings(mode=AiMode.BYO, environment=env)
        assert hop_posture_from_ai(ai, enforcement=_WARN) == HopPosture(
            is_phi=is_phi, enforcing=False
        )
        assert hop_posture_from_ai(ai, enforcement=_ENFORCE) == HopPosture(
            is_phi=is_phi, enforcing=True
        )


def test_hop_posture_from_ai_explicit_posture_overrides_name() -> None:
    ai = AiSettings(mode=AiMode.BYO, environment="poc", data_class=DataClass.PHI, production=True)
    assert hop_posture_from_ai(ai, enforcement=_ENFORCE) == HopPosture(is_phi=True, enforcing=True)


def test_hop_posture_from_ai_custom_unresolved_fails_closed() -> None:
    # A custom env with no explicit data_class -> is_phi unknown -> strictest (fail-closed True).
    ai = AiSettings(mode=AiMode.BYO, environment="poc")
    assert hop_posture_from_ai(ai, enforcement=_ENFORCE) == HopPosture(is_phi=True, enforcing=True)


# --- decision 7 wiring: build_check_registry stamps the posture during connector construction ---
def test_build_check_registry_stamps_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.pipeline import wiring_runner as wr

    seen: list[HopPosture | None] = []

    def fake_build_destination(dest: Destination) -> object:
        # A cell built inside build_check_registry sees the stamped posture here (this is exactly
        # what a real connector's __init__ will read to key its posture-keyed refusal).
        seen.append(current_hop_posture())
        return object()

    monkeypatch.setattr(wr, "build_destination", fake_build_destination)

    reg = Registry()
    reg.add_outbound(build_outbound_connection("OB", File(directory=".")))

    posture = HopPosture(is_phi=True, enforcing=True)
    wr.build_check_registry(
        reg,
        inbound_bind_host="127.0.0.1",
        env_values={},
        egress=EgressSettings(),
        posture=posture,
    )
    assert seen == [posture]
    # The posture is scoped to the build: it is unstamped again once the call returns.
    assert current_hop_posture() is None


def test_build_check_registry_none_posture_leaves_unstamped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry.pipeline import wiring_runner as wr

    seen: list[HopPosture | None] = []
    monkeypatch.setattr(wr, "build_destination", lambda dest: seen.append(current_hop_posture()))

    reg = Registry()
    reg.add_outbound(build_outbound_connection("OB", File(directory=".")))
    wr.build_check_registry(
        reg, inbound_bind_host="127.0.0.1", env_values={}, egress=EgressSettings(), posture=None
    )
    # Unstamped -> None; the cell fail-closes on its own (treats the hop as prod-PHI).
    assert seen == [None]
