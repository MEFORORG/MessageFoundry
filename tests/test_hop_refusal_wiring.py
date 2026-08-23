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
from messagefoundry.pipeline.wiring_runner import WiringError, check_inbound_revocation


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
    s = Source(
        type=ConnectorType.REMOTEFILE,
        settings={},
        tls_hop_attested=True,
        tls_hop_attested_reason="terminated at the mesh sidecar",
    )
    assert s.tls_hop_attested is True
    with pytest.raises(ValueError, match="without"):
        Source(type=ConnectorType.REMOTEFILE, settings={}, tls_hop_attested_reason="x")


def test_attestation_now_requires_a_reason() -> None:
    """ADR 0153 decision 2, retro-fitted: the flag alone is no longer a valid attestation.

    An attestation asserting *this hop is secure by means the engine cannot see* is the one input that
    can silently ALLOW an enforcing cleartext hop, so it is precisely the claim that must carry a
    written justification when it is audited. Both models enforce it, and so does [logging]'s sibling."""
    with pytest.raises(ValueError, match="requires tls_hop_attested_reason"):
        Source(type=ConnectorType.REMOTEFILE, settings={}, tls_hop_attested=True)
    with pytest.raises(ValueError, match="requires tls_hop_attested_reason"):
        Destination(
            name="OB", type=ConnectorType.REST, settings={"url": "http://x"}, tls_hop_attested=True
        )


# --- ADR 0153 decision 2: the cleartext-acceptance pair, load-validated ------------------------
def test_destination_cleartext_acceptance_defaults_off() -> None:
    d = Destination(name="OB", type=ConnectorType.REST, settings={"url": "https://x"})
    assert d.cleartext_accepted is False
    assert d.cleartext_reason is None


def test_destination_cleartext_acceptance_with_reason_ok() -> None:
    d = Destination(
        name="OB",
        type=ConnectorType.REST,
        settings={"url": "http://legacy.internal"},
        cleartext_accepted=True,
        cleartext_reason="vendor firmware predates TLS; segment is not isolated",
    )
    assert d.cleartext_accepted is True
    assert d.cleartext_reason is not None


def test_destination_cleartext_acceptance_rejects_incoherent_pairs() -> None:
    """All three fail-loud rules: flag without reason, blank reason, reason without flag."""
    with pytest.raises(ValueError, match="requires cleartext_reason"):
        Destination(
            name="OB",
            type=ConnectorType.REST,
            settings={"url": "http://x"},
            cleartext_accepted=True,
        )
    with pytest.raises(ValueError, match="must be non-empty"):
        Destination(
            name="OB",
            type=ConnectorType.REST,
            settings={"url": "http://x"},
            cleartext_accepted=True,
            cleartext_reason="   ",
        )
    with pytest.raises(ValueError, match="without cleartext_accepted"):
        Destination(
            name="OB",
            type=ConnectorType.REST,
            settings={"url": "http://x"},
            cleartext_reason="orphaned reason",
        )


def test_cleartext_acceptance_is_destination_only() -> None:
    """ADR 0153 decision 2 is explicit: putting the pair on Source would be a setting nothing consumes.

    Inbound binds are governed by a different mechanism (_inbound_insecure_bind_permitted plus the four
    exposed-gates), which this ADR does not change. Pinned so a later "symmetry" refactor cannot add a
    dead inbound knob that reads like a working control."""
    assert "cleartext_accepted" not in Source.model_fields
    assert "cleartext_reason" not in Source.model_fields
    assert "cleartext_accepted" in Destination.model_fields


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


# --- ADR 0153 decision 2: the AUTHORING surfaces for the cleartext-acceptance pair --------------


def test_outbound_factory_accepts_the_pair_and_validates_it() -> None:
    """`outbound()` / `build_outbound_connection` is the code-first surface. The coherence rules are
    enforced at THIS choke point (not only on the model), so a bad pair fails at `messagefoundry check`
    / dry-run with the connection name attached rather than at connector construction."""
    from messagefoundry.config.wiring import Tcp, WiringError

    oc = build_outbound_connection(
        "OB",
        Tcp(host="10.0.0.5", port=5000),
        cleartext_accepted=True,
        cleartext_reason="vendor firmware predates TLS",
    )
    assert oc.cleartext_accepted is True and oc.cleartext_reason is not None

    with pytest.raises(WiringError, match="requires cleartext_reason"):
        build_outbound_connection("OB", Tcp(host="10.0.0.5", port=5000), cleartext_accepted=True)
    with pytest.raises(WiringError, match="without cleartext_accepted"):
        build_outbound_connection("OB", Tcp(host="10.0.0.5", port=5000), cleartext_reason="why")


def test_connections_toml_desugars_to_the_same_declaration(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """ADR 0007's promise: the TOML surface desugars through the SAME factories into an identical
    Registry entry. Asserted on the DISPOSITION, not just the field, so a pair that survives the loader
    but never reaches the hop authority would still fail here."""
    from messagefoundry.config.wiring import Tcp, load_config
    from messagefoundry.pipeline.wiring_runner import _dest_config

    (tmp_path / "logic.py").write_text(
        "from messagefoundry import Send, handler, router\n\n"
        '@router("r")\n'
        "def route(msg):\n"
        '    return ["h"]\n\n'
        '@handler("h")\n'
        "def handle(msg):\n"
        '    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    (tmp_path / "connections.toml").write_text(
        "[[outbound]]\n"
        'name = "OB"\n'
        'transport = "tcp"\n'
        "cleartext_accepted = true\n"
        'cleartext_reason = "vendor firmware predates TLS"\n'
        "  [outbound.settings]\n"
        '  host = "10.0.0.5"\n'
        "  port = 5000\n",
        encoding="utf-8",
    )
    from_toml = load_config(tmp_path).outbound["OB"]
    from_code = build_outbound_connection(
        "OB",
        Tcp(host="10.0.0.5", port=5000),
        cleartext_accepted=True,
        cleartext_reason="vendor firmware predates TLS",
    )
    assert (from_toml.cleartext_accepted, from_toml.cleartext_reason) == (
        from_code.cleartext_accepted,
        from_code.cleartext_reason,
    )
    # ...and both reach the typed Destination the connectors decide on.
    for oc in (from_toml, from_code):
        dest = _dest_config(oc, {})
        assert dest.cleartext_accepted is True
        assert dest.cleartext_reason == "vendor firmware predates TLS"


def test_toml_rejects_the_pair_under_settings(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """They are TOP-LEVEL outbound keys, not transport settings. Under `[settings]` they are passed to
    the transport factory (which IS the settings schema) and rejected — pinned so the two surfaces
    cannot silently diverge into accepting both spellings with different semantics.

    Driven through the LOADER, not through a factory signature: a signature check is a proxy that would
    still pass if `_build_spec` ever grew a pass-through for unknown keys, which is the drift this test
    is for."""
    from messagefoundry.config.wiring import WiringError, load_config

    (tmp_path / "logic.py").write_text(
        "from messagefoundry import Send, handler, router\n\n"
        '@router("r")\n'
        "def route(msg):\n"
        '    return ["h"]\n\n'
        '@handler("h")\n'
        "def handle(msg):\n"
        '    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    (tmp_path / "connections.toml").write_text(
        "[[outbound]]\n"
        'name = "OB"\n'
        'transport = "tcp"\n'
        "  [outbound.settings]\n"
        '  host = "10.0.0.5"\n'
        "  port = 5000\n"
        "  cleartext_accepted = true\n",
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="cleartext_accepted"):
        load_config(tmp_path)


# --- ADR 0153 decision 3: NO TLS default is flipped --------------------------------------------


def test_no_transport_factory_flips_its_tls_default() -> None:
    """ADR 0153's most emphatic non-goal, pinned so it cannot rot.

    An earlier draft proposed `tls: bool = True` on the transport factories. It was sized and REJECTED:
    it is redundant (an undeclared cleartext hop already refuses), it hard-fails every inbound MLLP
    listener (`_mllp_ssl_context(server=True)` raises before any policy runs — including on the loopback
    binds arm 1 exempts), and it disarms the four inbound exposed-gates, which early-return when
    `settings["tls"]` is truthy. "Secure by default" is delivered by the REFUSAL, not by this default.
    """
    import inspect

    from messagefoundry.config.wiring import DICOM, MLLP, Ftp, Http

    for factory in (MLLP, Http, DICOM, Ftp):
        param = inspect.signature(factory).parameters["tls"]
        assert param.default is False, (
            f"{factory.__name__}() now defaults tls={param.default!r}. ADR 0153 decision 3 keeps it "
            "False on all four factories — see the ADR before changing this."
        )


def test_dest_config_mirrors_the_declaration_into_the_resolved_settings() -> None:
    """The runner's settings MIRROR is the only path a graph-authored declaration takes to the deep
    settings-driven seams — HTTP Digest, the OAuth2 / SMART token endpoints, the forward-proxy
    credential. Nothing else covers it: those seams' own tests hand the settings dict in by hand, and
    the desugaring test asserts only the typed `Destination` fields. Without this, that mirroring could
    be deleted and a declared connection using `http_auth=digest` or `oauth2_*` over cleartext would die
    at construction with no test noticing."""
    from messagefoundry.config.wiring import Tcp
    from messagefoundry.pipeline.wiring_runner import _dest_config

    declared = build_outbound_connection(
        "OB_LEGACY",
        Tcp(host="10.0.0.5", port=5000),
        cleartext_accepted=True,
        cleartext_reason="vendor firmware predates TLS",
    )
    settings = _dest_config(declared, {}).settings
    assert settings["cleartext_accepted"] is True
    assert settings["cleartext_reason"] == "vendor firmware predates TLS"
    # The NAME rides with it, so the acceptance audit record those seams emit can name the declaration.
    assert settings["cleartext_connection"] == "OB_LEGACY"


def test_dest_config_writes_no_mirror_keys_when_nothing_is_declared() -> None:
    """The other half: an undeclared outbound must be byte-identical — no empty governance keys in the
    resolved settings, which several surfaces render."""
    from messagefoundry.config.wiring import Tcp
    from messagefoundry.pipeline.wiring_runner import _dest_config

    plain = build_outbound_connection("OB_PLAIN", Tcp(host="10.0.0.5", port=5000))
    settings = _dest_config(plain, {}).settings
    assert "cleartext_accepted" not in settings
    assert "cleartext_reason" not in settings
    assert "cleartext_connection" not in settings


def test_logging_forward_hop_attestation_also_requires_a_reason() -> None:
    """Rule 3 of the retro-fit reaches `[logging].forward_hop_attested` — the documented `[logging]`
    sibling of a connection's `tls_hop_attested`, sharing the same validator.

    Asserted here rather than claimed in a sibling test's docstring: docs/PHI.md already described this
    reason as mandatory, so an unenforced rule would leave a documented guarantee false exactly where an
    auditor looks."""
    from messagefoundry.config.settings import LoggingSettings

    with pytest.raises(ValueError, match="requires tls_hop_attested_reason"):
        LoggingSettings(forward_hop_attested=True)
    # ...and the coherent pair still loads.
    ok = LoggingSettings(
        forward_hop_attested=True, forward_hop_attested_reason="management segment is isolated"
    )
    assert ok.forward_hop_attested is True


# --- BACKLOG #1005 scope 3: the revocation-gap refusal ------------------------------------------
#
# The revocation sibling of the cleartext exposed-gate above, and it fires on the OPPOSITE
# condition: those refuse a listener with NO TLS, this refuses one whose TLS is correct but whose
# client certificates are never checked for revocation. Measured on this tree, a revoked-but-
# chain-valid client is ACCEPTED, so a partner certificate revoked this morning would keep
# authenticating until its notAfter.


def _mtls(**overrides: object) -> Source:
    """An MLLP listener with mTLS ON. Paths are never opened by the gate -- it reads settings only."""
    settings: dict[str, object] = {"tls": True, "tls_cert_file": "c.pem", "tls_ca_file": "ca.pem"}
    settings.update({k: v for k, v in overrides.items() if k != "attested"})
    return Source(
        type=ConnectorType.MLLP,
        settings=settings,
        tls_revocation_attested=bool(overrides.get("attested", False)),
    )


_PHI_ENFORCING = HopPosture(is_phi=True, enforcing=True)


def test_mtls_without_a_crl_is_refused_on_an_enforcing_phi_instance() -> None:
    # THE CONTROL ITSELF. Everything below is a rung of its escape ladder, so this must fail first
    # or none of them mean anything.
    with pytest.raises(WiringError, match="no revocation"):
        check_inbound_revocation(_mtls(), "IB_PARTNER", posture=_PHI_ENFORCING)


def test_a_configured_crl_passes() -> None:
    # POSITIVE CONTROL: the refusal can be SATISFIED, not merely avoided. Without this the test
    # above would pass equally well against a gate that refuses every mTLS listener.
    check_inbound_revocation(_mtls(tls_crl_file="ca_and_crl.pem"), "IB", posture=_PHI_ENFORCING)


def test_the_per_connection_attestation_passes() -> None:
    # The surgical opt-in: a site whose PKI checks revocation OUTSIDE the engine declines the
    # in-engine control without being refused. Mirrors Destination.tls_revocation_attested, and
    # every sibling refusal here pairs with an attestation.
    check_inbound_revocation(_mtls(attested=True), "IB", posture=_PHI_ENFORCING)


def test_a_non_phi_instance_warns_rather_than_refusing() -> None:
    check_inbound_revocation(_mtls(), "IB", posture=HopPosture(is_phi=False, enforcing=True))


def test_a_non_enforcing_instance_warns_rather_than_refusing() -> None:
    check_inbound_revocation(_mtls(), "IB", posture=HopPosture(is_phi=True, enforcing=False))


def test_an_unstamped_posture_never_acquires_a_new_refusal() -> None:
    # posture=None means the check ran OUTSIDE the enforced gate -- a direct or embedding call.
    # The sibling makes the same promise, and it is what keeps this an ADD at the enforced surface
    # rather than a new refusal for callers who never opted into the gate.
    check_inbound_revocation(_mtls(), "IB", posture=None)


def test_tls_without_mtls_is_not_a_revocation_gap() -> None:
    # PLACEMENT GUARD: no tls_ca_file means no client certificate is requested, so there is nothing
    # whose revocation could matter. Refusing here would demand a CRL from every TLS listener.
    src = Source(type=ConnectorType.MLLP, settings={"tls": True, "tls_cert_file": "c.pem"})
    check_inbound_revocation(src, "IB", posture=_PHI_ENFORCING)


def test_a_connector_with_no_mtls_surface_is_ignored() -> None:
    # Raw TCP/X12 have no TLS option at all, so they cannot hold a client certificate to revoke.
    src = Source(type=ConnectorType.TCP, settings={"tls": True, "tls_ca_file": "ca.pem"})
    check_inbound_revocation(src, "IB", posture=_PHI_ENFORCING)


def test_the_dimse_and_http_listeners_are_covered_too() -> None:
    # The item's whole point is that an HTTP proxy can terminate neither MLLP framing nor DIMSE, so
    # for those the documented out-of-engine delegation does not reach. Both must be gated.
    for connector in (ConnectorType.DIMSE, ConnectorType.HTTP):
        src = Source(
            type=connector,
            settings={"tls": True, "tls_cert_file": "c.pem", "tls_ca_file": "ca.pem"},
        )
        with pytest.raises(WiringError, match="no revocation"):
            check_inbound_revocation(src, f"IB_{connector.name}", posture=_PHI_ENFORCING)
