# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The per-connection ``tls_hop_attested`` authoring surface (ADR 0092, owner ruling 2026-09-24).

Before the ruling no factory took the attestation, yet ``_source_config`` / ``_dest_config`` read it
straight out of the transport settings dict. A config module could write it there and cross an
enforcing refusal with no validation at the factory and no entry in any loosening report. These tests
pin the replacement: a typed field on each declaration, the raw keys refused, and one reader behind
every report, so the gate and the reports cannot disagree about which hops are attested."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecretRotationSettings,
    SecuritySettings,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.config.wiring import (
    MLLP,
    InboundConnection,
    Registry,
    Tcp,
    WiringError,
    attested_secure_hops,
    build_inbound_connection,
    build_outbound_connection,
    env,
    load_config,
)
from messagefoundry.pipeline.wiring_runner import (
    _dest_config,
    _source_config,
    check_mllp_tls_exposure,
)

REASON = "TLS terminates at the site's stunnel sidecar"
ENFORCING = HopPosture(enforcing=True)

_LOGIC = (
    "from messagefoundry import Send, handler, router\n\n"
    '@router("r")\n'
    "def route(msg):\n"
    '    return ["h"]\n\n'
    '@handler("h")\n'
    "def handle(msg):\n"
    '    return Send("OB", msg)\n'
)


def _open_mllp_inbound(**kwargs: Any) -> InboundConnection:
    return build_inbound_connection(
        "IB", MLLP(port=2575), router="r", bind_address="0.0.0.0", **kwargs
    )


# --- the hatch the ruling closed ---------------------------------------------------------------


def test_the_raw_settings_hatch_no_longer_crosses_the_mllp_gate(tmp_path: Path) -> None:
    """The exact reproduction from the finding: write the pair into the factory's settings dict and
    declare a non-loopback MLLP bind with no TLS. It used to PASS the enforcing gate. Now the
    declaration refuses it at load, naming the supported surface."""
    (tmp_path / "feed.py").write_text(
        "from messagefoundry import MLLP, inbound, router\n"
        "_s = MLLP(port=2575)\n"
        '_s.settings["tls_hop_attested"] = True\n'
        '_s.settings["tls_hop_attested_reason"] = "x"\n'
        'inbound("IB", _s, router="r", bind_address="0.0.0.0")\n'
        '@router("r")\n'
        "def r(msg):\n"
        "    return []\n",
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="is not a transport setting"):
        load_config(tmp_path)


@pytest.mark.parametrize("key", ["tls_hop_attested", "tls_hop_attested_reason"])
def test_either_raw_key_alone_is_refused_on_both_directions(key: str) -> None:
    spec = MLLP(port=2575)
    spec.settings[key] = True if key == "tls_hop_attested" else REASON
    with pytest.raises(WiringError, match=key):
        _source_config(build_inbound_connection("IB", spec, router="r"), "127.0.0.1", {})
    out_spec = Tcp(host="10.0.0.5", port=5000)
    out_spec.settings[key] = True if key == "tls_hop_attested" else REASON
    with pytest.raises(WiringError, match=key):
        _dest_config(build_outbound_connection("OB", out_spec), {})


def test_a_raw_key_written_after_the_declaration_is_still_refused() -> None:
    """The refusal is repeated at the build choke point, because the settings dict stays mutable
    after inbound() returns and a declaration-time check alone would miss this write."""
    spec = MLLP(port=2575)
    ic = build_inbound_connection("IB", spec, router="r", bind_address="0.0.0.0")
    spec.settings["tls_hop_attested"] = True
    with pytest.raises(WiringError, match="is not a transport setting"):
        _source_config(ic, "127.0.0.1", {})


# --- the supported surface -----------------------------------------------------------------------


def test_the_declared_attestation_crosses_the_gate_and_the_undeclared_control_does_not() -> None:
    attested = _source_config(
        _open_mllp_inbound(tls_hop_attested=True, tls_hop_attested_reason=REASON),
        "127.0.0.1",
        {},
    )
    assert (attested.tls_hop_attested, attested.tls_hop_attested_reason) == (True, REASON)
    check_mllp_tls_exposure(attested, "IB", allow_insecure_bind=False, posture=ENFORCING)

    control = _source_config(_open_mllp_inbound(), "127.0.0.1", {})
    assert control.tls_hop_attested is False
    with pytest.raises(WiringError, match="without TLS"):
        check_mllp_tls_exposure(control, "IB", allow_insecure_bind=False, posture=ENFORCING)


def test_the_bind_warning_records_the_attestation_reason(caplog: pytest.LogCaptureFixture) -> None:
    """An attested bind is ALLOWed, so its WARNING line is where the operator's reason is kept. The
    flag route names only the flag, since it has no reason."""
    attested = _source_config(
        _open_mllp_inbound(tls_hop_attested=True, tls_hop_attested_reason=REASON), "127.0.0.1", {}
    )
    with caplog.at_level("WARNING"):
        check_mllp_tls_exposure(attested, "IB", allow_insecure_bind=False, posture=ENFORCING)
    assert f"tls_hop_attested; reason: {REASON}" in caplog.text

    caplog.clear()
    flagged = _source_config(_open_mllp_inbound(), "127.0.0.1", {})
    with caplog.at_level("WARNING"):
        check_mllp_tls_exposure(flagged, "IB", allow_insecure_bind=True, posture=None)
    # PR 1510's wording: serve folds require_encryption_for_remote = false into the same flag.
    assert "(--allow-insecure-bind / require_encryption_for_remote = false)" in caplog.text
    assert "tls_hop_attested" not in caplog.text


def test_the_declared_pair_is_mirrored_for_the_settings_driven_seams() -> None:
    """The SMART, OAuth2, Digest and FTP seams read only a settings mapping, so the declared pair is
    mirrored there. Written only when declared, so an undeclared connection is byte-identical."""
    dest = _dest_config(
        build_outbound_connection(
            "OB",
            Tcp(host="10.0.0.5", port=5000),
            tls_hop_attested=True,
            tls_hop_attested_reason=REASON,
        ),
        {},
    )
    assert (dest.tls_hop_attested, dest.tls_hop_attested_reason) == (True, REASON)
    assert dest.settings["tls_hop_attested"] is True
    assert dest.settings["tls_hop_attested_reason"] == REASON

    plain = _dest_config(build_outbound_connection("OB", Tcp(host="10.0.0.5", port=5000)), {})
    assert "tls_hop_attested" not in plain.settings
    assert "tls_hop_attested_reason" not in plain.settings


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"tls_hop_attested": True}, "requires tls_hop_attested_reason"),
        ({"tls_hop_attested_reason": REASON}, "set without tls_hop_attested=true"),
        ({"tls_hop_attested": True, "tls_hop_attested_reason": "  "}, "must be non-empty"),
    ],
)
def test_an_incoherent_pair_fails_at_declaration_in_both_directions(
    kwargs: dict[str, Any], match: str
) -> None:
    with pytest.raises(WiringError, match=f"inbound connection 'IB'.*{match}"):
        build_inbound_connection("IB", MLLP(port=2575), router="r", **kwargs)
    with pytest.raises(WiringError, match=f"outbound connection 'OB'.*{match}"):
        build_outbound_connection("OB", Tcp(host="10.0.0.5", port=5000), **kwargs)


def test_connections_toml_takes_the_pair_top_level_on_both_directions(tmp_path: Path) -> None:
    (tmp_path / "logic.py").write_text(_LOGIC, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(
        "[[inbound]]\n"
        'name = "IB"\n'
        'transport = "mllp"\n'
        'router = "r"\n'
        'bind_address = "0.0.0.0"\n'
        "tls_hop_attested = true\n"
        f'tls_hop_attested_reason = "{REASON}"\n'
        "  [inbound.settings]\n"
        "  port = 2575\n"
        "[[outbound]]\n"
        'name = "OB"\n'
        'transport = "tcp"\n'
        "tls_hop_attested = true\n"
        f'tls_hop_attested_reason = "{REASON}"\n'
        "  [outbound.settings]\n"
        '  host = "10.0.0.5"\n'
        "  port = 5000\n",
        encoding="utf-8",
    )
    registry = load_config(tmp_path)
    source = _source_config(registry.inbound["IB"], "127.0.0.1", {})
    check_mllp_tls_exposure(source, "IB", allow_insecure_bind=False, posture=ENFORCING)
    assert _dest_config(registry.outbound["OB"], {}).tls_hop_attested is True
    assert attested_secure_hops(registry) == [("OB", REASON), ("inbound:IB", REASON)]


def test_connections_toml_refuses_the_pair_under_settings(tmp_path: Path) -> None:
    (tmp_path / "logic.py").write_text(_LOGIC, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(
        "[[outbound]]\n"
        'name = "OB"\n'
        'transport = "tcp"\n'
        "  [outbound.settings]\n"
        '  host = "10.0.0.5"\n'
        "  port = 5000\n"
        "  tls_hop_attested = true\n"
        f'  tls_hop_attested_reason = "{REASON}"\n',
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="tls_hop_attested"):
        load_config(tmp_path)


def test_an_attestation_and_a_cleartext_acceptance_are_refused_together() -> None:
    """Opposite claims. The attestation is checked first, so with both set the acceptance's WARN and
    audit record would never fire."""
    with pytest.raises(WiringError, match="opposite claims"):
        build_outbound_connection(
            "OB",
            Tcp(host="10.0.0.5", port=5000),
            cleartext_accepted=True,
            cleartext_reason="legacy firmware",
            tls_hop_attested=True,
            tls_hop_attested_reason=REASON,
        )


def test_an_env_reference_or_a_control_character_is_refused() -> None:
    """An env() reference is always truthy, so it would attest the hop in every environment. A
    control character in the reason could forge a line in the bind WARNING that records it."""
    with pytest.raises(WiringError, match="must be true or false"):
        build_outbound_connection(
            "OB",
            Tcp(host="10.0.0.5", port=5000),
            tls_hop_attested=env("attest", cast=bool),  # type: ignore[arg-type]
            tls_hop_attested_reason=REASON,
        )
    with pytest.raises(WiringError, match="control characters"):
        build_outbound_connection(
            "OB",
            Tcp(host="10.0.0.5", port=5000),
            tls_hop_attested=True,
            tls_hop_attested_reason="sidecar\nWARNING forged line",
        )


def test_a_fhir_lookup_flag_written_without_its_reason_is_refused_by_the_executor() -> None:
    """The FhirLookup executor reads the attestation from the lookup's settings. A flag written there
    by hand, with no reason, is refused rather than crossing unexplained."""
    from messagefoundry.transports.fhir import FhirLookupExecutor

    with pytest.raises(ValueError, match="requires tls_hop_attested_reason"):
        FhirLookupExecutor({"fl": {"url": "https://fhir.example/fhir", "tls_hop_attested": True}})


def test_the_check_line_lists_every_attested_hop(tmp_path: Path) -> None:
    from messagefoundry.checks import _check_hop_attested

    (tmp_path / "logic.py").write_text(_LOGIC, encoding="utf-8")
    (tmp_path / "ob.py").write_text(
        "from messagefoundry import Tcp, outbound\n"
        'outbound("OB", Tcp(host="10.0.0.5", port=5000), tls_hop_attested=True,\n'
        f"         tls_hop_attested_reason={REASON!r})\n",
        encoding="utf-8",
    )
    result = _check_hop_attested(tmp_path)
    assert result.ok and not result.required
    assert f"OB ({REASON})" in result.detail

    (tmp_path / "ob.py").write_text(
        'from messagefoundry import Tcp, outbound\noutbound("OB", Tcp(host="10.0.0.5", port=5000))\n',
        encoding="utf-8",
    )
    assert _check_hop_attested(tmp_path).detail == "no hop is attested secure"


# --- the lookup and reference-source carriers ----------------------------------------------------


def test_every_carrier_is_named_by_the_one_reader(tmp_path: Path) -> None:
    """Each carrier a hop gate reads has a factory parameter, and the shared reader names every one.
    A carrier left out here would be a hop crossed on an attestation no report names."""
    (tmp_path / "logic.py").write_text(_LOGIC, encoding="utf-8")
    (tmp_path / "carriers.py").write_text(
        "from messagefoundry import (\n"
        "    DatabaseLookup, DatabaseRef, FhirLookup, Reference, Tcp, outbound,\n"
        ")\n"
        f"R = {REASON!r}\n"
        'outbound("OB", Tcp(host="10.0.0.5", port=5000))\n'
        'FhirLookup("fl", url="https://fhir.example/fhir", tls_hop_attested=True,\n'
        "           tls_hop_attested_reason=R)\n"
        'DatabaseLookup("dl", server="db.example", database="d", tls_hop_attested=True,\n'
        "               tls_hop_attested_reason=R)\n"
        'Reference("rs", source=DatabaseRef(server="db.example", database="d",\n'
        '          statement="SELECT k, v FROM t", key_column="k", tls_hop_attested=True,\n'
        "          tls_hop_attested_reason=R))\n",
        encoding="utf-8",
    )
    registry = load_config(tmp_path)
    assert attested_secure_hops(registry) == [
        ("db_lookup:dl", REASON),
        ("fhir_lookup:fl", REASON),
        ("reference:rs", REASON),
    ]


def test_a_lookup_carrier_validates_the_pair_at_its_factory(tmp_path: Path) -> None:
    (tmp_path / "logic.py").write_text(_LOGIC, encoding="utf-8")
    (tmp_path / "bad.py").write_text(
        "from messagefoundry import FhirLookup, Tcp, outbound\n"
        'outbound("OB", Tcp(host="10.0.0.5", port=5000))\n'
        'FhirLookup("fl", url="https://fhir.example/fhir", tls_hop_attested=True)\n',
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="fhir lookup 'fl'.*requires tls_hop_attested_reason"):
        load_config(tmp_path)


def test_an_undeclared_lookup_carries_no_attestation_keys(tmp_path: Path) -> None:
    (tmp_path / "logic.py").write_text(_LOGIC, encoding="utf-8")
    (tmp_path / "plain.py").write_text(
        "from messagefoundry import FhirLookup, Tcp, outbound\n"
        'outbound("OB", Tcp(host="10.0.0.5", port=5000))\n'
        'FhirLookup("fl", url="https://fhir.example/fhir")\n',
        encoding="utf-8",
    )
    registry = load_config(tmp_path)
    assert "tls_hop_attested" not in registry.fhir_lookups["fl"].settings
    assert attested_secure_hops(registry) == []


# --- the loosening report ------------------------------------------------------------------------


def _loosening_names(attested_hops: tuple[str, ...]) -> list[str]:
    return [
        name
        for name, _ in security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            unverified_db_hops=(),
            attested_hops=attested_hops,
            revocation_attested_hops=(),
            store_privilege=None,
            audit_chain_unkeyed=None,
        )
    ]


def test_security_loosenings_names_an_attested_hop_and_only_then() -> None:
    assert "tls_hop_attested" in _loosening_names(("inbound:IB",))
    assert "tls_hop_attested" not in _loosening_names(())


def test_the_reader_is_empty_on_an_empty_graph() -> None:
    assert attested_secure_hops(Registry()) == []
