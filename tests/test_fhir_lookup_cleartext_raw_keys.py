# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A raw ``cleartext_accepted`` key in a ``FhirLookup``'s settings is stripped, never honoured.

BACKLOG #2050. ``FhirLookupSpec.settings`` is a mutable dict, and the read executor reads the ADR 0153
pair out of the resolved settings. ``wiring_runner._fhir_lookup_settings`` stripped the raw revocation
keys (ADR 0173) but not the raw cleartext keys, so a config module that wrote ``cleartext_accepted``
into a lookup's settings crossed an enforcing cleartext refusal without the load-validated
declaration, and could name any connection in the audit record.

The declaration now lives in typed fields on the spec, as the revocation pair does. One helper,
``_mirror_declarations``, clears all six declaration keys and re-mirrors them from those fields for
both ``_dest_config`` and ``_fhir_lookup_settings``, and the loosening readers read the typed fields.
Every executor case runs through both builders -- the ``check`` build and the live build -- so
neither can keep an unstripped settings path.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, InsecureHopRefused
from messagefoundry.config.wiring import (
    FhirLookupSpec,
    Registry,
    WiringError,
    accepted_cleartext_hops,
    load_config,
    revocation_attested_hops,
)
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    _fhir_lookup_settings,
    build_check_registry,
)

_ENFORCING = HopPosture(enforcing=True)
# RFC 2606 documentation host, never dialled: building the executor reads settings only.
_CLEARTEXT_URL = "http://fhir.example.org/fhir"
_REASON = "legacy on-prem FHIR facade has no TLS"
_RAW: dict[str, object] = {
    "cleartext_accepted": True,
    "cleartext_reason": "spoofed",
    "connection_name": "OB_OTHER",
}
_RAW_REVOCATION: dict[str, object] = {
    "tls_revocation_attested": True,
    "tls_revocation_attested_reason": "spoofed",
    "connection_name": "OB_OTHER",
}


def _lookup_registry(tmp_path: Path, *, declared: bool) -> Registry:
    # One cleartext FhirLookup, declared or not, whose settings then gain the raw keys -- the same
    # dict a code-first `spec.settings.update(...)` in a config module would write.
    accept = f', cleartext_accepted=True, cleartext_reason="{_REASON}"'
    (tmp_path / "lookup.py").write_text(
        "from messagefoundry import FhirLookup\n"
        f'FhirLookup("epic", url="{_CLEARTEXT_URL}"{accept if declared else ""})\n',
        encoding="utf-8",
    )
    reg = load_config(tmp_path, allow_empty=True)
    reg.fhir_lookups["epic"].settings.update(_RAW)
    return reg


def _build_check(reg: Registry) -> None:
    build_check_registry(
        reg,
        inbound_bind_host="127.0.0.1",
        env_values={},
        egress=EgressSettings(),
        posture=_ENFORCING,
    )


def _build_live(reg: Registry) -> None:
    # The live builder start and reload use. It reads only these five attributes, so a stand-in for
    # the runner drives the real method without a store.
    runner = SimpleNamespace(
        registry=reg,
        _env_values={},
        _egress=EgressSettings(),
        _hop_posture=_ENFORCING,
        _trust_anchor_policy=None,
    )
    RegistryRunner._build_fhir_lookup_executor(cast(RegistryRunner, runner))


_BUILDERS = pytest.mark.parametrize("build", [_build_check, _build_live], ids=["check", "live"])


@_BUILDERS
def test_raw_cleartext_keys_do_not_cross_the_lookup_read_hop(
    tmp_path: Path, build: Callable[[Registry], None]
) -> None:
    # Undeclared lookup plus raw keys: the cleartext read hop is refused, as an undeclared one is.
    reg = _lookup_registry(tmp_path, declared=False)
    with pytest.raises((WiringError, InsecureHopRefused)):
        build(reg)


@_BUILDERS
def test_a_declared_lookup_crosses_and_its_audit_line_ignores_the_raw_keys(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, build: Callable[[Registry], None]
) -> None:
    # CONTROL for the refusal above: the same hop with the declaration crosses. The raw keys cannot
    # rename or reword the audit record; it names the lookup and its declared reason.
    reg = _lookup_registry(tmp_path, declared=True)
    with caplog.at_level(logging.WARNING):
        build(reg)
    audit = " ".join(
        r.getMessage() for r in caplog.records if "cleartext_accepted" in r.getMessage()
    )
    assert "'fhir_lookup:epic'" in audit and _REASON in audit
    assert "OB_OTHER" not in audit and "spoofed" not in audit


def test_fhir_lookup_settings_strips_every_raw_declaration_key() -> None:
    spec = FhirLookupSpec("epic", {"url": _CLEARTEXT_URL, **_RAW, **_RAW_REVOCATION})
    settings = _fhir_lookup_settings(spec, {}, None)
    assert not any(k.startswith(("cleartext_", "tls_revocation_attested")) for k in settings)
    assert settings["connection_name"] == "fhir_lookup:epic"  # its own name, not the raw one
    assert settings["url"] == _CLEARTEXT_URL  # control: only the declaration keys went


def test_fhir_lookup_settings_mirrors_only_the_typed_declaration() -> None:
    spec = FhirLookupSpec(
        "epic",
        {"url": _CLEARTEXT_URL, **_RAW},
        cleartext_accepted=True,
        cleartext_reason=_REASON,
    )
    settings = _fhir_lookup_settings(spec, {}, None)
    assert settings["cleartext_accepted"] is True
    assert settings["cleartext_reason"] == _REASON
    assert settings["connection_name"] == "fhir_lookup:epic"


def test_a_directly_built_spec_cannot_accept_without_a_reason() -> None:
    with pytest.raises(WiringError, match="fhir lookup 'epic'"):
        FhirLookupSpec("epic", {"url": _CLEARTEXT_URL}, cleartext_accepted=True)


def test_the_factory_sets_the_typed_fields(tmp_path: Path) -> None:
    reg = _lookup_registry(tmp_path, declared=True)
    spec = reg.fhir_lookups["epic"]
    assert spec.cleartext_accepted is True
    assert spec.cleartext_reason == _REASON


def test_the_loosening_report_reads_the_typed_declaration(tmp_path: Path) -> None:
    # The report must name what the executor honours: a raw key is not reported, because it is
    # stripped, and a typed declaration with no settings copy is reported, because it crosses.
    raw_only = _lookup_registry(tmp_path, declared=False)
    assert accepted_cleartext_hops(raw_only) == []
    reg = Registry()
    reg.add_fhir_lookup(
        FhirLookupSpec(
            "typed",
            {"url": _CLEARTEXT_URL, **_RAW_REVOCATION},
            cleartext_accepted=True,
            cleartext_reason=_REASON,
        )
    )
    assert accepted_cleartext_hops(reg) == [("fhir_lookup:typed", _REASON)]
    # The revocation sibling has the same contract: its raw key is stripped, so it is not reported.
    assert revocation_attested_hops(reg) == []


def test_messagefoundry_check_reports_the_declared_lookup(tmp_path: Path) -> None:
    from messagefoundry.checks import _check_cleartext_accepted

    # `check` loads the graph without allow_empty, so it needs a connection beside the lookups.
    (tmp_path / "lookup.py").write_text(
        f"""
from messagefoundry import MLLP, FhirLookup, inbound, router

inbound("IB", MLLP(port=15099), router="r")
FhirLookup("epic", url="{_CLEARTEXT_URL}", cleartext_accepted=True, cleartext_reason="{_REASON}")
FhirLookup("raw", url="{_CLEARTEXT_URL}").settings.update({_RAW!r})


@router("r")
def route(msg):
    return []
""",
        encoding="utf-8",
    )
    result = _check_cleartext_accepted(tmp_path)
    assert result.ok and not result.skipped
    assert "fhir_lookup:epic" in result.detail and _REASON in result.detail
    # The raw-key lookup is not reported: the executor strips its keys, so nothing crosses on them.
    assert "fhir_lookup:raw" not in result.detail and "spoofed" not in result.detail


def test_a_raw_hop_attestation_cannot_pair_with_the_typed_acceptance() -> None:
    # Opposite claims. The attestation wins in the disposition, so the hop would cross with no WARN or
    # audit record while the loosening report listed it as accepted. The factory refuses the pair;
    # a raw attestation written into settings afterwards is refused at the one settings builder.
    spec = FhirLookupSpec(
        "epic", {"url": _CLEARTEXT_URL}, cleartext_accepted=True, cleartext_reason=_REASON
    )
    # Written AFTER construction, which refuses the pair outright; `settings` stays mutable.
    spec.settings.update(
        {"tls_hop_attested": True, "tls_hop_attested_reason": "sidecar terminates TLS"}
    )
    with pytest.raises(WiringError, match="opposite claims"):
        _fhir_lookup_settings(spec, {}, None)
