# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The revocation-attestation audit line names the connection that declared it (ADR 0173).

``RevocationHopGuard.enforce_construction`` logs a WARNING when a per-connection
``tls_revocation_attested`` suppresses an enforcing refusal. The line carried the cell, the host and
the reason, but not the declaring connection. The cell is a static family label, so with two
destinations to the same host an auditor could not tell which declaration crossed -- the reason
``cleartext_acceptance_audit_sink`` names its connection. The inbound sibling in
``check_inbound_revocation`` already named it; both lines now come from one record builder.

Every outbound case builds a real connector (or the SMART provider through the settings mirror a
real authoring surface writes), because a name threaded into the guard but dropped at one call site
is exactly the defect this file exists to catch.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopPosture,
    InsecureHopRefused,
    RevocationHopGuard,
    active_hop_posture,
)
from messagefoundry.config.wiring import FHIR, DICOMweb, Rest, Soap, load_config
from messagefoundry.pipeline.wiring_runner import (
    _dest_config,
    _source_config,
    check_inbound_revocation,
)
from messagefoundry.redaction import redact
from messagefoundry.transports import build_destination
from messagefoundry.transports.email import EmailDestination
from messagefoundry.transports.mllp import MLLPDestination
from messagefoundry.transports.smart import token_provider_from_settings
from tests.test_revocation_attestation_authoring import _toml

_ENFORCING = HopPosture(enforcing=True)
_REASON = "partner PKI runs OCSP at the site edge"
_HOST = "10.0.0.5"  # non-loopback, never dialled: construction reads settings only


@pytest.fixture(autouse=True)
def _no_blanket_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)


def _audit(caplog: pytest.LogCaptureFixture) -> str:
    return " ".join(
        r.getMessage() for r in caplog.records if "operator attestation" in r.getMessage()
    )


def _dest(
    name: str, ctype: ConnectorType, settings: dict[str, object], *, attested: bool
) -> Destination:
    return Destination(
        name=name,
        type=ctype,
        settings=settings,
        tls_revocation_attested=attested,
        tls_revocation_attested_reason=_REASON if attested else None,
    )


# --- the scenario the brief names: two outbounds, one host, one attested -------------------------


def test_two_outbounds_to_one_host_the_audit_line_names_the_attested_one(
    caplog: pytest.LogCaptureFixture,
) -> None:
    url = f"https://{_HOST}/ingest"
    with active_hop_posture(_ENFORCING), caplog.at_level(logging.WARNING):
        build_destination(
            _dest("OB_LAB_A", ConnectorType.REST, Rest(url=url).settings, attested=True)
        )
        # CONTROL: the unattested sibling to the SAME host is refused, so it cannot be the
        # connection the audit line names, and the line above is the attestation firing.
        with pytest.raises(InsecureHopRefused, match="revocation"):
            build_destination(
                _dest("OB_LAB_B", ConnectorType.REST, Rest(url=url).settings, attested=False)
            )
    audit = _audit(caplog)
    assert "connection OB_LAB_A" in audit
    assert "OB_LAB_B" not in audit
    assert _REASON in audit


# --- every outbound call site passes the name ------------------------------------------------------

_HTTP = {
    "REST": (ConnectorType.REST, Rest, f"https://{_HOST}/x"),
    "SOAP": (ConnectorType.SOAP, Soap, f"https://{_HOST}/svc"),
    "FHIR": (ConnectorType.FHIR, FHIR, f"https://{_HOST}/fhir"),
    "DICOMWEB": (ConnectorType.DICOMWEB, DICOMweb, f"https://{_HOST}/dicom-web"),
}


@pytest.mark.parametrize("cell", list(_HTTP))
def test_the_http_family_audit_line_names_the_connection(
    cell: str, caplog: pytest.LogCaptureFixture
) -> None:
    ctype, factory, url = _HTTP[cell]
    with active_hop_posture(_ENFORCING), caplog.at_level(logging.WARNING):
        build_destination(_dest(f"OB_{cell}", ctype, factory(url=url).settings, attested=True))
    assert f"connection OB_{cell}" in _audit(caplog)


def test_the_mllp_audit_line_names_the_connection(caplog: pytest.LogCaptureFixture) -> None:
    settings: dict[str, object] = {"host": _HOST, "port": 5000, "tls": True}
    with active_hop_posture(_ENFORCING), caplog.at_level(logging.WARNING):
        MLLPDestination(_dest("OB_MLLP_X", ConnectorType.MLLP, settings, attested=True))
    assert "connection OB_MLLP_X" in _audit(caplog)


def test_the_email_audit_line_names_the_connection(caplog: pytest.LogCaptureFixture) -> None:
    settings: dict[str, object] = {
        "host": _HOST,
        "sender": "engine@example.org",
        "recipients": ["clinician@example.org"],
    }
    with active_hop_posture(_ENFORCING), caplog.at_level(logging.WARNING):
        EmailDestination(_dest("OB_MAIL_X", ConnectorType.EMAIL, settings, attested=True))
    assert "connection OB_MAIL_X" in _audit(caplog)


# --- the SMART token hop gets the name through the settings mirror ---------------------------------


@pytest.fixture(scope="module")
def smart_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return (
        ec.generate_private_key(ec.SECP384R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


def _smart(key: str) -> dict[str, object]:
    return {
        "smart_token_url": f"https://{_HOST}/token",
        "smart_client_id": "cid",
        "smart_private_key": key,
        "smart_algorithm": "ES384",
    }


def test_the_smart_token_hop_of_an_outbound_names_the_connection(
    tmp_path: Path, smart_key: str, caplog: pytest.LogCaptureFixture
) -> None:
    toml_attest = f'tls_revocation_attested = true\ntls_revocation_attested_reason = "{_REASON}"\n'
    # `_dest_config` is the mirror a running engine uses; the provider sees only its settings.
    dest = _dest_config(_toml(tmp_path, ob_extra=toml_attest).outbound["OB"], {})
    with active_hop_posture(_ENFORCING), caplog.at_level(logging.WARNING):
        token_provider_from_settings({**dest.settings, **_smart(smart_key)})
    assert "connection OB:" in _audit(caplog)


def test_the_smart_token_hop_of_a_fhir_lookup_names_the_lookup(
    tmp_path: Path, smart_key: str, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "lookup.py").write_text(
        "from messagefoundry import FhirLookup\n"
        f'FhirLookup("epic", url="https://ehr.example.org/fhir", tls_revocation_attested=True, '
        f'tls_revocation_attested_reason="{_REASON}")\n',
        encoding="utf-8",
    )
    spec = load_config(tmp_path, allow_empty=True).fhir_lookups["epic"]
    with active_hop_posture(_ENFORCING), caplog.at_level(logging.WARNING):
        token_provider_from_settings({**spec.settings, **_smart(smart_key)})
    assert "connection epic:" in _audit(caplog)


# --- the shared record: inbound shape, and a hop with no connection --------------------------------


def test_the_inbound_line_uses_the_same_record(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ib_attest = f'tls_revocation_attested = true\ntls_revocation_attested_reason = "{_REASON}"\n'
    src = _source_config(_toml(tmp_path, ib_extra=ib_attest).inbound["IB"], "127.0.0.1", {})
    with caplog.at_level(logging.WARNING):
        check_inbound_revocation(src, "IB", posture=_ENFORCING)
    audit = _audit(caplog)
    assert "connection IB:" in audit and _REASON in audit


def test_a_hop_with_no_connection_renders_unnamed(caplog: pytest.LogCaptureFixture) -> None:
    guard = RevocationHopGuard.capture(
        host=_HOST,
        cell="REST destination",
        description="verified https egress",
        attested=True,
        attested_reason=_REASON,
        posture=_ENFORCING,
    )
    with caplog.at_level(logging.WARNING):
        guard.enforce_construction()
    assert "connection (unnamed)" in _audit(caplog)


def test_the_name_survives_the_phi_redaction_filter(caplog: pytest.LogCaptureFixture) -> None:
    # The record is only findable if the redaction filter leaves the marker and the name intact:
    # `_NAME_RUN` scrubs two or more adjacent ALL-CAPS tokens, and connection names are upper-case.
    # "MLLP outbound" follows the name in the rendered line, so this is the adjacency that could bite.
    settings: dict[str, object] = {"host": _HOST, "port": 5000, "tls": True}
    with active_hop_posture(_ENFORCING), caplog.at_level(logging.WARNING):
        MLLPDestination(_dest("ACME", ConnectorType.MLLP, settings, attested=True))
    assert "connection ACME: MLLP outbound" in redact(_audit(caplog))
