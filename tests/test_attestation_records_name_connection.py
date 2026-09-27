# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every hop record and refusal names the connection behind it, in a shape the log filters keep.

Follow-ups to PR 1516, which made the ``tls_revocation_attested`` audit line name its connection. The
same defect sat in the neighbouring records: a ``tls_hop_attested`` crossing and an enforcing refusal
named no connection, so two destinations to one host read identically. A ``FhirLookup`` rendered its
bare name, which an outbound can share. Its cleartext declaration was still read from its mutable
``settings``. Its name was never validated, and two cell labels lost words to the log redaction.
"""

from __future__ import annotations

import inspect
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
from messagefoundry.config.wiring import (
    FhirLookupSpec,
    Registry,
    Rest,
    WiringError,
    accepted_cleartext_hops,
    load_config,
)
from messagefoundry.pipeline.wiring_runner import _fhir_lookup_settings
from messagefoundry.redaction import redact
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.transports import build_destination
from messagefoundry.transports.email import EmailDestination
from messagefoundry.transports.mllp import InsecureHopGuard as MllpHopGuard
from messagefoundry.transports.mllp import MLLPDestination
from messagefoundry.transports.rest import refuse_unrevoked_verified_hop, refuse_verify_off
from tests.test_hop_refusal_rawtcp import dicom_cfg, mllp_cfg

_ENFORCING = HopPosture(enforcing=True)
_HOST = "10.0.0.5"  # non-loopback, never dialled: construction reads settings only
_REASON = "segment is a proxy-terminated trusted enclave"


@pytest.fixture(autouse=True)
def _no_escapes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)


def _shipped(text: str) -> str:
    # The two text filters a shipped log line passes through that can eat a word.
    return scrub_credentials(redact(text))


def _lines(caplog: pytest.LogCaptureFixture, marker: str) -> str:
    return " ".join(r.getMessage() for r in caplog.records if marker in r.getMessage())


def _rest(name: str, url: str, *, hop_attested: bool = False) -> Destination:
    return Destination(
        name=name,
        type=ConnectorType.REST,
        settings=Rest(url=url).settings,
        tls_hop_attested=hop_attested,
        tls_hop_attested_reason=_REASON if hop_attested else None,
    )


# --- a tls_hop_attested crossing names its connection ------------------------------------------------


def test_an_attested_cleartext_mllp_hop_names_its_connection(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with active_hop_posture(_ENFORCING), caplog.at_level(logging.WARNING):
        MLLPDestination(mllp_cfg(_HOST, attested=True, reason=_REASON))
    line = _shipped(_lines(caplog, "on operator attestation"))
    assert "connection 'OB_MLLP';" in line
    assert "(tls_hop_attested; reason: " in line and _REASON in line


def test_an_attested_cleartext_rest_hop_names_its_connection(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with active_hop_posture(_ENFORCING), caplog.at_level(logging.WARNING):
        build_destination(_rest("OB_REST_A", f"http://{_HOST}/x", hop_attested=True))
    assert "connection 'OB_REST_A';" in _shipped(_lines(caplog, "ATTESTED secure"))


# --- a refusal names the connection to fix -----------------------------------------------------------


def test_a_revocation_refusal_names_the_refused_connection() -> None:
    with active_hop_posture(_ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        build_destination(_rest("OB_LAB_B", f"https://{_HOST}/x"))
    assert "connection 'OB_LAB_B';" in str(exc.value)


def test_a_cleartext_refusal_names_the_refused_connection() -> None:
    with active_hop_posture(_ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        MLLPDestination(mllp_cfg(_HOST))
    assert "connection 'OB_MLLP';" in str(exc.value)


def test_a_verify_off_refusal_names_the_refused_connection() -> None:
    with active_hop_posture(_ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        refuse_verify_off("https", f"https://{_HOST}/x", connector="REST", connection="OB_V")
    assert "connection 'OB_V';" in str(exc.value)


def test_a_hop_that_is_not_a_connection_refuses_without_a_name() -> None:
    # CONTROL: the prefix is the connection's, not decoration every refusal gains.
    guard = RevocationHopGuard.capture(
        host=_HOST,
        cell="[store] test",
        description="d",
        attested=False,
        posture=_ENFORCING,
        connection=None,
    )
    with pytest.raises(InsecureHopRefused) as exc:
        guard.enforce_construction()
    assert "connection" not in str(exc.value).split(":", 1)[0]


# --- a connection call site cannot silently omit the name --------------------------------------------


@pytest.mark.parametrize(
    "fn",
    [
        RevocationHopGuard.capture,
        MllpHopGuard.capture,
        refuse_unrevoked_verified_hop,
        refuse_verify_off,
    ],
    ids=["revocation-guard", "mllp-hop-guard", "refuse-unrevoked", "refuse-verify-off"],
)
def test_connection_is_a_required_keyword(fn: object) -> None:
    # A default of None is what let a connection site log "(unnamed)". Required, a new site that
    # forgets it fails at the call rather than shipping an untraceable record.
    param = inspect.signature(fn).parameters["connection"]  # type: ignore[arg-type]
    assert param.default is inspect.Parameter.empty
    assert param.kind is inspect.Parameter.KEYWORD_ONLY


# --- a FhirLookup: its own namespace, typed declarations, a validated name ---------------------------


def _lookup(tmp_path: Path, extra: str = "") -> Registry:
    (tmp_path / "lookup.py").write_text(
        "from messagefoundry import FhirLookup\n"
        f'FhirLookup("epic", url="http://ehr.example.org/fhir"{extra})\n',
        encoding="utf-8",
    )
    return load_config(tmp_path, allow_empty=True)


def test_a_lookup_mirror_names_the_lookup_namespace(tmp_path: Path) -> None:
    # An outbound may also be named "epic". The lookup's records must still be told apart from its.
    reg = _lookup(tmp_path, f', cleartext_accepted=True, cleartext_reason="{_REASON}"')
    settings = _fhir_lookup_settings(reg.fhir_lookups["epic"], {}, None)
    assert settings["cleartext_connection"] == "fhir_lookup:epic"
    assert reg.fhir_lookups["epic"].settings["cleartext_connection"] == "fhir_lookup:epic"


def test_raw_cleartext_keys_on_a_lookup_are_not_honoured(tmp_path: Path) -> None:
    # `spec.settings` is a mutable dict. A config module can write the pair after the factory ran,
    # and the read executor must not cross a cleartext hop on it, nor report it as a declaration.
    reg = _lookup(tmp_path)
    reg.fhir_lookups["epic"].settings.update(
        {"cleartext_accepted": True, "cleartext_reason": "spoofed", "cleartext_connection": "X"}
    )
    settings = _fhir_lookup_settings(reg.fhir_lookups["epic"], {}, None)
    assert not any(k.startswith("cleartext_") for k in settings)
    assert accepted_cleartext_hops(reg) == []


def test_a_declared_lookup_is_still_honoured_and_reported(tmp_path: Path) -> None:
    # CONTROL for the one above: the typed declaration still reaches the executor and the report.
    reg = _lookup(tmp_path, f', cleartext_accepted=True, cleartext_reason="{_REASON}"')
    settings = _fhir_lookup_settings(reg.fhir_lookups["epic"], {}, None)
    assert settings["cleartext_accepted"] is True and settings["cleartext_reason"] == _REASON
    assert accepted_cleartext_hops(reg) == [("fhir_lookup:epic", _REASON)]


def test_a_directly_built_lookup_spec_cannot_accept_cleartext_without_a_reason() -> None:
    with pytest.raises(WiringError, match="cleartext_reason"):
        FhirLookupSpec("epic", {"url": "http://h/fhir"}, cleartext_accepted=True)


@pytest.mark.parametrize("name", ["Epic Prod", "epic:prod", "epic=1", ""])
def test_a_lookup_name_must_match_the_connection_name_rule(name: str) -> None:
    with pytest.raises(WiringError, match="invalid fhir lookup name"):
        Registry().add_fhir_lookup(FhirLookupSpec(name, {"url": "https://h/fhir"}))


def test_a_valid_lookup_name_registers() -> None:
    # CONTROL: the rule refuses the bad shapes above, not every lookup.
    reg = Registry()
    reg.add_fhir_lookup(FhirLookupSpec("epic_prod-1", {"url": "https://h/fhir"}))
    assert "epic_prod-1" in reg.fhir_lookups


# --- cell labels survive the log redaction -----------------------------------------------------------


def test_the_email_revocation_label_survives_redaction(caplog: pytest.LogCaptureFixture) -> None:
    cfg = Destination(
        name="OB_MAIL",
        type=ConnectorType.EMAIL,
        settings={
            "host": _HOST,
            "sender": "engine@example.org",
            "recipients": ["clinician@example.org"],
        },
        tls_revocation_attested=True,
        tls_revocation_attested_reason=_REASON,
    )
    with active_hop_posture(_ENFORCING), caplog.at_level(logging.WARNING):
        EmailDestination(cfg)
    assert "Email destination (verified TLS on SMTP," in _shipped(
        _lines(caplog, "on operator attestation")
    )


def test_the_dicom_cleartext_label_survives_redaction() -> None:
    pytest.importorskip("pynetdicom")
    from messagefoundry.transports.dicom import DicomScuDestination

    with active_hop_posture(_ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        DicomScuDestination(dicom_cfg(_HOST))
    assert "DICOM C-STORE client (SCU)" in _shipped(str(exc.value))


def test_the_old_labels_were_scrubbed() -> None:
    # CONTROL: the redaction does fire on the old shapes, so the two passes above are the new labels
    # at work and not a filter that never fires.
    assert "[redacted]" in _shipped("Email destination (verified SMTP TLS, no revocation check)")
    assert "[redacted]" in _shipped("DICOM C-STORE SCU")
