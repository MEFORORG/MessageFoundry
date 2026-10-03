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

from messagefoundry.config.impact import plan_rename
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopPosture,
    InsecureHopRefused,
    RevocationHopGuard,
    active_hop_posture,
)
from messagefoundry.config.wiring import (
    Database,
    FhirLookupSpec,
    Registry,
    Rest,
    WiringError,
    accepted_cleartext_hops,
    load_config,
)
from messagefoundry.pipeline.wiring_runner import _dest_config, _fhir_lookup_settings
from messagefoundry.redaction import redact
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.transports import build_destination
from messagefoundry.transports.database import DatabaseSource, generic_cleartext_hop_guard
from messagefoundry.transports.email import EmailDestination
from messagefoundry.transports.http_auth import HttpAuthError, digest_handler_from_settings
from messagefoundry.transports.mllp import InsecureHopGuard as MllpHopGuard
from messagefoundry.transports.mllp import MLLPDestination
from messagefoundry.transports.remotefile import RemoteFileSource, _anon_ftp_guard, _validate_common
from messagefoundry.transports.rest import InsecureHopGuard as RestHopGuard
from messagefoundry.transports.rest import (
    egress_route_from_settings,
    proxy_auth_handler_from_settings,
    proxy_config_from_settings,
    refuse_cleartext_credential_hop,
    refuse_cleartext_credentials,
    refuse_cleartext_egress,
    refuse_unrevoked_verified_hop,
    refuse_verify_off,
)
from messagefoundry.transports.smart import SmartAuthError, token_provider_from_settings
from tests.test_hop_refusal_db_inbound import _generic_source
from tests.test_hop_refusal_rawtcp import dicom_cfg, mllp_cfg
from tests.test_revocation_attestation_authoring import _toml

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
        build_destination(
            _rest("OB_REST_A", f"http://{_HOST}/x", hop_attested=True),
            egress=EgressSettings(deny_by_default=False),
        )
    assert "connection 'OB_REST_A';" in _shipped(_lines(caplog, "ATTESTED secure"))


# --- a refusal names the connection to fix -----------------------------------------------------------


def test_a_revocation_refusal_names_the_refused_connection() -> None:
    with active_hop_posture(_ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        build_destination(
            _rest("OB_LAB_B", f"https://{_HOST}/x"), egress=EgressSettings(deny_by_default=False)
        )
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
    assert settings["connection_name"] == "fhir_lookup:epic"


def test_raw_cleartext_keys_on_a_lookup_are_not_honoured(tmp_path: Path) -> None:
    # `spec.settings` is a mutable dict. A config module can write the pair after the factory ran,
    # and the read executor must not cross a cleartext hop on it, nor report it as a declaration.
    reg = _lookup(tmp_path)
    reg.fhir_lookups["epic"].settings.update(
        {"cleartext_accepted": True, "cleartext_reason": "spoofed", "connection_name": "X"}
    )
    settings = _fhir_lookup_settings(reg.fhir_lookups["epic"], {}, None)
    assert "cleartext_accepted" not in settings and "cleartext_reason" not in settings
    assert settings["connection_name"] == "fhir_lookup:epic"
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


# --- round 1 of the review: the settings-driven seams, inbound names, the rename tool ----------------


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


def test_an_undeclared_smart_token_hop_refusal_names_its_connection(
    tmp_path: Path, smart_key: str
) -> None:
    # The name used to ride only with a declaration, so the REFUSING case -- nothing declared -- had
    # none. The runner now mirrors it for every outbound.
    dest = _dest_config(_toml(tmp_path).outbound["OB"], {})
    smart = {
        "smart_token_url": f"https://{_HOST}/token",
        "smart_client_id": "cid",
        "smart_private_key": smart_key,
        "smart_algorithm": "ES384",
    }
    with active_hop_posture(_ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        token_provider_from_settings({**dest.settings, **smart})
    assert "connection 'OB';" in str(exc.value)


def test_an_inbound_remote_file_refusal_names_its_connection() -> None:
    # RemoteFileSource was the one connection call site that passed no name at all.
    src = Source(
        name="IB_FTP",
        type=ConnectorType.REMOTEFILE,
        settings={"host": _HOST, "remote_dir": "/in", "protocol": "ftp"},
    )
    with active_hop_posture(_ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        RemoteFileSource(src)
    assert "connection 'inbound:IB_FTP';" in str(exc.value)


def test_an_inbound_database_refusal_names_its_namespace_and_keeps_its_label() -> None:
    # Inbound and outbound may share a name; the loosening reports already say "inbound:<name>".
    # The label lost "ODBC DATABASE" to the name-run redaction before it was reworded.
    with active_hop_posture(_ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        DatabaseSource(_generic_source())
    shipped = _shipped(str(exc.value))
    assert "connection 'inbound:IB_DB_GEN';" in shipped
    assert "cleartext generic-ODBC hop to a database" in shipped


@pytest.mark.parametrize("guard", ["rest", "mllp"])
def test_a_send_time_refusal_names_its_connection(guard: str) -> None:
    if guard == "rest":
        with pytest.raises(InsecureHopRefused) as exc:
            RestHopGuard(
                posture=_ENFORCING, attested=False, cell="HTTP cleartext egress", connection="OB_S"
            ).assert_send(_HOST, f"http://{_HOST}/x")
    else:
        g = MllpHopGuard(
            host=_HOST,
            port=5000,
            cell="MLLP outbound",
            description="cleartext MLLP egress",
            attested=False,
            attested_reason=None,
            posture=_ENFORCING,
            connection="OB_S",
        )
        with pytest.raises(InsecureHopRefused) as exc:
            g.assert_send()
    assert "connection 'OB_S';" in str(exc.value)


def test_a_rename_refuses_a_lookup_name_that_would_not_load(tmp_path: Path) -> None:
    (tmp_path / "lookup.py").write_text(
        'from messagefoundry import FhirLookup\nFhirLookup("epic", url="https://h/fhir")\n',
        encoding="utf-8",
    )
    reg = load_config(tmp_path, allow_empty=True)
    with pytest.raises(WiringError, match="not a valid connection name"):
        plan_rename(reg, tmp_path, "fhir_lookup", "epic", "epic.prod")
    # CONTROL: a valid new name still plans.
    assert plan_rename(reg, tmp_path, "fhir_lookup", "epic", "epic_prod").edits


def test_a_directly_built_lookup_spec_cannot_claim_both_secure_and_not() -> None:
    with pytest.raises(WiringError, match="opposite claims"):
        FhirLookupSpec(
            "epic",
            {"url": "http://h/fhir", "tls_hop_attested": True, "tls_hop_attested_reason": "r"},
            cleartext_accepted=True,
            cleartext_reason="x",
        )


@pytest.mark.parametrize(
    "fn",
    [
        refuse_cleartext_egress,
        refuse_cleartext_credentials,
        refuse_cleartext_credential_hop,
        proxy_config_from_settings,
        egress_route_from_settings,
        generic_cleartext_hop_guard,
        _anon_ftp_guard,
        _validate_common,
    ],
)
def test_every_hop_guard_wrapper_requires_the_name(fn: object) -> None:
    param = inspect.signature(fn).parameters["connection"]  # type: ignore[arg-type]
    assert param.default is inspect.Parameter.empty


# --- round 2 of the review: the re-wrapped refusals, the SQL Server preset, a mutated lookup ---------


def _smart_http(key: str) -> dict[str, object]:
    return {
        "smart_token_url": f"http://{_HOST}/token",
        "smart_client_id": "cid",
        "smart_private_key": key,
        "smart_algorithm": "ES384",
    }


def test_a_cleartext_smart_token_refusal_names_its_connection(
    tmp_path: Path, smart_key: str
) -> None:
    # This seam catches InsecureHopRefused and re-raises its own error, which used to drop the name.
    dest = _dest_config(_toml(tmp_path).outbound["OB"], {})
    with active_hop_posture(_ENFORCING), pytest.raises(SmartAuthError) as exc:
        token_provider_from_settings({**dest.settings, **_smart_http(smart_key)})
    assert "connection 'OB';" in str(exc.value)


def test_a_cleartext_digest_refusal_names_its_connection(tmp_path: Path) -> None:
    dest = _dest_config(_toml(tmp_path).outbound["OB"], {})
    digest = {"http_auth": "digest", "http_auth_user": "u", "http_auth_password": "p"}
    with active_hop_posture(_ENFORCING), pytest.raises(HttpAuthError) as exc:
        digest_handler_from_settings({**dest.settings, **digest}, url=f"http://{_HOST}/x")
    assert "connection 'OB';" in str(exc.value)


def test_a_credentialed_plain_ftp_refusal_names_its_connection() -> None:
    s = {"host": _HOST, "remote_dir": "/x", "protocol": "ftp", "username": "u", "password": "p"}
    with pytest.raises(ValueError, match="plain ftp transmits credentials") as exc:
        _validate_common(s, connection="OB_F")
    assert "connection 'OB_F';" in str(exc.value)


def test_a_weakened_sql_server_refusal_names_its_connection() -> None:
    settings = {**Database(server="db.example", database="d", statement="SELECT 1").settings}
    settings["trust_server_certificate"] = True
    cfg = Destination(name="OB_SS", type=ConnectorType.DATABASE, settings=settings)
    with active_hop_posture(_ENFORCING), pytest.raises(ValueError, match="TLS is weakened") as exc:
        build_destination(cfg, egress=EgressSettings(deny_by_default=False))
    assert "connection 'OB_SS';" in str(exc.value)


def test_a_lookup_mutated_into_both_claims_is_refused_where_the_executor_reads_it(
    tmp_path: Path,
) -> None:
    reg = _lookup(tmp_path, f', cleartext_accepted=True, cleartext_reason="{_REASON}"')
    reg.fhir_lookups["epic"].settings.update(
        {"tls_hop_attested": True, "tls_hop_attested_reason": "x"}
    )
    with pytest.raises(WiringError, match="opposite claims"):
        _fhir_lookup_settings(reg.fhir_lookups["epic"], {}, None)


def test_a_lookup_spec_with_one_claim_loads() -> None:
    # CONTROL for the two opposite-claims tests: either claim alone is fine.
    FhirLookupSpec("a", {"url": "http://h/fhir"}, cleartext_accepted=True, cleartext_reason="x")
    FhirLookupSpec(
        "b", {"url": "http://h/fhir", "tls_hop_attested": True, "tls_hop_attested_reason": "r"}
    )


def test_proxy_auth_handler_requires_the_name_as_a_keyword() -> None:
    param = inspect.signature(proxy_auth_handler_from_settings).parameters["connection"]
    assert param.default is inspect.Parameter.empty
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
