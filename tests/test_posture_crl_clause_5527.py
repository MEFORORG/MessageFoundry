# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The posture entries' CRL clauses name every condition a CRL check needs (BACKLOG #5527).

Item 54: ``alerts.email_tls_revocation_attested`` said the SMTP relay checks "no CRL unless
[tls].crl_file is set". A loopback relay gets no CRL whatever that file says, and a sink built
by a caller that hands it no ``[tls]`` policy gets none either, so ``GET /security/posture``,
the serve-start warning and ``security show`` stated a check that does not run on those paths.
Item 55 finding 8: the ``[ai]`` entry's "the endpoint is not loopback" means the engine's own
reading of loopback, under which ``localhost.`` is remote and gets the CRL.

The text tests pin the entries, the SMTP bullet of docs/SECURITY-LOOSENING.md, and the loopback
wording of the ``ai_broker`` docstring and the ``AiSettings`` comment. The anchor tests pin,
through ``resolve_trust_anchor`` alone,
the loopback reading the text describes; no test here builds the SMTP sink or the AI opener,
and none pins which callers hand the ``[tls]`` policy over. No message body is involved.
"""

from __future__ import annotations

from pathlib import Path

from messagefoundry.config.settings import (
    AiSettings,
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    SecretRotationSettings,
    SecretsSettings,
    SecuritySettings,
    StoreSettings,
    alert_revocation_attestations,
    security_loosenings,
)
from messagefoundry.config.tls_policy import TrustAnchorPolicy, resolve_trust_anchor

_REASON = "synthetic: the relay certificate lives 24 hours"
_CRL = "C:/synthetic/crl.pem"


def _smtp_clause() -> str:
    alerts = AlertsSettings(
        email_tls_revocation_attested=True, email_tls_revocation_attested_reason=_REASON
    )
    entries = {switch: crl for switch, _hop, crl, _reason in alert_revocation_attestations(alerts)}
    return entries["alerts.email_tls_revocation_attested"]


_ROOT = Path(__file__).resolve().parent.parent
_SMTP_ALERTS = AlertsSettings(
    email_tls_revocation_attested=True, email_tls_revocation_attested_reason=_REASON
)


def _ai_entry() -> str:
    ai = AiSettings(endpoint_revocation_attested=True, endpoint_revocation_attested_reason=_REASON)
    return _entries(AlertsSettings(), ai=ai)["ai.endpoint_revocation_attested"]


def _entries(alerts: AlertsSettings, *, ai: AiSettings | None = None) -> dict[str, str]:
    return dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            alerts,
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            path_form_fhir_hops=(),
            ech_cleartext_sidecar_hops=(),
            listener_trusted_proxy_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            cert_monitor=CertMonitorSettings(),
            backup=BackupSettings(),
            secrets=SecretsSettings(),
            ai=ai if ai is not None else AiSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
            service_env=None,
        )
    )


def test_the_smtp_clause_names_all_three_conditions() -> None:
    clause = _smtp_clause()
    assert clause.startswith("and no CRL unless all three hold: [tls].crl_file is set")
    assert "the [tls] policy reaches the caller that builds the sink" in clause
    assert "the relay host is not loopback as config.tls_policy.is_loopback_hop_host" in clause


def test_the_smtp_clause_names_the_loopback_relay_as_checking_no_crl() -> None:
    assert "at least a loopback relay checks no CRL whatever [tls].crl_file says" in _smtp_clause()


def test_the_ai_entry_says_how_loopback_is_read() -> None:
    entry = _ai_entry()
    assert "the endpoint host is not loopback as config.tls_policy.is_loopback_hop_host" in entry
    assert (
        "at least the name localhost with a trailing dot reads as remote and gets the CRL, though "
        "the bare name localhost reads as loopback" in entry
    )


def test_the_revocation_entries_hold_no_serve_warning_joiner() -> None:
    """The serve-start warning joins entries with "; ", so a "; " inside an entry splits it there
    for a reader. The reason is the operator's own text and can still hold one; this one does
    not, so the test reads the engine's own text."""
    ai = AiSettings(endpoint_revocation_attested=True, endpoint_revocation_attested_reason=_REASON)
    entries = _entries(_SMTP_ALERTS, ai=ai)
    for switch in ("alerts.email_tls_revocation_attested", "ai.endpoint_revocation_attested"):
        assert "; " not in entries[switch], switch


def test_the_smtp_loosening_doc_bullet_names_the_loopback_reading() -> None:
    doc = (_ROOT / "docs" / "SECURITY-LOOSENING.md").read_text(encoding="utf-8")
    start = doc.index("- **What the attestation can truthfully rest on:** for the SMTP relay")
    bullet = doc[start : doc.index("\n- **", start + 1)]
    assert "is_loopback_hop_host" in bullet
    assert "`localhost.` reads as remote" in bullet


def test_the_ai_source_text_reads_loopback_as_the_code_does() -> None:
    """``transports/ai_broker.py``'s module docstring and the ``AiSettings`` comment said "not
    loopback" with no reading; the code reads loopback with ``is_loopback_hop_host``."""
    broker = (_ROOT / "messagefoundry" / "transports" / "ai_broker.py").read_text(encoding="utf-8")
    assert "and the endpoint is not loopback" not in broker
    assert broker.count("``tls_policy.is_loopback_hop_host`` reads it") >= 2
    settings = (_ROOT / "messagefoundry" / "config" / "settings.py").read_text(encoding="utf-8")
    start = settings.index("# Attest that revocation of the AI endpoint's server certificate")
    comment = settings[start : settings.index("endpoint_revocation_attested:", start)]
    assert "the endpoint is not loopback" not in comment
    assert "config.tls_policy.is_loopback_hop_host reads it" in comment


def test_a_loopback_relay_resolves_no_crl_whatever_the_file_says() -> None:
    """The behaviour the SMTP clause's loopback condition describes."""
    policy = TrustAnchorPolicy(crl_file=_CRL)
    for host in ("127.0.0.1", "localhost", "LOCALHOST", "::1"):
        anchor = resolve_trust_anchor(connection_ca_file=None, host=host, policy=policy)
        assert anchor.crl_file is None, host
    pinned = resolve_trust_anchor(
        connection_ca_file="C:/synthetic/ca.pem", host="::1", policy=policy
    )
    assert pinned.crl_file is None


def test_localhost_with_a_trailing_dot_reads_remote_and_gets_the_crl() -> None:
    """The behaviour the ``[ai]`` entry's trailing-dot clause describes."""
    policy = TrustAnchorPolicy(crl_file=_CRL)
    anchor = resolve_trust_anchor(connection_ca_file=None, host="localhost.", policy=policy)
    assert anchor.crl_file == _CRL
