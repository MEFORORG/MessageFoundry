# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The posture entries' CRL clauses name every condition a CRL check needs (BACKLOG #5527).

Item 54: ``alerts.email_tls_revocation_attested`` said the SMTP relay checks "no CRL unless
[tls].crl_file is set". A loopback relay gets no CRL whatever that file says, and a sink built
by a caller that hands it no ``[tls]`` policy gets none either, so ``GET /security/posture``,
the serve-start warning and ``security show`` stated a check that does not run on those paths.
Item 55 finding 8: the ``[ai]`` entry's "the endpoint is not loopback" means the engine's own
reading of loopback, under which ``localhost.`` is remote and gets the CRL.

The text tests pin the entries. The anchor tests pin the behaviour the text describes, so a
change to either that leaves them disagreeing goes red here. No message body is involved.
"""

from __future__ import annotations

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


def _ai_entry() -> str:
    ai = AiSettings(endpoint_revocation_attested=True, endpoint_revocation_attested_reason=_REASON)
    return dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
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
            ai=ai,
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
            service_env=None,
        )
    )["ai.endpoint_revocation_attested"]


def test_the_smtp_clause_names_all_three_conditions() -> None:
    clause = _smtp_clause()
    assert clause.startswith("and no CRL unless all three hold: [tls].crl_file is set")
    assert "the [tls] policy reaches the caller that builds the sink" in clause
    assert "the relay host is not loopback" in clause


def test_the_smtp_clause_names_the_loopback_relay_as_checking_no_crl() -> None:
    assert "at least a loopback relay checks no CRL whatever [tls].crl_file says" in _smtp_clause()


def test_the_ai_entry_says_how_loopback_is_read() -> None:
    entry = _ai_entry()
    assert "the endpoint host is not loopback as the engine reads it" in entry
    assert "(so localhost. gets the CRL)" in entry


def test_a_loopback_relay_resolves_no_crl_whatever_the_file_says() -> None:
    """The behaviour the SMTP clause's loopback condition describes."""
    policy = TrustAnchorPolicy(crl_file=_CRL)
    for host in ("127.0.0.1", "localhost", "::1"):
        anchor = resolve_trust_anchor(connection_ca_file=None, host=host, policy=policy)
        assert anchor.crl_file is None, host
    pinned = resolve_trust_anchor(
        connection_ca_file="C:/synthetic/ca.pem", host="::1", policy=policy
    )
    assert pinned.crl_file is None


def test_localhost_with_a_trailing_dot_reads_remote_and_gets_the_crl() -> None:
    """The behaviour the ``[ai]`` entry's parenthesis describes."""
    policy = TrustAnchorPolicy(crl_file=_CRL)
    anchor = resolve_trust_anchor(connection_ca_file=None, host="localhost.", policy=policy)
    assert anchor.crl_file == _CRL
