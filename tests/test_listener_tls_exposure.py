# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Cleartext-bind guard for raw-TCP/X12 LISTEN connectors (SEC-002, CWE-319).

Regression intent: ``check_tcp_tls_exposure`` must refuse a **non-loopback** raw-TCP or X12 listener
at start — these connectors are plaintext-only (no ``tls=`` option), so an off-loopback bind puts
raw-TCP/X12 payloads (frequently PHI: X12 270/271 eligibility, FHIR/raw bodies) on the wire in
cleartext. This is the TCP/X12 sibling of the MLLP/DICOM exposed-gates (ADR 0002 §0 / ADR 0025 §9),
generalizing the refusal to the remaining cleartext-only LISTEN types. The only escapes are a loopback
bind, OS-level firewall/segmentation, or ``serve --allow-insecure-bind`` (which downgrades to a warn).
Before the fix, neither TCP nor X12 had any exposure guard and a 0.0.0.0 bind started silently.
"""

from __future__ import annotations

import logging

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import WiringError
from messagefoundry.pipeline.wiring_runner import check_tcp_tls_exposure


def _source(conn_type: ConnectorType, host: str) -> Source:
    return Source(type=conn_type, settings={"host": host, "port": 9000})


@pytest.mark.parametrize("conn_type", [ConnectorType.TCP, ConnectorType.X12])
def test_non_loopback_plaintext_refused(conn_type: ConnectorType) -> None:
    """A non-loopback TCP/X12 bind without --allow-insecure-bind raises naming the cleartext risk."""
    with pytest.raises(WiringError) as exc:
        check_tcp_tls_exposure(_source(conn_type, "0.0.0.0"), "IB", allow_insecure_bind=False)
    msg = str(exc.value).lower()
    assert "cleartext" in msg
    assert "plaintext" in msg
    assert "0.0.0.0" in str(exc.value)
    assert "IB" in str(exc.value)


@pytest.mark.parametrize("conn_type", [ConnectorType.TCP, ConnectorType.X12])
@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_passes(conn_type: ConnectorType, host: str) -> None:
    """Every loopback host passes unconditionally — no network exposure."""
    check_tcp_tls_exposure(_source(conn_type, host), "IB", allow_insecure_bind=False)


@pytest.mark.parametrize("conn_type", [ConnectorType.TCP, ConnectorType.X12])
def test_override_warns(conn_type: ConnectorType, caplog: pytest.LogCaptureFixture) -> None:
    """--allow-insecure-bind does not raise on a non-loopback bind but logs a cleartext warning."""
    with caplog.at_level(logging.WARNING):
        check_tcp_tls_exposure(_source(conn_type, "0.0.0.0"), "IB", allow_insecure_bind=True)
    assert any("cleartext" in rec.getMessage().lower() for rec in caplog.records)


@pytest.mark.parametrize("conn_type", [ConnectorType.FILE, ConnectorType.MLLP])
def test_guard_ignores_non_tcp(conn_type: ConnectorType) -> None:
    """The guard is keyed on TCP/X12 only — a FILE/MLLP source passes through with no raise even on
    a non-loopback host (MLLP has its own dedicated guard; FILE never binds the network)."""
    check_tcp_tls_exposure(_source(conn_type, "0.0.0.0"), "IB", allow_insecure_bind=False)
