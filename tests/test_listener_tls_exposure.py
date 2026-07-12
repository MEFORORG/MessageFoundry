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
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import WiringError
from messagefoundry.pipeline.wiring_runner import check_tcp_tls_exposure

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


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


# --- certificate-revocation posture: serve-time refusal for in-process off-loopback [api] TLS -----
#
# ADR 0078 (ASVS 12.1.4): the engine performs NO OCSP/CRL revocation (stdlib ssl has none; on-prem
# offline-by-default). So an in-process, off-loopback [api] TLS bind must PROVE revocation in front —
# a declared TLS-terminating proxy OR the MEFOR_TLS_REVOCATION_ATTESTED opt-out — else `serve` refuses.
# Patterned on the exposed-bind gate assertions in test_cli.py (main(["serve", ...]) → 2/0, uvicorn +
# the app + the SSL-context builder mocked so no socket/cert is touched). `--env dev` is synthetic, so
# the keyless / open-egress / MFA-at-exposure gates stay quiet and only the revocation gate is tested.


def _mock_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralize everything after the gates so a permitted serve returns 0 without opening a socket."""
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    # The in-process-TLS start path builds an SSLContext from the cert PEM before uvicorn.run; stub it
    # so the tests need no on-disk cert (the GATE, not context-building, is under test).
    monkeypatch.setattr("messagefoundry.api.tls.build_api_ssl_context", lambda api: object())


def test_serve_refuses_inprocess_tls_offloopback_without_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # AC-1: in-process TLS off-loopback, no proxy-termination, no attestation → refuse (exit 2). The
    # cert path need not exist — the gate returns before any context is built.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_TLS_REVOCATION_ATTESTED", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\nhost = "0.0.0.0"\ntls_cert_file = "cert.pem"\n', encoding="utf-8"
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 2
    err = capsys.readouterr().err
    assert "in-process TLS on non-loopback" in err
    assert "12.1.4" in err
    assert "MEFOR_TLS_REVOCATION_ATTESTED=1" in err


def test_serve_inprocess_tls_offloopback_attested_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # AC-4: the documented opt-out — MEFOR_TLS_REVOCATION_ATTESTED=1 lets the same bind start.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_TLS_REVOCATION_ATTESTED", "1")
    _mock_start(monkeypatch)
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\nhost = "0.0.0.0"\ntls_cert_file = "cert.pem"\n', encoding="utf-8"
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "refusing to serve the API with in-process TLS" not in capsys.readouterr().err


def test_serve_loopback_inprocess_tls_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # AC-2: the loopback default never trips the gate, even with in-process TLS and NO attestation —
    # byte-identical to the pre-ADR-0078 start.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_TLS_REVOCATION_ATTESTED", raising=False)
    _mock_start(monkeypatch)
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\nhost = "127.0.0.1"\ntls_cert_file = "cert.pem"\n', encoding="utf-8"
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "in-process TLS on non-loopback" not in capsys.readouterr().err


def test_serve_proxy_terminated_offloopback_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # AC-3: a declared TLS-terminating proxy (tls_terminated_upstream + trusted_proxies) is "revocation
    # proven in front" — the engine terminates no TLS itself, so the gate passes without attestation.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_TLS_REVOCATION_ATTESTED", raising=False)
    _mock_start(monkeypatch)
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\nhost = "0.0.0.0"\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.7"]\n',
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "in-process TLS on non-loopback" not in capsys.readouterr().err
