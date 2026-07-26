# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""#200 (ADR 0092) residual: the off-box log/audit forwarder brought under the shared hop gradient.

``[logging].forward_*`` (ADR 0080) ships a copy of every log record — and, via ``emit_audit_tee``, of
every ``audit_log`` row — to a syslog/SIEM collector. The stream is PHI-**redacted**, but it still
carries usernames, connection names, message ids, client addresses, and the tamper-evident audit chain,
and ``forward_protocol`` defaults to plaintext ``udp`` (RFC 5426). It was the ONE egress path with **no
posture gate at all**: an operator who named a collector shipped that evidence off-box in the clear,
silently, on a production-PHI instance.

Native TLS-syslog has existed since ADR 0080 (``forward_protocol = "tls"``, RFC 5425, CA-anchored), so
this is a *default* problem rather than a capability gap. The forwarding hop now consumes the SAME pure
authority (``tls_policy.insecure_hop_disposition``) the transports do, via
``settings.forward_hop_disposition``:

* loopback collector → ALLOW — the ADR 0080 "point ``tcp``/``udp`` at ``127.0.0.1`` and let a local
  rsyslog/Vector agent add TLS" deployment is preserved byte-identical;
* ``forward_hop_attested`` → ALLOW — the acknowledged, reasoned opt-out (the ``[logging]`` sibling of a
  connection's ``tls_hop_attested``), so a plaintext hop is an ACKNOWLEDGED escape, not a silent default;
* synthetic instance → ALLOW, silently; non-enforcing PHI → WARN; enforcing PHI → REFUSE.

``serve`` decides BEFORE ``configure_logging`` installs the handler, so a refused hop never emits a
single record.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    LoggingSettings,
    forward_hop_disposition,
)
from messagefoundry.config.tls_policy import HopDisposition, HopPosture

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

PROD_PHI = HopPosture(is_phi=True, enforcing=True)
STAGING_PHI = HopPosture(is_phi=True, enforcing=False)  # PHI, dial at warn
SYNTHETIC = HopPosture(is_phi=False, enforcing=True)  # not is_phi → always ALLOW

REMOTE = "10.0.0.5"  # RFC 1918, non-loopback (never resolves; treated as off-box)
LOOPBACK = "127.0.0.1"


def _log(**kw: object) -> LoggingSettings:
    base: dict[str, object] = {"forward_host": REMOTE, "forward_enabled": True}
    base.update(kw)
    return LoggingSettings(**base)  # type: ignore[arg-type]


# --- the plaintext default is what the gate exists for -------------------------------------------


def test_plaintext_udp_is_still_the_shipped_default() -> None:
    # Guards the premise: if this ever flips to tls, the gate below stops being the interesting one.
    assert LoggingSettings().forward_protocol.value == "udp"


def test_prod_phi_plaintext_udp_collector_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    assert forward_hop_disposition(_log(), PROD_PHI) is HopDisposition.REFUSE


def test_prod_phi_plaintext_tcp_collector_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    assert forward_hop_disposition(_log(forward_protocol="tcp"), PROD_PHI) is HopDisposition.REFUSE


def test_prod_phi_global_escape_cannot_relax_the_forward_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The blunt escape is CLAMPED to non-enforcing upstream, so it is inert here (ADR 0092 decision 2).
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    assert forward_hop_disposition(_log(), PROD_PHI) is HopDisposition.REFUSE


# --- the secure transport, and the paths that must stay open -------------------------------------


def test_verified_tls_collector_allowed() -> None:
    # The ADR 0080 secure transport: encrypted + CA-anchored + hostname-checked → nothing to gate.
    settings = _log(forward_protocol="tls", forward_tls_ca_file="/etc/pki/siem-ca.pem")
    assert forward_hop_disposition(settings, PROD_PHI) is HopDisposition.ALLOW


def test_tls_with_verification_disabled_is_not_a_secure_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # forward_tls_verify=false is CERT_NONE — encrypted but unauthenticated, so MITM-able. It is the
    # documented insecure opt-out and belongs on the gradient, not in the ALLOW carve-out.
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    settings = _log(forward_protocol="tls", forward_tls_verify=False)
    assert forward_hop_disposition(settings, PROD_PHI) is HopDisposition.REFUSE


def test_loopback_collector_allowed_so_the_local_agent_deployment_survives() -> None:
    # ADR 0080 explicitly keeps "udp/tcp to 127.0.0.1 + a local agent that adds TLS" as a supported
    # (throughput-friendly) deployment. It must never be refused — there is no network crossing.
    assert forward_hop_disposition(_log(forward_host=LOOPBACK), PROD_PHI) is HopDisposition.ALLOW


def test_synthetic_instance_plaintext_collector_allowed_silently() -> None:
    assert forward_hop_disposition(_log(), SYNTHETIC) is HopDisposition.ALLOW


def test_non_enforcing_phi_plaintext_collector_warns_and_crosses() -> None:
    assert forward_hop_disposition(_log(), STAGING_PHI) is HopDisposition.WARN


def test_attested_hop_allowed_on_enforcing_phi(monkeypatch: pytest.MonkeyPatch) -> None:
    # The acknowledged escape: the operator affirms the collector hop is secure by other means.
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    settings = _log(
        forward_hop_attested=True,
        forward_hop_attested_reason="dedicated out-of-band management VLAN",
    )
    assert forward_hop_disposition(settings, PROD_PHI) is HopDisposition.ALLOW


# --- the attestation pair is validated by the SHARED rule, never re-forked -----------------------


def test_attestation_reason_without_the_flag_is_a_config_error() -> None:
    with pytest.raises(ValueError, match="forward_hop_attested"):
        _log(forward_hop_attested_reason="because")


def test_blank_attestation_reason_rejected() -> None:
    with pytest.raises(ValueError, match="forward_hop_attested"):
        _log(forward_hop_attested=True, forward_hop_attested_reason="   ")


# --- serve() wiring: refused BEFORE the handler is installed -------------------------------------

_SECURE_RETENTION = (
    "security.delete_message_bodies_after_days = 30\n[retention]\ndead_letter_days = 30\n"
)
_SECURE_ALERTS = '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'
_PRE_CLEARED = "security.block_unlisted_outbound = true\n" + _SECURE_RETENTION + _SECURE_ALERTS


def _serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, forwarding: str, *, env: str = "prod"
) -> int:
    """Serve a prod-PHI instance whose every OTHER secure-by-default gate is pre-cleared, so only the
    forwarding hop decides the outcome. create_managed_app/uvicorn are mocked — nothing binds."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)  # passes the keyless gate
    (tmp_path / "messagefoundry.toml").write_text(
        _PRE_CLEARED + "[logging]\n" + forwarding, encoding="utf-8"
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", env])


def test_serve_refuses_prod_phi_plaintext_forwarding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _serve(tmp_path, monkeypatch, f'forward_host = "{REMOTE}"\n')
    assert rc == 2
    err = capsys.readouterr().err
    assert "off-box forwarding" in err and "forward_hop_attested" in err


def test_serve_allows_prod_phi_forwarding_when_attested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc = _serve(
        tmp_path,
        monkeypatch,
        f'forward_host = "{REMOTE}"\n'
        "forward_hop_attested = true\n"
        'forward_hop_attested_reason = "out-of-band management VLAN"\n',
    )
    assert rc == 0


def test_serve_allows_prod_phi_forwarding_to_a_local_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _serve(tmp_path, monkeypatch, f'forward_host = "{LOOPBACK}"\n') == 0


def test_serve_without_a_collector_is_byte_identical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No forward_host → forwarding stays OFF and the gate never runs (the overwhelmingly common case).
    assert _serve(tmp_path, monkeypatch, 'level = "INFO"\n') == 0
