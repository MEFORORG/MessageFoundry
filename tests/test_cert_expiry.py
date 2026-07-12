# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the TLS-certificate expiry monitor (pipeline/cert_expiry.py, Q5c)."""

from __future__ import annotations

import asyncio
import datetime
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.settings import CertMonitorSettings
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.cert_expiry import (
    CertExpiryRunner,
    MonitoredCert,
    certs_from_registry,
)

_UTC = datetime.timezone.utc
# A fixed reference instant so the cert windows + the runner's clock are deterministic.
_REF = datetime.datetime(2026, 6, 15, 12, 0, tzinfo=_UTC)
_REF_TS = _REF.timestamp()


def _write_cert(path: Path, *, not_after: datetime.datetime) -> None:
    """Write a self-signed PEM cert with the given expiry (fast EC key — no slow RSA keygen)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - datetime.timedelta(days=400))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class _RecordingSink:
    """An AlertSink that records cert_expiry calls; the other methods are inert."""

    def __init__(self) -> None:
        self.cert_calls: list[tuple[str, str, str, int]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        pass

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        pass

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        pass

    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None:
        self.cert_calls.append((name, path, not_after, days_remaining))

    def secret_rotation_due(
        self, name: str, *, secret: str, last_rotated: str, days_overdue: int
    ) -> None:
        pass


def _runner(
    certs: list[MonitoredCert], sink: _RecordingSink, warn_days: int = 30
) -> CertExpiryRunner:
    return CertExpiryRunner(
        lambda: certs,
        CertMonitorSettings(warn_days=warn_days),
        alert_sink=sink,
        clock=lambda: _REF_TS,
    )


# --- run_once: the core scan ------------------------------------------------


def test_healthy_cert_does_not_alert(tmp_path: Path) -> None:
    p = tmp_path / "api.pem"
    _write_cert(p, not_after=_REF + datetime.timedelta(days=90))
    sink = _RecordingSink()
    checks = _runner([MonitoredCert("api", str(p))], sink).run_once()
    assert sink.cert_calls == []
    assert len(checks) == 1
    assert checks[0].days_remaining == 90
    assert checks[0].expired is False


def test_near_expiry_alerts_with_days_remaining(tmp_path: Path) -> None:
    p = tmp_path / "mllp.pem"
    _write_cert(p, not_after=_REF + datetime.timedelta(days=10))
    sink = _RecordingSink()
    _runner([MonitoredCert("IB_PARTNER", str(p))], sink).run_once()
    assert len(sink.cert_calls) == 1
    name, path, _not_after, days = sink.cert_calls[0]
    assert name == "IB_PARTNER"
    assert path == str(p)
    assert days == 10


def test_expired_cert_alerts_with_negative_days(tmp_path: Path) -> None:
    p = tmp_path / "old.pem"
    _write_cert(p, not_after=_REF - datetime.timedelta(days=5))
    sink = _RecordingSink()
    checks = _runner([MonitoredCert("api", str(p))], sink).run_once()
    assert len(sink.cert_calls) == 1
    assert sink.cert_calls[0][3] == -5
    assert checks[0].expired is True


def test_boundary_is_inclusive(tmp_path: Path) -> None:
    # Exactly warn_days away → still alerts (<=).
    p = tmp_path / "edge.pem"
    _write_cert(p, not_after=_REF + datetime.timedelta(days=30))
    sink = _RecordingSink()
    _runner([MonitoredCert("api", str(p))], sink, warn_days=30).run_once()
    assert len(sink.cert_calls) == 1


def test_missing_file_is_skipped_not_fatal(tmp_path: Path) -> None:
    sink = _RecordingSink()
    checks = _runner([MonitoredCert("gone", str(tmp_path / "nope.pem"))], sink).run_once()
    assert sink.cert_calls == []
    assert checks == []


def test_unparseable_file_is_skipped(tmp_path: Path) -> None:
    p = tmp_path / "junk.pem"
    p.write_text("not a certificate")
    sink = _RecordingSink()
    checks = _runner([MonitoredCert("junk", str(p))], sink).run_once()
    assert sink.cert_calls == []
    assert checks == []


def test_one_bad_cert_does_not_block_others(tmp_path: Path) -> None:
    good = tmp_path / "good.pem"
    _write_cert(good, not_after=_REF + datetime.timedelta(days=3))
    sink = _RecordingSink()
    certs = [MonitoredCert("missing", str(tmp_path / "x.pem")), MonitoredCert("good", str(good))]
    _runner(certs, sink).run_once()
    assert [c[0] for c in sink.cert_calls] == ["good"]


# --- certs_from_registry ----------------------------------------------------


def _conn(name: str, settings: dict[str, object]) -> SimpleNamespace:
    return SimpleNamespace(name=name, spec=SimpleNamespace(settings=settings))


def test_certs_from_registry_enumerates_api_and_mllp() -> None:
    reg = SimpleNamespace(
        inbound={
            "IB_MLLP": _conn("IB_MLLP", {"tls_cert_file": "/c/ib.pem"}),
            "IB_PLAIN": _conn("IB_PLAIN", {"port": 2575}),  # no tls_cert_file → skipped
        },
        outbound={"OB_MLLP": _conn("OB_MLLP", {"tls_cert_file": "/c/ob.pem"})},
    )
    certs = certs_from_registry(reg, "/c/api.pem")
    assert {(c.label, c.path) for c in certs} == {
        ("api", "/c/api.pem"),
        ("IB_MLLP", "/c/ib.pem"),
        ("OB_MLLP", "/c/ob.pem"),
    }


def test_certs_from_registry_skips_non_str_path() -> None:
    # An unresolved env() reference (not a literal str) is skipped, not crashed on.
    reg = SimpleNamespace(
        inbound={"IB": _conn("IB", {"tls_cert_file": object()})},
        outbound={},
    )
    assert certs_from_registry(reg, None) == []


def test_certs_from_registry_none_registry_yields_only_api() -> None:
    certs = certs_from_registry(None, "/c/api.pem")
    assert [(c.label, c.path) for c in certs] == [("api", "/c/api.pem")]
    assert certs_from_registry(None, None) == []


# --- enabled / lifecycle ----------------------------------------------------


def test_disabled_when_warn_days_zero() -> None:
    runner = CertExpiryRunner(lambda: [], CertMonitorSettings(warn_days=0))
    assert runner.enabled is False


def test_start_stop_clean_with_no_certs() -> None:
    async def _go() -> None:
        sink = _RecordingSink()
        settings = CertMonitorSettings(warn_days=30, check_interval_seconds=0.01)
        runner = CertExpiryRunner(lambda: [], settings, alert_sink=sink)
        runner.start()
        await asyncio.sleep(0.03)
        await runner.stop()
        assert sink.cert_calls == []

    asyncio.run(_go())


def test_start_is_noop_when_disabled() -> None:
    async def _go() -> None:
        runner = CertExpiryRunner(lambda: [], CertMonitorSettings(warn_days=0))
        runner.start()
        await runner.stop()  # idempotent, no task ever spawned

    asyncio.run(_go())


# --- the sinks --------------------------------------------------------------


def test_logging_sink_cert_expiry_does_not_raise() -> None:
    sink = LoggingAlertSink()
    sink.cert_expiry(
        "api", path="/c/api.pem", not_after="2026-07-01T00:00:00+00:00", days_remaining=5
    )
    sink.cert_expiry(
        "api", path="/c/api.pem", not_after="2026-06-01T00:00:00+00:00", days_remaining=-3
    )


def test_notifier_sink_emits_cert_expiry_event() -> None:
    class _RecordTransport:
        name = "rec"

        def __init__(self) -> None:
            self.events: list[dict[str, object]] = []

        async def send(self, event: dict[str, object]) -> None:
            self.events.append(event)

    async def _go() -> None:
        t = _RecordTransport()
        sink = NotifierAlertSink([t], realert_seconds=0.0)
        sink.start()
        sink.cert_expiry(
            "api", path="/c/api.pem", not_after="2026-07-01T00:00:00+00:00", days_remaining=5
        )
        await asyncio.sleep(0.02)
        await sink.aclose()
        assert any(
            e["type"] == "cert_expiry" and e["connection"] == "api" and e["days_remaining"] == 5
            for e in t.events
        )

    asyncio.run(_go())
