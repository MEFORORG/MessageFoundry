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
    client_cert_label,
    peer_cert_expiry,
)

_UTC = datetime.UTC
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


# --- ASVS 6.4.5 arm 3: service-caller (inbound mTLS client) cert monitoring ----------------------


def test_certs_from_registry_folds_in_client_cert_files() -> None:
    # [api].tls_client_cert_files are certs the engine VERIFIES, not ones it presents — they are invisible
    # to the served-cert enumeration, so folding them in is what catches a caller that stopped connecting.
    certs = certs_from_registry(None, "/c/api.pem", ["/c/svc-billing.pem", "/c/svc-labs.pem"])
    assert [(c.label, c.path) for c in certs] == [
        ("api", "/c/api.pem"),
        ("api-client:/c/svc-billing.pem", "/c/svc-billing.pem"),
        ("api-client:/c/svc-labs.pem", "/c/svc-labs.pem"),
    ]
    # Default (omitted) is byte-identical to before — no client certs watched.
    assert certs_from_registry(None, "/c/api.pem") == [MonitoredCert("api", "/c/api.pem")]


def test_client_cert_label_is_namespaced_and_never_collides_with_api() -> None:
    # The label is the alert's throttle/routing key: it must never collide with the "api" served cert
    # or a connection name, even for a file literally named api.pem.
    assert client_cert_label("/c/api.pem") != "api"
    assert client_cert_label("/c/api.pem").startswith("api-client:")


def test_same_basename_client_certs_get_DISTINCT_labels() -> None:
    """REGRESSION: the label is the alert's throttle key, so it MUST be injective over the list.

    A stem-derived label collapsed the natural per-partner layout (`…/acme/client.pem`,
    `…/globex/client.pem`) onto ONE key. `run_once` emits every cert in a single synchronous pass, so
    the second landed inside the first's `realert_seconds` cooldown and was dropped before any
    transport saw it — on every pass, forever. Invisible under LoggingAlertSink (no throttle); it bit
    only where a real notifier was wired, i.e. exactly where an operator relies on being paged. That
    silently defeats the one arm covering a caller that has STOPPED connecting.
    """
    paths = ["/certs/acme/client.pem", "/certs/globex/client.pem"]
    labels = [c.label for c in certs_from_registry(None, None, paths)]
    assert len(set(labels)) == 2, f"labels collapsed onto one throttle key: {labels}"


def test_both_same_basename_certs_actually_reach_a_transport(tmp_path: Path) -> None:
    """The end-to-end half of the regression, through the sink that really throttles.

    Driven with the DEFAULT realert cooldown (not 0), because the defect was precisely that the second
    cert's alert died inside that cooldown — a test using realert_seconds=0 would pass either way.
    """

    class _RecordTransport:
        name = "t"

        def __init__(self) -> None:
            self.events: list[dict[str, object]] = []

        async def send(self, event: dict[str, object], **_kw: object) -> None:
            self.events.append(event)

    acme = tmp_path / "acme" / "client.pem"
    globex = tmp_path / "globex" / "client.pem"
    for p in (acme, globex):
        p.parent.mkdir(parents=True, exist_ok=True)
        _write_cert(p, not_after=_REF + datetime.timedelta(days=5))  # inside the 30-day warn window

    async def _go() -> None:
        t = _RecordTransport()
        sink = NotifierAlertSink([t])  # default realert_seconds (300s) — the throttle under test
        sink.start()
        runner = CertExpiryRunner(
            lambda: certs_from_registry(None, None, [str(acme), str(globex)]),
            CertMonitorSettings(warn_days=30),
            alert_sink=sink,
            clock=lambda: _REF_TS,
        )
        runner.run_once()  # ONE synchronous pass emits both certs microseconds apart
        await asyncio.sleep(0.02)
        await sink.aclose()
        fired = {e["connection"] for e in t.events if e["type"] == "cert_expiry"}
        assert len(fired) == 2, (
            f"only {sorted(fired)} reached a transport — a same-basename sibling was swallowed by the "
            "re-alert cooldown, which is the whole failure this arm must not have"
        )

    asyncio.run(_go())


def _peercert_expiring(*, in_days: float, now: float) -> dict[str, object]:
    """A synthetic ``getpeercert()`` dict whose notAfter is ``in_days`` from ``now``, in OpenSSL's own
    textual form (the shape ``ssl.cert_time_to_seconds`` parses)."""
    when = datetime.datetime.fromtimestamp(now + in_days * 86_400, tz=_UTC)
    return {"notAfter": when.strftime("%b %d %H:%M:%S %Y GMT")}


def test_peer_cert_expiry_reports_iso_and_days_remaining() -> None:
    cert = _peercert_expiring(in_days=10, now=_REF_TS)
    got = peer_cert_expiry(cert, now=_REF_TS)
    assert got is not None
    not_after_iso, days_remaining = got
    assert days_remaining == 10
    # The ISO instant round-trips to the same second the textual notAfter named.
    assert datetime.datetime.fromisoformat(not_after_iso).timestamp() == _REF_TS + 10 * 86_400


def test_peer_cert_expiry_is_negative_once_expired() -> None:
    got = peer_cert_expiry(_peercert_expiring(in_days=-3, now=_REF_TS), now=_REF_TS)
    assert got is not None and got[1] == -3


def test_peer_cert_expiry_none_when_absent_or_unparseable() -> None:
    # A monitoring signal must degrade to "say nothing", never raise onto the auth path it hangs off.
    assert peer_cert_expiry({}, now=_REF_TS) is None
    assert peer_cert_expiry({"notAfter": ""}, now=_REF_TS) is None
    assert peer_cert_expiry({"notAfter": "not a date at all"}, now=_REF_TS) is None
    assert peer_cert_expiry({"notAfter": 12345}, now=_REF_TS) is None  # type: ignore[dict-item]


def test_peer_cert_expiry_day_math_matches_the_pem_path() -> None:
    # The handshake arm and the file arm must never disagree about the SAME cert by a day, so the day
    # length is pinned equal to pki's (which read_cert_facts / the file monitor use).
    from messagefoundry import pki
    from messagefoundry.pipeline import cert_expiry as ce

    assert ce._SECONDS_PER_DAY == pki._SECONDS_PER_DAY


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

        async def send(self, event: dict[str, object], **_kw: object) -> None:
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
