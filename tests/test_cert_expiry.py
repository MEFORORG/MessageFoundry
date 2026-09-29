# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the TLS-certificate expiry monitor (pipeline/cert_expiry.py, Q5c)."""

from __future__ import annotations

import asyncio
import datetime
import fnmatch
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import BaseModel

from messagefoundry.config.settings import (
    ApiSettings,
    AuthSettings,
    CertMonitorSettings,
    LoggingSettings,
    ServiceSettings,
    StoreBackend,
    StoreSettings,
    TlsSettings,
)
from messagefoundry.config.wiring import MLLP, InboundConnection, Registry
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.cert_expiry import (
    CertExpiryRunner,
    MonitoredCert,
    certs_from_registry,
    client_cert_label,
    crls_from_settings,
    peer_cert_expiry,
)
from messagefoundry.pipeline.engine import Engine

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
        self.crl_calls: list[tuple[str, str, str, int]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        pass

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        pass

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        pass

    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None:
        self.cert_calls.append((name, path, not_after, days_remaining))

    def crl_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None:
        self.crl_calls.append((name, path, not_after, days_remaining))

    def secret_rotation_due(
        self, name: str, *, class_id: str, last_rotated: str, days_overdue: int
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
    assert peer_cert_expiry({"notAfter": 12345}, now=_REF_TS) is None


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


# --- BACKLOG #1005 scope 4: the CRL pre-expiry alarm --------------------------------------------
#
# A CRL is watched by the same monitor because the operator question is identical -- "is a file I
# depend on about to expire" -- but it alerts down a SEPARATE sink method, and that separation is
# the property under test. An expiring CERTIFICATE degrades one identity and is fixed by reissuing
# it. An EXPIRED CRL makes OpenSSL refuse EVERY client presenting a certificate under that issuer,
# not merely revoked ones, so it is a total interface outage fixed by a PKI refresh. One method for
# both would hand an operator one string for two causes with opposite remedies.


def _write_crl(path: Path, *, next_update: datetime.datetime) -> None:
    """A CA bundled with its own CRL, which the monitor reads. harden_crl_check loads it only where the same CA is loaded first (#1890)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-test-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(next_update - datetime.timedelta(days=400))
        .not_valid_after(next_update + datetime.timedelta(days=400))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(next_update - datetime.timedelta(days=30))
        .next_update(next_update)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(
        ca.public_bytes(serialization.Encoding.PEM) + crl.public_bytes(serialization.Encoding.PEM)
    )


def test_a_crl_inside_the_warn_window_alerts_crl_expiry_not_cert_expiry(tmp_path: Path) -> None:
    # THE SEPARATION IS THE POINT. Asserting crl_calls alone would pass if the runner fired BOTH.
    crl = tmp_path / "ca_and_crl.pem"
    _write_crl(crl, next_update=_REF + datetime.timedelta(days=5))
    sink = _RecordingSink()
    _runner([MonitoredCert("IB_PARTNER", str(crl), kind="crl")], sink).run_once()
    assert len(sink.crl_calls) == 1
    assert sink.cert_calls == []
    name, path, _, days = sink.crl_calls[0]
    assert (name, path) == ("IB_PARTNER", str(crl))
    assert days == 5


def test_an_expired_crl_reports_negative_days(tmp_path: Path) -> None:
    # Negative days_remaining is what tells the sink to escalate: past nextUpdate the listener is
    # already refusing every client, so this is not an approaching deadline.
    crl = tmp_path / "stale.pem"
    _write_crl(crl, next_update=_REF - datetime.timedelta(days=3))
    sink = _RecordingSink()
    _runner([MonitoredCert("IB_PARTNER", str(crl), kind="crl")], sink).run_once()
    assert len(sink.crl_calls) == 1
    assert sink.crl_calls[0][3] == -3


def test_a_fresh_crl_alerts_nothing(tmp_path: Path) -> None:
    # POSITIVE CONTROL: the alarm can stay SILENT. Without it the two tests above would pass just as
    # well against a monitor that alerts on every CRL it is handed.
    crl = tmp_path / "fresh.pem"
    _write_crl(crl, next_update=_REF + datetime.timedelta(days=365))
    sink = _RecordingSink()
    _runner([MonitoredCert("IB_PARTNER", str(crl), kind="crl")], sink).run_once()
    assert sink.crl_calls == []
    assert sink.cert_calls == []


def test_a_cert_and_a_crl_on_one_connection_route_to_their_own_methods(tmp_path: Path) -> None:
    # The realistic configuration: one listener presenting a server identity AND checking a CRL.
    # Both expire, and an operator must be able to tell which one from the alert alone.
    cert = tmp_path / "server.pem"
    crl = tmp_path / "ca_and_crl.pem"
    _write_cert(cert, not_after=_REF + datetime.timedelta(days=7))
    _write_crl(crl, next_update=_REF + datetime.timedelta(days=2))
    sink = _RecordingSink()
    _runner(
        [
            MonitoredCert("IB_PARTNER", str(cert)),
            MonitoredCert("IB_PARTNER", str(crl), kind="crl"),
        ],
        sink,
    ).run_once()
    assert [c[3] for c in sink.cert_calls] == [7]
    assert [c[3] for c in sink.crl_calls] == [2]


def test_an_inbound_tls_crl_file_is_collected_from_the_registry() -> None:
    # Scope 1 wired the setting into the three listeners; this is what makes the monitor SEE it.
    # Only inbound connections carry a tls_crl_file. The outbound CRLs are instance-wide settings,
    # which crls_from_settings collects (BACKLOG #299, tested below).
    registry = Registry()
    registry.inbound["IB_PARTNER"] = InboundConnection(
        name="IB_PARTNER",
        spec=MLLP(
            port=2575,
            tls=True,
            tls_cert_file="c.pem",
            tls_ca_file="ca.pem",
            tls_crl_file="ca_and_crl.pem",
        ),
        router="r",
    )
    collected = certs_from_registry(registry, None)
    kinds = {(mc.kind, mc.path) for mc in collected}
    assert ("crl", "ca_and_crl.pem") in kinds
    assert ("cert", "c.pem") in kinds


# --- BACKLOG #299: the settings-level CRL files, mostly on OUTBOUND hops ------------------------
#
# No connection carries these, so the registry scan never saw them. A stale one stayed silent
# until the next context build refused it, or a handshake failed with "CRL has expired".


def _all_crl_settings(tmp_path: Path, *, next_update: datetime.datetime) -> ServiceSettings:
    """Settings naming a DIFFERENT CRL file in each of the five settings-level knobs."""
    paths = {}
    for knob in ("tls", "forward", "oidc", "store", "api"):
        paths[knob] = tmp_path / f"{knob}_crl.pem"
        _write_crl(paths[knob], next_update=next_update)
    return ServiceSettings(
        tls=TlsSettings(crl_file=str(paths["tls"])),
        logging=LoggingSettings(forward_tls_crl_file=str(paths["forward"])),
        auth=AuthSettings(oidc_tls_crl_file=str(paths["oidc"])),
        # ssl_crl_file loads on either verifying postgres branch since BACKLOG #300; this is the pinned-CA
        # one, which the cert-expiry sweep reads the same way.
        store=StoreSettings(
            backend=StoreBackend.POSTGRES,
            server="db",
            database="mefor",
            username="mefor",
            ssl_root_cert=str(paths["store"]),
            ssl_crl_file=str(paths["store"]),
        ),
        api=ApiSettings(tls_client_crl_file=str(paths["api"])),
    )


def test_every_settings_level_crl_is_collected_under_its_own_setting_name(tmp_path: Path) -> None:
    settings = _all_crl_settings(tmp_path, next_update=_REF + datetime.timedelta(days=365))
    collected = crls_from_settings(settings)
    assert {mc.kind for mc in collected} == {"crl"}
    assert {mc.label: Path(mc.path).name for mc in collected} == {
        "tls.crl_file": "tls_crl.pem",
        "logging.forward_tls_crl_file": "forward_crl.pem",
        "auth.oidc_tls_crl_file": "oidc_crl.pem",
        "store.ssl_crl_file": "store_crl.pem",
        "api.tls_client_crl_file": "api_crl.pem",
    }


def test_an_alert_rule_that_copies_a_settings_crl_label_matches_it(tmp_path: Path) -> None:
    # AlertRule.connection is matched with fnmatch, which reads "[tls]" as a one-character class
    # and "*" or "?" as wildcards. A label holding any of them would not match a rule that copied
    # it verbatim, or would match more than it names. The notifier appends " (CRL)" to the label,
    # so that is the string a rule sees.
    settings = _all_crl_settings(tmp_path, next_update=_REF + datetime.timedelta(days=365))
    for mc in crls_from_settings(settings):
        assert not set("[]*?") & set(mc.label), mc.label
        seen = f"{mc.label} (CRL)"
        assert fnmatch.fnmatchcase(seen, seen), seen


def test_every_crl_file_setting_is_watched() -> None:
    # The knob list in crls_from_settings is written by hand. This walks every settings section for
    # a field whose name ends in "crl_file", so a CRL setting added later cannot be missed silently.
    sections: dict[str, BaseModel] = {}
    expected: set[str] = set()
    for section, field in ServiceSettings.model_fields.items():
        model = field.annotation
        if not (isinstance(model, type) and issubclass(model, BaseModel)):
            continue
        knobs = {name: f"{name}.pem" for name in model.model_fields if name.endswith("crl_file")}
        if knobs:
            # model_construct skips validation, so the paths need not exist on disk.
            sections[section] = model.model_construct(**knobs)
            expected |= {f"{section}.{name}" for name in knobs}
    # POSITIVE CONTROL: the walk must find knobs we know exist, or an empty set proves nothing.
    assert {"tls.crl_file", "store.ssl_crl_file"} <= expected
    collected = crls_from_settings(ServiceSettings.model_construct(**sections))
    assert {mc.label for mc in collected} == expected


def test_an_unset_crl_knob_adds_nothing(tmp_path: Path) -> None:
    # POSITIVE CONTROL for the test above: the default settings name no CRL, so nothing is watched,
    # and one knob set gives exactly one row rather than rows for its unset siblings.
    assert crls_from_settings(ServiceSettings()) == []
    crl = tmp_path / "tls_crl.pem"
    _write_crl(crl, next_update=_REF + datetime.timedelta(days=365))
    only_tls = crls_from_settings(ServiceSettings(tls=TlsSettings(crl_file=str(crl))))
    assert only_tls == [MonitoredCert("tls.crl_file", str(crl), kind="crl")]


def test_an_outbound_crl_past_next_update_raises_crl_expiry(tmp_path: Path) -> None:
    crl = tmp_path / "outbound_crl.pem"
    _write_crl(crl, next_update=_REF - datetime.timedelta(days=2))
    settings = ServiceSettings(tls=TlsSettings(crl_file=str(crl)))
    sink = _RecordingSink()
    _runner(crls_from_settings(settings), sink).run_once()
    assert sink.cert_calls == []
    assert [(c[0], c[1], c[3]) for c in sink.crl_calls] == [("tls.crl_file", str(crl), -2)]


def test_an_outbound_crl_inside_the_warn_window_warns(tmp_path: Path) -> None:
    crl = tmp_path / "forward_crl.pem"
    _write_crl(crl, next_update=_REF + datetime.timedelta(days=5))
    settings = ServiceSettings(logging=LoggingSettings(forward_tls_crl_file=str(crl)))
    sink = _RecordingSink()
    _runner(crls_from_settings(settings), sink).run_once()
    assert [(c[0], c[3]) for c in sink.crl_calls] == [("logging.forward_tls_crl_file", 5)]


def _crl_block(issuer_cn: str, *, next_update: datetime.datetime) -> bytes:
    """One bare PEM CRL from a throwaway issuer."""
    key = ec.generate_private_key(ec.SECP256R1())
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .last_update(next_update - datetime.timedelta(days=30))
        .next_update(next_update)
        .sign(key, hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.PEM)


def test_a_later_stale_crl_in_a_multi_issuer_file_still_alerts(tmp_path: Path) -> None:
    # [tls].crl_file may hold one CRL per issuer, and OpenSSL fails a handshake once ANY of them
    # lapses. Reading only the first block would report the fresh partner-a CRL and stay silent.
    crl = tmp_path / "org_crls.pem"
    crl.write_bytes(
        _crl_block("partner-a", next_update=_REF + datetime.timedelta(days=300))
        + _crl_block("partner-b", next_update=_REF - datetime.timedelta(days=3))
    )
    sink = _RecordingSink()
    checks = _runner([MonitoredCert("tls.crl_file", str(crl), kind="crl")], sink).run_once()
    assert [c[3] for c in sink.crl_calls] == [-3]
    assert checks[0].expired is True


def test_one_unreadable_block_does_not_hide_a_sibling_about_to_lapse(tmp_path: Path) -> None:
    # A broken block must not drop the whole file out of monitoring: the good CRL beside it is
    # still judged, and it is about to lapse.
    crl = tmp_path / "org_crls.pem"
    crl.write_bytes(
        b"-----BEGIN X509 CRL-----\nbm90IGEgQ1JM\n-----END X509 CRL-----\n"
        + _crl_block("partner-a", next_update=_REF + datetime.timedelta(days=4))
    )
    sink = _RecordingSink()
    _runner([MonitoredCert("tls.crl_file", str(crl), kind="crl")], sink).run_once()
    assert [c[3] for c in sink.crl_calls] == [4]


def test_a_multi_issuer_file_with_every_crl_fresh_alerts_nothing(tmp_path: Path) -> None:
    # POSITIVE CONTROL for the test above: two fresh CRLs stay silent, so the alert there came from
    # the stale second block and not from reading two blocks at all.
    crl = tmp_path / "org_crls.pem"
    crl.write_bytes(
        _crl_block("partner-a", next_update=_REF + datetime.timedelta(days=300))
        + _crl_block("partner-b", next_update=_REF + datetime.timedelta(days=200))
    )
    sink = _RecordingSink()
    checks = _runner([MonitoredCert("tls.crl_file", str(crl), kind="crl")], sink).run_once()
    assert sink.crl_calls == []
    assert checks[0].days_remaining == 200


def test_every_settings_crl_alerts_under_a_distinct_label(tmp_path: Path) -> None:
    # The realert throttle keys on the label, so two hops sharing one would lose the second alert
    # to the first one's cooldown in the same pass. Five stale CRLs must give five distinct labels.
    settings = _all_crl_settings(tmp_path, next_update=_REF - datetime.timedelta(days=1))
    sink = _RecordingSink()
    _runner(crls_from_settings(settings), sink).run_once()
    labels = [c[0] for c in sink.crl_calls]
    assert len(labels) == 5
    assert len(set(labels)) == 5


def test_the_engine_hands_the_settings_crls_to_its_expiry_monitor(tmp_path: Path) -> None:
    crl = tmp_path / "tls_crl.pem"
    _write_crl(crl, next_update=_REF + datetime.timedelta(days=5))
    watched = crls_from_settings(ServiceSettings(tls=TlsSettings(crl_file=str(crl))))

    async def _go() -> list[MonitoredCert]:
        eng = await Engine.create(tmp_path / "crl.db", settings_crls=watched)
        try:
            return eng._monitored_certs()
        finally:
            await eng.stop()

    assert asyncio.run(_go()) == watched


def test_the_crl_log_line_names_no_direction(caplog: pytest.LogCaptureFixture) -> None:
    # The old text said "this listener refuses EVERY client", which is false for an outbound hop.
    # Asserted on the level and on hop words, not on "EXPIRED": in a full run a log redaction filter
    # another test installs can rewrite that token, which is not what this test is about.
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().crl_expiry(
            "tls.crl_file",
            path="crl.pem",
            not_after="2026-06-13T12:00:00+00:00",
            days_remaining=-2,
        )
    assert [r.levelno for r in caplog.records] == [logging.ERROR]
    text = caplog.text
    assert "this listener" not in text
    assert "outbound hop cannot connect" in text
    assert "restart the engine" in text
