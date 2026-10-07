# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2319: three follow-ups engine PR 1751 shipped open on the CRL held-copy monitor.

1. **The alert says whose date it is.** When a running hop's older copy lapses before the file, the
   ``crl_expiry`` alert's ``not_after`` is that copy's ``nextUpdate``. The alert now carries
   ``held_copy`` and a ``detail`` naming the hop's setting and what to do; before, only the scan's
   own log line said so, and the notifier payload read as the file's date.
2. **A file two settings share says so.** Held copies are matched by file, not hop, so a stale copy
   is reported under every row naming its file. Each alert now names the other rows
   (``shared_with``), and the ``detail`` names the hop that holds the copy.
3. **A CRL inside a CA bundle is recorded.** ``cafile=`` loads it with the CA, and a hop that checks
   revocation reads it, so it lapses like any CRL. It was invisible to the monitor. Recording,
   rather than refusing, keeps every CA file that loads today loading.

Each behaviour test was run with its fix reverted and failed; the controls pass either way.
All material is synthetic and minted here. No PHI.
"""

from __future__ import annotations

import datetime
import gc
import logging
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.loaded_crls import held_contexts, held_crl_copies
from messagefoundry.config.settings import CertMonitorSettings
from messagefoundry.config.tls_policy import TrustAnchor, build_verifying_client_context
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import HELD_COPY_NOTE, LoggingAlertSink
from messagefoundry.pipeline.cert_expiry import (
    CertExpiryRunner,
    MonitoredCert,
    held_crl_label,
)
from messagefoundry.pipeline.crl_reload import reload_replaced_crls
from tests.test_cert_expiry import _RecordingSink


@dataclass(frozen=True)
class _Ca:
    key: ec.EllipticCurvePrivateKey
    name: x509.Name
    pem: bytes

    def crl(self, *, days: float, number: int) -> bytes:
        """A CRL this CA signed, revoking nothing, whose nextUpdate is ``days`` from now."""
        now = datetime.datetime.now(datetime.UTC)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.name)
            .last_update(now - datetime.timedelta(hours=1, minutes=number))
            .next_update(now + datetime.timedelta(days=days))
            .add_extension(x509.CRLNumber(number), False)
            .sign(self.key, hashes.SHA256())
        )
        return crl.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def ca() -> _Ca:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-2319-ca")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=400))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return _Ca(key, name, cert.public_bytes(serialization.Encoding.PEM))


def _hop(ca_file: Path, crl_file: Path | None) -> ssl.SSLContext:
    """An outbound hop built the way ``[tls].internal_ca_file`` and ``[tls].crl_file`` reach one."""
    return build_verifying_client_context(
        TrustAnchor(
            cafile=str(ca_file),
            load_system_roots=False,
            crl_file=None if crl_file is None else str(crl_file),
            cafile_setting="[tls].internal_ca_file",
        )
    )


def _mine(sink: _RecordingSink, path: Path) -> list[int]:
    """The indexes of the CRL alerts about ``path``. Another test's context not yet collected
    would add its own ``held-crl:`` row, so a test reads only its own file's."""
    return [
        i
        for i, call in enumerate(sink.crl_calls)
        if Path(call[1]).exists() and Path(call[1]).samefile(path)
    ]


# --- 1. the alert says whose date it is ------------------------------------------------------------


def test_an_alert_dated_by_a_held_copy_says_so_and_names_its_hop(ca: _Ca, tmp_path: Path) -> None:
    # The hop loads a CRL that lapses in about five days; the file is then replaced with one good
    # for ninety. The alert's date is the hop's copy, and the alert must say so. Before the fix
    # the sink was handed only the four date fields, so nothing marked it.
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.pem)
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=5.5, number=1))
    hop = _hop(ca_file, crl)
    crl.write_bytes(ca.crl(days=90, number=2))
    sink = _RecordingSink()
    runner = CertExpiryRunner(
        lambda: [MonitoredCert("tls.crl_file", str(crl), kind="crl")],
        CertMonitorSettings(warn_days=30),
        alert_sink=sink,
    )

    runner.run_once(now=time.time())

    assert [c[3] for c in sink.crl_calls] == [5]
    held_copy, detail, shared_with = sink.crl_notes[0]
    assert held_copy is True
    assert "[tls].crl_file" in detail  # the hop that holds it
    assert "A reload is pending" in detail  # and what to do, in the scan's own words
    assert shared_with == ()
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_control_an_alert_dated_by_the_file_is_not_marked(ca: _Ca, tmp_path: Path) -> None:
    # THE CONTROL. The same hop holding exactly the file's bytes: the date is the file's, and the
    # alert carries no held-copy note. So the mark above comes from the held copy alone.
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.pem)
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=5.5, number=1))
    hop = _hop(ca_file, crl)
    sink = _RecordingSink()
    runner = CertExpiryRunner(
        lambda: [MonitoredCert("tls.crl_file", str(crl), kind="crl")],
        CertMonitorSettings(warn_days=30),
        alert_sink=sink,
    )

    runner.run_once(now=time.time())

    assert [c[3] for c in sink.crl_calls] == [5]
    assert sink.crl_notes == [(False, "", ())]
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_held_copy_that_outlasts_the_file_does_not_take_its_date(ca: _Ca, tmp_path: Path) -> None:
    # The hop holds a copy good for ninety days and the file was replaced with one good for five.
    # The date is the file's, so held_copy is False, but the detail still says a hop holds an
    # older copy, which a restart or the reload would replace.
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.pem)
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=1))
    hop = _hop(ca_file, crl)
    crl.write_bytes(ca.crl(days=5.5, number=2))
    sink = _RecordingSink()
    runner = CertExpiryRunner(
        lambda: [MonitoredCert("tls.crl_file", str(crl), kind="crl")],
        CertMonitorSettings(warn_days=30),
        alert_sink=sink,
    )

    runner.run_once(now=time.time())

    assert [c[3] for c in sink.crl_calls] == [5]
    held_copy, detail, _ = sink.crl_notes[0]
    assert held_copy is False
    assert "still holds a copy" in detail
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def _captured(sink_call: Any) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    class _Capture(NotifierAlertSink):
        def _emit(self, event: dict[str, Any]) -> None:
            events.append(event)

    sink_call(_Capture.__new__(_Capture))
    return events


def test_the_notifier_payload_marks_a_held_copy_and_names_the_shared_rows() -> None:
    events = _captured(
        lambda s: s.crl_expiry(
            "tls.crl_file",
            path="crl.pem",
            not_after="2026-06-13T12:00:00+00:00",
            days_remaining=5,
            held_copy=True,
            detail="A running TLS hop ([tls].crl_file) still holds a copy.",
            shared_with=("logging.forward_tls_crl_file",),
        )
    )

    assert len(events) == 1
    event = events[0]
    assert event["type"] == "cert_expiry"
    assert event["connection"] == "tls.crl_file (CRL)"
    assert event["held_copy"] is True
    assert event["shared_with"] == ["logging.forward_tls_crl_file"]
    assert event["detail"].startswith(HELD_COPY_NOTE)
    assert "[tls].crl_file" in event["detail"]


def test_control_a_plain_crl_alert_payload_is_unchanged() -> None:
    # A CRL alert with nothing to add carries exactly the fields it always did, so a rule, a
    # template or a webhook consumer keyed on the old payload sees no new key.
    events = _captured(
        lambda s: s.crl_expiry(
            "tls.crl_file", path="crl.pem", not_after="2026-06-13T12:00:00+00:00", days_remaining=5
        )
    )

    assert events == [
        {
            "type": "cert_expiry",
            "connection": "tls.crl_file (CRL)",
            "path": "crl.pem",
            "not_after": "2026-06-13T12:00:00+00:00",
            "days_remaining": 5,
        }
    ]


def test_the_logging_sink_says_whose_date_it_is(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().crl_expiry(
            "tls.crl_file",
            path="crl.pem",
            not_after="2026-06-13T12:00:00+00:00",
            days_remaining=5,
            held_copy=True,
            detail="Restart the engine.",
        )
        plain_from = len(caplog.records)
        LoggingAlertSink().crl_expiry(
            "tls.crl_file", path="crl.pem", not_after="2026-06-13T12:00:00+00:00", days_remaining=5
        )

    held = [r.getMessage() for r in caplog.records[:plain_from]]
    plain = [r.getMessage() for r in caplog.records[plain_from:]]
    assert any(HELD_COPY_NOTE in line and "Restart the engine." in line for line in held)
    assert len(plain) == 1  # the control: no note line for a date that is the file's
    assert HELD_COPY_NOTE not in plain[0]


# --- 2. a file two settings share says so ----------------------------------------------------------


def test_a_stale_copy_of_a_shared_file_names_the_other_rows_and_its_hop(
    ca: _Ca, tmp_path: Path
) -> None:
    # One CRL file serves two settings. Only the [tls].crl_file hop holds the old copy, but the copy
    # is matched by file, so both rows report it. Each alert must now say the file is shared, and
    # the detail must name the hop that holds the copy, so the forwarder row is not read as the
    # forwarder's own fault.
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.pem)
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=5.5, number=1))
    hop = _hop(ca_file, crl)
    crl.write_bytes(ca.crl(days=90, number=2))
    sink = _RecordingSink()
    rows = [
        MonitoredCert("tls.crl_file", str(crl), kind="crl"),
        MonitoredCert("logging.forward_tls_crl_file", str(crl), kind="crl"),
    ]
    runner = CertExpiryRunner(lambda: rows, CertMonitorSettings(warn_days=30), alert_sink=sink)

    runner.run_once(now=time.time())

    assert [c[0] for c in sink.crl_calls] == ["tls.crl_file", "logging.forward_tls_crl_file"]
    (_, tls_detail, tls_shared), (_, fwd_detail, fwd_shared) = sink.crl_notes
    assert tls_shared == ("logging.forward_tls_crl_file",)
    assert fwd_shared == ("tls.crl_file",)
    assert "([tls].crl_file)" in fwd_detail  # the holder, under the row that is not its own
    assert "also serves tls.crl_file" in fwd_detail
    assert "also serves logging.forward_tls_crl_file" in tls_detail
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


# --- 3. a CRL inside a CA bundle is recorded -------------------------------------------------------


def test_a_crl_inside_the_ca_bundle_is_recorded_when_the_hop_checks_revocation(
    ca: _Ca, tmp_path: Path
) -> None:
    # Before the fix nothing recorded the bundle's CRL, so the monitor never saw it, though
    # OpenSSL holds it and reads it at every handshake once revocation checking is on.
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))

    hop = _hop(bundle, crl)

    copies = held_crl_copies(bundle)
    assert len(copies) == 1
    assert copies[0].ca_bundle is True
    assert copies[0].setting == "[tls].internal_ca_file"
    assert copies[0].facts.days_remaining == 5
    assert hop.cert_store_stats()["crl"] == 2  # OpenSSL holds both, which is why it matters


def test_control_a_hop_that_checks_no_revocation_records_nothing(ca: _Ca, tmp_path: Path) -> None:
    # With no CRL setting the check flag is off and OpenSSL never reads a CRL in the store, so the
    # bundle's CRL cannot refuse a peer and must not raise an alert.
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))

    hop = _hop(bundle, None)

    assert held_crl_copies(bundle) == []
    assert hop.cert_store_stats()["crl"] == 1
    assert not hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_replaced_bundle_crl_keeps_its_alert_and_asks_for_a_restart(
    ca: _Ca, tmp_path: Path
) -> None:
    # The operator refreshes the CRL in the CA bundle. The hop still holds the old one, the reload
    # pass does not touch a CA file, so the alert stays on the held copy's date and says restart.
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))
    hop = _hop(bundle, crl)
    bundle.write_bytes(ca.pem + ca.crl(days=80, number=3))
    sink = _RecordingSink()
    runner = CertExpiryRunner(
        list,
        CertMonitorSettings(warn_days=30),
        alert_sink=sink,
        watch_unlisted_held_crls=True,
    )

    runner.run_once(now=time.time())

    mine = _mine(sink, bundle)
    assert len(mine) == 1
    label, path, _, days = sink.crl_calls[mine[0]]
    assert label == held_crl_label(path)
    assert days == 5
    held_copy, detail, _ = sink.crl_notes[mine[0]]
    assert held_copy is True
    assert "Restart the engine to apply the CA file" in detail
    assert "A reload is pending" not in detail
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_the_reload_pass_leaves_a_bundle_copy_alone(ca: _Ca, tmp_path: Path) -> None:
    # A changed CA file is a restart's to apply. The reload's rules are a CRL setting's, so had it
    # tried, a CA file that gained a CA would be refused as a file to fix.
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))
    hop = _hop(bundle, crl)
    held_before = held_crl_copies(bundle)
    bundle.write_bytes(ca.pem + ca.crl(days=80, number=3))

    outcomes = reload_replaced_crls(now=time.time())

    assert not [o for o in outcomes if Path(o.path).exists() and Path(o.path).samefile(bundle)]
    assert held_crl_copies(bundle) == held_before
    assert hop.cert_store_stats()["crl"] == 2


def test_one_file_as_both_the_crl_setting_and_the_ca_bundle_stays_reloadable(
    ca: _Ca, tmp_path: Path
) -> None:
    # The same CA+CRL file named by both settings: harden_crl_check records it with its blocks, so
    # the reload can apply it. The bundle record must not merge in and make that record unknown.
    both = tmp_path / "ca-and-crl.pem"
    both.write_bytes(ca.pem + ca.crl(days=5.5, number=1))

    hop = _hop(both, both)

    mine = [held for ctx, held in held_contexts() if ctx is hop]
    assert len(mine) == 1
    assert mine[0].ca_bundle is False
    assert mine[0].blocks  # known, so a reload can prove it supersedes them
    del hop
    gc.collect()
