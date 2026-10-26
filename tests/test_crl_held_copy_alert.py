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
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config import loaded_crls
from messagefoundry.config.loaded_crls import (
    ReloadRefusal,
    clear_reload_refusal,
    crl_fingerprint,
    held_contexts,
    held_crl_copies,
    record_reload_refusal,
)
from messagefoundry.config.settings import CertMonitorSettings
from messagefoundry.config.tls_policy import (
    TrustAnchor,
    build_anchored_https_handler,
    build_verifying_client_context,
)
from messagefoundry.logging_setup import SyslogForward, _build_tls_context
from messagefoundry.pipeline import crl_reload
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import HELD_COPY_NOTE, LoggingAlertSink, crl_expiry_detail
from messagefoundry.pipeline.cert_expiry import (
    _CA_FILE_HOP_RESTARTS,
    CertExpiryRunner,
    MonitoredCert,
    held_crl_label,
)
from messagefoundry.pipeline.crl_reload import reload_replaced_crls
from messagefoundry.pki import CrlSignature
from messagefoundry.redaction import log_timestamp, safe_text
from tests.test_cert_expiry import _RecordingSink


@dataclass(frozen=True)
class _Ca:
    key: ec.EllipticCurvePrivateKey
    name: x509.Name
    pem: bytes

    def crl(
        self,
        *,
        days: float,
        number: int,
        starts_in_days: float = 0.0,
        key: ec.EllipticCurvePrivateKey | None = None,
        delta: bool = False,
        names_key: bool = False,
    ) -> bytes:
        """A CRL naming this CA, revoking nothing, whose nextUpdate is ``days`` from now. It takes
        effect ``starts_in_days`` from now, is signed by ``key`` in place of the CA's own, and is a
        delta CRL when ``delta`` (those three for BACKLOG #3176). With ``names_key`` its authority
        key identifier names this CA's key, whoever signed it (BACKLOG #3512)."""
        now = datetime.datetime.now(datetime.UTC)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.name)
            .last_update(
                now
                - datetime.timedelta(hours=1, minutes=number)
                + datetime.timedelta(days=starts_in_days)
            )
            .next_update(now + datetime.timedelta(days=days))
            .add_extension(x509.CRLNumber(number), False)
        )
        if delta:
            builder = builder.add_extension(x509.DeltaCRLIndicator(number - 1), True)
        if names_key:
            akid = x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key())
            builder = builder.add_extension(akid, False)
        crl = builder.sign(key or self.key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def ca() -> _Ca:
    return _another_ca("mefor-2319-ca")


def _another_ca(cn: str = "mefor-2319-other-ca", *, ski: bool = False) -> _Ca:
    """A self-signed CA. With ``ski`` it carries a Subject Key Identifier, which a CRL must match
    for the engine to prove its signature bad (BACKLOG #3512)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=400))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    if ski:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
    cert = builder.sign(key, hashes.SHA256())
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
    assert "Held by: [tls].crl_file" in detail
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
            detail="Restart the engine. Held by: [tls].crl_file.",
            shared_with=("logging.forward_tls_crl_file",),
        )
    )

    assert len(events) == 1
    event = events[0]
    assert event["type"] == "cert_expiry"
    assert event["connection"] == "tls.crl_file (CRL)"
    assert event["held_copy"] is True
    assert event["shared_with"] == ["logging.forward_tls_crl_file"]
    # The marker, then the remedy: the alert instance's reason keeps about the first 200 characters.
    assert event["detail"].startswith(f"{HELD_COPY_NOTE} Restart the engine. Held by:")
    assert "also serves logging.forward_tls_crl_file" in event["detail"]


def test_a_shared_file_with_no_held_copy_mentions_no_held_copy() -> None:
    note = crl_expiry_detail(held_copy=False, detail="", shared_with=("tls.crl_file",))
    assert note == "The same file also serves tls.crl_file."


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
    assert "Held by: [tls].crl_file" in fwd_detail  # the holder, under the row that is not its own
    assert "Held by: [tls].crl_file" in tls_detail
    # Each sink adds the sharing sentence through the one helper both use.
    fwd_note = crl_expiry_detail(held_copy=True, detail=fwd_detail, shared_with=fwd_shared)
    assert "also serves tls.crl_file" in fwd_note
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


def _bundle_scan(bundle: Path) -> tuple[_RecordingSink, list[int]]:
    sink = _RecordingSink()
    runner = CertExpiryRunner(
        list, CertMonitorSettings(warn_days=30), alert_sink=sink, watch_unlisted_held_crls=True
    )
    runner.run_once(now=time.time())
    return sink, _mine(sink, bundle)


def test_a_certificate_added_beside_an_unchanged_bundle_crl_is_not_a_stale_copy(
    ca: _Ca, tmp_path: Path
) -> None:
    # A held copy from a CA file is a copy of its CRLs. Adding a certificate to the file leaves the
    # CRL the hop holds the same as the file's, so the alert is the file's and says nothing more.
    crl_pem = ca.crl(days=5.5, number=1)
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + crl_pem)
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))
    hop = _hop(bundle, crl)
    bundle.write_bytes(ca.pem + _another_ca().pem + crl_pem)

    sink, mine = _bundle_scan(bundle)

    assert len(mine) == 1
    assert sink.crl_notes[mine[0]] == (False, "", ())
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_crl_moved_out_of_the_ca_file_asks_for_a_restart(ca: _Ca, tmp_path: Path) -> None:
    # The operator followed the advice and moved the CRL to the CRL setting. The hop still holds
    # the bundle's copy, and a CA file with no CRL starts, so a restart is the remedy, not a fix.
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))
    hop = _hop(bundle, crl)
    bundle.write_bytes(ca.pem)

    sink, mine = _bundle_scan(bundle)

    assert len(mine) == 1
    held_copy, detail, _ = sink.crl_notes[mine[0]]
    assert held_copy is True
    assert detail.startswith("Restart the engine to apply the CA file")
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_an_expired_crl_put_in_the_ca_file_is_not_answered_with_a_restart(
    ca: _Ca, tmp_path: Path
) -> None:
    # Nothing judges a CA file's CRL at start, so "restart" here would load the expired CRL and
    # refuse every peer under its issuer at once. The remedy must say to replace it first.
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))
    hop = _hop(bundle, crl)
    bundle.write_bytes(ca.pem + ca.crl(days=-0.01, number=3))  # lapsed about 14 minutes ago

    sink, mine = _bundle_scan(bundle)

    assert len(mine) == 1
    held_copy, detail, _ = sink.crl_notes[mine[0]]
    assert held_copy is False  # the file's expired CRL is the sooner date
    assert detail.startswith("Replace the CRL in the CA file with a current one before restarting")
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_an_unreadable_ca_file_asks_for_it_to_be_restored_first(ca: _Ca, tmp_path: Path) -> None:
    # A restart would refuse a CA file it cannot read, so the remedy names the CA file, not a CRL.
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))
    hop = _hop(bundle, crl)
    bundle.unlink()
    sink = _RecordingSink()
    runner = CertExpiryRunner(
        lambda: [MonitoredCert("held", str(bundle), kind="crl")],
        CertMonitorSettings(warn_days=30),
        alert_sink=sink,
    )

    runner.run_once(now=time.time())

    assert [c[3] for c in sink.crl_calls] == [5]
    assert sink.crl_notes[0][1].startswith("Restore a readable CA file before restarting")
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_the_https_augment_arm_records_its_ca_bundle_crl(ca: _Ca, tmp_path: Path) -> None:
    # The HTTP family's augment arm loads the CA into urllib's own context, then the CRL. It is a
    # separate call site from build_verifying_client_context, so it is tested on its own.
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))

    handler = build_anchored_https_handler(
        anchor=TrustAnchor(
            cafile=str(bundle),
            load_system_roots=True,
            crl_file=str(crl),
            cafile_setting="[tls].internal_ca_file",
        ),
        connector="REST test",
    )

    copies = held_crl_copies(bundle)
    assert [c.ca_bundle for c in copies] == [True]
    assert handler is not None


def test_the_syslog_forwarder_records_its_ca_bundle_crl(ca: _Ca, tmp_path: Path) -> None:
    # The forwarder builds its own context from forward_tls_ca_file by cafile=, a third call site.
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))

    ctx = _build_tls_context(
        SyslogForward(
            host="siem.example.test",
            protocol="tls",
            tls_ca_file=str(bundle),
            tls_crl_file=str(crl),
        )
    )

    copies = held_crl_copies(bundle)
    assert [(c.ca_bundle, c.setting) for c in copies] == [(True, "[logging].forward_tls_ca_file")]
    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


# --- BACKLOG #3176: CA-file remedies that would restart into a refusal -----------------------------


def _replaced_bundle(ca: _Ca, tmp_path: Path, new_crl: bytes) -> tuple[ssl.SSLContext, Path]:
    """A hop that loaded a CA file whose CRL lapses in about five days, after which the operator
    put ``new_crl`` in its place."""
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))
    hop = _hop(bundle, crl)
    bundle.write_bytes(ca.pem + new_crl)
    return hop, bundle


def _bundle_detail(bundle: Path) -> str:
    sink, mine = _bundle_scan(bundle)
    assert len(mine) == 1
    held_copy, detail, _ = sink.crl_notes[mine[0]]
    assert held_copy is True  # the hop's five-day copy is the sooner date
    return detail


def test_a_not_yet_valid_crl_put_in_the_ca_file_is_not_answered_with_a_restart(
    ca: _Ca, tmp_path: Path
) -> None:
    # Alone for its issuer, a CRL not in effect yet is the one OpenSSL picks, and it refuses every
    # peer under that issuer with "CRL is not yet valid". Before the fix this read "Restart".
    hop, bundle = _replaced_bundle(ca, tmp_path, ca.crl(days=90, number=3, starts_in_days=2))

    detail = _bundle_detail(bundle)

    assert detail.startswith("Replace the CRL in the CA file with one in effect now, or wait")
    assert "Restart the engine" not in detail
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_badly_signed_crl_put_in_the_ca_file_is_not_answered_with_a_restart(
    tmp_path: Path,
) -> None:
    # The CRL names this CA's key but another key signed it: the proven case, state ``bad``.
    # OpenSSL checks that only at the handshake, so a restart loads it and then every handshake it
    # judges fails. Before #3176: "Restart". The CA carries the key identifier the CRL names.
    ca = _another_ca("mefor-3512-ca", ski=True)
    forged = ca.crl(days=90, number=3, key=_another_ca().key, names_key=True)
    hop, bundle = _replaced_bundle(ca, tmp_path, forged)

    detail = _bundle_detail(bundle)

    assert detail.startswith("Replace the CRL in the CA file with one its CA signed")
    assert "a handshake OpenSSL judges by it fails" in detail
    assert "Restart the engine" not in detail
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_ca_file_crl_from_a_renewed_ca_key_is_unconfirmed_not_failing(
    ca: _Ca, tmp_path: Path
) -> None:
    # BACKLOG #3512: the CA renewed its key under the same name, and the CRL, which carries no key
    # identifier, was signed by the old key. That is state ``unproven``, and handshakes can still
    # pass (docs/CONFIGURATION.md). Before the fix the remedy said "every handshake it judges would
    # fail" for it, as for a proven bad signature. The old CA is a certificate of its own, with the
    # CA's name and its own key, and that certificate verifies the CRL: a renewal, not a forgery.
    old_ca = _another_ca("mefor-2319-ca")
    renewed_crl = ca.crl(days=90, number=3, key=old_ca.key)
    old_cert = x509.load_pem_x509_certificate(old_ca.pem)
    assert old_cert.subject == ca.name
    assert old_cert.public_key() == old_ca.key.public_key()
    assert x509.load_pem_x509_crl(renewed_crl).is_signature_valid(old_ca.key.public_key())
    hop, bundle = _replaced_bundle(ca, tmp_path, renewed_crl)

    detail = _bundle_detail(bundle)

    assert detail.startswith("Check that the CRL in the CA file is one its CA signed")
    assert "could not confirm its signature" in detail
    assert "then restart the engine to apply the CA file" in detail
    assert "handshake" not in detail
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


@pytest.mark.parametrize(
    ("states", "lead"),
    [
        ({"uncheckable"}, "Check that the CRL in the CA file"),
        ({"unproven", "verified"}, "Check that the CRL in the CA file"),
        ({"bad", "unproven"}, "Replace the CRL in the CA file with one its CA signed"),
        ({"unlisted", "verified"}, "Restart the engine to apply the CA file"),
    ],
)
def test_the_ca_file_remedy_follows_the_strongest_signature_state(
    ca: _Ca, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, states: set[Any], lead: str
) -> None:
    # BACKLOG #3512: the states a CA file's CRLs give, merged. ``bad`` leads over the unconfirmed
    # two, and only it claims that handshakes fail. ``uncheckable`` has no CRL of its own here.
    hop, bundle = _replaced_bundle(ca, tmp_path, ca.crl(days=90, number=3))

    def _states(pem: bytes, cas: object) -> list[CrlSignature]:
        return [CrlSignature(f"CRL block {i}", s) for i, s in enumerate(sorted(states), 1)]

    monkeypatch.setattr("messagefoundry.pipeline.cert_expiry.judge_crl_signatures", _states)

    detail = _bundle_detail(bundle)

    assert detail.startswith(lead), detail
    assert ("a handshake OpenSSL judges by it fails" in detail) == ("bad" in states), detail
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


_UNCHECKED_LATER_CRL = "could not check the signature of a later CRL"


def _blocks_then(first: str, error: type[Exception]) -> Any:
    """A stand-in for ``judge_crl_signatures``: one block in state ``first``, then ``error``."""

    def _states(pem: bytes, cas: object) -> Iterator[CrlSignature]:
        yield CrlSignature("CRL block 1", first)  # type: ignore[arg-type]
        raise error("synthetic unreadable block")

    return _states


@pytest.mark.parametrize(
    ("first", "error", "lead"),
    [
        ("unproven", ValueError, "Check that the CRL in the CA file is one its CA signed"),
        ("unproven", RuntimeError, "Check the CRL in the CA file before restarting: the scan"),
        ("verified", ValueError, "Replace the CRL in the CA file with one the engine can judge"),
        ("verified", RuntimeError, "Check the CRL in the CA file before restarting: the scan"),
        ("bad", ValueError, "Replace the CRL in the CA file with one its CA signed"),
        ("bad", RuntimeError, "Replace the CRL in the CA file with one its CA signed"),
    ],
)
def test_a_later_block_the_signature_check_cannot_read_keeps_an_earlier_verdict(
    ca: _Ca,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    first: str,
    error: type[Exception],
    lead: str,
) -> None:
    # BACKLOG #3512: main's check stopped at the first unconfirmed block, so a later block that
    # does not parse (ValueError, the failure judge_crl_signatures documents) never cost that
    # verdict. Draining every block must not change that, and the kept verdict is logged with its
    # cause, naming the CA file. Any other type is unexpected and takes the outer path, as before.
    # Controls: a verified block before the raise leaves nothing to keep, and a ``bad`` block stops
    # the check, so a later raise is never reached.
    hop, bundle = _replaced_bundle(ca, tmp_path, ca.crl(days=90, number=3))
    monkeypatch.setattr(
        "messagefoundry.pipeline.cert_expiry.judge_crl_signatures", _blocks_then(first, error)
    )

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.cert_expiry"):
        detail = _bundle_detail(bundle)

    assert detail.startswith(lead), detail
    # The held-copy line is always logged here, so the walk below reads a log that has lines.
    assert caplog.records
    assert any("still holds a copy" in r.getMessage() for r in caplog.records), caplog.records
    kept = [r for r in caplog.records if _UNCHECKED_LATER_CRL in r.getMessage()]
    if (first, error) == ("unproven", ValueError):
        assert len(kept) == 1, kept
        assert kept[0].levelno == logging.WARNING
        # A held-crl row spells the path in key form, which folds case on Windows.
        assert str(bundle).lower() in kept[0].getMessage().lower(), kept[0].getMessage()
        assert kept[0].exc_info is not None and kept[0].exc_info[0] is ValueError
    else:
        assert kept == [], kept
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_later_unchecked_crl_is_logged_once_a_pass_for_the_rows_sharing_its_ca_file(
    ca: _Ca, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # BACKLOG #3512: two rows name one CA file, and each judges it. The kept verdict's line is
    # folded as the held-copy line is: once a pass for the file, naming the other row. Each row
    # still gets its own alert with the kept verdict.
    hop, bundle = _replaced_bundle(ca, tmp_path, ca.crl(days=90, number=3))
    monkeypatch.setattr(
        "messagefoundry.pipeline.cert_expiry.judge_crl_signatures",
        _blocks_then("unproven", ValueError),
    )
    rows = [
        MonitoredCert("a.crl_file", str(bundle), kind="crl"),
        MonitoredCert("b.crl_file", str(bundle), kind="crl"),
    ]
    sink = _RecordingSink()
    runner = CertExpiryRunner(lambda: rows, CertMonitorSettings(warn_days=30), alert_sink=sink)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.cert_expiry"):
        runner.run_once(now=time.time())
        runner.run_once(now=time.time())

    assert [c[0] for c in sink.crl_calls] == ["a.crl_file", "b.crl_file"] * 2
    assert all(
        note[1].startswith("Check that the CRL in the CA file is one its CA signed")
        for note in sink.crl_notes
    ), sink.crl_notes
    kept = [r.getMessage() for r in caplog.records if _UNCHECKED_LATER_CRL in r.getMessage()]
    assert len(kept) == 2, kept  # one a pass, two passes
    assert all("'a.crl_file'" in m and "b.crl_file" in m and str(bundle) in m for m in kept), kept
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


@pytest.mark.parametrize("kind", ["delta", "garbled"])
def test_a_crl_the_engine_cannot_judge_in_the_ca_file_is_fixed_before_a_restart(
    ca: _Ca, tmp_path: Path, kind: str
) -> None:
    # The two ways a CA file's CRL cannot be judged: a delta CRL, which only the strict reading
    # refuses (before the fix it read "Restart"), and a block that does not parse at all.
    garbled = b"-----BEGIN X509 CRL-----\nbm90IGEgQ1JM\n-----END X509 CRL-----\n"
    new_crl = ca.crl(days=90, number=3, delta=True) if kind == "delta" else garbled
    hop, bundle = _replaced_bundle(ca, tmp_path, new_crl)

    detail = _bundle_detail(bundle)

    assert detail.startswith(
        "Replace the CRL in the CA file with one the engine can judge before restarting"
    )
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_ca_file_crl_minutes_from_taking_effect_gets_no_clock_skew(
    ca: _Ca, tmp_path: Path
) -> None:
    # A CRL setting's start allows five minutes of skew; a CA file's CRL meets no check at start,
    # and OpenSSL allows none, so a CRL two minutes out still refuses peers until then.
    two_minutes_out = (63 + 2) / (24 * 60)  # crl() starts an hour and `number` minutes back
    hop, bundle = _replaced_bundle(
        ca, tmp_path, ca.crl(days=90, number=3, starts_in_days=two_minutes_out)
    )

    detail = _bundle_detail(bundle)

    assert detail.startswith("Replace the CRL in the CA file with one in effect now, or wait")
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_ca_file_the_scan_cannot_stage_keeps_the_held_copy_date(
    ca: _Ca, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A disk that refuses the private copy says nothing about the file. The held copy's date and a
    # check-first remedy must survive it, not fall back to the file's later date.
    hop, bundle = _replaced_bundle(ca, tmp_path, ca.crl(days=90, number=3))

    def _no_room(pem: bytes) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("messagefoundry.pipeline.cert_expiry.staged_crl", _no_room)

    detail = _bundle_detail(bundle)

    assert detail.startswith("Check the CRL in the CA file before restarting")
    assert "PermissionError" in detail
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_control_a_good_crl_from_an_issuer_the_ca_file_does_not_list_still_restarts(
    ca: _Ca, tmp_path: Path
) -> None:
    # THE CONTROL for the signature check's scope. The CRL's issuer is not in this CA file: it
    # may be an intermediate the peer sends, so the file is not refused for it, and a refreshed
    # CA file is still a restart's to apply.
    hop, bundle = _replaced_bundle(ca, tmp_path, _another_ca().crl(days=90, number=3))

    detail = _bundle_detail(bundle)

    assert detail.startswith("Restart the engine to apply the CA file")
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def _shared_as_crl_and_ca_file(
    ca: _Ca, tmp_path: Path, new_crl: bytes | None = None
) -> tuple[list[ssl.SSLContext], Path]:
    """One file that hop A loads as its CRL setting and hop B as its CA file, then refreshed with
    ``new_crl``, by default a good one."""
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.pem)
    both = tmp_path / "ca-and-crl.pem"
    both.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))
    hops = [_hop(ca_file, both), _hop(both, crl)]
    both.write_bytes(ca.pem + (ca.crl(days=80, number=3) if new_crl is None else new_crl))
    return hops, both


def _row_detail(path: Path) -> str:
    sink = _RecordingSink()
    runner = CertExpiryRunner(
        lambda: [MonitoredCert("tls.crl_file", str(path), kind="crl")],
        CertMonitorSettings(warn_days=30),
        alert_sink=sink,
    )
    runner.run_once(now=time.time())
    assert [c[3] for c in sink.crl_calls] == [5]
    return sink.crl_notes[0][1]


def test_a_file_held_as_a_crl_and_as_a_ca_file_leads_with_the_restart(
    ca: _Ca, tmp_path: Path
) -> None:
    # Before the fix: "A reload is pending ..." then "... needs a restart either way", and the
    # alert instance kept only the first. Only a restart clears the CA file's copy, so that leads.
    hops, both = _shared_as_crl_and_ca_file(ca, tmp_path)

    detail = _row_detail(both)

    assert detail.startswith("Restart the engine once the reload has applied the file")
    assert "A reload is pending" not in detail
    assert "either way" not in detail
    assert "[tls].crl_file" in detail
    assert "[tls].internal_ca_file" in detail
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)


def test_a_refused_reload_of_such_a_file_keeps_its_remedy_first(ca: _Ca, tmp_path: Path) -> None:
    # A refusal's remedy leads its reason (review round 2 of #2319, untested until now). The CA-file
    # hop's restart comes after both, as a next step: a "Wait" remedy says not to restart yet.
    hops, both = _shared_as_crl_and_ca_file(ca, tmp_path)
    remedy = "Wait: the engine applies the file once its CRL takes effect"
    record_reload_refusal(both, ReloadRefusal(crl_fingerprint(both.read_bytes()), "why", remedy))
    try:
        detail = _row_detail(both)
    finally:
        clear_reload_refusal(both)

    assert detail.startswith(f"{remedy}. Reason: why. Once the file is applied, a hop that ")
    assert "either way" not in detail
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)


def test_a_refusal_that_already_says_restart_gets_no_second_restart(
    ca: _Ca, tmp_path: Path
) -> None:
    # A reload refused with "Restart the engine" never applies the file, so a clause that waits for
    # it to be applied would send the operator after an event that never comes.
    hops, both = _shared_as_crl_and_ca_file(ca, tmp_path)
    remedy = "Restart the engine to apply the file"
    record_reload_refusal(both, ReloadRefusal(crl_fingerprint(both.read_bytes()), "why", remedy))
    try:
        detail = _row_detail(both)
    finally:
        clear_reload_refusal(both)

    assert detail.startswith(f"{remedy}. Reason: why. Held by: ")
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)


def test_a_refused_reload_keeps_its_remedy_beside_a_ca_file_fix(ca: _Ca, tmp_path: Path) -> None:
    # BACKLOG #3512: the CA-file arm outranked a recorded refusal and dropped the reload's remedy,
    # which the 0.5.2 CHANGELOG.md entry for #3176 promised. The CA-file fix still leads, as a
    # refusal's remedy can be a restart, which would load this CRL into the CA-file hop. The reason
    # follows the remedy, as in the plain refused arm: one policy for the alert (BACKLOG #3512).
    hops, both = _shared_as_crl_and_ca_file(
        ca, tmp_path, ca.crl(days=90, number=3, starts_in_days=2)
    )
    remedy = crl_reload.WAIT
    reason = "synthetic reload reason"
    record_reload_refusal(both, ReloadRefusal(crl_fingerprint(both.read_bytes()), reason, remedy))
    try:
        detail = _row_detail(both)
    finally:
        clear_reload_refusal(both)

    assert detail.startswith("Replace the CRL in the CA file with one in effect now, or wait")
    assert (
        ". Do that first. The reload refused the file for a hop that loads it as its CRL" in detail
    )
    assert f": {remedy}. Reason: {reason}. {_CA_FILE_HOP_RESTARTS}. Held by: " in detail, detail
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)


#: The CA-file step origin/main gives a CRL not yet in effect, word for word, wait included.
_MAINS_NOT_IN_EFFECT_STEP = (
    "Replace the CRL in the CA file with one in effect now, or wait until {when}, before "
    "restarting: until then it refuses every peer under its issuer"
)


@pytest.mark.parametrize(
    ("starts_in_days", "remedy", "shared"),
    [
        pytest.param(2, crl_reload.WAIT, True, id="wait-refusal"),
        pytest.param(2, None, True, id="no-refusal-crl-setting-too"),
        pytest.param(2, None, False, id="no-refusal-ca-file-only"),
        pytest.param(10, None, False, id="no-refusal-ca-file-only-lapses-first"),
        pytest.param(10, crl_reload.LAPSES_FIRST, True, id="lapses-first-refusal"),
    ],
)
def test_the_ca_file_step_offers_main_s_wait_in_main_s_words(
    ca: _Ca, tmp_path: Path, starts_in_days: float, remedy: str | None, shared: bool
) -> None:
    # BACKLOG #3512: the advice must be no worse than main's. An earlier repair withheld the wait,
    # or said "Do not wait", read from a held copy's soonest CRL, which counts superseded CRLs the
    # reload does not; it could withhold a safe wait. So the CA-file step keeps main's sentence,
    # wait and all, whatever the reload recorded. The hop's copy lapses in about five days, so at
    # ten days the reload records LAPSES_FIRST, whose own remedy follows the step.
    crl = ca.crl(days=90, number=3, starts_in_days=starts_in_days)
    if shared:
        hops, path = _shared_as_crl_and_ca_file(ca, tmp_path, crl)
        if remedy is not None:
            fp = crl_fingerprint(path.read_bytes())
            record_reload_refusal(path, ReloadRefusal(fp, "why", remedy))
        try:
            detail = _row_detail(path)
        finally:
            clear_reload_refusal(path)
    else:
        hops = [_replaced_bundle(ca, tmp_path, crl)[0]]
        detail = _bundle_detail(tmp_path / "ca-bundle.pem")
    when = log_timestamp(x509.load_pem_x509_crl(crl).last_update_utc)

    assert detail.startswith(f"{_MAINS_NOT_IN_EFFECT_STEP.format(when=when)}. "), detail
    assert detail.lower().count("wait until") == 1, detail
    assert "Do not wait" not in detail, detail
    if remedy is not None:
        assert f": {remedy}. Reason: why. {_CA_FILE_HOP_RESTARTS}. Held by: " in detail, detail
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)


def _alert_list_reason(detail: str) -> str:
    """What the alert list shows for a held copy's ``detail``: the held-copy marker leads, and the
    store keeps the first 200 characters, cut at a whole token."""
    return safe_text(crl_expiry_detail(held_copy=True, detail=detail, shared_with=()), limit=200)


@pytest.mark.parametrize(
    ("new_crl", "states", "lead"),
    [
        pytest.param({"starts_in_days": 2}, None, "Replace the CRL", id="not-in-effect"),
        pytest.param({}, {"bad"}, "Replace the CRL", id="proven-bad"),
        pytest.param({}, {"unproven"}, "Check that the CRL", id="unconfirmed"),
    ],
)
@pytest.mark.parametrize("ca_file_only", [True, False], ids=["ca-file-only", "crl-setting-too"])
def test_the_ca_file_step_and_its_reason_fit_inside_the_alert_list_s_cut(
    ca: _Ca,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    new_crl: dict[str, Any],
    states: set[Any] | None,
    lead: str,
    ca_file_only: bool,
) -> None:
    # BACKLOG #3512 (vault #4150, #4155): the alert list keeps about 200 characters, and the
    # held-copy marker takes the first 51. The CA-file step's first sentence, its action and its
    # reason, must survive the cut. What follows it, such as the reload's steps where a CRL setting
    # names the file too, may fall past it. Before the fix the proven-bad step was cut at "before
    # restarting: a hands". The not-in-effect step is main's, wait included, and the end of its
    # reason falls past the cut as on main; its action and its wait survive.
    if states is not None:

        def _states(pem: bytes, cas: object) -> list[CrlSignature]:
            return [CrlSignature(f"CRL block {i}", s) for i, s in enumerate(sorted(states), 1)]

        monkeypatch.setattr("messagefoundry.pipeline.cert_expiry.judge_crl_signatures", _states)
    crl = ca.crl(days=90, number=3, **new_crl)
    if ca_file_only:
        hops = [_replaced_bundle(ca, tmp_path, crl)[0]]
        detail = _bundle_detail(tmp_path / "ca-bundle.pem")
    else:
        hops, both = _shared_as_crl_and_ca_file(ca, tmp_path, crl)
        detail = _row_detail(both)

    first = detail.split(". ", 1)[0]
    assert first.startswith(lead), detail
    assert ": " in first, first  # the action, then its reason
    kept = first if states is not None else first.split(": ", 1)[0]
    assert f"{HELD_COPY_NOTE} {kept}" in _alert_list_reason(detail), detail
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)


@pytest.mark.parametrize(
    "remedy",
    [
        pytest.param(None, id="no-refusal"),
        pytest.param(crl_reload.FIX, id="fix"),
        pytest.param(crl_reload.WAIT, id="wait"),
        pytest.param(crl_reload.LAPSES_FIRST, id="lapses-first"),
        pytest.param(crl_reload.RESTART, id="restart"),
        pytest.param(crl_reload.BAD_SIGNATURE, id="bad-signature"),
        pytest.param(crl_reload._NOT_PROVABLE, id="not-provable"),
        pytest.param(crl_reload.NO_ISSUER, id="no-issuer"),
        pytest.param(crl_reload.RETRY, id="retry"),
    ],
)
def test_an_unconfirmed_crl_in_a_file_that_is_also_a_crl_setting_restarts_after_the_reload(
    ca: _Ca, tmp_path: Path, remedy: str | None
) -> None:
    # BACKLOG #3512: hop A loads the file as its CRL setting and hop B as its CA file, and the new
    # CRL's signature is unconfirmed (no key identifier, another key). The CA-file step orders no
    # restart, because the restart comes after the reload's verdict (#3176). Then either the
    # restart once the reload applies the file, or a refused reload's remedy and, unless that
    # remedy is a restart, the CA-file hop's restart after it. Exactly one restart order, after any
    # fix or wait. Before the fix the lead said "then restart the engine", ahead of both.
    hops, both = _shared_as_crl_and_ca_file(
        ca, tmp_path, ca.crl(days=80, number=3, key=_another_ca().key)
    )
    if remedy is not None:
        fp = crl_fingerprint(both.read_bytes())
        record_reload_refusal(both, ReloadRefusal(fp, "synthetic reason", remedy))
    try:
        detail = _row_detail(both)
    finally:
        clear_reload_refusal(both)

    assert detail.startswith(
        "Check that the CRL in the CA file is one its CA signed before restarting: "
    ), detail
    lead, _, rest = detail.partition(". Do that first. ")
    assert rest, detail
    assert "restart" not in lead.lower().replace("before restarting", ""), detail
    low = detail.lower()
    orders = sum(
        low.count(o) for o in ("restart the engine", "still needs", "a restart applies the file")
    )
    # _NOT_PROVABLE's own sentence says when a restart applies the file to the CRL-setting hop.
    # It orders no restart of the CA-file hop, so that hop's restart follows it.
    assert orders == (2 if remedy == crl_reload._NOT_PROVABLE else 1), detail
    if remedy is None:
        assert rest.startswith("Restart the engine once the reload has applied the file"), detail
    else:
        assert rest.startswith("The reload refused the file for a hop that loads it"), detail
        assert f"{remedy}. Reason: synthetic reason" in rest, detail
        if "Restart the engine" not in remedy:
            # The fix or the wait comes first, then the CA-file hop's restart.
            assert rest.index(remedy) < rest.index("still needs a restart"), detail
        else:
            # A plain restart applies the CA file too, so no second restart follows it.
            assert "still needs a restart" not in rest, detail
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)


def test_a_crl_setting_row_whose_hop_holds_no_stale_copy_restarts_with_no_reload_wait(
    ca: _Ca, tmp_path: Path
) -> None:
    # BACKLOG #3512: only the CA-file hop holds a stale copy, and a CRL setting names the file, as
    # [store].ssl_crl_file can, which records no held copy. The reload judges stale CRL-setting
    # copies alone (crl_reload._held_by_path), so no verdict comes: the step is a restart, as on
    # main. A start judges that setting, so the step checks the CRL before restarting rather than
    # ordering "then restart the engine to apply the CA file" (review round one of #3512).
    hop, bundle = _replaced_bundle(ca, tmp_path, ca.crl(days=90, number=3, key=_another_ca().key))

    detail = _row_detail(bundle)

    assert detail.startswith(
        "Check that the CRL in the CA file is one its CA signed before restart"
    )
    assert "then restart the engine to apply the CA file" not in detail
    assert "Do that first" not in detail
    assert "once the reload has applied" not in detail
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_current_crl_setting_copy_beside_a_stale_ca_file_copy_waits_for_no_reload(
    ca: _Ca, tmp_path: Path
) -> None:
    # BACKLOG #3512: hop A already holds the file's CRL through its CRL setting, and hop B a stale
    # copy through its CA file. No stale CRL-setting copy means no reload verdict to wait for, so
    # the step is a restart. Hop A still names the file as a CRL setting, so it checks first.
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.pem)
    both = tmp_path / "ca-and-crl.pem"
    both.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))
    stale = _hop(both, crl)
    both.write_bytes(ca.pem + ca.crl(days=80, number=3, key=_another_ca().key))
    current = _hop(ca_file, both)

    detail = _row_detail(both)

    assert detail.startswith(
        "Check that the CRL in the CA file is one its CA signed before restart"
    )
    assert "Do that first" not in detail
    assert "once the reload has applied" not in detail
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in (stale, current))


def test_every_reload_remedy_gets_the_ca_file_restart_main_gave_it(ca: _Ca, tmp_path: Path) -> None:
    # BACKLOG #3512: the CA-file hop's restart follows a refused reload's remedy unless that remedy
    # orders a plain restart of the engine. main tested that by the substring "Restart the
    # engine"; cert_expiry now names the set, and this pins it to main's choice for every remedy.
    # An earlier repair read crl_reload._SAYS_RESTART instead, and dropped the CA-file hop's
    # restart after _NOT_PROVABLE, whose restart is conditional on the CRL-setting hop's trust.
    hops, both = _shared_as_crl_and_ca_file(ca, tmp_path)
    fp = crl_fingerprint(both.read_bytes())
    for remedy in crl_reload._PRECEDENCE:
        record_reload_refusal(both, ReloadRefusal(fp, "synthetic reason", remedy))
        try:
            detail = _row_detail(both)
        finally:
            clear_reload_refusal(both)
        restarts = "Restart the engine" in remedy
        assert ("still needs a restart" in detail) is not restarts, (remedy, detail)
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)


def test_a_not_provable_refusal_keeps_the_ca_file_hop_s_restart(ca: _Ca, tmp_path: Path) -> None:
    # BACKLOG #3512, the point PR 2521 closed on: a _NOT_PROVABLE refusal dropped the CA-file
    # hop's restart. Its remedy speaks of the CRL-setting hop alone, and only a restart applies
    # the CA file, so the CA-file hop's restart must follow it, in both arms that carry a refusal.
    hops, both = _shared_as_crl_and_ca_file(ca, tmp_path)
    remedy = crl_reload._NOT_PROVABLE
    record_reload_refusal(both, ReloadRefusal(crl_fingerprint(both.read_bytes()), "why", remedy))
    try:
        plain = _row_detail(both)
    finally:
        clear_reload_refusal(both)
    (tmp_path / "unconfirmed").mkdir()
    unconfirmed_hops, unconfirmed = _shared_as_crl_and_ca_file(
        ca, tmp_path / "unconfirmed", ca.crl(days=80, number=3, key=_another_ca().key)
    )
    fp = crl_fingerprint(unconfirmed.read_bytes())
    record_reload_refusal(unconfirmed, ReloadRefusal(fp, "why", remedy))
    try:
        ca_step = _row_detail(unconfirmed)
    finally:
        clear_reload_refusal(unconfirmed)

    for detail in (plain, ca_step):
        assert f"{remedy}. Reason: why. {_CA_FILE_HOP_RESTARTS}. Held by: " in detail, detail
    assert ca_step.startswith("Check that the CRL in the CA file is one its CA signed")
    assert all(h.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for h in (*hops, *unconfirmed_hops))


# --- BACKLOG #3176: a failure grouping the rows, or recording a CA-file CRL -------------------------


def test_a_failure_grouping_the_crl_rows_costs_only_the_shared_rows_note(
    ca: _Ca, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Before the fix the grouping ran before the loop, so it raised out of run_once and no row was
    # judged or alerted that pass. Now it is logged once, and only shared_with is lost.
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=5.5, number=1))
    cert = tmp_path / "cert.pem"
    cert.write_bytes(ca.pem)

    def _broken(*args: object) -> dict[str, tuple[str, ...]]:
        raise RuntimeError("synthetic grouping failure")

    monkeypatch.setattr("messagefoundry.pipeline.cert_expiry._rows_by_crl_file", _broken)
    rows = [MonitoredCert("tls.crl_file", str(crl), kind="crl"), MonitoredCert("api", str(cert))]
    sink = _RecordingSink()
    runner = CertExpiryRunner(lambda: rows, CertMonitorSettings(warn_days=500), alert_sink=sink)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.cert_expiry"):
        checks = runner.run_once(now=time.time())

    assert [c.label for c in checks] == ["tls.crl_file", "api"]
    assert [c[0] for c in sink.cert_calls] == ["api"]
    assert [c[0] for c in sink.crl_calls] == ["tls.crl_file"]
    assert sink.crl_notes == [(False, "", ())]
    errors = [r for r in caplog.records if "could not group the CRL rows" in r.getMessage()]
    assert len(errors) == 1
    # Its own failure, not a TypeError from a stub that took the wrong arguments (BACKLOG #3512).
    assert errors[0].exc_info is not None and errors[0].exc_info[0] is RuntimeError


def test_a_failure_keying_a_crl_path_costs_only_the_shared_rows_note(
    ca: _Ca, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # BACKLOG #3512: the grouping's guard cannot help when crl_path_key itself raises, because the
    # alert's shared_with keys the path again inside the guard around the sink. Before the fix the
    # row's alert was lost under a "crl_expiry alert sink failed" line.
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=5.5, number=1))

    def _broken(path: object) -> str:
        raise OSError("synthetic path-key failure")

    monkeypatch.setattr("messagefoundry.pipeline.cert_expiry.crl_path_key", _broken)
    rows = [MonitoredCert("tls.crl_file", str(crl), kind="crl")]
    sink = _RecordingSink()
    runner = CertExpiryRunner(lambda: rows, CertMonitorSettings(warn_days=500), alert_sink=sink)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.cert_expiry"):
        runner.run_once(now=time.time())

    assert [c[0] for c in sink.crl_calls] == ["tls.crl_file"]
    assert sink.crl_notes == [(False, "", ())]
    messages = [r.getMessage() for r in caplog.records]
    assert not any("alert sink failed" in m for m in messages), messages
    assert sum("could not key CRL" in m for m in messages) == 1, messages


def test_one_crl_path_that_cannot_be_keyed_costs_only_its_own_grouping(
    ca: _Ca, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # BACKLOG #3512 (vault #4152, #4158): one comprehension keyed every path, so one path that
    # could not be keyed folded nothing for any row. Now two rows naming a good file still share
    # it, and only the bad path's two rows share with none, logged once.
    good = tmp_path / "good.pem"
    good.write_bytes(ca.crl(days=5.5, number=1))
    bad = tmp_path / "bad.pem"
    bad.write_bytes(ca.crl(days=5.5, number=2))
    real = loaded_crls.crl_path_key

    def _key(path: str) -> str:
        if path == str(bad):
            raise OSError("synthetic path-key failure")
        return real(path)

    monkeypatch.setattr("messagefoundry.pipeline.cert_expiry.crl_path_key", _key)
    rows = [
        MonitoredCert("a.crl_file", str(good), kind="crl"),
        MonitoredCert("b.crl_file", str(good), kind="crl"),
        MonitoredCert("c.crl_file", str(bad), kind="crl"),
        MonitoredCert("d.crl_file", str(bad), kind="crl"),
    ]
    sink = _RecordingSink()
    runner = CertExpiryRunner(lambda: rows, CertMonitorSettings(warn_days=500), alert_sink=sink)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.cert_expiry"):
        runner.run_once(now=time.time())

    shared = {call[0]: note[2] for call, note in zip(sink.crl_calls, sink.crl_notes, strict=True)}
    assert shared == {
        "a.crl_file": ("b.crl_file",),
        "b.crl_file": ("a.crl_file",),
        "c.crl_file": (),
        "d.crl_file": (),
    }
    messages = [r.getMessage() for r in caplog.records]
    assert sum("could not key CRL" in m for m in messages) == 1, messages
    assert not any("could not group the CRL rows" in m for m in messages), messages


def test_a_failure_recording_a_ca_file_crl_is_logged_as_a_defect_not_a_bad_crl(
    ca: _Ca, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Before the fix a ValueError from the record fell into the clause for a CRL the monitor
    # cannot judge, and told the operator to move a good CRL.
    real = loaded_crls.record_crl_load

    def _broken(*args: Any, **kwargs: Any) -> None:
        if kwargs.get("ca_bundle"):
            raise ValueError("synthetic record failure")
        real(*args, **kwargs)  # the CRL setting's own record, untouched

    monkeypatch.setattr(loaded_crls, "record_crl_load", _broken)
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_bytes(ca.pem + ca.crl(days=5.5, number=1))
    crl = tmp_path / "crl.pem"
    crl.write_bytes(ca.crl(days=90, number=2))

    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.tls_policy"):
        hop = _hop(bundle, crl)

    lines = [(r.levelno, r.getMessage()) for r in caplog.records]
    assert any(level == logging.ERROR and "could not record the CRL" in m for level, m in lines)
    assert not any("cannot judge" in m for _, m in lines)
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
