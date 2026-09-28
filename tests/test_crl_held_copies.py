# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #299: replacing a CRL file must not clear the expiry alert while a hop holds the old copy.

A hop reads its CRL when it builds its TLS context and keeps that copy for every handshake until a
restart or a rebuild. The expiry monitor used to read only the file, so replacing an expiring CRL
cleared the ``crl_expiry`` alert while the running hop still held the copy that would lapse and then
refuse every peer. ``harden_crl_check`` now records each load against its context, weakly, and the
monitor judges those held copies as well as the file.

What this file proves, and the instrument for each:

* **The defect's own shape** (red before the fix): build a hop context, replace the file with a
  fresh CRL, and the monitor still alerts with the held copy's days.
* **The alert clears when the hop does.** Drop the context and collect it, and the same pass is
  silent. That is the control that shows the alert above comes from the held copy and nothing else.
* **A rebuilt hop reads the new file**, so its own copy raises nothing.
* **An unreadable file no longer silences the check** while a hop holds a copy of it.
* **A per-connection builder does not record**, and the Postgres store is one.
* **The key is the configured path**, so a relative and an absolute spelling meet.

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

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.loaded_crls import held_crl_copies
from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.config.tls_policy import (
    TrustAnchor,
    build_verifying_client_context,
    harden_crl_check,
)
from messagefoundry.pipeline.cert_expiry import CertCheck, MonitoredCert
from tests.test_cert_expiry import _RecordingSink, _runner


@dataclass(frozen=True)
class _Pki:
    ca_file: Path
    key: ec.EllipticCurvePrivateKey
    name: x509.Name
    crl: Path

    def write_crl(self, *, days: float, number: int) -> None:
        """Replace the CRL file with a bare CRL (no certificate block) whose nextUpdate is ``days``
        from now. One CA key signs every version, which is what a real refresh looks like."""
        now = datetime.datetime.now(datetime.UTC)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.name)
            .last_update(now - datetime.timedelta(hours=1))
            .next_update(now + datetime.timedelta(days=days))
            .add_extension(x509.CRLNumber(number), False)
            .sign(self.key, hashes.SHA256())
        )
        self.crl.write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    def hop(self, crl: Path | None = None) -> ssl.SSLContext:
        """An outbound hop context, built the way ``[tls].crl_file`` reaches every outbound hop."""
        return build_verifying_client_context(
            TrustAnchor(
                cafile=str(self.ca_file), load_system_roots=False, crl_file=str(crl or self.crl)
            )
        )


@pytest.fixture
def pki(tmp_path: Path) -> _Pki:
    """A CA, and a CRL file from it that lapses in about five and a half days."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-299-ca")])
    now = datetime.datetime.now(datetime.UTC)
    ca = (
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
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    made = _Pki(ca_file=ca_file, key=key, name=name, crl=tmp_path / "crl.pem")
    made.write_crl(days=5.5, number=1)
    return made


def _scan(pki: _Pki) -> tuple[_RecordingSink, list[CertCheck]]:
    sink = _RecordingSink()
    runner = _runner([MonitoredCert("tls.crl_file", str(pki.crl), kind="crl")], sink)
    checks = runner.run_once(now=time.time())
    assert sink.cert_calls == []  # a CRL never alerts down cert_expiry
    return sink, checks


_RESTART = "Restart the engine to apply the file"


def _warned(caplog: pytest.LogCaptureFixture) -> bool:
    return any(_RESTART in r.getMessage() for r in caplog.records)


@pytest.fixture(autouse=True)
def _capture_warnings(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="messagefoundry.pipeline.cert_expiry")


def test_replacing_the_file_does_not_clear_the_alert_while_a_hop_holds_the_old_copy(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    # THE DEFECT. Before the fix this pass read only the file, which now says 90 days, and raised
    # nothing, while the hop below still held the copy that lapses in about 5.
    hop = pki.hop()
    pki.write_crl(days=90, number=2)

    sink, _ = _scan(pki)

    assert len(sink.crl_calls) == 1
    label, path, _, days = sink.crl_calls[0]
    assert (label, path) == ("tls.crl_file", str(pki.crl))
    assert days == 5
    assert _warned(caplog)
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF  # and keeps the context alive to here


def test_the_alert_clears_once_the_context_holding_the_old_copy_is_gone(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    # THE CONTROL for the test above: the same file, the same pass, and the only change is that the
    # stale context has been collected. So the alert above came from the held copy alone.
    hop = pki.hop()
    pki.write_crl(days=90, number=2)
    del hop
    gc.collect()

    sink, checks = _scan(pki)

    assert sink.crl_calls == []
    assert checks[0].days_remaining >= 89
    assert not _warned(caplog)


def test_a_hop_rebuilt_from_the_replaced_file_raises_nothing(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    # A restart or a reload rebuilds the hop, and the rebuilt context holds the new copy, which
    # matches the file. So the fix does not leave the alert stuck once the operator has restarted.
    old = pki.hop()
    pki.write_crl(days=90, number=2)
    del old
    gc.collect()
    rebuilt = pki.hop()

    sink, _ = _scan(pki)

    assert sink.crl_calls == []
    assert not _warned(caplog)
    assert len(held_crl_copies(pki.crl)) == 1
    assert rebuilt.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_an_unchanged_file_is_judged_from_the_file(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    # A hop that holds exactly the file's bytes is not a stale copy, and its alert is the file's.
    hop = pki.hop()

    sink, _ = _scan(pki)

    assert [c[3] for c in sink.crl_calls] == [5]
    assert not _warned(caplog)
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_held_copy_keeps_the_check_alive_when_the_file_cannot_be_read(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    # Before the fix a missing file was logged and skipped, so the alert cleared while the hop still
    # held a copy that lapses. Now the held copy is judged, and a restart would refuse to start on
    # the missing file, which is harden_crl_check's own fail-closed rule.
    hop = pki.hop()
    pki.crl.unlink()

    sink, _ = _scan(pki)

    assert [c[3] for c in sink.crl_calls] == [5]
    assert _warned(caplog)
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_replaced_file_far_from_expiry_warns_without_alerting(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    # A CRL replaced to add a revocation, well inside its window: the hop still accepts the newly
    # revoked certificate until it is rebuilt. Nothing is near expiry, so no crl_expiry alert, but
    # the scan says the running hop holds an older copy and that a restart applies the file.
    pki.write_crl(days=200, number=1)
    hop = pki.hop()
    pki.write_crl(days=210, number=2)

    sink, _ = _scan(pki)

    assert sink.crl_calls == []
    assert _warned(caplog)
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_load_told_not_to_record_is_not_recorded(pki: _Pki) -> None:
    # A builder that makes a fresh context for every connection reads the file on each handshake, so
    # the file is the truth for it, and a spent context kept alive by an open connection must not
    # read as a stale copy.
    ctx = ssl.create_default_context(cafile=str(pki.ca_file))
    harden_crl_check(ctx, str(pki.crl), setting="[store].ssl_crl_file", record_held_copy=False)

    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF  # the check itself is unchanged
    assert held_crl_copies(pki.crl) == []


def test_the_postgres_store_context_does_not_record(pki: _Pki) -> None:
    # The one per-connection hop today (BACKLOG #300). Its pool keeps the pool-open context alive
    # for the pool's life without ever handshaking with it, so a record would be a permanent false
    # "restart needed" for a hop that already reads the file on every connection.
    from messagefoundry.store.postgres import _verifying_context

    settings = StoreSettings(
        backend=StoreBackend.POSTGRES,
        server="db.example.test",
        database="mefor",
        username="mefor",
        ssl_root_cert=str(pki.ca_file),
        ssl_crl_file=str(pki.crl),
    )
    ctx = _verifying_context(settings)

    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF  # the store hop still checks
    assert held_crl_copies(pki.crl) == []


def test_a_relative_and_an_absolute_spelling_of_one_path_meet(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The key is the configured path made absolute, so a hop given "crl.pem" and a monitor given the
    # full path agree. Links are deliberately NOT resolved; loaded_crls' docstring says why.
    monkeypatch.chdir(pki.crl.parent)
    hop = pki.hop(Path("crl.pem"))

    assert len(held_crl_copies(pki.crl)) == 1
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
