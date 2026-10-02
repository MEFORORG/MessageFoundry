# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #299: a replaced CRL file reaches the running hops that hold the old copy, without a restart.

What this file proves, and the instrument for each:

* **A running hop enforces a revocation added to the replaced file.** A real TLS handshake against the
  SAME context object, before and after one reload pass. Before the pass it accepts the peer (the
  control), after it refuses with ``certificate revoked``. Both directions: an outbound hop verifying
  a server, and a listener verifying a client.
* **The alert clears once every held copy is current, and not before.** The expiry monitor raises
  ``crl_expiry`` for a stale held copy; after the reload it raises nothing. With one context the reload
  must refuse, the alert stays until that context is gone.
* **A bad replacement is refused and the old copy kept.** Expired, delta, unparseable, a planted CA,
  and a file no newer than the held copy. Each leaves the context accepting the peer it accepted
  before, leaves its certificate count unchanged, records the refusal, and logs it once.

All material is synthetic and minted here. No PHI.
"""

from __future__ import annotations

import asyncio
import datetime
import gc
import logging
import re
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from messagefoundry.config.loaded_crls import (
    crl_fingerprint,
    held_crl_copies,
    record_crl_load,
    reload_refusal,
)
from messagefoundry.config.tls_policy import (
    TrustAnchor,
    build_verifying_client_context,
    harden_crl_check,
)
from messagefoundry.pipeline.cert_expiry import MonitoredCert
from messagefoundry.pipeline.crl_reload import (
    CrlReloadRunner,
    ReloadOutcome,
    reload_replaced_crls,
    supersede_refusal,
)
from messagefoundry.pki import CrlBlock, read_crl_blocks, read_soonest_crl_facts
from tests.test_cert_expiry import _RecordingSink
from tests.test_crl_bundle_anchors import _ku
from tests.test_trust_anchor_byte_binding import _handshake

_NOW = datetime.datetime.now(datetime.UTC)
_DAY = datetime.timedelta(days=1)


@dataclass
class _Pki:
    """One CA that keeps its key, a leaf it issued for server and client auth, and a CRL file."""

    key: ec.EllipticCurvePrivateKey
    name: x509.Name
    aki: x509.AuthorityKeyIdentifier
    ca_pem: bytes
    ca_file: Path
    leaf_serial: int
    leaf: Path
    leaf_key: Path
    crl: Path

    def crl_pem(
        self,
        *,
        issued: datetime.timedelta,
        lasts: datetime.timedelta,
        revoke: bool = False,
        delta: bool = False,
    ) -> bytes:
        """A CRL issued ``issued`` ago (negative is in the future) that runs ``lasts`` from now."""
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.name)
            .last_update(_NOW - issued)
            .next_update(_NOW + lasts)
            .add_extension(self.aki, False)
            .add_extension(x509.CRLNumber(int(time.time() * 1000)), False)
        )
        if revoke:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(self.leaf_serial)
                .revocation_date(_NOW - _DAY)
                .build()
            )
        if delta:
            builder = builder.add_extension(x509.DeltaCRLIndicator(1), critical=True)
        return builder.sign(self.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    def outbound_hop(self) -> ssl.SSLContext:
        """An outbound hop context, built the way ``[tls].crl_file`` reaches every outbound hop."""
        return build_verifying_client_context(
            TrustAnchor(cafile=str(self.ca_file), load_system_roots=False, crl_file=str(self.crl))
        )

    def server(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.leaf, self.leaf_key)
        return ctx

    def listener(self) -> ssl.SSLContext:
        """An mTLS listener whose client CA is this CA, with the CRL loaded the way listeners do."""
        ctx = self.server()
        ctx.load_verify_locations(cadata=self.ca_pem.decode("ascii"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        harden_crl_check(ctx, str(self.crl), setting="[api].tls_client_crl_file")
        return ctx

    def client(self) -> ssl.SSLContext:
        """A TLS 1.2 client presenting the leaf, so the listener's verdict lands in the handshake."""
        ctx = ssl.create_default_context(cadata=self.ca_pem.decode("ascii"))
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.leaf, self.leaf_key)
        return ctx


def _make_pki(d: Path, cn: str) -> _Pki:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _DAY)
        .not_valid_after(_NOW + 365 * _DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(aki, False)
        .add_extension(_ku(ca=True), critical=True)
        .sign(key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    serial = x509.random_serial_number()
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(_NOW - _DAY)
        .not_valid_after(_NOW + 90 * _DAY)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(aki, False)
        .add_extension(_ku(ca=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    (d / f"{cn}.pem").write_bytes(ca_pem)
    (d / f"{cn}-leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (d / f"{cn}-leaf-key.pem").write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    made = _Pki(
        key,
        name,
        aki,
        ca_pem,
        d / f"{cn}.pem",
        serial,
        d / f"{cn}-leaf.pem",
        d / f"{cn}-leaf-key.pem",
        d / f"{cn}-crl.pem",
    )
    # The CRL a hop starts with: issued two days ago, clean, about five and a half days left.
    made.crl.write_bytes(made.crl_pem(issued=2 * _DAY, lasts=5.5 * _DAY))
    return made


@pytest.fixture
def pki(tmp_path: Path) -> _Pki:
    return _make_pki(tmp_path, "mefor-299-reload-ca")


def _accepts(client: ssl.SSLContext, server: ssl.SSLContext) -> bool:
    try:
        _handshake(client, server)
    except ssl.SSLError as exc:
        assert "revoked" in str(exc), exc  # the only refusal these tests expect
        return False
    return True


def _reload(pki: _Pki) -> ReloadOutcome | None:
    """One pass, reduced to this test's file. The registry is process-wide, so other tests' contexts
    may still be held; collecting first drops the ones that are gone."""
    gc.collect()
    mine = [o for o in reload_replaced_crls() if Path(o.path) == pki.crl.resolve()]
    return mine[0] if mine else None


def _fresher(pki: _Pki, *, revoke: bool = True) -> bytes:
    """A proper refresh: issued after the starting CRL, in effect now, and running longer."""
    return pki.crl_pem(issued=_DAY, lasts=60 * _DAY, revoke=revoke)


# --- a running hop picks up the replaced file --------------------------------------------------------


def test_an_outbound_hop_enforces_a_revocation_added_to_the_replaced_file(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    assert _accepts(hop, pki.server())  # control: the clean CRL admits the server

    pki.crl.write_bytes(_fresher(pki))
    assert _accepts(hop, pki.server())  # replacing the file alone changes nothing in the hop

    outcome = _reload(pki)

    assert outcome is not None and (outcome.reloaded, outcome.refusal) == (1, None)
    assert not _accepts(hop, pki.server())  # the SAME context now refuses the revoked server
    (held,) = held_crl_copies(pki.crl)
    assert held.fingerprint == crl_fingerprint(pki.crl.read_bytes())


def test_a_listener_enforces_a_revocation_added_to_the_replaced_file(pki: _Pki) -> None:
    listener = pki.listener()
    assert _accepts(pki.client(), listener)

    pki.crl.write_bytes(_fresher(pki))
    outcome = _reload(pki)

    assert outcome is not None and outcome.reloaded == 1
    assert not _accepts(pki.client(), listener)


def test_an_unchanged_file_does_nothing(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    before = hop.cert_store_stats()

    assert _reload(pki) is None
    assert hop.cert_store_stats() == before


# --- the expiry alert --------------------------------------------------------------------------------


def _alerts(pki: _Pki) -> list[int]:
    from tests.test_cert_expiry import _runner

    sink = _RecordingSink()
    runner = _runner([MonitoredCert("tls.crl_file", str(pki.crl), kind="crl")], sink)
    runner.run_once(now=time.time())
    return [days for *_, days in sink.crl_calls]


def test_the_alert_clears_once_the_reload_brings_the_held_copy_current(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    pki.crl.write_bytes(_fresher(pki, revoke=False))
    assert _alerts(pki) == [5]  # the held copy, not the 60-day file, before the reload

    _reload(pki)

    assert _alerts(pki) == []
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF  # keeps the context alive to here


def test_the_alert_stays_while_any_held_copy_is_not_current(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    # Two hops hold the starting copy. The second one's blocks were not recorded, so the reload must
    # refuse it rather than guess. The first is brought current, the second is not, and the alert
    # stays until the second is gone.
    current = pki.outbound_hop()
    unproven = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    pem = pki.crl.read_bytes()
    record_crl_load(unproven, str(pki.crl), pem, read_soonest_crl_facts(pem, now=time.time()))
    pki.crl.write_bytes(_fresher(pki, revoke=False))

    outcome = _reload(pki)

    assert outcome is not None and outcome.reloaded == 1
    assert outcome.refusal is not None and outcome.refusal.restart_applies
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.cert_expiry"):
        assert _alerts(pki) == [5]
    assert "refused to apply" in caplog.text and "not recorded" in caplog.text
    del unproven
    assert _alerts(pki) == []
    assert current.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


# --- a bad replacement is refused and the old copy kept --------------------------------------------


def _planted_bundle(pki: _Pki, tmp_path: Path) -> bytes:
    (tmp_path / "planted").mkdir()
    planted = _make_pki(tmp_path / "planted", "mefor-299-planted-ca")
    return planted.ca_pem + _fresher(pki)


@pytest.mark.parametrize(
    ("replacement", "restart_applies", "says"),
    [
        (lambda p, _d: p.crl_pem(issued=10 * _DAY, lasts=-_DAY, revoke=True), False, "expired"),
        (lambda p, _d: p.crl_pem(issued=_DAY, lasts=60 * _DAY, delta=True), False, "delta CRL"),
        (
            lambda _p, _d: b"-----BEGIN X509 CRL-----\nnot base64\n-----END X509 CRL-----\n",
            False,
            "block 1",
        ),
        (_planted_bundle, False, "not a CA certificate|does not already trust"),
        # Issued no later than the held copy: OpenSSL would go on choosing the held one.
        (
            lambda p, _d: p.crl_pem(issued=3 * _DAY, lasts=60 * _DAY, revoke=True),
            True,
            "issued after",
        ),
        # Issued later but ending sooner: the held copy could stand in once it lapsed.
        (lambda p, _d: p.crl_pem(issued=_DAY, lasts=4 * _DAY, revoke=True), True, "runs at least"),
        # Not yet in effect: OpenSSL would not use it yet.
        (lambda p, _d: p.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True), True, "in effect"),
    ],
    ids=["expired", "delta", "unparseable", "planted-ca", "not-newer", "shorter", "future"],
)
def test_a_bad_replacement_is_refused_and_the_old_copy_kept(
    pki: _Pki,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    replacement: object,
    restart_applies: bool,
    says: str,
) -> None:
    hop = pki.outbound_hop()
    (old,) = held_crl_copies(pki.crl)
    stats = hop.cert_store_stats()
    assert callable(replacement)
    pki.crl.write_bytes(replacement(pki, tmp_path))

    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        outcome = _reload(pki)
        again = _reload(pki)

    assert outcome is not None and outcome.reloaded == 0 and outcome.refusal is not None
    assert outcome.refusal.restart_applies is restart_applies
    assert re.search(says, outcome.refusal.reason), outcome.refusal.reason
    assert hop.cert_store_stats() == stats  # nothing reached the live context
    assert _accepts(hop, pki.server())  # and it still checks against the old copy
    assert held_crl_copies(pki.crl) == [old]
    assert reload_refusal(pki.crl, crl_fingerprint(pki.crl.read_bytes())) == outcome.refusal
    # Logged once per file version, though every pass retries it.
    assert again is not None and again.refusal == outcome.refusal
    assert sum("refused to apply" in r.getMessage() for r in caplog.records) == 1


def test_a_refusal_clears_once_the_file_is_fixed(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    pki.crl.write_bytes(pki.crl_pem(issued=10 * _DAY, lasts=-_DAY))
    refused = _reload(pki)
    assert refused is not None and refused.refusal is not None

    pki.crl.write_bytes(_fresher(pki))
    fixed = _reload(pki)

    assert fixed is not None and (fixed.reloaded, fixed.refusal) == (1, None)
    assert not _accepts(hop, pki.server())


# --- the superseding rule, alone --------------------------------------------------------------------


def _block(issuer: str, issued_days_ago: float, lasts_days: float, tag: bytes) -> CrlBlock:
    return CrlBlock(issuer, _NOW - issued_days_ago * _DAY, _NOW + lasts_days * _DAY, tag)


def test_the_superseding_rule() -> None:
    now = _NOW.timestamp()
    held = [_block("CN=a", 2, 5, b"old")]
    assert supersede_refusal(held, [_block("CN=a", 1, 30, b"new")], now=now) is None
    assert supersede_refusal(held, [_block("CN=a", 2, 5, b"old")], now=now) is None  # same CRL
    assert supersede_refusal(held, [_block("CN=a", 1, 5, b"new")], now=now) is None  # ends together
    assert supersede_refusal(held, [_block("CN=b", 1, 30, b"new")], now=now)  # issuer dropped
    assert supersede_refusal(held, [_block("CN=a", 1, 4, b"new")], now=now)  # ends sooner
    assert supersede_refusal(held, [_block("CN=a", 2, 30, b"new")], now=now)  # not issued later
    assert supersede_refusal(held, [_block("CN=a", -1, 30, b"new")], now=now)  # not in effect
    assert supersede_refusal([], [_block("CN=a", 1, 30, b"new")], now=now)  # held unknown


def test_read_crl_blocks_names_each_block(pki: _Pki) -> None:
    pem = pki.crl.read_bytes() + _fresher(pki)
    blocks = read_crl_blocks(pem)
    assert [b.issuer for b in blocks] == ["CN=mefor-299-reload-ca"] * 2
    assert blocks[0].this_update < blocks[1].this_update
    assert blocks[0].fingerprint != blocks[1].fingerprint


# --- the runner -------------------------------------------------------------------------------------


def test_the_runner_reloads_off_the_loop_and_stops() -> None:
    seen: list[str] = []

    def fake() -> None:
        seen.append(threading.current_thread().name)

    async def drive() -> None:
        runner = CrlReloadRunner(interval_seconds=0.01, reload=fake)
        runner.start()
        runner.start()  # idempotent
        for _ in range(200):
            if len(seen) >= 2:
                break
            await asyncio.sleep(0.01)
        await runner.stop()
        await runner.stop()  # idempotent

    asyncio.run(drive())
    assert len(seen) >= 2
    assert threading.main_thread().name not in seen
