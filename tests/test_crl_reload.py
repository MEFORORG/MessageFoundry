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
import shutil
import ssl
import tempfile
import threading
import time
import weakref
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from messagefoundry.config import loaded_crls
from messagefoundry.config import tls_policy as tls_policy_module
from messagefoundry.config.loaded_crls import (
    ReloadRefusal,
    crl_fingerprint,
    held_crl_copies,
    record_crl_load,
    reload_refusal,
)
from messagefoundry.config.settings import CertMonitorSettings
from messagefoundry.config.tls_policy import (
    CRL_CLOCK_SKEW_SECONDS,
    CrlNotInEffect,
    TrustAnchor,
    build_verifying_client_context,
    crl_not_in_effect,
    harden_crl_check,
)
from messagefoundry.pipeline import crl_reload
from messagefoundry.pipeline.cert_expiry import MonitoredCert
from messagefoundry.pipeline.crl_reload import (
    BAD_SIGNATURE,
    FIX,
    LAPSES_FIRST,
    MAX_RELOADS,
    NO_ISSUER,
    RESTART,
    RETRY,
    WAIT,
    CrlReloadRunner,
    ReloadOutcome,
    reload_replaced_crls,
    supersede_refusal,
)
from messagefoundry.pki import (
    CrlBlock,
    crl_signature_refusal,
    judge_every_crl,
    read_soonest_crl_facts,
)
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
        scope: bool = False,
        signer: ec.EllipticCurvePrivateKey | None = None,
        aki: x509.AuthorityKeyIdentifier | None = None,
    ) -> bytes:
        """A CRL issued ``issued`` ago (negative is in the future) that runs ``lasts`` from now."""
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.name)
            .last_update(_NOW - issued)
            .next_update(_NOW + lasts)
            .add_extension(aki or self.aki, False)
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
        if scope:
            # A narrower scope OpenSSL scores lower for a leaf, so it would keep the held CRL.
            builder = builder.add_extension(
                x509.IssuingDistributionPoint(
                    full_name=None,
                    relative_name=None,
                    only_contains_user_certs=False,
                    only_contains_ca_certs=True,
                    only_some_reasons=None,
                    indirect_crl=False,
                    only_contains_attribute_certs=False,
                ),
                critical=True,
            )
        signed = builder.sign(signer or self.key, hashes.SHA256())
        return signed.public_bytes(serialization.Encoding.PEM)

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


def _ca_cert(
    name: x509.Name,
    key: ec.EllipticCurvePrivateKey,
    issuer: x509.Name,
    signer: ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _DAY)
        .not_valid_after(_NOW + 365 * _DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False
        )
        .add_extension(_ku(ca=True), critical=True)
        .sign(signer, hashes.SHA256())
    )


def _leaf(
    issuer: x509.Name, signer: ec.EllipticCurvePrivateKey
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """A ``localhost`` leaf for server and client auth, issued by ``issuer`` and signed by
    ``signer``, and its key."""
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False
        )
        .add_extension(_ku(ca=False), critical=True)
        .sign(signer, hashes.SHA256())
    )
    return leaf, key


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _make_pki(d: Path, cn: str) -> _Pki:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
    ca = _ca_cert(name, key, name, key)
    leaf, leaf_key = _leaf(name, key)
    serial = leaf.serial_number
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    (d / f"{cn}.pem").write_bytes(ca_pem)
    (d / f"{cn}-leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (d / f"{cn}-leaf-key.pem").write_bytes(_key_pem(leaf_key))
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


@pytest.fixture(autouse=True)
def _fresh_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test starts with no held copies, no refusals and no pass state, so no test sees another's
    contexts or a refusal recorded for a path it reuses. Restored after the test."""
    monkeypatch.setattr(loaded_crls, "_HELD", weakref.WeakKeyDictionary())
    monkeypatch.setattr(loaded_crls, "_REFUSED", {})
    monkeypatch.setattr(crl_reload, "_SEEN", {})
    monkeypatch.setattr(crl_reload, "_UNREADABLE", set())
    monkeypatch.setattr(crl_reload, "_FAILED", {})


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


def _reload(pki: _Pki, *, max_reloads: int = MAX_RELOADS) -> ReloadOutcome | None:
    """One pass, reduced to this test's file. The fixture empties the registry per test, and
    collecting first drops this test's own contexts that are gone."""
    gc.collect()
    outcomes = reload_replaced_crls(max_reloads=max_reloads)
    mine = [o for o in outcomes if Path(o.path) == pki.crl.resolve()]
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
    assert outcome.refusal is not None and outcome.refusal.remedy == RESTART
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
    ("replacement", "remedy", "says"),
    [
        (lambda p, _d: p.crl_pem(issued=10 * _DAY, lasts=-_DAY, revoke=True), FIX, "expired"),
        (lambda p, _d: p.crl_pem(issued=_DAY, lasts=60 * _DAY, delta=True), FIX, "delta CRL"),
        (
            lambda _p, _d: b"-----BEGIN X509 CRL-----\nnot base64\n-----END X509 CRL-----\n",
            FIX,
            "block 1",
        ),
        (_planted_bundle, FIX, "does not already trust"),
        # Issued no later than the held copy: OpenSSL would go on choosing the held one.
        (lambda p, _d: p.crl_pem(issued=3 * _DAY, lasts=60 * _DAY, revoke=True), RESTART, "choose"),
        # Issued later but ending sooner: the held copy could stand in once it lapsed.
        (lambda p, _d: p.crl_pem(issued=_DAY, lasts=4 * _DAY, revoke=True), RESTART, "choose"),
        # A narrower scope: OpenSSL scores it below the held CRL and keeps using the held one.
        # Measured by review: without the selection check this read as reloaded and changed nothing.
        (
            lambda p, _d: p.crl_pem(issued=_DAY, lasts=60 * _DAY, revoke=True, scope=True),
            RESTART,
            "same scope",
        ),
        # Not yet in effect: OpenSSL would not use it yet, and a restart now would break the hop.
        (
            lambda p, _d: p.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True),
            WAIT,
            "not in effect",
        ),
    ],
    ids=[
        "expired",
        "delta",
        "unparseable",
        "planted-ca",
        "not-newer",
        "shorter",
        "scope",
        "future",
    ],
)
def test_a_bad_replacement_is_refused_and_the_old_copy_kept(
    pki: _Pki,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    replacement: object,
    remedy: str,
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
    assert outcome.refusal.remedy == remedy
    assert outcome.refusal.sticky is (remedy not in (WAIT, LAPSES_FIRST))
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
    rescoped = replace(_block("CN=a", 1, 30, b"new"), selection=(b"idp", None, frozenset()))

    def waits(new: list[CrlBlock], against: list[CrlBlock] = held) -> bool:
        verdict = supersede_refusal(against, new, now=now)
        assert verdict is not None
        return verdict[1] in (WAIT, LAPSES_FIRST)

    assert not waits([_block("CN=b", 1, 30, b"new")])  # issuer dropped
    assert not waits([_block("CN=a", 1, 4, b"new")])  # ends sooner
    assert not waits([_block("CN=a", 2, 30, b"new")])  # not issued later
    assert not waits([rescoped])  # same timing, a scope OpenSSL scores differently
    assert not waits([_block("CN=a", 1, 30, b"new")], against=[])  # held copy unknown
    assert waits([_block("CN=a", -1, 30, b"new")])  # not in effect yet: only time is missing
    # Not in effect until after the held copy lapses: waiting leaves a gap, so the file must change.
    late = supersede_refusal(held, [_block("CN=a", -7, 30, b"new")], now=now)
    assert late is not None and late[1] == LAPSES_FIRST


def test_judge_every_crl_names_each_block(pki: _Pki) -> None:
    pem = pki.crl.read_bytes() + _fresher(pki)
    blocks = [block for _, block in judge_every_crl(pem, now=time.time())]
    assert [b.issuer for b in blocks] == ["CN=mefor-299-reload-ca"] * 2
    assert blocks[0].this_update < blocks[1].this_update
    assert blocks[0].fingerprint != blocks[1].fingerprint


# --- the runner -------------------------------------------------------------------------------------


def test_the_runner_reloads_off_the_loop_and_stops() -> None:
    seen: list[str] = []

    def fake() -> None:
        seen.append(threading.current_thread().name)

    async def drive() -> None:
        runner = CrlReloadRunner(interval_seconds=0.01, reload=fake, skip_when_idle=False)
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


def test_a_context_stops_taking_reloads_at_the_cap(pki: _Pki) -> None:
    # Every reload stays in the trust store, so the count is bounded and a restart compacts it.
    hop = pki.outbound_hop()
    pki.crl.write_bytes(_fresher(pki, revoke=False))
    assert (first := _reload(pki, max_reloads=1)) is not None and first.reloaded == 1

    pki.crl.write_bytes(pki.crl_pem(issued=0.5 * _DAY, lasts=90 * _DAY, revoke=True))
    second = _reload(pki, max_reloads=1)

    assert second is not None and second.reloaded == 0 and second.refusal is not None
    assert second.refusal.remedy == RESTART and "reloads" in second.refusal.reason
    assert _accepts(hop, pki.server())


def test_a_refusal_names_the_configured_path(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    pki.crl.write_bytes(pki.crl_pem(issued=10 * _DAY, lasts=-_DAY))
    outcome = _reload(pki)
    assert outcome is not None and outcome.refusal is not None
    assert repr(str(pki.crl)) in outcome.refusal.reason
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


# --- round-two review findings ----------------------------------------------------------------------


def test_a_crl_with_a_bad_signature_is_refused_and_handshakes_still_succeed(pki: _Pki) -> None:
    # Right issuer name and AKID, signed by a key that is not the CA's.
    forged = pki.crl_pem(
        issued=_DAY, lasts=60 * _DAY, revoke=True, signer=ec.generate_private_key(ec.SECP256R1())
    )
    hop = pki.outbound_hop()
    stats = hop.cert_store_stats()
    # Control: a context given these bytes fails every handshake, which is what the check prevents.
    broken = pki.outbound_hop()
    pki.crl.write_bytes(forged)
    broken.load_verify_locations(cafile=str(pki.crl))
    with pytest.raises(ssl.SSLError, match="signature"):
        _handshake(broken, pki.server())
    del broken

    outcome = _reload(pki)

    assert outcome is not None and outcome.reloaded == 0 and outcome.refusal is not None
    assert outcome.refusal.remedy == BAD_SIGNATURE and outcome.refusal.sticky
    assert "does not verify" in outcome.refusal.reason
    assert hop.cert_store_stats() == stats
    assert _accepts(hop, pki.server())  # the old copy is kept, and the hop still works


def test_a_file_whose_crl_takes_effect_after_the_held_copy_lapses_is_not_told_to_wait(
    pki: _Pki,
) -> None:
    hop = pki.outbound_hop()  # its copy lapses in about five and a half days
    pki.crl.write_bytes(pki.crl_pem(issued=-7 * _DAY, lasts=60 * _DAY, revoke=True))

    outcome = _reload(pki)

    assert outcome is not None and outcome.refusal is not None
    assert outcome.refusal.remedy == LAPSES_FIRST and not outcome.refusal.sticky
    assert "lapses earlier" in outcome.refusal.reason
    assert _accepts(hop, pki.server())


def test_a_start_refuses_a_crl_not_in_effect_yet(pki: _Pki) -> None:
    pki.crl.write_bytes(pki.crl_pem(issued=-_DAY, lasts=60 * _DAY))
    with pytest.raises(CrlNotInEffect, match="does not take effect until"):
        pki.outbound_hop()


def test_a_start_accepts_a_future_crl_beside_a_current_one(pki: _Pki) -> None:
    # OpenSSL prefers the CRL in effect, so the future one beside it is harmless until it starts.
    pki.crl.write_bytes(pki.crl.read_bytes() + pki.crl_pem(issued=-_DAY, lasts=60 * _DAY))
    assert _accepts(pki.outbound_hop(), pki.server())


def test_a_crl_whose_akid_names_the_ca_by_issuer_and_serial_does_not_supersede(pki: _Pki) -> None:
    # Same key identifier, plus an issuer and serial: OpenSSL matches those too, so it scores apart.
    hop = pki.outbound_hop()
    fuller = x509.AuthorityKeyIdentifier(
        key_identifier=pki.aki.key_identifier,
        authority_cert_issuer=[x509.DirectoryName(pki.name)],
        authority_cert_serial_number=1,
    )
    pki.crl.write_bytes(pki.crl_pem(issued=_DAY, lasts=60 * _DAY, revoke=True, aki=fuller))

    outcome = _reload(pki)

    assert outcome is not None and outcome.refusal is not None
    assert outcome.refusal.remedy == RESTART and "same scope" in outcome.refusal.reason
    assert _accepts(hop, pki.server())


def test_the_reload_reads_the_path_as_configured(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    (held,) = held_crl_copies(pki.crl)
    assert held.file_path == str(pki.crl.absolute())  # case kept; path_key may be case-folded
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_an_unchanged_file_is_not_read_again(pki: _Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    hop = pki.outbound_hop()
    assert _reload(pki) is None  # the first pass reads the file once and remembers its stamp
    reads: list[str] = []
    real = crl_reload._read

    def spy(
        key: str, path: str, stamp: tuple[int, int, int] | None = None
    ) -> tuple[bytes, tuple[int, int]] | None:
        reads.append(path)
        return real(key, path, stamp)

    monkeypatch.setattr(crl_reload, "_read", spy)

    assert _reload(pki) is None
    assert reads == []
    pki.crl.write_bytes(_fresher(pki))
    assert (outcome := _reload(pki)) is not None and outcome.reloaded == 1
    assert reads  # a changed file is read
    assert not _accepts(hop, pki.server())


def test_a_cleanup_failure_after_a_reload_is_not_a_refusal(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    hop = pki.outbound_hop()
    pki.crl.write_bytes(_fresher(pki))

    def fail(path: str) -> None:
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(shutil, "rmtree", fail)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.tls_policy"):
        outcome = _reload(pki)

    assert outcome is not None and (outcome.reloaded, outcome.refusal) == (1, None)
    assert "could not remove" in caplog.text
    assert not _accepts(hop, pki.server())


def test_a_staging_failure_is_logged_once_though_each_temp_path_differs(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    hop = pki.outbound_hop()
    pki.crl.write_bytes(_fresher(pki))
    calls = iter(range(100))

    def fail(prefix: str) -> str:
        raise PermissionError(13, "Permission denied", f"C:/tmp/{prefix}{next(calls)}")

    monkeypatch.setattr(tempfile, "mkdtemp", fail)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        first, second = _reload(pki), _reload(pki)

    assert first is not None and first.refusal is not None and not first.refusal.sticky
    assert second is not None and second.refusal == first.refusal
    assert sum("refused to apply" in r.getMessage() for r in caplog.records) == 1
    assert _accepts(hop, pki.server())


def test_an_unexpected_failure_is_logged_once_with_its_traceback(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    hop = pki.outbound_hop()
    pki.crl.write_bytes(_fresher(pki))

    def boom(pem: bytes, ca_ders: object) -> None:
        raise RuntimeError("a defect")

    monkeypatch.setattr(crl_reload, "crl_signature_refusal", boom)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        first, second = _reload(pki), _reload(pki)

    assert first is not None and first.refusal is not None
    assert "RuntimeError" in first.refusal.reason and not first.refusal.sticky
    assert second is not None and second.refusal == first.refusal
    logged = [r for r in caplog.records if "refused to apply" in r.getMessage()]
    assert len(logged) == 1 and logged[0].exc_info is not None
    assert _accepts(hop, pki.server())


def test_stop_does_not_wait_for_a_hung_pass() -> None:
    release = threading.Event()

    def hung() -> None:
        release.wait(10)

    async def drive() -> float:
        runner = CrlReloadRunner(
            interval_seconds=0.01, reload=hung, stop_timeout_seconds=0.1, skip_when_idle=False
        )
        runner.start()
        await asyncio.sleep(0.1)  # the pass is now blocked in its worker thread
        started = time.monotonic()
        try:
            await runner.stop()
            return time.monotonic() - started
        finally:
            release.set()  # so asyncio.run's executor shutdown does not wait on the thread

    assert asyncio.run(drive()) < 5


def test_the_cap_is_a_cert_monitor_setting() -> None:
    assert CertMonitorSettings().crl_max_reloads == MAX_RELOADS
    with pytest.raises(ValueError, match="crl_max_reloads"):
        CertMonitorSettings(crl_max_reloads=0)


# --- round-three review findings --------------------------------------------------------------------


def _make_intermediate_pki(d: Path) -> tuple[_Pki, Path]:
    """A root, an intermediate it signed, and a leaf the intermediate signed. The CRL is the
    intermediate's. The hop's CA file holds the root alone, as a partner's PKI often has it, and
    the server sends the intermediate in its chain. Also returns a CA file holding both."""
    pem = serialization.Encoding.PEM
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-299-root")])
    root = _ca_cert(root_name, root_key, root_name, root_key)
    mid_key = ec.generate_private_key(ec.SECP256R1())
    mid_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-299-intermediate")])
    mid = _ca_cert(mid_name, mid_key, root_name, root_key)
    mid_aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(mid_key.public_key())
    leaf, leaf_key = _leaf(mid_name, mid_key)
    (d / "root.pem").write_bytes(root.public_bytes(pem))
    (d / "root-and-intermediate.pem").write_bytes(root.public_bytes(pem) + mid.public_bytes(pem))
    (d / "chain.pem").write_bytes(leaf.public_bytes(pem) + mid.public_bytes(pem))
    (d / "leaf-key.pem").write_bytes(_key_pem(leaf_key))
    made = _Pki(
        mid_key,
        mid_name,
        mid_aki,
        root.public_bytes(pem),
        d / "root.pem",
        leaf.serial_number,
        d / "chain.pem",
        d / "leaf-key.pem",
        d / "intermediate-crl.pem",
    )
    made.crl.write_bytes(made.crl_pem(issued=2 * _DAY, lasts=5.5 * _DAY))
    return made, d / "root-and-intermediate.pem"


def test_a_crl_from_an_intermediate_the_hop_does_not_list_is_retried_and_names_the_fix(
    tmp_path: Path,
) -> None:
    pki, both = _make_intermediate_pki(tmp_path)
    hop = pki.outbound_hop()  # root only: the server sends the intermediate
    listed = build_verifying_client_context(
        TrustAnchor(cafile=str(both), load_system_roots=False, crl_file=str(pki.crl))
    )
    assert _accepts(hop, pki.server()) and _accepts(listed, pki.server())

    pki.crl.write_bytes(_fresher(pki))
    outcome = _reload(pki)

    # The hop that lists the intermediate takes the file. The other cannot verify the signature.
    assert outcome is not None and outcome.reloaded == 1 and outcome.refusal is not None
    assert outcome.refusal.remedy == NO_ISSUER and not outcome.refusal.sticky
    assert "intermediate" in outcome.refusal.remedy and "CA file" in outcome.refusal.remedy
    assert not _accepts(listed, pki.server())
    assert _accepts(hop, pki.server())  # kept its copy, and was not told the refusal is final
    # Retried on the next pass rather than refused for good.
    again = _reload(pki)
    assert again is not None and again.refusal == outcome.refusal
    # Control: a restart applies the same file to a root-only hop, so the remedy is true.
    assert not _accepts(pki.outbound_hop(), pki.server())


def test_one_context_failing_does_not_stop_the_rest_or_stick(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    failing, other = pki.outbound_hop(), pki.outbound_hop()
    pki.crl.write_bytes(_fresher(pki))

    def boom(binary_form: bool = False) -> list[bytes]:
        raise RuntimeError("a defect in one context")

    failing.get_ca_certs = boom  # type: ignore[method-assign, assignment]
    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        outcome = _reload(pki)

    assert outcome is not None and outcome.reloaded == 1 and outcome.refusal is not None
    assert outcome.refusal.remedy == RETRY and not outcome.refusal.sticky
    assert not _accepts(other, pki.server())  # loaded although the context before it failed
    assert "to 1 running TLS context(s)" in caplog.text  # only the failed one is reported
    del failing.get_ca_certs
    retried = _reload(pki)
    assert retried is not None and (retried.reloaded, retried.refusal) == (1, None)
    assert not _accepts(failing, pki.server())


def _in_minutes(minutes: float) -> datetime.timedelta:
    """The ``issued`` that puts a CRL's thisUpdate ``minutes`` from the real now, not ``_NOW``."""
    return _NOW - datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=minutes)


def test_a_wait_never_outranks_a_context_at_the_cap(pki: _Pki) -> None:
    capped = pki.outbound_hop()
    pki.crl.write_bytes(_fresher(pki, revoke=False))
    assert (first := _reload(pki, max_reloads=1)) is not None and first.reloaded == 1
    fresh = pki.outbound_hop()  # built from that file, no reloads yet
    pki.crl.write_bytes(pki.crl_pem(issued=-_DAY, lasts=90 * _DAY, revoke=True))  # not in effect

    outcome = _reload(pki, max_reloads=1)

    # Waiting would never apply the file to the capped hop, so the restart is what is reported.
    assert outcome is not None and outcome.refusal is not None
    assert outcome.refusal.remedy == RESTART and "reloads" in outcome.refusal.reason
    assert not outcome.refusal.sticky  # the other hop's wait is still retried
    # And it does not send the operator into a start that refuses the same file.
    assert "a start until then refuses this file too" in outcome.refusal.reason
    assert _accepts(capped, pki.server()) and _accepts(fresh, pki.server())


def test_a_wait_never_outranks_a_file_to_fix(pki: _Pki, tmp_path: Path) -> None:
    hop = pki.outbound_hop()
    (tmp_path / "planted").mkdir()
    planted = _make_pki(tmp_path / "planted", "mefor-299-planted-ca")
    future = pki.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True)
    pki.crl.write_bytes(planted.ca_pem + future)

    outcome = _reload(pki)

    assert outcome is not None and outcome.refusal is not None
    assert outcome.refusal.remedy == FIX and "does not already trust" in outcome.refusal.reason
    assert _accepts(hop, pki.server())


def test_the_superseding_rule_reports_a_restart_over_a_wait_and_the_last_lapse() -> None:
    now = _NOW.timestamp()
    # One held CRL is only waiting, another has no successor: the restart is the answer.
    held = [_block("CN=a", 2, 5, b"a"), _block("CN=b", 2, 5, b"b")]
    verdict = supersede_refusal(held, [_block("CN=a", -1, 30, b"a2")], now=now)
    assert verdict is not None and verdict[1] == RESTART and "CN=b" in verdict[0]
    # The hop holds an older CRL lapsing in 3 days beside a newer one lapsing in 30. Every peer is
    # refused only once both lapse, so a successor in effect in 7 days is a plain wait.
    overlap = [_block("CN=a", 4, 3, b"older"), _block("CN=a", 2, 30, b"newer")]
    verdict = supersede_refusal(overlap, [_block("CN=a", -7, 30, b"next")], now=now)
    assert verdict is not None and verdict[1] == WAIT


@pytest.mark.parametrize(("minutes", "starts"), [(2, True), (10, False)])
def test_a_start_allows_five_minutes_of_clock_skew(
    pki: _Pki, caplog: pytest.LogCaptureFixture, minutes: int, starts: bool
) -> None:
    assert CRL_CLOCK_SKEW_SECONDS == 300
    pki.crl.write_bytes(pki.crl_pem(issued=_in_minutes(minutes), lasts=60 * _DAY))
    if starts:
        with caplog.at_level(logging.WARNING, logger="messagefoundry.config.tls_policy"):
            assert pki.outbound_hop().verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
        # OpenSSL allows no skew, so the start says why peers fail for those minutes.
        assert "accepted as clock skew" in caplog.text
    else:
        with pytest.raises(CrlNotInEffect, match="does not take effect until"):
            pki.outbound_hop()


@pytest.mark.parametrize(("minutes", "applied"), [(2, True), (10, False)])
def test_a_reload_allows_five_minutes_of_clock_skew(pki: _Pki, minutes: int, applied: bool) -> None:
    hop = pki.outbound_hop()
    pki.crl.write_bytes(pki.crl_pem(issued=_in_minutes(minutes), lasts=60 * _DAY, revoke=True))

    outcome = _reload(pki)

    assert outcome is not None
    if applied:
        assert (outcome.reloaded, outcome.refusal) == (1, None)
    else:
        assert outcome.reloaded == 0 and outcome.refusal is not None
        assert outcome.refusal.remedy == WAIT
    # Either way the hop still admits the server now: OpenSSL keeps choosing the copy in effect.
    assert _accepts(hop, pki.server())


def test_one_context_loading_one_file_twice_is_one_record_and_one_reload(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    harden_crl_check(hop, str(pki.crl), setting="[api].other_crl_file")
    (held,) = held_crl_copies(pki.crl)
    assert held.setting == "[tls].crl_file and [api].other_crl_file"  # both knobs are named
    pki.crl.write_bytes(_fresher(pki))

    outcome = _reload(pki)

    assert outcome is not None and (outcome.reloaded, outcome.refusal) == (1, None)
    assert len(held_crl_copies(pki.crl)) == 1
    assert not _accepts(hop, pki.server())


def test_a_refusal_is_forgotten_once_no_hop_holds_the_file(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    pki.crl.write_bytes(pki.crl_pem(issued=10 * _DAY, lasts=-_DAY))
    assert (refused := _reload(pki)) is not None and refused.refusal is not None
    fingerprint = crl_fingerprint(pki.crl.read_bytes())
    assert reload_refusal(pki.crl, fingerprint) is not None

    del hop
    assert _reload(pki) is None

    assert reload_refusal(pki.crl, fingerprint) is None


def test_the_runner_starts_no_thread_while_no_crl_is_held(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(crl_reload, "reload_replaced_crls", lambda **_: calls.append(1))

    async def drive(hold: bool) -> None:
        runner = CrlReloadRunner(interval_seconds=0.01)
        held = pki.outbound_hop() if hold else None
        runner.start()
        await asyncio.sleep(0.2)
        await runner.stop()
        del held

    # A refusal left for a file no hop holds is dropped even though no pass runs.
    loaded_crls.record_reload_refusal(pki.crl, ReloadRefusal((1, 2), "gone", RESTART))
    asyncio.run(drive(hold=False))
    assert calls == []
    assert reload_refusal(pki.crl, (1, 2)) is None
    asyncio.run(drive(hold=True))
    assert calls  # control: the same runner works once a CRL is held


def test_a_wait_reports_any_held_crl_that_lapses_first() -> None:
    # The file refreshes issuer a and adds issuer b, whose only CRL starts in 10 days. Nothing in
    # the file reaches the hop until then, and the hop's copy of a lapses in 5.5 days.
    now = _NOW.timestamp()
    held = [_block("CN=a", 2, 5.5, b"a")]
    new = [_block("CN=a", 1, 60, b"a2"), _block("CN=b", -10, 60, b"b")]
    verdict = supersede_refusal(held, new, now=now)
    assert verdict is not None and verdict[1] == LAPSES_FIRST
    assert "'CN=a' lapses earlier" in verdict[0] and "'CN=b'" in verdict[0]
    # And the wait names when the WHOLE file applies, the latest issuer's CRL, not the earliest.
    later = [
        _block("CN=a", 1, 60, b"a2"),
        _block("CN=b", -2, 60, b"b"),
        _block("CN=c", -4, 60, b"c"),
    ]
    verdict = supersede_refusal([_block("CN=a", 2, 30, b"a")], later, now=now)
    assert verdict is not None and verdict[1] == WAIT and "'CN=c'" in verdict[0]
    unmet = crl_not_in_effect(later, now=now)
    assert unmet is not None and unmet.issuer == "CN=c"


def test_a_held_crl_that_lapses_outranks_a_restart() -> None:
    refusals = crl_reload._Refusals()
    refusals.add("capped", RESTART)
    refusals.add("lapses", LAPSES_FIRST)
    refusals.add("waits", WAIT)
    assert refusals.strongest == ("lapses", LAPSES_FIRST)


# --- code-review round two --------------------------------------------------------------------------


def test_a_context_at_the_cap_still_reports_a_copy_that_lapses_first(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    pki.crl.write_bytes(pki.crl_pem(issued=_DAY, lasts=6 * _DAY))  # supersedes, lapses in 6 days
    assert (first := _reload(pki, max_reloads=1)) is not None and first.reloaded == 1
    pki.crl.write_bytes(pki.crl_pem(issued=-7 * _DAY, lasts=60 * _DAY, revoke=True))

    outcome = _reload(pki, max_reloads=1)

    # A restart after the file takes effect would come a day too late: say so, not "restart".
    assert outcome is not None and outcome.refusal is not None
    assert outcome.refusal.remedy == LAPSES_FIRST and "lapses earlier" in outcome.refusal.reason
    assert _accepts(hop, pki.server())


def test_a_lapse_before_the_file_applies_is_found_beside_a_held_crl_with_no_successor() -> None:
    now = _NOW.timestamp()
    held = [_block("CN=a", 2, 1, b"a"), _block("CN=b", 2, 30, b"b")]
    new = [_block("CN=a", -2, 30, b"a2")]
    restart = supersede_refusal(held, new, now=now)
    assert restart is not None and restart[1] == RESTART  # b has no successor
    late = crl_reload._time_verdict(held, new, now=now)
    assert late is not None and late[1] == LAPSES_FIRST  # and a lapses before a2 starts


def test_a_badly_signed_crl_is_reported_over_one_whose_ca_is_not_listed(
    pki: _Pki, tmp_path: Path
) -> None:
    (tmp_path / "other").mkdir()
    other = _make_pki(tmp_path / "other", "mefor-299-unlisted-ca")
    forged = pki.crl_pem(
        issued=_DAY, lasts=60 * _DAY, signer=ec.generate_private_key(ec.SECP256R1())
    )
    anchors = [x509.load_pem_x509_certificate(pki.ca_pem).public_bytes(serialization.Encoding.DER)]
    unlisted_first = other.crl.read_bytes() + forged
    verdict = crl_signature_refusal(unlisted_first, anchors)
    assert verdict is not None and verdict[1] is True and "block 2" in verdict[0]
    alone = crl_signature_refusal(other.crl.read_bytes(), anchors)  # control: unlisted alone
    assert alone is not None and alone[1] is False


# --- Lander hold on PR 1963: a CRL block OpenSSL does not load -------------------------------------


def _indented(pem: bytes) -> bytes:
    """``pem`` with its BEGIN line indented one space; ``pki._crl_blocks`` records what OpenSSL
    does with that."""
    return b" " + pem


def _openssl_count(tmp_path: Path, pem: bytes) -> int:
    path = tmp_path / "count.pem"
    path.write_bytes(pem)
    scratch = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    scratch.load_verify_locations(cafile=str(path))
    return int(scratch.cert_store_stats()["crl"])


_BOM = b"\xef\xbb\xbf"


@pytest.mark.parametrize(
    ("shape", "loads"),
    [
        (lambda a, b: a + b, 2),
        (lambda a, b: a + _indented(b), 1),
        (lambda a, b: a + b"\t" + b, 1),
        (lambda a, b: _BOM + a + _BOM + b, 2),
        (lambda a, b: a + _BOM + _BOM + b, 1),
        (lambda a, b: (a + b).replace(b"\n", b"\r\n"), 2),
        (lambda a, b: a.replace(b"CRL-----\n", b"CRL-----  \n", 1) + b, 2),
    ],
    ids=["plain", "indented", "tab", "bom", "two-boms", "crlf", "trailing-spaces"],
)
def test_the_parser_counts_the_crls_openssl_loads(
    pki: _Pki, tmp_path: Path, shape: object, loads: int
) -> None:
    # Against OpenSSL itself, so an OpenSSL that changes its PEM rule turns this red.
    assert callable(shape)
    pem = shape(pki.crl.read_bytes(), _fresher(pki))
    assert _openssl_count(tmp_path, pem) == loads
    if loads == 2:
        assert len(judge_every_crl(pem, now=time.time())) == 2  # accepted, both judged
    else:
        with pytest.raises(ValueError, match="does not start a line"):
            judge_every_crl(pem, now=time.time())


def test_a_superseding_crl_in_an_indented_block_is_refused_and_the_alert_kept(
    pki: _Pki,
) -> None:
    hop = pki.outbound_hop()
    (old,) = held_crl_copies(pki.crl)
    pki.crl.write_bytes(pki.crl.read_bytes() + _indented(_fresher(pki)))
    assert _alerts(pki) == [5]

    outcome = _reload(pki)

    assert outcome is not None and outcome.reloaded == 0 and outcome.refusal is not None
    assert outcome.refusal.remedy == FIX and "does not start a line" in outcome.refusal.reason
    assert held_crl_copies(pki.crl) == [old]  # not recorded as applied
    assert _alerts(pki) == [5]  # the old copy's alert stays up
    assert _accepts(hop, pki.server())  # and the hop still checks the old CRL
    # Control: the same CRL in a plain block applies.
    pki.crl.write_bytes(_fresher(pki))
    applied = _reload(pki)
    assert applied is not None and (applied.reloaded, applied.refusal) == (1, None)
    assert not _accepts(hop, pki.server())


def test_a_start_refuses_a_crl_in_an_indented_block(pki: _Pki) -> None:
    pki.crl.write_bytes(pki.crl.read_bytes() + _indented(_fresher(pki)))
    with pytest.raises(ValueError, match="does not start a line"):
        pki.outbound_hop()


@pytest.mark.parametrize(("judged", "loads"), [(2, 1), (1, 2)], ids=["fewer", "more"])
def test_a_crl_count_openssl_disagrees_with_is_refused_at_start_and_at_reload(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, judged: int, loads: int
) -> None:
    # The guard behind the parser, for any shape the two still read differently. Simulated by
    # having the parser see one CRL more than OpenSSL loads, or one fewer.
    hop = pki.outbound_hop()
    fresher = _fresher(pki)
    pki.crl.write_bytes(fresher if loads == 1 else pki.crl.read_bytes() + fresher)
    real = tls_policy_module.judge_crl_bytes

    def skewed(pem: bytes, **kwargs: object) -> tuple[object, tuple[CrlBlock, ...]]:
        facts, blocks = real(pem, **kwargs)  # type: ignore[arg-type]
        return facts, (*blocks, replace(blocks[0], fingerprint=b"never loaded"))[:judged]

    monkeypatch.setattr(tls_policy_module, "judge_crl_bytes", skewed)
    monkeypatch.setattr(crl_reload, "judge_crl_bytes", skewed)

    outcome = _reload(pki)

    said = f"OpenSSL loads {loads} CRL(s) from this file, but {judged} were checked"
    assert outcome is not None and outcome.reloaded == 0 and outcome.refusal is not None
    assert outcome.refusal.remedy == FIX and said in outcome.refusal.reason
    assert _accepts(hop, pki.server())
    with pytest.raises(ValueError, match="OpenSSL loads"):
        pki.outbound_hop()


def test_a_file_openssl_cannot_load_is_a_fix_even_when_every_context_needs_a_restart(
    pki: _Pki,
) -> None:
    # Every stale context is refused before the load (here, at the cap), so no context is ready.
    # OpenSSL's own reading must still run: a start would refuse this file, so "restart" is wrong.
    hop = pki.outbound_hop()
    pki.crl.write_bytes(_fresher(pki, revoke=False))
    assert (first := _reload(pki, max_reloads=1)) is not None and first.reloaded == 1
    pki.crl.write_bytes(_fresher(pki).replace(b"-----END X509 CRL", b" -----END X509 CRL"))

    outcome = _reload(pki, max_reloads=1)

    assert outcome is not None and outcome.refusal is not None
    assert outcome.refusal.remedy == FIX
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_start_on_a_context_that_already_holds_crls_still_counts_them(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Once a context holds the file's CRL, a second load adds none, so its own count proves
    # nothing; a scratch copy of the judged bytes is counted instead. Simulated disagreement.
    hop = pki.outbound_hop()
    harden_crl_check(hop, str(pki.crl), setting="[tls].crl_file")  # control: a second load passes
    real = tls_policy_module.judge_crl_bytes

    def one_more(pem: bytes, **kwargs: object) -> tuple[object, tuple[CrlBlock, ...]]:
        facts, blocks = real(pem, **kwargs)  # type: ignore[arg-type]
        return facts, (*blocks, replace(blocks[0], fingerprint=b"never loaded"))

    monkeypatch.setattr(tls_policy_module, "judge_crl_bytes", one_more)
    with pytest.raises(ValueError, match="OpenSSL loads 1 CRL"):
        harden_crl_check(hop, str(pki.crl), setting="[tls].crl_file")


@pytest.mark.parametrize("bad", ["planted-ca", "forged"])
def test_a_file_to_fix_is_reported_for_a_context_at_the_cap(
    pki: _Pki, tmp_path: Path, bad: str
) -> None:
    # A context the cap holds back still gets the file checks: a restart would refuse a planted
    # CA, and would load a forged CRL that then fails every handshake it judges.
    hop = pki.outbound_hop()
    pki.crl.write_bytes(_fresher(pki, revoke=False))
    assert (first := _reload(pki, max_reloads=1)) is not None and first.reloaded == 1
    if bad == "planted-ca":
        replacement, remedy = _planted_bundle(pki, tmp_path), FIX
    else:
        signer = ec.generate_private_key(ec.SECP256R1())
        replacement = pki.crl_pem(issued=0.5 * _DAY, lasts=90 * _DAY, signer=signer)
        remedy = BAD_SIGNATURE
    pki.crl.write_bytes(replacement)

    outcome = _reload(pki, max_reloads=1)

    assert outcome is not None and outcome.refusal is not None
    assert outcome.refusal.remedy == remedy
    assert _accepts(hop, pki.server())
