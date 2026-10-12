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
    monkeypatch.setattr(crl_reload, "_LABELS", {})


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


def _reload(
    pki: _Pki, *, max_reloads: int = MAX_RELOADS, now: float | None = None
) -> ReloadOutcome | None:
    """One pass, reduced to this test's file. The fixture empties the registry per test, and
    collecting first drops this test's own contexts that are gone. ``now`` is the clock the pass
    judges by, for a test that needs time to have passed."""
    gc.collect()
    outcomes = reload_replaced_crls(max_reloads=max_reloads, now=now)
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


def _planted_ca(tmp_path: Path) -> _Pki:
    """A second CA, which no hop trusts unless a test gives it that CA's certificate."""
    (tmp_path / "planted").mkdir()
    return _make_pki(tmp_path / "planted", "mefor-299-planted-ca")


def _planted_bundle(pki: _Pki, tmp_path: Path) -> bytes:
    return _planted_ca(tmp_path).ca_pem + _fresher(pki)


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


def _listener_holding(pki: _Pki, setting: str) -> ssl.SSLContext:
    ctx = pki.server()
    ctx.load_verify_locations(cadata=pki.ca_pem.decode("ascii"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    harden_crl_check(ctx, str(pki.crl), setting=setting)
    return ctx


def test_a_refusal_for_a_shared_crl_names_the_path_not_one_holder(pki: _Pki) -> None:
    """Vault BACKLOG #1997: inbound listeners now record their connection's ``tls_crl_file``, so two
    listeners sharing one CRL hold two settings. The refusal names the file by its path, not
    whichever listener the pass met first. Red against the first-holder rule, which named 'b-in'."""
    hops = [
        _listener_holding(pki, "inbound connection 'b-in' tls_crl_file"),
        _listener_holding(pki, "inbound connection 'a-in' tls_crl_file"),
    ]
    pki.crl.write_bytes(pki.crl_pem(issued=10 * _DAY, lasts=-_DAY))
    outcome = _reload(pki)
    assert outcome is not None and outcome.refusal is not None
    reason = outcome.refusal.reason
    assert f"CRL file {str(pki.crl)!r}" in reason, reason
    assert "a-in" not in reason and "b-in" not in reason, reason
    assert len(hops) == 2  # both contexts stay alive, so both hold the file during the pass


def test_a_refusal_for_one_holder_names_its_setting(pki: _Pki) -> None:
    """The control: one listener's CRL refusal still leads with that listener's setting."""
    hop = _listener_holding(pki, "inbound connection 'a-in' tls_crl_file")
    pki.crl.write_bytes(pki.crl_pem(issued=10 * _DAY, lasts=-_DAY))
    outcome = _reload(pki)
    assert outcome is not None and outcome.refusal is not None
    assert "inbound connection 'a-in' tls_crl_file" in outcome.refusal.reason
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


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
    future = pki.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True)
    pki.crl.write_bytes(_planted_ca(tmp_path).ca_pem + future)

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


# --- vault BACKLOG #2866 item 1: a start that cannot stage its private copy -----------------------


def _fail_mkdtemp(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(prefix: str) -> str:
        raise PermissionError(13, "Permission denied", f"C:/tmp/{prefix}random")

    monkeypatch.setattr(tempfile, "mkdtemp", fail)


def _fail_the_private_write(monkeypatch: pytest.MonkeyPatch) -> None:
    real = Path.write_bytes

    def fail(self: Path, data: bytes) -> int:
        if self.parent.name.startswith("mefor-crl-"):
            raise OSError(28, "No space left on device", str(self))
        return real(self, data)

    monkeypatch.setattr(Path, "write_bytes", fail)


def _scratch_load_raises(monkeypatch: pytest.MonkeyPatch, exc: OSError) -> None:
    """Make OpenSSL's read of the private copy raise ``exc``."""

    def fail(crl_file: str, blocks: object, *, label: str) -> ssl.SSLContext:
        raise exc

    monkeypatch.setattr(tls_policy_module, "crl_scratch_context", fail)


def _fail_the_private_read(monkeypatch: pytest.MonkeyPatch) -> None:
    gone = FileNotFoundError(2, "No such file or directory", "C:/tmp/mefor-crl-random/crl.pem")
    _scratch_load_raises(monkeypatch, gone)


@pytest.mark.parametrize(
    ("fail", "why"),
    [
        (_fail_mkdtemp, "Permission denied"),
        (_fail_the_private_write, "No space left on device"),
        (_fail_the_private_read, "No such file or directory"),
    ],
    ids=["mkdtemp", "write", "read"],
)
def test_a_start_that_cannot_stage_its_private_copy_is_a_refusal_that_names_the_file(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, fail: object, why: str
) -> None:
    # The private copy is staged only on a context that already holds a CRL, as a built hop does.
    hop = pki.outbound_hop()
    harden_crl_check(hop, str(pki.crl), setting="[tls].crl_file")  # control: a second load passes
    assert callable(fail)
    fail(monkeypatch)

    with pytest.raises(ValueError, match="private copy") as refused:
        harden_crl_check(hop, str(pki.crl), setting="[tls].crl_file")

    said = str(refused.value)
    assert said.startswith(f"[tls].crl_file ({str(pki.crl)!r})")  # the setting and the file
    assert why in said
    assert "mefor-crl-" not in said  # never the random path, as the reload's reason leaves it out
    # Still an OSError, so a caller that carries on or retries on one does what it did before.
    assert isinstance(refused.value, OSError)
    assert isinstance(refused.value.__cause__, OSError)


def test_an_openssl_error_on_the_private_copy_is_not_reworded_as_a_staging_failure(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ``ssl.SSLError`` is an ``OSError``. It is about the bytes, so it must not read as a full disk.
    hop = pki.outbound_hop()
    unreadable = ssl.SSLError(ssl.SSL_ERROR_SSL, "[X509] no certificate or crl found")
    _scratch_load_raises(monkeypatch, unreadable)

    with pytest.raises(ssl.SSLError, match="no certificate or crl found") as passed:
        harden_crl_check(hop, str(pki.crl), setting="[tls].crl_file")
    assert passed.value is unreadable and not isinstance(passed.value, ValueError)


# --- vault BACKLOG #2866 item 2: a BEGIN marker inside a comment still refuses the file -----------


def test_a_begin_marker_inside_a_comment_line_refuses_the_file_and_says_why(
    pki: _Pki, tmp_path: Path
) -> None:
    # Kept on purpose: OpenSSL loads this file's one CRL, and the engine refuses the file anyway.
    # ``judge_every_crl`` records why, where it counts the markers.
    crl = pki.crl.read_bytes()
    commented = b"# the -----BEGIN X509 CRL----- block below is the root CRL\n" + crl
    assert _openssl_count(tmp_path, commented) == 1
    # Control: a comment line without the marker is judged, so the marker is what refuses.
    assert len(judge_every_crl(b"# the block below is the root CRL\n" + crl, now=time.time())) == 1

    with pytest.raises(ValueError, match="does not start a line") as refused:
        judge_every_crl(commented, now=time.time())
    assert "cannot tell it from a CRL" in str(refused.value)  # the reason, in the refusal itself

    pki.crl.write_bytes(commented)
    with pytest.raises(ValueError, match="inside a comment"):
        pki.outbound_hop()


# --- vault BACKLOG #2866 items 3 and 4: a refusal that holds still across passes -------------------


def _refusals_logged(caplog: pytest.LogCaptureFixture) -> int:
    return sum("refused to apply" in r.getMessage() for r in caplog.records)


def _assert_refused_for_good(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Two passes over the file as it is now. The first refuses it as a file to fix, for good. The
    second hands that refusal back without judging the bytes again, and logs nothing more."""
    judged: list[int] = []
    real = tls_policy_module.judge_crl_bytes

    def spy(pem: bytes, **kwargs: object) -> object:
        judged.append(len(pem))
        return real(pem, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(crl_reload, "judge_crl_bytes", spy)
    caplog.clear()  # a control pass before this one logged its own refusal
    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        first, second = _reload(pki), _reload(pki)

    assert first is not None and first.refusal is not None
    assert first.refusal.remedy == FIX and first.refusal.sticky
    assert second is not None and second.refusal == first.refusal
    assert len(judged) == 1  # the second pass did not judge the same bytes again
    assert _refusals_logged(caplog) == 1


def test_a_file_openssl_cannot_load_is_refused_for_good_beside_a_copy_that_lapses_first(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # No context can ever take a file OpenSSL will not load. The hop's copy also lapses before the
    # file's CRL takes effect, which is recorded first and which time can lift. Red before the
    # fix: that second refusal alone made the pass judge the same bytes again every minute.
    hop = pki.outbound_hop()
    late = pki.crl_pem(issued=-7 * _DAY, lasts=60 * _DAY, revoke=True)
    pki.crl.write_bytes(late)
    lapses = _reload(pki)
    # Control: with a file OpenSSL loads, these dates give the refusal that time can lift.
    assert lapses is not None and lapses.refusal is not None
    assert lapses.refusal.remedy == LAPSES_FIRST and not lapses.refusal.sticky

    pki.crl.write_bytes(late.replace(b"-----END X509 CRL", b" -----END X509 CRL"))
    _assert_refused_for_good(pki, monkeypatch, caplog)
    assert _accepts(hop, pki.server())


def test_a_context_that_waits_and_also_fails_a_file_check_is_refused_for_good(
    pki: _Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The file's CRL is not in effect yet, and it carries a certificate the hop does not trust.
    # Waiting cannot help this hop: once the wait lifts, the certificate still refuses the file.
    # Red before the fix, which left the pass open because a wait had been recorded.
    hop = pki.outbound_hop()
    future = pki.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True)
    pki.crl.write_bytes(future)
    waits = _reload(pki)
    # Control: without the certificate, the same CRL is a plain wait, retried every pass.
    assert waits is not None and waits.refusal is not None
    assert waits.refusal.remedy == WAIT and not waits.refusal.sticky

    pki.crl.write_bytes(_planted_ca(tmp_path).ca_pem + future)
    _assert_refused_for_good(pki, monkeypatch, caplog)
    assert _accepts(hop, pki.server())


def test_a_file_check_on_one_context_keeps_the_pass_open_for_one_that_only_waits(
    pki: _Pki, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Two hops hold the file. ``strict`` does not trust the certificate it carries, which no wait
    # lifts. ``trusting`` does, so only time holds it back, and it must get the file once the CRL
    # takes effect. A fix refusal that closed the pass whatever else it held would never give it
    # the file: the pass would hand back the first refusal for good.
    planted = _planted_ca(tmp_path)
    both = tmp_path / "both.pem"
    both.write_bytes(pki.ca_pem + planted.ca_pem)
    strict = pki.outbound_hop()
    trusting = build_verifying_client_context(
        TrustAnchor(cafile=str(both), load_system_roots=False, crl_file=str(pki.crl))
    )
    old = crl_fingerprint(pki.crl.read_bytes())
    pki.crl.write_bytes(planted.ca_pem + pki.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True))
    new = crl_fingerprint(pki.crl.read_bytes())

    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        waiting = _reload(pki)
        # Two days on, the CRL is in effect and both held copies are still in date.
        later = _reload(pki, now=time.time() + (2 * _DAY).total_seconds())

    assert waiting is not None and waiting.reloaded == 0 and waiting.refusal is not None
    assert waiting.refusal.remedy == FIX and not waiting.refusal.sticky
    assert later is not None and later.reloaded == 1
    assert sorted(held.fingerprint for held in held_crl_copies(pki.crl)) == sorted([old, new])
    # Only ``strict`` is left, refused for good, with the reason it had while the other waited.
    assert later.refusal == replace(waiting.refusal, sticky=True)
    assert _refusals_logged(caplog) == 1
    assert strict.verify_flags & trusting.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_only_a_refusal_that_stops_a_context_or_is_reported_keeps_a_pass_open() -> None:
    def sticky(*recorded: tuple[str, bool]) -> bool:
        refusals = crl_reload._Refusals()
        for remedy, stops in recorded:
            refusals.add("why", remedy, stops=stops)
        return refusals.sticky

    assert sticky((FIX, True))  # control: a file to fix, alone
    # A refusal time can lift, recorded beside a file check that stops the context for good.
    assert sticky((LAPSES_FIRST, False), (FIX, True))
    assert sticky((WAIT, False), (BAD_SIGNATURE, True))
    # A hop at the cap whose copy lapses first, beside a hop that fails a file check. A restart
    # stops the first whenever the lapse ends, and the file to fix is what is reported.
    assert sticky((LAPSES_FIRST, False), (RESTART, True), (FIX, True))
    # Another context is stopped by the wait alone, so the pass stays open for it.
    assert not sticky((WAIT, False), (FIX, True), (WAIT, True))
    assert not sticky((RESTART, False), (NO_ISSUER, True))
    # The refusal reported is one time can lift, though a restart is what stops the context.
    assert not sticky((LAPSES_FIRST, False), (RESTART, True))


# --- vault BACKLOG #3099 item 2: a retried refusal keeps its label --------------------------------


def _holder(pki: _Pki, ca_file: Path, name: str) -> ssl.SSLContext:
    """A hop that trusts ``ca_file`` and holds ``pki``'s CRL under a setting that names it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(ca_file))
    harden_crl_check(ctx, str(pki.crl), setting=f"outbound connection '{name}' tls_crl_file")
    return ctx


@pytest.mark.parametrize("held_back_by", [RETRY, NO_ISSUER], ids=["a-defect", "unlisted-issuer"])
def test_a_retried_refusal_keeps_its_label_once_another_holder_takes_the_file(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, held_back_by: str
) -> None:
    """Two hops with different settings share one CRL. The first pass brings one current and
    refuses the other, and names the file by its path, since the two settings differ. Red before
    the fix: the second pass read the label from the one hop still stale, so it led with that
    hop's setting, the reason changed, and the refusal was logged again."""
    pki, both = _make_intermediate_pki(tmp_path)
    taker = _holder(pki, both, "takes-it")
    # The root alone cannot verify the intermediate's CRL, which the reload retries every pass.
    refused = _holder(pki, pki.ca_file if held_back_by == NO_ISSUER else both, "refused")
    if held_back_by == RETRY:

        def boom(binary_form: bool = False) -> list[bytes]:
            raise RuntimeError("a defect in one context")

        refused.get_ca_certs = boom  # type: ignore[method-assign, assignment]
    pki.crl.write_bytes(_fresher(pki))

    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        first, second = _reload(pki), _reload(pki)

    assert first is not None and first.reloaded == 1 and first.refusal is not None
    assert first.refusal.remedy == held_back_by and not first.refusal.sticky
    assert f"CRL file {str(pki.crl)!r}" in first.refusal.reason, first.refusal.reason
    assert "takes-it" not in first.refusal.reason and "'refused'" not in first.refusal.reason
    # The same bytes, judged again with one holder now current: the same refusal, logged once.
    assert second is not None and (second.reloaded, second.refusal) == (0, first.refusal)
    assert _refusals_logged(caplog) == 1
    assert taker.verify_flags & refused.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_retried_refusal_keeps_its_label_while_a_short_lived_holder_comes_and_goes(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """One hop is refused and names its setting. A context built later from the file as it is
    now, under another setting, holds the file for a while and is then collected, as a context
    built for one send is. Neither changes the label. Red against a label read from every holder
    on each pass, which turned into the path while that context lived and back when it went."""
    pki, both = _make_intermediate_pki(tmp_path)
    refused = _holder(pki, pki.ca_file, "refused")
    pki.crl.write_bytes(_fresher(pki))

    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        first = _reload(pki)
        passing = _holder(pki, both, "passing")  # current from the start: it read the new file
        beside = _reload(pki)
        del passing
        after = _reload(pki)

    assert first is not None and first.refusal is not None
    assert first.refusal.remedy == NO_ISSUER
    assert "outbound connection 'refused' tls_crl_file" in first.refusal.reason
    assert beside is not None and beside.refusal == first.refusal
    assert after is not None and after.refusal == first.refusal
    assert _refusals_logged(caplog) == 1
    assert refused.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_bytes_put_back_after_a_change_are_named_by_the_hops_that_hold_the_file_now(
    pki: _Pki,
) -> None:
    # The kept label lasts as long as its refusal. Here the refused file is taken away, the hop
    # that held it goes, and two others load the file. The same bytes put back must be named by
    # the two hops stale now, so by the path. Red while the label outlived the refusal: it still
    # read "outbound connection 'gone' tls_crl_file", a setting no hop had any more.
    original = pki.crl.read_bytes()
    future = pki.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True)
    gone = _holder(pki, pki.ca_file, "gone")
    pki.crl.write_bytes(future)
    first = _reload(pki)
    assert first is not None and first.refusal is not None
    assert "outbound connection 'gone' tls_crl_file" in first.refusal.reason  # control

    pki.crl.write_bytes(original)
    assert _reload(pki) is None  # every holder is current again, so the refusal is dropped
    del gone
    hops = [_holder(pki, pki.ca_file, "one"), _holder(pki, pki.ca_file, "two")]
    pki.crl.write_bytes(future)
    again = _reload(pki)

    assert again is not None and again.refusal is not None
    assert again.refusal.fingerprint == first.refusal.fingerprint  # the same bytes
    assert f"CRL file {str(pki.crl)!r}" in again.refusal.reason, again.refusal.reason
    assert "'gone'" not in again.refusal.reason
    assert len(hops) == 2  # both contexts stay alive, so both hold the file during the pass
