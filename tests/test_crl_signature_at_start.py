# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2905: a start checks each CRL's signature, and refuses only a proven bad one.

The owner ruling of 2026-10-05: refuse at start only a CRL whose signature fails against a CA the
CRL names by key identifier. Everything short of that loads, with one warning.

What this file proves, and the instrument for each:

* **The proven case refuses, and names the setting.** ``harden_crl_check`` on a real context. The
  control is OpenSSL itself: it loads the same bytes without complaint, and then a real handshake
  fails with a signature error that does not name the CRL file.
* **Two CAs with one subject and different keys.** No test covered that before. The table runs
  every pairing of listed CAs, signing key and key identifier through the judgment and through a
  start.
* **What OpenSSL does with those files.** Real handshakes. Both CAs listed, OpenSSL takes the CRL's
  issuer from the peer's chain, whichever same-name CA the file lists first. One CA listed and the
  peer sending the renewed CA, a CRL that names no key still judges the peer. Each is one chain
  shape, measured on this interpreter's OpenSSL, not a rule about every shape.

All material is synthetic and minted here. No PHI.
"""

from __future__ import annotations

import datetime
import ssl
import weakref
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
from cryptography.x509.oid import NameOID

from messagefoundry import pki as pki_module
from messagefoundry.config import loaded_crls
from messagefoundry.config.tls_policy import (
    _UNCONFIRMED_SIGNATURE,
    TrustAnchor,
    build_verifying_client_context,
    harden_crl_check,
)
from messagefoundry.pipeline.crl_reload import BAD_SIGNATURE
from messagefoundry.pki import crl_signature_refusal, judge_crl_signatures
from tests.test_crl_reload import _ca_cert, _key_pem, _leaf
from tests.test_trust_anchor_byte_binding import _handshake

_NOW = datetime.datetime.now(datetime.UTC)
_DAY = datetime.timedelta(days=1)
_PEM = serialization.Encoding.PEM
_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-2905-twin-ca")])
_SETTING = "[tls].crl_file"
#: An issuer no hop in this file lists.
_OTHER_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-2905-unlisted-ca")])

_CaKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | dsa.DSAPrivateKey


def _ca(key: _CaKey, signer: _CaKey, *, name: x509.Name = _NAME) -> x509.Certificate:
    """A CA certificate for ``key`` named ``name``, issued under that same name by ``signer``."""
    return _ca_cert(name, key, name, signer)


def _hop(ca_file: Path, crl: Path) -> ssl.SSLContext:
    """An outbound hop whose CA file is ``ca_file``, with ``crl`` loaded as every hop loads it."""
    return build_verifying_client_context(
        TrustAnchor(cafile=str(ca_file), load_system_roots=False, crl_file=str(crl))
    )


def _crl(
    signer: _CaKey,
    *,
    names: _CaKey | None,
    revoke: int | None = None,
    name: x509.Name = _NAME,
    age: datetime.timedelta = _DAY,
) -> bytes:
    """A CRL from ``name`` issued ``age`` ago, signed by ``signer``. Its key identifier is that
    of ``names``, or it carries none. ``revoke`` is a serial number to list."""
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(_NOW - age)
        .next_update(_NOW + 30 * _DAY)
        .add_extension(x509.CRLNumber(1), False)
    )
    if names is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(names.public_key()), False
        )
    if revoke is not None:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(revoke)
            .revocation_date(_NOW - _DAY)
            .build()
        )
    return builder.sign(signer, hashes.SHA256()).public_bytes(_PEM)


@dataclass
class _Twins:
    """Two CAs with ONE subject and different keys, as a CA that renewed its key leaves behind.
    ``old`` and ``new`` are each self-signed. ``renewed`` is the new key certified by the old one,
    which a peer can send in its chain. The leaf is issued under the new key."""

    old_key: ec.EllipticCurvePrivateKey
    new_key: ec.EllipticCurvePrivateKey
    stranger: ec.EllipticCurvePrivateKey
    old_ca: Path
    new_ca: Path
    both: Path
    leaf_serial: int
    leaf_chain: Path
    leaf_alone: Path
    leaf_key: Path
    crl: Path

    def keys(self, which: str | None) -> ec.EllipticCurvePrivateKey | None:
        return {
            "old": self.old_key,
            "new": self.new_key,
            "stranger": self.stranger,
            None: None,
        }[which]

    def ca_file(self, listed: str) -> Path:
        return {"old": self.old_ca, "new": self.new_ca, "both": self.both}[listed]

    def write_crl(self, signer: str, names: str | None, *, revoke: bool = False) -> bytes:
        key = self.keys(signer)
        assert key is not None
        pem = _crl(key, names=self.keys(names), revoke=self.leaf_serial if revoke else None)
        self.crl.write_bytes(pem)
        return pem

    def hop(self, listed: str) -> ssl.SSLContext:
        """An outbound hop whose CA file is ``listed``, with the CRL loaded as every hop does."""
        return _hop(self.ca_file(listed), self.crl)

    def server(self, *, sends_renewed: bool) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.leaf_chain if sends_renewed else self.leaf_alone, self.leaf_key)
        return ctx


@pytest.fixture(autouse=True)
def _fresh_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """No held copy and no logged finding from another test, so nothing here depends on what ran
    before it. Restored after the test."""
    monkeypatch.setattr(loaded_crls, "_HELD", weakref.WeakKeyDictionary())
    monkeypatch.setattr(loaded_crls, "_UNCONFIRMED", {})


@pytest.fixture
def twins(tmp_path: Path) -> _Twins:
    old_key = ec.generate_private_key(ec.SECP256R1())
    new_key = ec.generate_private_key(ec.SECP256R1())
    old, new = _ca(old_key, old_key), _ca(new_key, new_key)
    renewed = _ca(new_key, old_key)
    leaf, leaf_key = _leaf(_NAME, new_key)
    made = _Twins(
        old_key,
        new_key,
        ec.generate_private_key(ec.SECP256R1()),
        tmp_path / "old.pem",
        tmp_path / "new.pem",
        tmp_path / "both.pem",
        leaf.serial_number,
        tmp_path / "leaf-and-renewed.pem",
        tmp_path / "leaf.pem",
        tmp_path / "leaf-key.pem",
        tmp_path / "crl.pem",
    )
    made.old_ca.write_bytes(old.public_bytes(_PEM))
    made.new_ca.write_bytes(new.public_bytes(_PEM))
    made.both.write_bytes(old.public_bytes(_PEM) + new.public_bytes(_PEM))  # the old CA first
    made.leaf_chain.write_bytes(leaf.public_bytes(_PEM) + renewed.public_bytes(_PEM))
    made.leaf_alone.write_bytes(leaf.public_bytes(_PEM))
    made.leaf_key.write_bytes(_key_pem(leaf_key))
    return made


def _ders(ca_file: Path) -> list[bytes]:
    return [
        cert.public_bytes(serialization.Encoding.DER)
        for cert in x509.load_pem_x509_certificates(ca_file.read_bytes())
    ]


def _raw_hop(ca_file: Path, crl: Path) -> ssl.SSLContext:
    """What OpenSSL does with a CRL file when the engine's checks are left out: load it, and turn
    leaf revocation checking on."""
    ctx = ssl.create_default_context(cafile=str(ca_file))
    ctx.load_verify_locations(cafile=str(crl))
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    return ctx


_WARNING = "could not confirm at start"


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if _WARNING in r.getMessage()]


# --- the refuse arm ------------------------------------------------------------------------------


def test_a_crl_that_names_a_listed_cas_key_and_is_not_signed_by_it_refuses_the_start(
    twins: _Twins,
) -> None:
    twins.write_crl("stranger", "new")  # right issuer name, right key identifier, wrong key

    # Control: OpenSSL loads the bytes without complaint. The failure comes at the handshake, and
    # its text does not name the file. This is the gap the start check closes.
    with pytest.raises(ssl.SSLError, match="signature") as at_handshake:
        _handshake(_raw_hop(twins.new_ca, twins.crl), twins.server(sends_renewed=False))
    assert twins.crl.name not in str(at_handshake.value)

    with pytest.raises(ValueError, match="does not verify the CRL's signature") as refused:
        twins.hop("new")
    text = str(refused.value)
    assert text.startswith(f"{_SETTING} ({str(twins.crl)!r})")
    assert "CRL block 1 of 1" in text and "mefor-2905-twin-ca" in text


def test_the_refusal_needs_no_named_ca_file(twins: _Twins) -> None:
    # A listener loads its CA from memory (``cadata=``), so no CA file is named anywhere. The
    # ruling of 2026-10-05 dropped the "named CA file only" condition, and so does the code.
    twins.write_crl("stranger", "new")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=twins.new_ca.read_text("ascii"))
    ctx.verify_mode = ssl.CERT_REQUIRED

    with pytest.raises(ValueError, match="does not verify the CRL's signature"):
        harden_crl_check(ctx, str(twins.crl), setting="[api].tls_client_crl_file")
    assert not ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_a_badly_signed_block_refuses_wherever_it_sits_and_logs_no_warning(
    twins: _Twins, caplog: pytest.LogCaptureFixture
) -> None:
    # Block 1 is from an issuer the hop does not list, which alone would only warn.
    twins.crl.write_bytes(
        _crl(twins.stranger, names=twins.stranger, name=_OTHER_NAME)
        + _crl(twins.stranger, names=twins.new_key)
    )
    with caplog.at_level("WARNING"), pytest.raises(ValueError, match="CRL block 2 of 2"):
        twins.hop("new")
    assert _warnings(caplog) == []


def test_a_planted_certificate_is_still_reported_as_that(twins: _Twins) -> None:
    # The file is wrong twice: a CA the hop does not trust, and a forged CRL. The BACKLOG #1890
    # refusal comes first, so the signature check cannot hide a planted trust anchor.
    planted = _ca(twins.stranger, twins.stranger, name=_NAME)
    twins.crl.write_bytes(planted.public_bytes(_PEM) + _crl(twins.stranger, names=twins.new_key))

    with pytest.raises(ValueError, match="BACKLOG #1890"):
        twins.hop("new")


# --- two CAs with one subject --------------------------------------------------------------------

#: (the CAs the hop lists, the key that signs the CRL, the key the CRL names, the judgment).
_TWIN_CASES = [
    pytest.param("both", "new", "new", "verified", id="both-listed-names-the-signer"),
    pytest.param("both", "new", None, "verified", id="both-listed-names-no-key"),
    pytest.param("both", "old", None, "verified", id="both-listed-old-key-signs"),
    pytest.param("old", "new", "new", "unlisted", id="old-listed-crl-names-the-new-key"),
    pytest.param("old", "new", None, "unproven", id="old-listed-crl-names-no-key"),
    pytest.param("both", "stranger", None, "unproven", id="both-listed-forged-names-no-key"),
    pytest.param("old", "stranger", "old", "bad", id="old-listed-forged-names-the-old-key"),
    pytest.param("both", "new", "old", "bad", id="both-listed-names-the-key-that-did-not-sign"),
]


@pytest.mark.parametrize(("listed", "signer", "names", "state"), _TWIN_CASES)
def test_two_cas_with_one_subject(
    twins: _Twins, listed: str, signer: str, names: str | None, state: str
) -> None:
    pem = twins.write_crl(signer, names)

    judged = list(judge_crl_signatures(pem, _ders(twins.ca_file(listed))))
    assert [signature.state for signature in judged] == [state]

    if state == "bad":
        with pytest.raises(ValueError, match="does not verify the CRL's signature"):
            twins.hop(listed)
    else:
        # Everything short of proof loads, and the hop checks revocation.
        assert twins.hop(listed).verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


@pytest.mark.parametrize(("listed", "signer", "names", "state"), _TWIN_CASES)
def test_the_reload_flag_follows_the_states(
    twins: _Twins, listed: str, signer: str, names: str | None, state: str
) -> None:
    # The reload's flag is wider than what a start refuses, on purpose. This pins the flag to
    # the states. That it equals what the reload returned before this change rests on the
    # older tests in tests/test_crl_reload.py, which pass unchanged.
    verdict = crl_signature_refusal(twins.write_crl(signer, names), _ders(twins.ca_file(listed)))
    expected = {"verified": None, "unlisted": False}.get(state, True)
    assert (verdict if verdict is None else verdict[1]) == expected


# --- what OpenSSL does with those files ----------------------------------------------------------


@pytest.mark.parametrize("names", ["new", None])
def test_with_both_cas_listed_openssl_takes_the_crl_issuer_from_the_peers_chain(
    twins: _Twins, names: str | None
) -> None:
    # The old CA sits first in the CA file. A check that tried only the first CA of that name
    # would call this CRL badly signed. OpenSSL does not: it judges the peer by it.
    twins.write_crl("new", names)
    _handshake(twins.hop("both"), twins.server(sends_renewed=False))  # raises if refused

    twins.write_crl("new", names, revoke=True)
    with pytest.raises(ssl.SSLError, match="revoked"):
        _handshake(twins.hop("both"), twins.server(sends_renewed=False))


def test_a_crl_that_names_no_key_judges_a_peer_whose_chain_carries_the_renewed_ca(
    twins: _Twins,
) -> None:
    # The hop lists the old CA alone. The peer sends the new key, certified by the old one. The
    # CRL is signed by the new key and names no key, so the old CA "fits" it and does not verify
    # it. This one chain shape is why that case warns and does not refuse.
    twins.write_crl("new", None)
    _handshake(twins.hop("old"), twins.server(sends_renewed=True))  # raises if refused

    twins.write_crl("new", None, revoke=True)
    with pytest.raises(ssl.SSLError, match="revoked"):
        _handshake(twins.hop("old"), twins.server(sends_renewed=True))


# --- "cannot check" is not "does not verify" -----------------------------------------------------


def test_a_key_of_another_kind_than_the_signature_is_cannot_check_not_bad(tmp_path: Path) -> None:
    # An RSA CA, and a CRL that names its key but carries an ECDSA signature. ``cryptography``
    # answers False for that pair without running a verification, so it is no proof.
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = _ca(rsa_key, rsa_key)
    pem = _crl(ec.generate_private_key(ec.SECP256R1()), names=rsa_key)
    crl = x509.load_pem_x509_crl(pem)

    assert crl.is_signature_valid(rsa_key.public_key()) is False
    assert pki_module._verifies(crl, ca) is None
    der = ca.public_bytes(serialization.Encoding.DER)
    assert [s.state for s in judge_crl_signatures(pem, [der])] == ["uncheckable"]

    (tmp_path / "ca.pem").write_bytes(ca.public_bytes(_PEM))
    (tmp_path / "crl.pem").write_bytes(pem)
    hop = _hop(tmp_path / "ca.pem", tmp_path / "crl.pem")
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF

    # Vault BACKLOG #3506. The reload holds this file back with BAD_SIGNATURE, and a start has
    # just loaded it, though the CRL names the CA's key. So that remedy may promise a start
    # refusal for the proven case only.
    verdict = crl_signature_refusal(pem, [der])
    assert verdict is not None and verdict[1] is True
    assert "only where it proves the signature bad" in BAD_SIGNATURE
    assert "names that CA's key, a start refuses" not in BAD_SIGNATURE


@pytest.mark.parametrize("error", [ValueError, TypeError])
def test_an_error_from_the_verification_is_cannot_check_and_warns(
    twins: _Twins,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    error: type[Exception],
) -> None:
    # Manager decision for this row: ``ValueError`` is the warn arm too, with ``TypeError`` and
    # ``UnsupportedAlgorithm``.
    def refuse(key: object, crl: x509.CertificateRevocationList) -> None:
        raise error("not a pair this can check")

    monkeypatch.setattr(pki_module, "_verify_with", refuse)
    pem = twins.write_crl("stranger", "new")

    judged = list(judge_crl_signatures(pem, _ders(twins.new_ca)))
    assert [signature.state for signature in judged] == ["uncheckable"]
    with caplog.at_level("WARNING"):
        hops = [twins.hop("new"), twins.hop("new")]
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)
    assert len(logged := _warnings(caplog)) == 1
    assert "cannot check its signature" in logged[0]


def test_a_ca_that_does_not_parse_is_ignored(twins: _Twins) -> None:
    pem = twins.write_crl("new", "new")
    judged = list(judge_crl_signatures(pem, [b"not a certificate", *_ders(twins.new_ca)]))
    assert [signature.state for signature in judged] == ["verified"]


# --- the warn arm: one line for the file, however many contexts load it -------------------------


def _postgres_shaped(twins: _Twins, listed: str) -> ssl.SSLContext:
    """A context built the way the Postgres store builds one per connection: nothing recorded."""
    ctx = ssl.create_default_context(cafile=str(twins.ca_file(listed)))
    harden_crl_check(ctx, str(twins.crl), setting="[store].ssl_crl_file", record_held_copy=False)
    return ctx


@pytest.mark.parametrize(
    ("signer", "names", "words"),
    [
        pytest.param("new", "new", "matched it to no CA certificate this hop lists", id="unlisted"),
        pytest.param("new", None, "a renewed CA key could explain it", id="unproven"),
    ],
)
def test_a_signature_short_of_proof_warns_once_however_many_contexts_load_the_file(
    twins: _Twins, caplog: pytest.LogCaptureFixture, signer: str, names: str | None, words: str
) -> None:
    twins.write_crl(signer, names)
    with caplog.at_level("WARNING"):
        first = twins.hop("old")
        logged = _warnings(caplog)
        # A context per connection, as the Postgres store builds them, and two more hops.
        kept = [_postgres_shaped(twins, "old") for _ in range(5)] + [twins.hop("old")] * 2

    assert len(logged) == 1 and _warnings(caplog) == logged
    assert logged[0].startswith(f"{_SETTING} ({str(twins.crl)!r})")
    assert "1 of the 1 CRL(s)" in logged[0] and words in logged[0]
    assert "CRL block 1 of 1" in logged[0] and "mefor-2905-twin-ca" in logged[0]
    assert all(ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for ctx in (first, *kept))


def test_a_file_whose_every_crl_verifies_logs_nothing(
    twins: _Twins, caplog: pytest.LogCaptureFixture
) -> None:
    # The zero here has its control in the tests above, where the same instrument counts one.
    twins.write_crl("new", "new")
    with caplog.at_level("WARNING"):
        twins.hop("both")
        twins.hop("new")
    assert _warnings(caplog) == []


def test_a_new_version_of_the_file_is_logged_again(
    twins: _Twins, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("WARNING"):
        first = twins.write_crl("new", None)
        twins.hop("old")
        twins.write_crl("new", None, revoke=True)  # other bytes, the same finding
        twins.hop("old")
        twins.hop("old")
        twins.crl.write_bytes(first)  # put back: a version this process has not just judged
        twins.hop("old")
    assert len(_warnings(caplog)) == 3


def test_a_hop_whose_ca_list_reaches_another_finding_logs_its_own_line(
    twins: _Twins, caplog: pytest.LogCaptureFixture
) -> None:
    twins.crl.write_bytes(
        _crl(twins.new_key, names=None)
        + _crl(twins.stranger, names=twins.stranger, name=_OTHER_NAME)
    )
    with caplog.at_level("WARNING"):
        twins.hop("old")  # block 1 unproven, block 2 unlisted
        twins.hop("old")
        twins.hop("both")  # block 1 verified, block 2 unlisted
        twins.hop("both")
        twins.hop("new")  # the same finding as "both"

    logged = _warnings(caplog)
    assert len(logged) == 2
    assert "2 of the 2 CRL(s)" in logged[0] and "1 of the 2 CRL(s)" in logged[1]


def test_the_warning_describes_three_crls_and_counts_the_rest(
    twins: _Twins, caplog: pytest.LogCaptureFixture
) -> None:
    blocks = b""
    for index in range(5):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"mefor-2905-unlisted-{index}")])
        blocks += _crl(twins.stranger, names=twins.stranger, name=name)
    twins.crl.write_bytes(blocks)
    with caplog.at_level("WARNING"):
        twins.hop("new")

    (line,) = _warnings(caplog)
    assert "5 of the 5 CRL(s)" in line and "and 2 more" in line
    assert "mefor-2905-unlisted-2" in line and "mefor-2905-unlisted-3" not in line


# --- round-one review repairs -------------------------------------------------------------------


def test_a_badly_signed_copy_refuses_beside_a_newer_good_crl_that_openssl_would_use(
    twins: _Twins,
) -> None:
    # Each CRL is judged on its own, as the expired-CRL refusal judges them. So this file refuses
    # at start although OpenSSL picks the newer CRL and its handshake passes. The refusal says to
    # remove the bad copy.
    twins.crl.write_bytes(
        _crl(twins.stranger, names=twins.new_key, age=3 * _DAY)
        + _crl(twins.new_key, names=twins.new_key, age=_DAY)
    )
    # Control: with the engine's checks left out, the handshake passes.
    _handshake(_raw_hop(twins.new_ca, twins.crl), twins.server(sends_renewed=False))

    with pytest.raises(ValueError, match="remove this CRL if a good one") as refused:
        twins.hop("new")
    assert "CRL block 1 of 2" in str(refused.value)


def test_a_forged_dsa_crl_that_names_the_cas_key_is_proven_bad() -> None:
    key = dsa.generate_private_key(key_size=2048)
    ca = _ca(key, key).public_bytes(serialization.Encoding.DER)

    good = _crl(key, names=key)
    forged = _crl(dsa.generate_private_key(key_size=2048), names=key)

    assert [s.state for s in judge_crl_signatures(good, [ca])] == ["verified"]
    assert [s.state for s in judge_crl_signatures(forged, [ca])] == ["bad"]


def test_a_ca_cryptography_cannot_read_is_skipped_alone(
    twins: _Twins, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Both CAs have the CRL's issuer name. Reading the old one's extensions raises an error that
    # is not a ``ValueError``. It is skipped, and the new CA still verifies the CRL.
    real = pki_module._akid_fit
    old = x509.load_pem_x509_certificate(twins.old_ca.read_bytes())

    def fit(crl: x509.CertificateRevocationList, ca: x509.Certificate) -> bool | None:
        if ca == old:
            raise x509.UnsupportedGeneralNameType("x400Address is not supported")
        return real(crl, ca)

    monkeypatch.setattr(pki_module, "_akid_fit", fit)
    pem = twins.write_crl("new", "new")

    judged = list(judge_crl_signatures(pem, _ders(twins.both)))
    assert [signature.state for signature in judged] == ["verified"]
    # Control: with only the unreadable CA listed, no CA fits.
    assert [s.state for s in judge_crl_signatures(pem, _ders(twins.old_ca))] == ["unlisted"]


def test_a_judgment_that_fails_warns_once_and_does_not_stop_the_start(
    twins: _Twins, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(crl: x509.CertificateRevocationList, ca: x509.Certificate) -> bool | None:
        raise RuntimeError("a defect in the check")

    monkeypatch.setattr(pki_module, "_verifies", broken)
    twins.write_crl("stranger", "new")  # proven bad, were the judgment to finish
    with caplog.at_level("WARNING"):
        hops = [twins.hop("new"), twins.hop("new")]

    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)
    logged = [
        r.getMessage() for r in caplog.records if "could not check the signatures" in r.getMessage()
    ]
    assert len(logged) == 1 and "RuntimeError" in logged[0]
    assert logged[0].startswith(f"{_SETTING} ({str(twins.crl)!r})")


# --- vault BACKLOG #3506: the texts claim no more than the code does ----------------------------

#: The twins' name with its ASCII letter case changed. OpenSSL folds that case when it compares
#: names, and since vault BACKLOG #3543 the engine does too.
_NAME_IN_OTHER_CASE = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MEFOR-2905-TWIN-CA")])


def _named_crl(twins: _Twins, signer: ec.EllipticCurvePrivateKey, name: x509.Name) -> bytes:
    """A CRL from ``name`` that names the twins' new key and revokes their leaf."""
    pem = _crl(signer, names=twins.new_key, name=name, revoke=twins.leaf_serial)
    twins.crl.write_bytes(pem)
    return pem


def test_a_crl_under_the_listed_cas_name_in_other_ascii_case_is_judged_by_that_ca(
    twins: _Twins, caplog: pytest.LogCaptureFixture
) -> None:
    """Vault BACKLOG #3543 item 2, and the remainder of #2905 closing item 1. The hop lists a CA
    whose subject differs from the CRL's issuer name only in ASCII letter case, and the CRL names
    that CA's key. The engine now takes that CA for the issuer, as OpenSSL does."""
    server = twins.server(sends_renewed=False)

    pem = _named_crl(twins, twins.new_key, _NAME_IN_OTHER_CASE)
    assert [s.state for s in judge_crl_signatures(pem, _ders(twins.new_ca))] == ["verified"]
    assert crl_signature_refusal(pem, _ders(twins.new_ca)) is None
    with caplog.at_level("WARNING"):
        hop = twins.hop("new")
    assert _warnings(caplog) == []
    # The premise, on this interpreter's OpenSSL: it takes that CA for the CRL's issuer, and
    # judges the peer by the CRL. Control: the next CRL, from the exact name, revokes nothing.
    with pytest.raises(ssl.SSLError, match="revoked"):
        _handshake(hop, server)
    twins.write_crl("new", "new")
    _handshake(twins.hop("new"), server)  # raises if refused

    # The badly signed one: proven bad, so the start refuses it. Before #3543 it started with a
    # warning. Control: OpenSSL loads the same bytes and then fails the handshake.
    pem = _named_crl(twins, twins.stranger, _NAME_IN_OTHER_CASE)
    assert [s.state for s in judge_crl_signatures(pem, _ders(twins.new_ca))] == ["bad"]
    with pytest.raises(ssl.SSLError, match="CRL signature failure"):
        _handshake(_raw_hop(twins.new_ca, twins.crl), server)
    with pytest.raises(ValueError, match="does not verify the CRL's signature"):
        twins.hop("new")
    verdict = crl_signature_refusal(pem, _ders(twins.new_ca))
    assert verdict is not None and verdict[1] is True  # the reload's BAD_SIGNATURE case


def test_an_akid_issuer_name_in_other_ascii_case_still_fits_the_ca(twins: _Twins) -> None:
    """The second name test inside "fits": a CRL's authority key identifier may carry the CA's
    issuer name and serial too, and OpenSSL compares that name by the same canonical form. So
    the engine folds ASCII case there as well, and a badly signed CRL of that kind is proven
    bad. Control: OpenSSL fits that CA and fails the handshake on the signature."""
    new_ca = x509.load_pem_x509_certificate(twins.new_ca.read_bytes())
    akid = x509.AuthorityKeyIdentifier(
        x509.SubjectKeyIdentifier.from_public_key(twins.new_key.public_key()).digest,
        [x509.DirectoryName(_NAME_IN_OTHER_CASE)],
        new_ca.serial_number,
    )
    pem = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_NAME)
        .last_update(_NOW - _DAY)
        .next_update(_NOW + 30 * _DAY)
        .add_extension(x509.CRLNumber(1), False)
        .add_extension(akid, False)
        .sign(twins.stranger, hashes.SHA256())
        .public_bytes(_PEM)
    )
    twins.crl.write_bytes(pem)

    assert [s.state for s in judge_crl_signatures(pem, _ders(twins.new_ca))] == ["bad"]
    with pytest.raises(ssl.SSLError, match="CRL signature failure"):
        _handshake(_raw_hop(twins.new_ca, twins.crl), twins.server(sends_renewed=False))
    with pytest.raises(ValueError, match="does not verify the CRL's signature"):
        twins.hop("new")


#: Names OpenSSL does NOT take for the twins' ``mefor-2905-twin-ca``. One differs in a letter. The
#: other is the twins' name made of non-ASCII letters, Cyrillic look-alikes in capitals: RFC 5280
#: would fold their case, but OpenSSL folds ASCII alone, and so does the engine.
_GENUINELY_OTHER = [
    pytest.param("mefor-2905-twin-cb", id="another-letter"),
    pytest.param("mefor-2905-twin-СА", id="non-ascii-capitals"),
]


@pytest.mark.parametrize("common_name", _GENUINELY_OTHER)
def test_a_name_that_genuinely_differs_is_still_unlisted(
    twins: _Twins, caplog: pytest.LogCaptureFixture, common_name: str
) -> None:
    """The fold must loosen nothing else. A CRL that names the listed CA's key, badly signed,
    under a name OpenSSL takes for another issuer, stays ``unlisted``: it warns at a start and
    never refuses it."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    pem = _named_crl(twins, twins.stranger, name)

    assert [s.state for s in judge_crl_signatures(pem, _ders(twins.new_ca))] == ["unlisted"]
    with caplog.at_level("WARNING"):
        hop = twins.hop("new")  # loads: no proof
    (line,) = _warnings(caplog)
    assert _UNCONFIRMED_SIGNATURE["unlisted"] in line
    verdict = crl_signature_refusal(pem, _ders(twins.new_ca))
    assert verdict is not None and verdict[1] is False  # the reload's NO_ISSUER case
    # The reload gives the same state the same words, so the two cannot drift apart.
    assert _UNCONFIRMED_SIGNATURE["unlisted"] in verdict[0]
    # The premise: OpenSSL finds no CRL for the leaf's issuer in this file, so it does not judge
    # the peer by it, and a leaf-checking hop fails for want of one, not on the signature.
    with pytest.raises(ssl.SSLError, match="unable to get certificate CRL"):
        _handshake(hop, twins.server(sends_renewed=False))


def test_a_name_that_differs_only_in_white_space_is_unlisted_though_openssl_matches_it(
    twins: _Twins, caplog: pytest.LogCaptureFixture
) -> None:
    """The residual :func:`messagefoundry.pki._issuer_name_key` names, measured. OpenSSL drops
    white space around a value when it compares names, and the engine does not. So this CRL reads
    ``unlisted`` and starts with the warning, while OpenSSL judges the peer by it. The words of
    that warning say the engine compares white space, so they stay true here."""
    spaced = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, " mefor-2905-twin-ca ")])
    pem = _named_crl(twins, twins.stranger, spaced)

    assert [s.state for s in judge_crl_signatures(pem, _ders(twins.new_ca))] == ["unlisted"]
    with caplog.at_level("WARNING"):
        hop = twins.hop("new")
    (line,) = _warnings(caplog)
    words = _UNCONFIRMED_SIGNATURE["unlisted"]
    assert words in line and "white space exactly" in words
    with pytest.raises(ssl.SSLError, match="CRL signature failure"):
        _handshake(hop, twins.server(sends_renewed=False))


_SHA256_WITH_RSA = bytes.fromhex("06092a864886f70d01010b")
_SHA1_WITH_RSA = bytes.fromhex("06092a864886f70d010105")
_SHA384_WITH_RSA = bytes.fromhex("06092a864886f70d01010c")


def _resigned(
    pem: bytes, signer: rsa.RSAPrivateKey, oid: bytes, digest: hashes.HashAlgorithm
) -> bytes:
    """``pem``, an RSA SHA-256 CRL, signed again by ``signer`` under another digest. The builder
    refuses SHA-1. So the two algorithm identifiers are swapped by hand for ``oid``, which has
    the same length, and the signature is replaced."""
    der = x509.load_pem_x509_crl(pem).public_bytes(serialization.Encoding.DER)
    assert der.count(_SHA256_WITH_RSA) == 2
    der = der.replace(_SHA256_WITH_RSA, oid)
    body = x509.load_der_x509_crl(der).tbs_certlist_bytes
    try:
        signature = signer.sign(body, padding.PKCS1v15(), digest)
    except UnsupportedAlgorithm:
        pytest.skip(f"this build cannot sign with {digest.name}, so the CRL cannot be minted")
    return x509.load_der_x509_crl(der[: -len(signature)] + signature).public_bytes(_PEM)


def test_an_rsa_sha1_crl_the_ca_signed_is_cannot_check_and_a_forged_one_is_bad(
    tmp_path: Path,
) -> None:
    """A CRL that names the CA's key and that the reload holds back, while a start loads it. The
    reload's remedy used to say a start refuses such a file. The SHA-384 CRL is the control for
    the hand-made encoding: the same swap under a digest the library accepts reads ``verified``.
    So ``uncheckable`` is about SHA-1, not about the swap."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = _ca(key, key)
    ders = [ca.public_bytes(serialization.Encoding.DER)]

    good = _resigned(_crl(key, names=key), key, _SHA1_WITH_RSA, hashes.SHA1())
    forged = _resigned(_crl(other, names=key), other, _SHA1_WITH_RSA, hashes.SHA1())
    control = _resigned(_crl(key, names=key), key, _SHA384_WITH_RSA, hashes.SHA384())

    assert [s.state for s in judge_crl_signatures(control, ders)] == ["verified"]
    assert [s.state for s in judge_crl_signatures(good, ders)] == ["uncheckable"]
    assert [s.state for s in judge_crl_signatures(forged, ders)] == ["bad"]
    verdict = crl_signature_refusal(good, ders)
    assert verdict is not None and verdict[1] is True  # the reload's BAD_SIGNATURE case

    ca_file, crl_file = tmp_path / "ca.pem", tmp_path / "crl.pem"
    ca_file.write_bytes(ca.public_bytes(_PEM))
    crl_file.write_bytes(good)
    assert _hop(ca_file, crl_file).verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    crl_file.write_bytes(forged)
    with pytest.raises(ValueError, match="does not verify the CRL's signature"):
        _hop(ca_file, crl_file)


def test_a_version_that_logs_nothing_in_between_does_not_reset_the_record(
    twins: _Twins, caplog: pytest.LogCaptureFixture
) -> None:
    # The record is touched only when there is a line to log. So a version that verifies, or
    # one that is refused, leaves it alone, and the first version is not logged again. The
    # control is the A, B, A test above, where the version in between warns and the count is 3.
    with caplog.at_level("WARNING"):
        first = twins.write_crl("new", None)  # unproven on a hop that lists the old CA
        twins.hop("old")
        twins.write_crl("old", "old")  # verifies
        twins.hop("old")
        twins.write_crl("stranger", "old")  # proven bad
        with pytest.raises(ValueError, match="does not verify the CRL's signature"):
            twins.hop("old")
        twins.crl.write_bytes(first)
        twins.hop("old")
    assert len(_warnings(caplog)) == 1


def test_a_crl_that_reaches_a_hop_through_its_ca_file_alone_is_not_signature_checked(
    twins: _Twins, tmp_path: Path
) -> None:
    """The start check judges the bytes of the CRL setting's file and nothing else. A forged CRL
    that names the listed CA's key refuses the start from the CRL setting, and loads from the CA
    file. It is in use there: the handshake fails on it."""
    forged = _crl(twins.stranger, names=twins.new_key)
    bundle = tmp_path / "ca-and-crl.pem"
    bundle.write_bytes(twins.new_ca.read_bytes() + forged)
    # The CRL setting holds another issuer's CRL, which only turns revocation checking on.
    twins.crl.write_bytes(_crl(twins.stranger, names=twins.stranger, name=_OTHER_NAME))

    hop = _hop(bundle, twins.crl)  # builds: the forged CRL in the CA file is not judged
    assert hop.cert_store_stats()["crl"] == 2
    with pytest.raises(ssl.SSLError, match="CRL signature failure"):
        _handshake(hop, twins.server(sends_renewed=False))

    # Controls. The same CRL in the CRL setting refuses. So does the same CA file once a CRL
    # setting names it, which is why the guide says "through its CA file alone".
    twins.crl.write_bytes(forged)
    with pytest.raises(ValueError, match="does not verify the CRL's signature"):
        twins.hop("new")
    with pytest.raises(ValueError, match="does not verify the CRL's signature"):
        _hop(bundle, bundle)
