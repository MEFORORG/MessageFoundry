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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID

from messagefoundry import pki as pki_module
from messagefoundry.config import loaded_crls
from messagefoundry.config.tls_policy import (
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


def test_the_unlisted_warning_is_true_of_a_listed_ca_whose_name_differs_only_in_case(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The engine compares names exactly and OpenSSL folds case. So a listed CA can have the
    CRL's issuer name, as OpenSSL reads it, and the key the CRL names, and still read
    ``unlisted``. The warning used to say no listed CA "has that name", which is the wrong cause
    here. This pins the words, not the matching: if the matching ever folds case, change both."""
    key = ec.generate_private_key(ec.SECP256R1())
    listed = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-3506-Case-CA")])
    lower = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-3506-case-ca")])
    ca = _ca(key, key, name=listed)
    leaf, leaf_key = _leaf(listed, key)
    ca_file, crl_file = tmp_path / "ca.pem", tmp_path / "crl.pem"
    ca_file.write_bytes(ca.public_bytes(_PEM))
    (tmp_path / "leaf.pem").write_bytes(leaf.public_bytes(_PEM))
    (tmp_path / "leaf-key.pem").write_bytes(_key_pem(leaf_key))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(tmp_path / "leaf.pem", tmp_path / "leaf-key.pem")

    pem = _crl(key, names=key, name=lower, revoke=leaf.serial_number)
    crl_file.write_bytes(pem)
    der = ca.public_bytes(serialization.Encoding.DER)
    assert [s.state for s in judge_crl_signatures(pem, [der])] == ["unlisted"]

    with caplog.at_level("WARNING"):
        hop = _hop(ca_file, crl_file)
    (line,) = _warnings(caplog)
    assert "matched it to no CA certificate this hop lists" in line
    assert "letter case included" in line
    assert "has that name" not in line

    # The premise, on this interpreter's OpenSSL: it takes that CA for the CRL's issuer, and
    # judges the peer by the CRL. Control: the same hop passes with a CRL that revokes nothing.
    with pytest.raises(ssl.SSLError, match="revoked"):
        _handshake(hop, server)
    crl_file.write_bytes(_crl(key, names=key, name=lower))
    _handshake(_hop(ca_file, crl_file), server)  # raises if refused


def test_the_reload_reason_for_an_unlisted_issuer_uses_the_start_warnings_words(
    twins: _Twins,
) -> None:
    # One cause, one set of words: the reload's reason must stay true of the case above too.
    verdict = crl_signature_refusal(twins.write_crl("new", "new"), _ders(twins.old_ca))
    assert verdict is not None and verdict[1] is False
    assert "matched it to no CA certificate this hop lists" in verdict[0]
    assert "letter case included" in verdict[0]
    assert "names no CA certificate" not in verdict[0]


def test_the_reload_remedy_promises_a_start_refusal_only_for_the_proven_case(
    tmp_path: Path,
) -> None:
    """The remedy used to say a start refuses the file "where the CRL names that CA's key". This
    is a file where that is false: the CRL names the RSA CA's key and carries an ECDSA signature.
    The reload holds it back with this remedy, and a start loads it."""
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = _ca(rsa_key, rsa_key)
    pem = _crl(ec.generate_private_key(ec.SECP256R1()), names=rsa_key)
    (tmp_path / "ca.pem").write_bytes(ca.public_bytes(_PEM))
    (tmp_path / "crl.pem").write_bytes(pem)

    verdict = crl_signature_refusal(pem, [ca.public_bytes(serialization.Encoding.DER)])
    assert verdict is not None and verdict[1] is True  # the reload's BAD_SIGNATURE case
    assert _hop(tmp_path / "ca.pem", tmp_path / "crl.pem").verify_flags & ssl.VERIFY_CRL_CHECK_LEAF

    assert "only where it proves the signature bad" in BAD_SIGNATURE
    assert "a signature the engine cannot check" in BAD_SIGNATURE
    assert "Where the CRL names that CA's key, a start refuses the file too" not in BAD_SIGNATURE


#: Sentences ``docs/CONFIGURATION.md`` carried and the code does not bear out (vault BACKLOG
#: #3506). Each is matched with runs of white space folded, as a reader sees the paragraph.
_RETRACTED_DOC_CLAIMS = (
    # Not when the engine cannot check with that key, nor when the name differs only in case.
    "A start refuses it when the CRL names the CA's key and that key did not sign it",
    # A version that returns is logged again; the A, B, A test above counts three lines.
    "logged once per engine process for each version of the file",
)


def test_the_configuration_guide_does_not_make_the_retracted_claims() -> None:
    guide = Path(__file__).resolve().parents[1] / "docs" / "CONFIGURATION.md"
    text = " ".join(guide.read_text(encoding="utf-8").split())
    # Control: this is the guide, and it still has the paragraph these claims sat in.
    assert "A start checks each CRL's signature too" in text
    assert "an earlier version that returns is logged again" in text
    assert "The engine never checks their signatures" in text
    for claim in _RETRACTED_DOC_CLAIMS:
        assert claim not in text, claim
