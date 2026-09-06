# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the `vault_transit` store cipher (store/crypto_transit.py, ADR 0138, ASVS 13.3.3).

Two layers:
  * **Fake-Transit unit tests** (always run, no live server): a local AES-GCM stand-in that binds
    `associated_data` exactly as OpenBao Transit does, so the `mfenc:v3` round-trip, the cell-AAD binding
    (a v3 blob moved to another cell fails closed), the keyless-audit contract, and every fail-closed path
    are exercised with NO live Vault — mirroring `test_keyprovider_vault.py`.
  * **Live OpenBao integration** (gated on `MEFOR_STORE_TRANSIT_KEY` + `MEFOR_STORE_VAULT_ADDR`): proves
    the real `open_store` seam routes through Transit and lands a DEK-FREE `mfenc:v3` value at rest —
    the property 13.3.3 is about. Deferred to a run with a `bao server -dev` + transit engine (like the
    SQL Server / Postgres legs); skipped in a bare CI checkout.
"""

from __future__ import annotations

import base64
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import crypto_transit
from messagefoundry.store.base import build_store_cipher
from messagefoundry.store.crypto import Cipher, CipherError, cell_aad
from messagefoundry.store.crypto_transit import TransitCipher, build_transit_cipher
from messagefoundry.store.keyprovider import KeyProviderError
from messagefoundry.store.store import MessageStore

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
_KEY_NAME = "mefor-store"


# --- a faithful local stand-in for OpenBao Transit ------------------------------------------------
# It performs REAL AES-GCM with `associated_data` as the GCM AAD, so cell-mismatch fails exactly like the
# live engine — the whole point of the cell-binding test. Ciphertext carries the `vault:v1:` prefix.


class _FakeTransit:
    def __init__(self) -> None:
        import hashlib
        import hmac

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._aes = AESGCM(b"\x00" * 32)  # a fixed fake data key held "inside the module"
        # A fixed per-key fake HMAC secret held "inside the module" — like Transit's generate_hmac, the
        # secret never leaves here; callers only ever see the resulting `vault:v1:` MAC string.
        self._hmac_secret = {"mefor-store": b"\x11" * 32, "mefor-audit": b"\x22" * 32}
        self._hmac = hmac
        self._hashlib = hashlib
        self.encrypts = 0
        # Per-key-name type override for the BACKLOG #1166 key-type checks; anything unnamed reports
        # the type a correctly provisioned store key has.
        self.key_types: dict[str, str] = {}
        self.read_calls: list[str] = []

    def read_key(self, *, name: str) -> dict[str, Any]:
        self.read_calls.append(name)
        return {"data": {"name": name, "type": self.key_types.get(name, "aes256-gcm96")}}

    def generate_hmac(
        self, *, name: str, hash_input: str, algorithm: str = "sha2-256", **_: Any
    ) -> dict[str, Any]:
        # Deterministic keyed MAC over the raw input, keyed by the module-held per-key secret — mirrors
        # Transit `generate_hmac`: same input+key ⇒ same MAC (round-trips at verify), different input or
        # a wrong key ⇒ a different MAC (tamper/forgery detected). The secret NEVER appears in the output.
        secret = self._hmac_secret[name]
        digest = self._hmac.new(secret, base64.b64decode(hash_input), self._hashlib.sha256).digest()
        return {"data": {"hmac": "vault:v1:" + base64.b64encode(digest).decode("ascii")}}

    def encrypt_data(
        self, *, name: str, plaintext: str, associated_data: str | None = None, **_: Any
    ) -> dict[str, Any]:
        self.encrypts += 1
        pt = base64.b64decode(plaintext)
        aad = base64.b64decode(associated_data) if associated_data is not None else None
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, pt, aad)
        return {"data": {"ciphertext": "vault:v1:" + base64.b64encode(nonce + ct).decode("ascii")}}

    def decrypt_data(
        self, *, name: str, ciphertext: str, associated_data: str | None = None, **_: Any
    ) -> dict[str, Any]:
        raw = base64.b64decode(ciphertext[len("vault:v1:") :])
        nonce, ct = raw[:12], raw[12:]
        aad = base64.b64decode(associated_data) if associated_data is not None else None
        pt = self._aes.decrypt(nonce, ct, aad)  # raises InvalidTag on a wrong/absent AAD
        return {"data": {"plaintext": base64.b64encode(pt).decode("ascii")}}


class _FakeSecrets:
    def __init__(self, transit: _FakeTransit) -> None:
        self.transit = transit


class _FakeClient:
    def __init__(self, transit: _FakeTransit) -> None:
        self.secrets = _FakeSecrets(transit)


def _use_fake(monkeypatch: pytest.MonkeyPatch, transit: _FakeTransit | None = None) -> _FakeTransit:
    transit = transit or _FakeTransit()
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", _KEY_NAME)
    monkeypatch.setattr(crypto_transit, "_build_client", lambda addr, token: _FakeClient(transit))
    return transit


# --- cipher behavior (fake Transit) ---------------------------------------------------------------


def test_transit_cipher_is_a_cipher_and_encrypts(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_fake(monkeypatch)
    cipher = build_transit_cipher(StoreSettings())
    assert isinstance(cipher, Cipher)  # structurally satisfies the store Cipher protocol
    assert cipher.encrypts is True


def test_round_trip_v3_marker_and_hides_plaintext(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_fake(monkeypatch)
    cipher = build_transit_cipher(StoreSettings())
    aad = cell_aad("messages", "raw", 42)
    token = cipher.encrypt(ADT, aad=aad)
    assert token.startswith("mfenc:v3:vault:v1:")  # Transit-wrapped, DEK never in this process
    assert cipher.is_encrypted(token)
    assert ADT not in token  # PHI hidden (contains '|'/'\r', never a base64 substring)
    assert cipher.decrypt(token, aad=aad) == ADT
    assert cipher.encrypt(ADT, aad=aad) != token  # fresh nonce inside Transit → tokens never repeat


def test_cell_aad_binding_rejects_a_moved_blob(monkeypatch: pytest.MonkeyPatch) -> None:
    # ASVS 11.3.3: a v3 blob cut-and-pasted into a different (table, column, pk) fails the tag inside
    # Transit → CipherError (confirmed against OpenBao 2.6.0; the fake binds the same associated_data).
    _use_fake(monkeypatch)
    cipher = build_transit_cipher(StoreSettings())
    token = cipher.encrypt(ADT, aad=cell_aad("messages", "raw", 42))
    with pytest.raises(CipherError):
        cipher.decrypt(token, aad=cell_aad("messages", "raw", 999))


def test_audit_mac_key_is_none_but_chain_is_keyed_in_transit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ADR 0138 follow-up: there is NO in-heap key (audit_mac_key() is None — the honest 'no key material'
    # signal), but the chain IS keyed — via an isolated-module MAC provider (audit_mac_fn) that runs the
    # HMAC inside Transit. This is the move from keyless SHA-256 → forgery-resistant without an in-heap key.
    _use_fake(monkeypatch)
    cipher = build_transit_cipher(StoreSettings())
    # audit_mac_key() is typed `-> None` (no in-heap key ever enters heap) — mypy proves it, so we assert
    # the meaningful half at runtime: despite no key, a MAC provider IS handed to the store (keyed chain).
    mac_fn = cipher.audit_mac_fn()
    assert callable(mac_fn)  # the chain is keyed, inside the module


def test_audit_hmac_is_deterministic_and_tamper_sensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    # The Transit MAC must round-trip (verify recomputes and string-compares) yet change on any edit.
    _use_fake(monkeypatch)
    cipher = build_transit_cipher(StoreSettings())
    a = cipher.audit_hmac(b"row-canonical-bytes")
    assert a.startswith("vault:v1:")  # Transit-computed MAC string, no local digest
    assert cipher.audit_hmac(b"row-canonical-bytes") == a  # deterministic → the chain verifies
    assert (
        cipher.audit_hmac(b"row-canonical-bytez") != a
    )  # one-byte edit → different MAC (tamper caught)


def test_audit_hmac_uses_dedicated_key_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    # MEFOR_STORE_TRANSIT_AUDIT_KEY domain-separates the audit MAC from the data key (different Transit key
    # ⇒ different MAC over identical bytes). The dedicated key's existence is verified at build (fail-closed).
    _use_fake(monkeypatch)
    default_mac = build_transit_cipher(StoreSettings()).audit_hmac(b"same-bytes")
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_AUDIT_KEY", "mefor-audit")
    dedicated_mac = build_transit_cipher(StoreSettings()).audit_hmac(b"same-bytes")
    assert dedicated_mac != default_mac  # keyed under a distinct Transit key → distinct MAC


def test_audit_hmac_failure_is_type_only(monkeypatch: pytest.MonkeyPatch) -> None:
    # A Transit error surfaces the exception TYPE only — the canonical row bytes are PHI-derived.
    class _BoomOnHmac(_FakeTransit):
        def generate_hmac(self, **_: Any) -> dict[str, Any]:
            raise RuntimeError("transit echoed PHI: DOE^JANE")

    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", _KEY_NAME)
    monkeypatch.setattr(
        crypto_transit, "_build_client", lambda addr, token: _FakeClient(_BoomOnHmac())
    )
    cipher = build_transit_cipher(StoreSettings())
    with pytest.raises(CipherError) as excinfo:
        cipher.audit_hmac(b"canonical")
    assert "RuntimeError" in str(excinfo.value)
    assert "DOE" not in str(excinfo.value)


def test_legacy_plaintext_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_fake(monkeypatch)
    assert build_transit_cipher(StoreSettings()).decrypt("not-a-marker") == "not-a-marker"


def test_in_process_marker_fails_closed_in_transit_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    # An mfenc:v1/v2 value is in-process AES-GCM; Transit holds no key that reads it — refuse, never
    # mis-decrypt (a store switched to Transit must be rotated first).
    _use_fake(monkeypatch)
    cipher = build_transit_cipher(StoreSettings())
    with pytest.raises(CipherError, match="rotate"):
        cipher.decrypt("mfenc:v1:deadbeef:AAAA")


# --- selection seam -------------------------------------------------------------------------------


def test_build_store_cipher_dispatches_to_transit(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_fake(monkeypatch)
    cipher = build_store_cipher(StoreSettings(cipher_provider="vault_transit"))
    assert isinstance(cipher, TransitCipher)


def test_default_cipher_provider_is_unchanged() -> None:
    # aesgcm (default) is the in-process cipher — byte-identical, no Transit involved.
    assert not isinstance(build_store_cipher(StoreSettings()), TransitCipher)


def test_unknown_cipher_provider_fails_closed() -> None:
    with pytest.raises(ValueError, match="not a known cipher provider"):
        build_store_cipher(StoreSettings(cipher_provider="nope"))


# --- fail-closed build paths ----------------------------------------------------------------------


def test_missing_transit_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_STORE_TRANSIT_KEY", raising=False)
    with pytest.raises(KeyProviderError, match="MEFOR_STORE_TRANSIT_KEY"):
        build_transit_cipher(StoreSettings())


def test_missing_hvac_extra_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", _KEY_NAME)
    monkeypatch.setitem(sys.modules, "hvac", None)  # a real `import hvac` now raises ImportError
    with pytest.raises(KeyProviderError, match="vault"):
        build_transit_cipher(StoreSettings())


def test_unreachable_transit_fails_closed_type_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", _KEY_NAME)

    class _BoomTransit:
        def read_key(self, *, name: str) -> dict[str, Any]:
            raise RuntimeError("connection refused to https://secret-host:8200")

    monkeypatch.setattr(
        crypto_transit,
        "_build_client",
        lambda addr, token: _FakeClient(_BoomTransit()),  # type: ignore[arg-type]
    )
    with pytest.raises(KeyProviderError) as excinfo:
        build_transit_cipher(StoreSettings())
    assert "RuntimeError" in str(excinfo.value)
    assert "secret-host" not in str(excinfo.value)  # type-only message, no host/secret leak


# --- the operator-chosen key TYPE is checked at startup (BACKLOG #1166, ASVS 11.2.3) --------------
#
# Owner ruling 2026-08-22: "check the type the product already fetches against what each of the three
# uses requires, and refuse to start on a mismatch. The round trip is already being paid for; only the
# answer is being thrown away." The pre-fix measurement and which types each use admits are recorded
# once, on the section header in store/keyprovider_vault.py.
#
# The positive control that this build path was otherwise live is
# `test_unreachable_transit_fails_closed_type_only` above, which refused in the same suite.


@pytest.mark.parametrize(
    "key_type",
    [
        "ecdsa-p256",  # signing only: cannot encrypt at all
        "ed25519",  # signing only
        "aes128-cmac",  # MAC only: cannot encrypt at all
        "rsa-2048",  # ~112 bits, and no associated_data support for the cell binding
        "rsa-4096",  # strong enough, but Transit RSA takes no associated_data -> no cell binding
        "hmac",  # fine for the audit MAC, useless for at-rest encryption
    ],
)
def test_data_key_of_the_wrong_type_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, key_type: str
) -> None:
    transit = _FakeTransit()
    transit.key_types[_KEY_NAME] = key_type
    _use_fake(monkeypatch, transit)
    with pytest.raises(KeyProviderError) as excinfo:
        build_transit_cipher(StoreSettings())
    assert key_type in str(excinfo.value)
    assert "MEFOR_STORE_TRANSIT_KEY" in str(excinfo.value)  # names the knob to change


@pytest.mark.parametrize("key_type", ["aes256-gcm96", "aes128-gcm96", "chacha20-poly1305"])
def test_data_key_of_a_supported_aead_type_still_builds(
    monkeypatch: pytest.MonkeyPatch, key_type: str
) -> None:
    transit = _FakeTransit()
    transit.key_types[_KEY_NAME] = key_type
    _use_fake(monkeypatch, transit)
    monkeypatch.delenv("MEFOR_STORE_TRANSIT_AUDIT_KEY", raising=False)
    assert isinstance(build_transit_cipher(StoreSettings()), TransitCipher)
    assert transit.read_calls == [_KEY_NAME]  # still exactly ONE round trip, as before the fix


def test_dedicated_audit_key_of_the_wrong_type_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transit = _FakeTransit()
    transit.key_types["mefor-audit"] = "ecdsa-p384"
    _use_fake(monkeypatch, transit)
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_AUDIT_KEY", "mefor-audit")
    with pytest.raises(KeyProviderError) as excinfo:
        build_transit_cipher(StoreSettings())
    assert "ecdsa-p384" in str(excinfo.value)
    assert "MEFOR_STORE_TRANSIT_AUDIT_KEY" in str(excinfo.value)


def test_dedicated_audit_key_may_be_vault_hmac_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """Vault's dedicated `hmac` key type is the RIGHT type for a MAC and must not be refused, even
    though the data key may not be one. That asymmetry is why the two sets differ."""
    transit = _FakeTransit()
    transit.key_types["mefor-audit"] = "hmac"
    _use_fake(monkeypatch, transit)
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_AUDIT_KEY", "mefor-audit")
    cipher = build_transit_cipher(StoreSettings())
    assert cipher.audit_hmac(b"row").startswith("vault:v1:")


def test_a_shared_key_is_held_to_the_narrower_data_key_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no dedicated audit key the ONE key does both jobs, so it must clear the stricter of the
    two sets. `hmac` clears the audit set and must still be refused here."""
    transit = _FakeTransit()
    transit.key_types[_KEY_NAME] = "hmac"
    _use_fake(monkeypatch, transit)
    monkeypatch.delenv("MEFOR_STORE_TRANSIT_AUDIT_KEY", raising=False)
    with pytest.raises(KeyProviderError, match="at-rest PHI encryption"):
        build_transit_cipher(StoreSettings())


def test_unreadable_key_type_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Shapeless(_FakeTransit):
        def read_key(self, *, name: str) -> dict[str, Any]:
            return {"data": {"name": name}}  # no 'type'

    _use_fake(monkeypatch, _Shapeless())
    with pytest.raises(KeyProviderError, match="did not report a key type"):
        build_transit_cipher(StoreSettings())


def test_transit_encrypt_failure_is_type_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", _KEY_NAME)

    class _BoomOnEncrypt(_FakeTransit):
        def encrypt_data(self, **_: Any) -> dict[str, Any]:
            raise RuntimeError("transit echoed PHI: DOE^JANE")

    monkeypatch.setattr(
        crypto_transit, "_build_client", lambda addr, token: _FakeClient(_BoomOnEncrypt())
    )
    cipher = build_transit_cipher(StoreSettings())
    with pytest.raises(CipherError) as excinfo:
        cipher.encrypt(ADT, aad=cell_aad("messages", "raw", 1))
    assert "RuntimeError" in str(excinfo.value)
    assert "DOE" not in str(excinfo.value)  # never surface the plaintext PHI


# --- store audit-chain integration (fake Transit; exercises the real store path) -----------------


def _audit_row_hashes(db_path: Path) -> list[str]:
    con = sqlite3.connect(db_path)
    try:
        return [str(r[0]) for r in con.execute("SELECT row_hash FROM audit_log ORDER BY id")]
    finally:
        con.close()


async def test_open_store_audit_chain_keyed_in_transit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The property this lane adds: in vault_transit mode the store's audit chain is keyed by an MAC that
    # runs INSIDE Transit — there is NO in-heap MAC key, yet the chain is forgery-resistant, not keyless.
    _use_fake(monkeypatch)
    from messagefoundry.store.base import open_store

    db = tmp_path / "audit.db"
    store = await open_store(StoreSettings(path=str(db), cipher_provider="vault_transit"))
    assert isinstance(store, MessageStore)  # narrow the Store protocol to the concrete SQLite store
    try:
        assert store._audit_mac_key is None  # no key material in engine heap
        assert store._audit_mac_fn is not None  # …but the chain is keyed via the isolated module
        assert store._audit_keyed_from == 1  # fresh store auto-keyed from the first row
        await store.record_audit("view", actor="u", detail='{"m":1}')
        await store.record_audit("export", actor="u", detail='{"m":2}')
        hashes = _audit_row_hashes(db)
        assert len(hashes) == 2
        # Every row's MAC is Transit's `vault:v1:` string — NOT a 64-hex local SHA-256/HMAC digest.
        assert all(h.startswith("vault:v1:") for h in hashes), hashes
        ok, msg = await store.verify_audit_chain()  # round-trips through Transit
        assert ok, msg
    finally:
        await store.close()


async def test_transit_audit_chain_detects_tampering(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # An out-of-band edit to a Transit-keyed row must break verification — the forgery-resistance the
    # keyed-in-Transit chain buys over keyless SHA-256 (an attacker who can write rows can't recompute it).
    _use_fake(monkeypatch)
    from messagefoundry.store.base import open_store

    db = tmp_path / "audit2.db"
    store = await open_store(StoreSettings(path=str(db), cipher_provider="vault_transit"))
    assert isinstance(store, MessageStore)  # narrow the Store protocol to the concrete SQLite store
    try:
        await store.record_audit("login", actor="u")
        await store.record_audit("view", actor="u")
        ok, _ = await store.verify_audit_chain()
        assert ok
        await store._db.execute("UPDATE audit_log SET action='HACKED' WHERE id=1")
        await store._db.commit()
        ok2, message = await store.verify_audit_chain()
        assert not ok2  # the Transit MAC no longer matches the tampered content
        assert "broken" in (message or "")
    finally:
        await store.close()


async def test_default_aesgcm_audit_chain_is_unchanged(tmp_path: Path) -> None:
    # Guard the byte-identical contract: with the default cipher there is NO mac_fn, so the audit chain
    # is the in-process keyless/keyed path exactly as before (row_hash is a 64-hex digest, not vault:v1:).
    from messagefoundry.store.base import open_store

    db = tmp_path / "plain.db"
    store = await open_store(StoreSettings(path=str(db)))  # default aesgcm/identity — no Transit
    assert isinstance(store, MessageStore)  # narrow the Store protocol to the concrete SQLite store
    try:
        assert store._audit_mac_fn is None  # the new seam is dormant on the default path
        await store.record_audit("view", actor="u")
        hashes = _audit_row_hashes(db)
        assert hashes and not any(h.startswith("vault:v1:") for h in hashes)
        assert all(
            len(h) == 64 for h in hashes
        )  # keyless SHA-256 hex — byte-identical to pre-ADR-0138
    finally:
        await store.close()


# --- live OpenBao integration (gated) -------------------------------------------------------------

_LIVE = bool(os.environ.get("MEFOR_STORE_TRANSIT_KEY") and os.environ.get("MEFOR_STORE_VAULT_ADDR"))
_live = pytest.mark.skipif(
    not _LIVE,
    reason="live OpenBao: set MEFOR_STORE_VAULT_ADDR / MEFOR_STORE_VAULT_TOKEN / MEFOR_STORE_TRANSIT_KEY "
    "against a `bao server -dev` with the transit engine + key enabled",
)


def _raw_at_rest(db_path: Path) -> str:
    con = sqlite3.connect(db_path)
    try:
        return str(con.execute("SELECT raw FROM messages").fetchone()[0])
    finally:
        con.close()


@_live
def test_live_transit_round_trip() -> None:
    cipher = build_transit_cipher(StoreSettings())
    aad = cell_aad("messages", "raw", 7)
    token = cipher.encrypt(ADT, aad=aad)
    assert token.startswith("mfenc:v3:vault:v1:")
    assert cipher.decrypt(token, aad=aad) == ADT
    with pytest.raises(CipherError):  # cell-binding is real end-to-end
        cipher.decrypt(token, aad=cell_aad("messages", "raw", 8))


@_live
def test_live_audit_hmac_round_trips_and_is_tamper_sensitive() -> None:
    # Real OpenBao generate_hmac: deterministic (verify recomputes), tamper-sensitive, and a `vault:v1:`
    # string — the key never leaves the module. Proves the audit MAC path end-to-end against live Transit.
    cipher = build_transit_cipher(StoreSettings())
    a = cipher.audit_hmac(b"canonical-row")
    assert a.startswith("vault:v1:")
    assert cipher.audit_hmac(b"canonical-row") == a
    assert cipher.audit_hmac(b"canonical-roX") != a


@_live
async def test_live_open_store_audit_chain_keyed_in_transit(tmp_path: Path) -> None:
    from messagefoundry.store.base import open_store

    db = tmp_path / "live-audit.db"
    store = await open_store(StoreSettings(path=str(db), cipher_provider="vault_transit"))
    assert isinstance(store, MessageStore)  # narrow the Store protocol to the concrete SQLite store
    try:
        assert store._audit_mac_key is None  # no in-heap MAC key
        assert store._audit_mac_fn is not None  # keyed inside OpenBao Transit
        await store.record_audit("view", actor="u", detail='{"m":1}')
        await store.record_audit("export", actor="u", detail='{"m":2}')
        assert all(h.startswith("vault:v1:") for h in _audit_row_hashes(db))
        ok, msg = await store.verify_audit_chain()
        assert ok, msg
        await store._db.execute("UPDATE audit_log SET action='HACKED' WHERE id=1")
        await store._db.commit()
        broken, _ = await store.verify_audit_chain()
        assert not broken  # the live Transit MAC catches the out-of-band edit
    finally:
        await store.close()


@_live
async def test_live_open_store_lands_dek_free_at_rest(tmp_path: Path) -> None:
    from messagefoundry.store.base import open_store

    db = tmp_path / "transit.db"
    settings = StoreSettings(path=str(db), cipher_provider="vault_transit")
    store = await open_store(settings)
    assert isinstance(store, MessageStore)  # narrow the Store protocol to the concrete SQLite store
    try:
        assert isinstance(store._cipher, TransitCipher)  # the seam built the Transit cipher
        await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[])
        at_rest = _raw_at_rest(db)
        # The property 13.3.3 is about: the value on disk is Transit-wrapped, and the plaintext PHI is
        # nowhere — the key that could decrypt it lives only inside OpenBao, never in this process.
        assert at_rest.startswith("mfenc:v3:vault:v1:")
        assert ADT not in at_rest
        # The store's own live Transit cipher round-trips a controlled cell.
        probe = store._cipher.encrypt("x", aad=cell_aad("t", "c", 1))
        assert store._cipher.decrypt(probe, aad=cell_aad("t", "c", 1)) == "x"
    finally:
        await store.close()
