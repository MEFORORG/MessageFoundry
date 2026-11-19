# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A retired store key with no active key is refused, by one rule at every seam (BACKLOG #5310,
#5308), and a key that fails to decode leaves no earlier decoded key unwiped (BACKLOG #5310).

Before the fix, ``make_cipher`` returned the identity cipher whenever the active key was empty,
whatever the retired keys held, so a rotation missing its new key would have written new rows
unencrypted; and ``resolve_decrypt_keys`` returned the retired keys for that configuration, so a
DR restore would have decrypted under a keyring the store itself then opened without."""

from __future__ import annotations

import pytest

from messagefoundry.__main__ import _keyless_store_gate, _store_key_configured, _unread_key_text
from messagefoundry.config.settings import (
    KEYLESS_REFUSED_BY_UNREAD_KEY,
    SecuritySettings,
    ServiceSettings,
    StoreSettings,
)
from messagefoundry.redaction import safe_exc
from messagefoundry.store import crypto
from messagefoundry.store.base import (
    StoreCipherConfigError,
    build_store_cipher,
    resolve_active_key,
    resolve_decrypt_keys,
)
from messagefoundry.store.crypto import (
    RETIRED_WITHOUT_ACTIVE,
    RETIRED_WITHOUT_ACTIVE_TRANSIT,
    AesGcmCipher,
    IdentityCipher,
    generate_key,
    make_cipher,
)

# --- make_cipher (BACKLOG #5310) ---------------------------------------------------------------


@pytest.mark.parametrize("active", [None, ""])
def test_make_cipher_refuses_retired_keys_with_no_active_key(active: str | None) -> None:
    with pytest.raises(ValueError) as caught:
        make_cipher(active, [generate_key()])
    assert str(caught.value) == RETIRED_WITHOUT_ACTIVE


def test_make_cipher_with_no_key_at_all_is_still_the_identity_cipher() -> None:
    # The control: the refusal is about the retired key, not the missing active one. Blank retired
    # entries are not keys, here as in the settings' comma split.
    assert isinstance(make_cipher(None), IdentityCipher)
    assert isinstance(make_cipher("", ["", "  "]), IdentityCipher)


def test_a_key_that_fails_to_decode_leaves_the_decoded_keys_wiped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoded: list[bytearray] = []
    real = crypto._decode_key

    def recording(key_b64: str, name: str) -> bytearray:
        buf = real(key_b64, name)
        decoded.append(buf)
        return buf

    monkeypatch.setattr(crypto, "_decode_key", recording)
    with pytest.raises(ValueError, match="must be valid base64"):
        make_cipher(generate_key(), [generate_key(), "not base64!"])
    # The active key and the first retired key decoded before the third failed.
    assert len(decoded) == 2
    assert all(len(buf) == 32 and not any(buf) for buf in decoded)


def test_a_cipher_build_that_fails_leaves_the_decoded_keys_wiped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoded: list[bytearray] = []
    real = crypto._decode_key

    def recording(key_b64: str, name: str) -> bytearray:
        buf = real(key_b64, name)
        decoded.append(buf)
        return buf

    def failing(*_args: object, **_kwargs: object) -> None:
        raise MemoryError("synthetic")

    monkeypatch.setattr(crypto, "_decode_key", recording)
    monkeypatch.setattr(crypto, "AesGcmCipher", failing)
    with pytest.raises(MemoryError):
        make_cipher(generate_key(), [generate_key()])
    assert len(decoded) == 2
    assert all(len(buf) == 32 and not any(buf) for buf in decoded)


def test_a_key_that_decodes_reaches_the_cipher_live() -> None:
    # The control for the wipe test: on success the keys reach the cipher live (it derives from
    # them before it wipes them), so the cipher round-trips.
    cipher = make_cipher(generate_key(), [generate_key()])
    assert cipher.decrypt(cipher.encrypt("MSH|^~\\&|A")) == "MSH|^~\\&|A"


# --- resolve_decrypt_keys and the cipher build agree (BACKLOG #5308) ----------------------------


def test_resolve_decrypt_keys_refuses_retired_keys_with_no_active_key() -> None:
    settings = StoreSettings(encryption_keys_retired=generate_key())
    with pytest.raises(StoreCipherConfigError) as caught:
        resolve_decrypt_keys(settings)
    assert str(caught.value) == RETIRED_WITHOUT_ACTIVE
    assert caught.value.__cause__ is None


def test_the_store_cipher_build_refuses_the_same_configuration_with_the_same_text() -> None:
    settings = StoreSettings(encryption_keys_retired=generate_key())
    with pytest.raises(StoreCipherConfigError) as caught:
        build_store_cipher(settings)
    # The text survives the build's fixed-text replacement, so the operator reads the cause.
    assert str(caught.value) == RETIRED_WITHOUT_ACTIVE


def test_resolve_active_key_refuses_the_same_configuration() -> None:
    # The DR backup and rotate-key resolve the active key alone; they get the same refusal, so a
    # backup cannot take this configuration for a keyless store either.
    with pytest.raises(StoreCipherConfigError) as caught:
        resolve_active_key(StoreSettings(encryption_keys_retired=generate_key()))
    assert str(caught.value) == RETIRED_WITHOUT_ACTIVE


def test_resolve_decrypt_keys_still_returns_the_keyring_when_an_active_key_is_set() -> None:
    # The controls: an active key with a retired one, and no key at all, resolve as before.
    active, retired = generate_key(), generate_key()
    settings = StoreSettings(encryption_key=active, encryption_keys_retired=retired)
    assert resolve_decrypt_keys(settings) == [active, retired]
    assert isinstance(build_store_cipher(settings), AesGcmCipher)
    assert resolve_active_key(settings) == active
    keyless = StoreSettings()
    assert resolve_active_key(keyless) is None
    assert resolve_decrypt_keys(keyless) == []
    assert isinstance(build_store_cipher(keyless), IdentityCipher)


def test_blank_retired_settings_are_no_retired_key_at_any_seam() -> None:
    # The settings seam and make_cipher read a blank entry alike when there is no active key: no
    # key, so keyless as before.
    keyless = StoreSettings(encryption_keys_retired=" , ")
    assert resolve_active_key(keyless) is None
    assert resolve_decrypt_keys(keyless) == []
    assert isinstance(build_store_cipher(keyless), IdentityCipher)


def test_under_vault_transit_the_dr_key_resolves_and_the_gate_still_refuse() -> None:
    # Transit's store open reads no local key, but the DR backup and restore do resolve one: a
    # backup with allow_unencrypted would otherwise write a cleartext archive beside a retired key,
    # and a restore would decrypt under the retired key alone.
    store = StoreSettings(cipher_provider="vault_transit", encryption_keys_retired=generate_key())
    for resolve in (resolve_active_key, resolve_decrypt_keys):
        with pytest.raises(StoreCipherConfigError) as caught:
            resolve(store)
        assert str(caught.value) == RETIRED_WITHOUT_ACTIVE_TRANSIT
    assert _keyless_store_gate(ServiceSettings(store=store)) == KEYLESS_REFUSED_BY_UNREAD_KEY


def test_under_vault_transit_the_refusal_text_does_not_claim_unencrypted_rows() -> None:
    # Transit encrypts the rows whatever the local keys are, so the text names what does read
    # them there, the DR backup and restore, and keeps the refusal (BACKLOG #5310, #5308).
    store = StoreSettings(cipher_provider="vault_transit", encryption_keys_retired=generate_key())
    text = _unread_key_text(ServiceSettings(store=store))
    assert "unencrypted" not in text
    assert "vault_transit" in text and "DR backup and restore" in text
    # The control: under aesgcm the text does name the unencrypted rows.
    aesgcm = StoreSettings(encryption_keys_retired=generate_key())
    assert "write new rows unencrypted" in _unread_key_text(ServiceSettings(store=aesgcm))


# --- a path that skips the key seam keeps the text (BACKLOG #5310, #5308) ------------------------


@pytest.mark.parametrize("host_key", ["", "   "])
def test_a_host_key_that_is_no_key_beside_a_retired_key_keeps_the_text(host_key: str) -> None:
    # A host key does not pass _checked_active_key, so the build records the refusal itself rather
    # than letting make_cipher's unrecorded ValueError be replaced by the generic text.
    settings = StoreSettings(encryption_keys_retired=generate_key())
    with pytest.raises(StoreCipherConfigError) as caught:
        build_store_cipher(settings, host_key=host_key)
    assert str(caught.value) == RETIRED_WITHOUT_ACTIVE
    assert caught.value.__cause__ is None


# --- an active key of blanks only is no active key (BACKLOG #5310, #5308) ------------------------


def test_make_cipher_reads_a_blank_active_key_as_no_key_beside_a_retired_key() -> None:
    with pytest.raises(ValueError) as caught:
        make_cipher("   ", [generate_key()])
    assert str(caught.value) == RETIRED_WITHOUT_ACTIVE
    # The control: with no retired key a blank active key is still refused as a bad key, never
    # the identity cipher.
    with pytest.raises(ValueError, match="must be valid base64") as bare:
        make_cipher("   ")
    assert str(bare.value) != RETIRED_WITHOUT_ACTIVE


@pytest.mark.parametrize("provider", ["auto", "env"])
def test_a_blank_active_key_beside_a_retired_key_is_refused_at_every_seam(provider: str) -> None:
    store = StoreSettings(
        key_provider=provider, encryption_key="   ", encryption_keys_retired=generate_key()
    )
    for resolve in (resolve_active_key, resolve_decrypt_keys, build_store_cipher):
        with pytest.raises(StoreCipherConfigError) as caught:
            resolve(store)
        assert str(caught.value) == RETIRED_WITHOUT_ACTIVE
    settings = ServiceSettings(store=store)
    assert _keyless_store_gate(settings) == KEYLESS_REFUSED_BY_UNREAD_KEY
    assert _unread_key_text(settings) == RETIRED_WITHOUT_ACTIVE
    # The control: with no retired key the gate leaves a blank key to the open, as before.
    blank_only = StoreSettings(key_provider=provider, encryption_key="   ")
    assert _keyless_store_gate(ServiceSettings(store=blank_only)) is None


# --- a blank retired entry beside an active key is still a bad key (BACKLOG #5310) ---------------


def test_a_blank_retired_entry_beside_an_active_key_is_refused_as_before() -> None:
    with pytest.raises(ValueError, match="MEFOR_STORE_ENCRYPTION_KEYS_RETIRED"):
        make_cipher(generate_key(), ["  "])
    # The control: the settings split drops it, so the store build beside an active key does not.
    settings = StoreSettings(encryption_key=generate_key(), encryption_keys_retired=" , ")
    assert isinstance(build_store_cipher(settings), AesGcmCipher)


def test_the_start_gate_refuses_before_the_open_whatever_the_opt_out_says() -> None:
    # serve, supervise and provision-admin take the gate's verdict before the store opens, so the
    # operator reads the cause rather than the keyless opt-out's remedy, which would not help.
    opted_out = SecuritySettings(
        allow_unencrypted_phi=True, allow_unencrypted_phi_under_strict_enforcement=True
    )
    store = StoreSettings(encryption_keys_retired=generate_key())
    for security in (SecuritySettings(), opted_out):
        settings = ServiceSettings(store=store, security=security)
        assert _keyless_store_gate(settings) == KEYLESS_REFUSED_BY_UNREAD_KEY
        assert _unread_key_text(settings) == RETIRED_WITHOUT_ACTIVE
    # The control: with no retired key the gate does not take this branch.
    assert _keyless_store_gate(ServiceSettings(store=StoreSettings())) != (
        KEYLESS_REFUSED_BY_UNREAD_KEY
    )


@pytest.mark.parametrize("cipher_provider", ["aesgcm", "vault_transit"])
def test_serve_runs_the_gate_for_a_blank_active_key_beside_a_retired_key(
    cipher_provider: str,
) -> None:
    # serve consults the gate only when _store_key_configured says unkeyed, so a blank key must
    # read as unkeyed there, or serve would skip the refusal (BACKLOG #5310, #5308).
    store = StoreSettings(
        cipher_provider=cipher_provider,
        encryption_key="   ",
        encryption_keys_retired=generate_key(),
    )
    assert _store_key_configured(ServiceSettings(store=store)) is False
    # The control: with no retired key a blank key still reads as configured, left to the open.
    blank_only = StoreSettings(cipher_provider=cipher_provider, encryption_key="   ")
    assert _store_key_configured(ServiceSettings(store=blank_only)) is True


def test_the_transit_refusal_survives_the_dr_backup_text_cut() -> None:
    # The DR backup, the one runtime reader under vault_transit, renders a refusal through
    # safe_exc, which cuts a long text; the cause and the remedy must survive.
    rendered = safe_exc(StoreCipherConfigError(RETIRED_WITHOUT_ACTIVE_TRANSIT))
    assert rendered.endswith(RETIRED_WITHOUT_ACTIVE_TRANSIT)
    # The control: safe_exc does cut a text as long as the aesgcm one, so the test above measures.
    assert not safe_exc(StoreCipherConfigError(RETIRED_WITHOUT_ACTIVE)).endswith(
        RETIRED_WITHOUT_ACTIVE
    )


def test_under_vault_transit_an_active_local_key_beside_a_retired_key_passes() -> None:
    # The control for the Transit refusals: with the active local key set, the DR key resolves
    # and the gate lets the start through.
    active, retired = generate_key(), generate_key()
    store = StoreSettings(
        cipher_provider="vault_transit", encryption_key=active, encryption_keys_retired=retired
    )
    assert resolve_active_key(store) == active
    assert resolve_decrypt_keys(store) == [active, retired]
    assert _keyless_store_gate(ServiceSettings(store=store)) is None
