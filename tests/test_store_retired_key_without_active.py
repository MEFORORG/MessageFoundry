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

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import crypto
from messagefoundry.store.base import (
    StoreCipherConfigError,
    build_store_cipher,
    resolve_active_key,
    resolve_decrypt_keys,
)
from messagefoundry.store.crypto import (
    RETIRED_WITHOUT_ACTIVE,
    AesGcmCipher,
    IdentityCipher,
    generate_key,
    make_cipher,
)


@pytest.fixture(autouse=True)
def _no_ambient_store_key(monkeypatch: pytest.MonkeyPatch) -> None:
    # The runner's own environment must not supply a store key to the settings under test.
    for name in (
        "MEFOR_STORE_ENCRYPTION_KEY",
        "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
        "MEFOR_STORE_ENCRYPTION_KEY_FILE",
        "MEFOR_STORE_KEY_PROVIDER",
    ):
        monkeypatch.delenv(name, raising=False)


# --- make_cipher (BACKLOG #5310) ---------------------------------------------------------------


@pytest.mark.parametrize("active", [None, ""])
def test_make_cipher_refuses_retired_keys_with_no_active_key(active: str | None) -> None:
    with pytest.raises(ValueError) as caught:
        make_cipher(active, [generate_key()])
    assert str(caught.value) == RETIRED_WITHOUT_ACTIVE


def test_make_cipher_with_no_key_at_all_is_still_the_identity_cipher() -> None:
    # The control: the refusal is about the retired key, not the missing active one. Empty retired
    # entries are not keys, as they never were.
    assert isinstance(make_cipher(None), IdentityCipher)
    assert isinstance(make_cipher("", ["", ""]), IdentityCipher)


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
