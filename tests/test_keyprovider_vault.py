# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the `vault` KeyProvider (store/keyprovider_vault.py, ADR 0019 §3, BACKLOG #196).

Covers the WP-BL3-04 acceptance criterion for the Vault provider: a faked Transit backend returns a
base64 key that flows straight through `make_cipher` and decrypts an `mfenc:v1` row with NO rotation;
the `resolve_key_provider` dispatch picks the shipped module up by name; and every fail-closed path
(missing hvac extra, missing env config, a Transit/transport failure) raises `KeyProviderError` — never
a silent degrade to the identity cipher, and never with key material in the message.
"""

from __future__ import annotations

import base64
import sys
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import keyprovider_vault
from messagefoundry.store.crypto import PREFIX, make_cipher
from messagefoundry.store.keyprovider import KeyProviderError, resolve_key_provider

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

# A fixed 32-byte base64 DEK — the shape Vault Transit returns as response['data']['plaintext'] when the
# sealed value is the raw 32 DEK bytes (ADR 0019 §3, no double-base64).
KEY_A = base64.b64encode(b"\x00" * 32).decode("ascii")

_TRANSIT_KEY = "mefor-store-kek"
_WRAPPED_DEK = "vault:v1:ZmFrZS13cmFwcGVkLWRlaw=="


class _FakeTransit:
    """Stands in for hvac's `client.secrets.transit`; records the unwrap call and returns a base64 DEK."""

    def __init__(self, plaintext: str) -> None:
        self._plaintext = plaintext
        self.calls: list[tuple[str, str]] = []

    def decrypt_data(self, *, name: str, ciphertext: str) -> dict[str, Any]:
        self.calls.append((name, ciphertext))
        return {"data": {"plaintext": self._plaintext}}


class _FakeSecrets:
    def __init__(self, transit: _FakeTransit) -> None:
        self.transit = transit


class _FakeClient:
    def __init__(self, transit: _FakeTransit) -> None:
        self.secrets = _FakeSecrets(transit)


def _configure_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", _TRANSIT_KEY)
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", _WRAPPED_DEK)


# --- happy path: a faked Transit backend's key flows through make_cipher -----


def test_vault_active_key_unwraps_and_decrypts_without_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)
    transit = _FakeTransit(KEY_A)
    # Substitute the client factory so no live Vault (or hvac import) is needed.
    monkeypatch.setattr(
        keyprovider_vault, "_build_client", lambda addr, token: _FakeClient(transit)
    )

    provider = keyprovider_vault.build_provider(StoreSettings())
    active = provider.active_key()
    assert active == KEY_A
    # The wrapped DEK + KEK name were passed straight through to Transit.
    assert transit.calls == [(_TRANSIT_KEY, _WRAPPED_DEK)]

    # A row written under KEY_A decrypts with the provider's key — NO re-encryption, mfenc:v1 unchanged.
    token = make_cipher(KEY_A).encrypt(ADT)
    assert token.startswith(PREFIX)
    cipher = make_cipher(active, provider.retired_keys())
    assert cipher.decrypt(token) == ADT


def test_resolve_key_provider_wires_the_vault_module(monkeypatch: pytest.MonkeyPatch) -> None:
    # The base dispatch (keyprovider._load_external_provider) imports store.keyprovider_vault by name and
    # calls build_provider — no edit to keyprovider.py.
    _configure_env(monkeypatch)
    transit = _FakeTransit(KEY_A)
    monkeypatch.setattr(
        keyprovider_vault, "_build_client", lambda addr, token: _FakeClient(transit)
    )
    provider = resolve_key_provider(StoreSettings(key_provider="vault"))
    assert isinstance(provider, keyprovider_vault.VaultKeyProvider)
    assert provider.active_key() == KEY_A


def test_vault_surfaces_built_in_retired_keys() -> None:
    key_b = base64.b64encode(b"\x01" * 32).decode("ascii")
    provider = keyprovider_vault.build_provider(
        StoreSettings(encryption_keys_retired=f" {KEY_A} , {key_b} ,")
    )
    # Per-element (never comma-joined) so each feeds _decode_key's 32-byte check straight through.
    assert list(provider.retired_keys()) == [KEY_A, key_b]


# --- fail-closed paths -------------------------------------------------------


def test_missing_hvac_fails_closed_naming_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch)
    # Make a real `import hvac` fail (None in sys.modules raises ImportError) — the fail-closed path when
    # the [vault] extra is not installed.
    monkeypatch.setitem(sys.modules, "hvac", None)
    provider = keyprovider_vault.build_provider(StoreSettings())
    with pytest.raises(KeyProviderError, match="vault"):
        provider.active_key()


def test_missing_config_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Neither env var set → misconfiguration, not a no-key degrade. The message names the missing var.
    monkeypatch.delenv("MEFOR_STORE_VAULT_TRANSIT_KEY", raising=False)
    monkeypatch.delenv("MEFOR_STORE_VAULT_WRAPPED_DEK", raising=False)
    provider = keyprovider_vault.build_provider(StoreSettings())
    with pytest.raises(KeyProviderError, match="MEFOR_STORE_VAULT_TRANSIT_KEY"):
        provider.active_key()


def test_transit_failure_fails_closed_without_leaking_ciphertext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)

    class _BoomTransit:
        def decrypt_data(self, *, name: str, ciphertext: str) -> dict[str, Any]:
            # A Transit error can echo the ciphertext — the provider must not surface it.
            raise RuntimeError(f"vault denied for ciphertext {ciphertext}")

    monkeypatch.setattr(
        keyprovider_vault,
        "_build_client",
        lambda addr, token: _FakeClient(_BoomTransit()),  # type: ignore[arg-type]
    )
    provider = keyprovider_vault.build_provider(StoreSettings())
    with pytest.raises(KeyProviderError) as excinfo:
        provider.active_key()
    # The message names the failure TYPE only — never the wrapped DEK / ciphertext (no key-material oracle).
    assert _WRAPPED_DEK not in str(excinfo.value)
    assert "RuntimeError" in str(excinfo.value)


def test_empty_plaintext_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch)
    monkeypatch.setattr(
        keyprovider_vault, "_build_client", lambda addr, token: _FakeClient(_FakeTransit(""))
    )
    provider = keyprovider_vault.build_provider(StoreSettings())
    with pytest.raises(KeyProviderError, match="empty"):
        provider.active_key()
