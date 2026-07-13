# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pluggable KeyProvider seam (ADR 0019, ASVS 13.3.3).

Covers: the default `auto` ladder is BYTE-IDENTICAL to the pre-seam `resolve_active_key`; the `env`/
`dpapi` built-ins pin a single source; `retired_keys()` is per-element (never comma-joined); external
HSM/KMS/Vault providers fail closed until built (the lazy hook); and a faked provider's base64 key
flows straight through `make_cipher` and decrypts an `mfenc:v1` row with no rotation (the WP-BL3-04
acceptance criterion). DPAPI round-trips are Windows-only, so the file branch is monkeypatched here."""

from __future__ import annotations

import base64
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings, _FILE_SECRET_KEYS
from messagefoundry.store.base import resolve_active_key
from messagefoundry.store.crypto import PREFIX, CipherError, cipher_info, make_cipher
from messagefoundry.store.keyprovider import (
    KNOWN_PROVIDERS,
    AutoKeyProvider,
    DpapiKeyProvider,
    EnvKeyProvider,
    KeyProvider,
    KeyProviderError,
    resolve_key_provider,
)

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

# Two fixed 32-byte base64 DEKs the keyring accepts (MEFOR_STORE_ENCRYPTION_KEY shape) — derived from
# bytes so the base64 length/padding is always valid, and deterministic across runs.
KEY_A = base64.b64encode(b"\x00" * 32).decode("ascii")
KEY_B = base64.b64encode(b"\x01" * 32).decode("ascii")


# --- the protocol + built-in providers --------------------------------------


def test_builtins_satisfy_the_runtime_checkable_protocol() -> None:
    s = StoreSettings()
    for provider in (AutoKeyProvider(s), EnvKeyProvider(s), DpapiKeyProvider(s)):
        assert isinstance(provider, KeyProvider)


def test_known_providers_is_the_full_adr_enum() -> None:
    # auto/env/dpapi (built-in) + the five external envelope-decrypt providers (ADR 0019 §2).
    assert KNOWN_PROVIDERS == (
        "auto",
        "env",
        "dpapi",
        "aws_kms",
        "azure_kv",
        "gcp_kms",
        "vault",
        "pkcs11",
    )


def test_default_key_provider_is_auto_and_not_a_secret() -> None:
    assert StoreSettings().key_provider == "auto"
    # `key_provider` names a provider, not key material — it must never be a file-secret (ADR 0019 §2).
    assert ("store", "key_provider") not in _FILE_SECRET_KEYS


# --- `auto`: byte-identical to the pre-seam ladder ---------------------------


def test_auto_prefers_env_key_over_file(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_path: object) -> str:
        raise AssertionError("key file must not be read when encryption_key is set")

    monkeypatch.setattr("messagefoundry.secrets_dpapi.load_protected_key", _boom)
    s = StoreSettings(encryption_key="QUJD", encryption_key_file="C:/x/key.dpapi")
    assert AutoKeyProvider(s).active_key() == "QUJD"


def test_auto_uses_key_file_when_no_env_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "messagefoundry.secrets_dpapi.load_protected_key", lambda path: f"decrypted:{path}"
    )
    s = StoreSettings(encryption_key=None, encryption_key_file="C:/x/key.dpapi")
    assert AutoKeyProvider(s).active_key() == "decrypted:C:/x/key.dpapi"


def test_auto_none_when_neither_configured() -> None:
    assert AutoKeyProvider(StoreSettings()).active_key() is None


# --- `env` / `dpapi`: each pins a single built-in source ---------------------


def test_env_provider_returns_env_key_and_never_reads_the_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(_path: object) -> str:
        raise AssertionError("the env provider must never touch the DPAPI file")

    monkeypatch.setattr("messagefoundry.secrets_dpapi.load_protected_key", _boom)
    s = StoreSettings(encryption_key="QUJD", encryption_key_file="C:/x/key.dpapi")
    assert EnvKeyProvider(s).active_key() == "QUJD"
    assert EnvKeyProvider(StoreSettings()).active_key() is None


def test_dpapi_provider_loads_the_file_even_when_an_env_key_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `dpapi` is the explicit file source: it loads the file and ignores the env key (unlike `auto`).
    monkeypatch.setattr(
        "messagefoundry.secrets_dpapi.load_protected_key", lambda path: f"decrypted:{path}"
    )
    s = StoreSettings(encryption_key="ENV-KEY-IGNORED", encryption_key_file="C:/x/key.dpapi")
    assert DpapiKeyProvider(s).active_key() == "decrypted:C:/x/key.dpapi"


def test_dpapi_provider_none_when_no_file_configured() -> None:
    assert DpapiKeyProvider(StoreSettings(encryption_key="ENV")).active_key() is None


# --- retired_keys() is per-element, never comma-joined (ADR 0019 §1) ---------


def test_retired_keys_are_split_per_element() -> None:
    s = StoreSettings(encryption_keys_retired=f" {KEY_A} , {KEY_B} ,")
    retired = AutoKeyProvider(s).retired_keys()
    # One element per key (stripped, empties dropped) — NOT a single comma-joined string that would
    # blow `_decode_key`'s 32-byte check.
    assert list(retired) == [KEY_A, KEY_B]
    # And the per-element list feeds straight into make_cipher (the contract make_cipher consumes).
    cipher = make_cipher(KEY_A, retired)
    assert cipher.decrypt(cipher.encrypt(ADT)) == ADT


def test_retired_keys_empty_by_default() -> None:
    assert list(EnvKeyProvider(StoreSettings()).retired_keys()) == []


# --- external providers: lazy + fail-closed (not built yet) ------------------


# `vault` is intentionally omitted: its provider module (store/keyprovider_vault.py) now ships (BACKLOG
# #196), so selecting it no longer fails closed as "not built yet" — its own fail-closed paths (missing
# hvac / missing config / Transit failure) are covered in tests/test_keyprovider_vault.py.
@pytest.mark.parametrize("name", ["aws_kms", "azure_kv", "gcp_kms", "pkcs11"])
def test_external_provider_fails_closed_until_built(name: str) -> None:
    # Selecting an external provider before its module ships raises (never a silent degrade to the
    # identity cipher), and the message names the optional extra so the operator knows what to install.
    with pytest.raises(KeyProviderError, match=name):
        resolve_key_provider(StoreSettings(key_provider=name))


def test_external_provider_lazy_hook_wires_a_shipped_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Prove the hook is a real import seam, not just a raise: a future per-provider module exposing
    # build_provider(settings) is picked up by resolve_key_provider with no edit to the dispatch.
    captured: dict[str, Any] = {}

    def _build_provider(settings: StoreSettings) -> KeyProvider:
        captured["settings"] = settings
        return EnvKeyProvider(settings)

    fake = ModuleType("messagefoundry.store.keyprovider_vault")
    fake.build_provider = _build_provider  # type: ignore[attr-defined]

    def _import(name: str) -> ModuleType:
        assert name == "messagefoundry.store.keyprovider_vault"
        return fake

    monkeypatch.setattr("messagefoundry.store.keyprovider.importlib.import_module", _import)
    s = StoreSettings(key_provider="vault", encryption_key="QUJD")
    provider = resolve_key_provider(s)
    assert isinstance(provider, EnvKeyProvider) and provider.active_key() == "QUJD"
    assert captured["settings"] is s


def test_unknown_provider_fails_closed() -> None:
    with pytest.raises(KeyProviderError, match="unknown"):
        resolve_key_provider(StoreSettings(key_provider="not-a-provider"))


# --- resolve_active_key dispatches through the seam --------------------------


def test_resolve_active_key_auto_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    # The default StoreSettings() routes through AutoKeyProvider — same results the pre-seam function
    # produced (env wins, file fallback, else None). Mirrors tests/test_secrets_dpapi.py.
    monkeypatch.setattr(
        "messagefoundry.secrets_dpapi.load_protected_key", lambda path: f"decrypted:{path}"
    )
    assert resolve_active_key(StoreSettings(encryption_key="QUJD")) == "QUJD"
    assert (
        resolve_active_key(StoreSettings(encryption_key_file="C:/x/key.dpapi"))
        == "decrypted:C:/x/key.dpapi"
    )
    assert resolve_active_key(StoreSettings()) is None


def test_resolve_active_key_honors_explicit_env_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_path: object) -> str:
        raise AssertionError("env provider must not read the file")

    monkeypatch.setattr("messagefoundry.secrets_dpapi.load_protected_key", _boom)
    s = StoreSettings(key_provider="env", encryption_key="QUJD", encryption_key_file="C:/x/k.dpapi")
    assert resolve_active_key(s) == "QUJD"


def test_resolve_active_key_propagates_unknown_provider() -> None:
    # Fail-closed propagates out of resolve_active_key → open_store → serve refuses to start.
    with pytest.raises(KeyProviderError):
        resolve_active_key(StoreSettings(key_provider="bogus"))


def test_resolve_active_key_propagates_dpapi_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.secrets_dpapi import DpapiError

    def _raise(_path: object) -> str:
        raise DpapiError("cannot read encryption_key_file")

    monkeypatch.setattr("messagefoundry.secrets_dpapi.load_protected_key", _raise)
    # A configured-but-unreadable key file fails closed (not a silent no-key degrade).
    with pytest.raises(DpapiError):
        resolve_active_key(StoreSettings(key_provider="dpapi", encryption_key_file="C:/x/k.dpapi"))


# --- WP-BL3-04 acceptance: a faked provider's key flows through make_cipher --


def test_faked_provider_key_decrypts_existing_mfenc_v1_rows_without_rotation() -> None:
    """The acceptance criterion (ADR 0019 §3 / WP-BL3-04): a provider that returns a base64 key feeds
    make_cipher unchanged and decrypts rows written under that same key — NO rotation, the keyring and
    mfenc:v1 format are byte-identical."""

    class FakeExternalProvider:
        """Stands in for a future aws_kms/vault provider — returns the unwrapped DEK as base64."""

        def __init__(self, active: str, retired: list[str]) -> None:
            self._active, self._retired = active, retired

        def active_key(self) -> str | None:
            return self._active

        def retired_keys(self) -> list[str]:
            return self._retired

    # A row written by today's cipher under KEY_A...
    token = make_cipher(KEY_A).encrypt(ADT)
    assert token.startswith(PREFIX)

    # ...is decrypted by a cipher built from the faked provider's bytes, with no re-encryption.
    provider: KeyProvider = FakeExternalProvider(active=KEY_A, retired=[])
    assert isinstance(provider, KeyProvider)  # satisfies the protocol structurally
    cipher = make_cipher(provider.active_key(), provider.retired_keys())
    assert cipher.decrypt(token) == ADT

    # A retired key the provider surfaces bridges a mid-rotation row (per-element, not comma-joined).
    rotating: KeyProvider = FakeExternalProvider(active=KEY_B, retired=[KEY_A])
    bridge = make_cipher(rotating.active_key(), rotating.retired_keys())
    assert bridge.decrypt(token) == ADT  # old KEY_A row still readable under the new active KEY_B


def test_make_cipher_identity_when_provider_returns_none() -> None:
    # active_key() == None → make_cipher returns the identity cipher (backward-compatible default).
    provider = AutoKeyProvider(StoreSettings())
    cipher = make_cipher(provider.active_key(), provider.retired_keys())
    assert not cipher.encrypts and cipher.encrypt(ADT) == ADT


def test_wrong_provider_key_fails_loudly() -> None:
    # Sanity: a provider handing back a different key cannot decrypt — the AEAD tag still guards.
    token = make_cipher(KEY_A).encrypt(ADT)
    other = SimpleNamespace(active_key=lambda: KEY_B, retired_keys=lambda: [])
    with pytest.raises(CipherError):
        make_cipher(other.active_key(), other.retired_keys()).decrypt(token)


# --- CRYPTO-3: cross-provider active_key_id parity + same mfenc:v1 fixture ---


class _FixedExternalProvider:
    """Stands in for a future aws_kms/azure_kv/gcp_kms/vault/pkcs11 provider: envelope-decrypts a
    wrapped DEK and surfaces the SAME base64 DEK bytes the built-ins do, with NO re-encoding (the Vault
    'return plaintext with no re-encoding' contract, keyprovider_vault.py). A provider that silently
    re-encoded/normalized/double-base64'd the DEK here is exactly what this parity test must catch."""

    def __init__(self, active: str | None, retired: list[str] | None = None) -> None:
        self._active, self._retired = active, list(retired or [])

    def active_key(self) -> str | None:
        return self._active

    def retired_keys(self) -> list[str]:
        return self._retired


def test_cross_provider_active_key_id_parity_same_mfenc_v1_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRIT-1 root-of-trust pin (ADR 0019 byte-identical): the built-in auto/env/dpapi providers AND a
    faked external HSM/KMS provider, all provisioning the SAME base64 DEK, agree on a single
    ``active_key_id`` fingerprint and each decrypts one shared ``mfenc:v1`` fixture with NO rotation.
    Guards a future provider (or a change to ``_fingerprint``/``make_cipher``) that silently re-encodes,
    normalizes, or double-base64s the DEK -- which would change which key is 'active' or orphan existing
    rows."""

    # `dpapi` is the only provider that reads a file -- monkeypatch the DPAPI branch to hand back KEY_A
    # (Windows-only CryptUnprotectData avoided, matching this file's existing pattern at lines 82/112).
    monkeypatch.setattr("messagefoundry.secrets_dpapi.load_protected_key", lambda path: KEY_A)

    # Every provider is pointed at the SAME key (KEY_A); each sources it via a different mechanism.
    providers: list[KeyProvider] = [
        AutoKeyProvider(StoreSettings(encryption_key=KEY_A)),
        EnvKeyProvider(StoreSettings(encryption_key=KEY_A)),
        DpapiKeyProvider(StoreSettings(encryption_key_file="C:/x/key.dpapi")),
        _FixedExternalProvider(active=KEY_A),
    ]
    for provider in providers:
        assert isinstance(provider, KeyProvider)  # each structurally satisfies the seam

    # One mfenc:v1 row written under KEY_A -- the fixture every provider must decrypt unchanged.
    fixture = make_cipher(KEY_A).encrypt(ADT)
    assert fixture.startswith(PREFIX)  # the FROZEN default v1 writer

    fingerprints: list[str | None] = []
    for provider in providers:
        cipher = make_cipher(provider.active_key(), provider.retired_keys())
        fingerprints.append(cipher_info(cipher).active_key_id)
        assert cipher.decrypt(fixture) == ADT  # SAME fixture, NO rotation

    # Identical, non-None fingerprint across all four providers -- the root-of-trust invariant.
    assert len(set(fingerprints)) == 1
    assert fingerprints[0] is not None

    # Negative guard so the parity is not vacuous: a provider handing back a DIFFERENT key (KEY_B)
    # yields a DIFFERENT fingerprint AND cannot decrypt the KEY_A fixture (the AEAD tag still guards).
    other = make_cipher(_FixedExternalProvider(active=KEY_B).active_key())
    assert cipher_info(other).active_key_id != fingerprints[0]
    with pytest.raises(CipherError):
        other.decrypt(fixture)
