"""Windows DPAPI secret-at-rest helper + store key-file resolution (WP-11d, ASVS 13.3.1/13.3.2).

The actual CryptProtectData round-trips are Windows-only (skipped elsewhere); the platform guard and
the `resolve_active_key` precedence are exercised on every CI leg via monkeypatching."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from messagefoundry.config.settings import StoreSettings, load_settings
from messagefoundry.secrets_dpapi import (
    DpapiError,
    DpapiUnavailable,
    dpapi_available,
    dpapi_protect,
    dpapi_unprotect,
    load_protected_key,
    protect_key_to_file,
)
from messagefoundry.store.base import resolve_active_key
from messagefoundry.store.crypto import generate_key

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")


def test_dpapi_available_matches_platform() -> None:
    assert dpapi_available() == (sys.platform == "win32")


def test_protect_and_unprotect_raise_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    # The Windows-only guard fires on a simulated non-Windows platform — callers must degrade to the
    # env-var key, never silently store unprotected. Covered on every platform.
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(DpapiUnavailable):
        dpapi_protect(b"secret")
    with pytest.raises(DpapiUnavailable):
        dpapi_unprotect(b"blob")


@windows_only
def test_dpapi_roundtrip() -> None:
    secret = b"a binary \x00\x01\xff payload"
    blob = dpapi_protect(secret)
    assert blob != secret  # actually encrypted, not pass-through
    assert dpapi_unprotect(blob) == secret


@windows_only
def test_dpapi_user_scope_roundtrip() -> None:
    secret = b"user-scoped secret"
    assert dpapi_unprotect(dpapi_protect(secret, machine_scope=False)) == secret


@windows_only
def test_key_file_roundtrip(tmp_path: Path) -> None:
    key = generate_key()
    out = tmp_path / "key.dpapi"
    protect_key_to_file(key, out)
    assert out.read_bytes() != key.encode("ascii")  # the file holds ciphertext, not the key
    assert load_protected_key(out) == key


def test_load_protected_key_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(DpapiError, match="cannot read"):
        load_protected_key(tmp_path / "does-not-exist.dpapi")


# --- resolve_active_key precedence (store/base.py) ---------------------------


def test_resolve_prefers_env_key_over_file(monkeypatch: pytest.MonkeyPatch) -> None:
    # When encryption_key is set it wins and the DPAPI file is never read (env overrides the file).
    def _boom(_path: object) -> str:
        raise AssertionError("key file must not be read when encryption_key is set")

    monkeypatch.setattr("messagefoundry.secrets_dpapi.load_protected_key", _boom)
    s = StoreSettings(encryption_key="QUJD", encryption_key_file="C:/x/key.dpapi")
    assert resolve_active_key(s) == "QUJD"


def test_resolve_uses_key_file_when_no_env_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "messagefoundry.secrets_dpapi.load_protected_key", lambda path: f"decrypted:{path}"
    )
    s = StoreSettings(encryption_key=None, encryption_key_file="C:/x/key.dpapi")
    assert resolve_active_key(s) == "decrypted:C:/x/key.dpapi"


def test_resolve_none_when_neither_configured() -> None:
    assert resolve_active_key(StoreSettings()) is None


def test_encryption_key_file_loads_from_env() -> None:
    # MEFOR_STORE_ENCRYPTION_KEY_FILE routes to [store].encryption_key_file (it's a path, not a secret).
    settings = load_settings(environ={"MEFOR_STORE_ENCRYPTION_KEY_FILE": "C:/data/key.dpapi"})
    assert settings.store.encryption_key_file == "C:/data/key.dpapi"
