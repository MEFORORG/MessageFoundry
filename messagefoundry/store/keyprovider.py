# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pluggable KeyProvider seam for sourcing the store's at-rest data-encryption key (ASVS 13.3.3).

This is the seam designed in [ADR 0019](../../docs/adr/0019-pluggable-keyprovider-hsm-kms-vault.md):
it changes **only how** the base64 active/retired DEK bytes are *provisioned*, never how they are used.
The :class:`~messagefoundry.store.crypto.Cipher`/``AesGcmCipher`` keyring, the ``mfenc:v1:<key_id>``
stored format, ``rotate-key``, and every backend are **byte-identical** when ``[store].key_provider`` is
unset/``auto``.

A :class:`KeyProvider` returns exactly the bytes :func:`~messagefoundry.store.crypto.make_cipher` already
consumes — ``active_key()`` is the base64 of a 32-byte DEK (or ``None`` → identity cipher) and
``retired_keys()`` is the decrypt-only keyring for a rotation window. Because the provider returns the
*same* key bytes, existing ``mfenc:v1`` rows decrypt with **no rotation**.

**Element-level contract for ``retired_keys()``** (ADR 0019 §1): it returns a ``Sequence`` of
**individual** base64 32-byte DEK strings — one element per key, each fed straight through
``_decode_key``. Do **not** pre-join with commas; the comma-split is a property only of the built-in
``[store].encryption_keys_retired`` string (handled here by :func:`_split_retired`).

**Providers** (dispatched by :func:`resolve_key_provider` on ``[store].key_provider``):

* ``auto`` (default) — the env-then-DPAPI ladder, **byte-identical** to the pre-seam ``resolve_active_key``.
* ``env`` — the ``MEFOR_STORE_ENCRYPTION_KEY`` value (``settings.encryption_key``).
* ``dpapi`` — the Windows DPAPI-protected ``encryption_key_file`` decrypted into memory.
* ``aws_kms`` | ``azure_kv`` | ``gcp_kms`` | ``vault`` | ``pkcs11`` — external HSM/KMS/Vault providers that
  **envelope-decrypt** a wrapped DEK inside an isolated security module. These are **lazy, optional
  extras** that are **not built here** (ADR 0019 §3/§5 — one provider per follow-on PR), so the base
  install pulls **zero** cloud SDKs. Selecting one before its module ships **fails closed** (ADR 0019
  §4) — it raises :class:`KeyProviderError` out of ``resolve_active_key``, never a silent degrade to the
  identity (plaintext) cipher.
"""

from __future__ import annotations

import importlib
from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from messagefoundry.config.settings import StoreSettings


class KeyProviderError(RuntimeError):
    """The configured ``[store].key_provider`` could not provision a key — an unknown provider name, or
    an external provider that is selected but not built / cannot resolve. Raised out of
    :func:`resolve_key_provider` (and thus ``resolve_active_key``) so ``open_store`` propagates it and
    ``serve`` **fails to start** rather than degrading to the identity cipher (ADR 0019 §4), mirroring
    the existing fail-closed ``DpapiError``/``DpapiUnavailable`` contract for an unreadable key file."""


@runtime_checkable
class KeyProvider(Protocol):
    """How the store's active/retired DEK bytes are provisioned (ADR 0019 §1).

    The contract is exactly what :func:`~messagefoundry.store.crypto.make_cipher` accepts:
    ``active_key()`` returns the base64 of a 32-byte DEK (or ``None`` → identity cipher) and
    ``retired_keys()`` returns the per-element decrypt-only keyring (default ``()``)."""

    def active_key(self) -> str | None: ...

    def retired_keys(self) -> Sequence[str]: ...


def _split_retired(retired: str) -> list[str]:
    """Comma-split the built-in ``[store].encryption_keys_retired`` string into the per-element list
    ``make_cipher`` expects (empties filtered) — the same split ``open_store`` has always applied."""
    return [k.strip() for k in retired.split(",") if k.strip()]


class EnvKeyProvider:
    """``env`` — the ``MEFOR_STORE_ENCRYPTION_KEY`` value (``settings.encryption_key``)."""

    def __init__(self, settings: StoreSettings) -> None:
        self._settings = settings

    def active_key(self) -> str | None:
        return self._settings.encryption_key or None

    def retired_keys(self) -> Sequence[str]:
        return _split_retired(self._settings.encryption_keys_retired)


class DpapiKeyProvider:
    """``dpapi`` — the Windows DPAPI-protected ``encryption_key_file`` ``CryptUnprotectData``'d into the
    base64 store key (WP-11d). A configured-but-unreadable/foreign file raises ``DpapiError`` here
    (fail-closed); an unset file yields ``None`` (→ identity cipher)."""

    def __init__(self, settings: StoreSettings) -> None:
        self._settings = settings

    def active_key(self) -> str | None:
        if not self._settings.encryption_key_file:
            return None
        from messagefoundry.secrets_dpapi import load_protected_key

        return load_protected_key(self._settings.encryption_key_file)

    def retired_keys(self) -> Sequence[str]:
        return _split_retired(self._settings.encryption_keys_retired)


class AutoKeyProvider:
    """``auto`` (the default) — the env-then-DPAPI ladder: the env key if set, else the DPAPI key file.

    **BYTE-IDENTICAL** to the pre-seam ``resolve_active_key``: the env key takes precedence so a
    deployment can override the file, and a configured-but-unreadable key file raises ``DpapiError``
    (fail-closed, not silently unencrypted)."""

    def __init__(self, settings: StoreSettings) -> None:
        self._settings = settings

    def active_key(self) -> str | None:
        if self._settings.encryption_key:
            return self._settings.encryption_key
        if self._settings.encryption_key_file:
            from messagefoundry.secrets_dpapi import load_protected_key

            return load_protected_key(self._settings.encryption_key_file)
        return None

    def retired_keys(self) -> Sequence[str]:
        return _split_retired(self._settings.encryption_keys_retired)


#: Built-in providers — fully reproduce today's behavior, no external dependency.
_BUILTIN_PROVIDERS = ("auto", "env", "dpapi")

#: External provider name → optional ``pyproject`` extra that will carry its SDK. Each envelope-decrypts
#: a wrapped DEK inside an isolated security module (ADR 0019 §3). NOT built here — see
#: :func:`_load_external_provider`. ``key_provider`` is **not** a file-secret: it names a provider, not
#: key material, so it must never be added to ``_FILE_SECRET_KEYS`` (ADR 0019 §2).
_EXTERNAL_PROVIDERS: dict[str, str] = {
    "aws_kms": "aws_kms",
    "azure_kv": "azure_kv",
    "gcp_kms": "gcp_kms",
    "vault": "vault",
    "pkcs11": "pkcs11",
}

#: Every accepted ``[store].key_provider`` value (built-in + external), for validation + error messages.
KNOWN_PROVIDERS: tuple[str, ...] = (*_BUILTIN_PROVIDERS, *tuple(_EXTERNAL_PROVIDERS))


def _load_external_provider(name: str, settings: StoreSettings) -> KeyProvider:
    """Lazy hook for an external HSM/KMS/Vault envelope-decrypt provider (ADR 0019 §3).

    The seam: a future per-provider PR ships ``messagefoundry/store/keyprovider_<name>.py`` exposing
    ``build_provider(settings) -> KeyProvider`` behind the optional ``<extra>`` extra; this dispatch
    picks it up by import with **no edit here**. Until that module ships the import fails and we **fail
    closed** — the base install pulls **zero** cloud SDKs (no dependency lands from ADR 0019)."""
    extra = _EXTERNAL_PROVIDERS[name]
    module_name = f"{__name__}_{name}"
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name:
            # The provider module itself hasn't shipped yet (the common case today).
            raise KeyProviderError(
                f"[store].key_provider={name!r} (external HSM/KMS/Vault envelope decryption, ADR 0019 "
                f"§3) is designed but not built yet — it lands per-provider under WP-BL3-04 behind the "
                f"optional {extra!r} extra. Use 'auto' (default), 'env', or 'dpapi' until then."
            ) from exc
        # The provider module shipped but a backend it imports (e.g. its cloud SDK) is missing — a
        # distinct, actionable failure: install the extra rather than "not built yet".
        raise KeyProviderError(
            f"[store].key_provider={name!r} could not load its backend ({exc.name!r} is missing) — "
            f"install the optional {extra!r} extra."
        ) from exc
    # The provider module owns its own construction; annotate the local so mypy keeps the contract.
    provider: KeyProvider = module.build_provider(settings)
    return provider


def resolve_key_provider(settings: StoreSettings) -> KeyProvider:
    """Build the :class:`KeyProvider` selected by ``[store].key_provider`` (ADR 0019 §2).

    ``auto`` (default) / ``env`` / ``dpapi`` are the built-ins; the external HSM/KMS/Vault names are
    lazy optional extras (:func:`_load_external_provider`). An unknown name **fails closed** with
    :class:`KeyProviderError` rather than silently falling back to the identity cipher."""
    name = settings.key_provider
    if name == "auto":
        return AutoKeyProvider(settings)
    if name == "env":
        return EnvKeyProvider(settings)
    if name == "dpapi":
        return DpapiKeyProvider(settings)
    if name in _EXTERNAL_PROVIDERS:
        return _load_external_provider(name, settings)
    raise KeyProviderError(
        f"unknown [store].key_provider {name!r}; valid values are {', '.join(KNOWN_PROVIDERS)}"
    )
