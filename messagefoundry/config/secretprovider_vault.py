# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``vault`` SecretProvider — HashiCorp Vault **KV v2** read of a connector credential (ADR 0019 §5).

The connector-secret twin of [store/keyprovider_vault.py](../store/keyprovider_vault.py): the base
``secretprovider.py`` dispatch imports this module **by name** (``_load_external_provider`` imports
``messagefoundry.config.secretprovider_<name>`` and calls its ``build_provider``) with **no edit to
secretprovider.py**. Where the store's Vault provider uses **Transit** to envelope-*decrypt* the store DEK,
a connector credential (an AD bind password, an SMTP password) is a plain secret **stored in Vault**, so
this provider does a **KV v2 read** and returns the field value.

**Reference syntax:** ``resolve("<path>#<field>")`` reads the KV secret at ``<path>`` under the configured
mount and returns key ``<field>`` from it. ``<field>`` is optional and defaults to ``value`` (i.e.
``resolve("mefor/ad")`` reads field ``value`` at path ``mefor/ad``). The mount point is
``MEFOR_SECRETS_VAULT_KV_MOUNT`` (default ``secret``, Vault's conventional KV v2 mount).

**Fail-closed (mirrors ADR 0019 §4):** a missing ``hvac`` extra, missing Vault address/token config, an
absent path/field, or any KV/transport failure raises
:class:`~messagefoundry.config.secretprovider.SecretProviderError` — the credential point propagates it so
the subsystem refuses to come up rather than binding with a blank credential. **The secret value is NEVER
logged or placed in an exception message**; only the reference/path label and the failure TYPE are.

``hvac`` (the official HashiCorp client, Apache-2.0) is **lazy-imported** in :func:`_import_hvac`, behind
the **same** optional ``[vault]`` extra the store's Vault KeyProvider already declares — so the base
install pulls **zero** Vault SDK and **no new dependency** is added. It ships no type stubs, so the client
is contained as a typed ``Any`` local here (never a repo-wide ignore).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from messagefoundry.config.secretprovider import SecretProviderError

if TYPE_CHECKING:
    from messagefoundry.config.settings import SecretsSettings

#: The optional extra that carries ``hvac`` — named in every fail-closed message. Deliberately the SAME
#: extra the store's Vault KeyProvider uses (no second Vault dependency).
_EXTRA = "vault"

# Vault connection config comes from the environment (never the config file): the address/token are
# host-specific/secret. They fall back to hvac's own VAULT_ADDR/VAULT_TOKEN conventions when the MEFOR_*
# overrides are unset, so a standard Vault-agent environment works unchanged.
_ENV_ADDR = "MEFOR_SECRETS_VAULT_ADDR"
_ENV_TOKEN = "MEFOR_SECRETS_VAULT_TOKEN"  # nosec B105 — the env-var NAME, not a token value
#: KV v2 mount point the connector secrets live under (Vault's conventional default is ``secret``).
_ENV_KV_MOUNT = "MEFOR_SECRETS_VAULT_KV_MOUNT"

#: Default field read from a KV secret when a reference omits ``#<field>``.
_DEFAULT_FIELD = "value"


def _import_hvac() -> Any:
    """Lazily import ``hvac`` (the optional ``[vault]`` extra), failing closed with a
    :class:`SecretProviderError` naming the extra. ``ImportError`` (not just ``ModuleNotFoundError``) is
    caught so a partially-broken install also fails closed."""
    try:
        # hvac ships no type stubs; the targeted ignore is contained here (never a repo-wide ignore).
        import hvac  # type: ignore[import-untyped]  # noqa: PLC0415  (lazy — base install pulls no SDK)
    except ImportError as exc:
        raise SecretProviderError(
            f"[secrets].provider={_EXTRA!r} requires the optional {_EXTRA!r} extra (hvac not "
            f"importable): install 'messagefoundry[{_EXTRA}]'."
        ) from exc
    return hvac


def _build_client(addr: str | None, token: str | None) -> Any:
    """Construct an ``hvac.Client``. Factored out so tests can substitute a fake KV backend without a live
    Vault. ``addr``/``token`` pass through; when ``None``, hvac falls back to its own VAULT_ADDR/VAULT_TOKEN
    environment conventions."""
    hvac = _import_hvac()
    client: Any = hvac.Client(url=addr, token=token)
    return client


def _split_ref(ref: str) -> tuple[str, str]:
    """Split a ``<path>#<field>`` reference into ``(path, field)``; ``field`` defaults to ``value``."""
    path, sep, field = ref.partition("#")
    path = path.strip()
    field = field.strip() if sep else _DEFAULT_FIELD
    if not path or not field:
        raise SecretProviderError(
            f"[secrets].provider={_EXTRA!r}: malformed secret reference {ref!r} — expected "
            f"'<kv-path>' or '<kv-path>#<field>'."
        )
    return path, field


class VaultSecretProvider:
    """``vault`` — read a connector credential from Vault KV v2 (ADR 0019 §5)."""

    def __init__(self, settings: SecretsSettings) -> None:
        self._settings = settings

    def resolve(self, ref: str) -> str:
        path, field = _split_ref(ref)
        mount = os.environ.get(_ENV_KV_MOUNT) or "secret"
        addr = os.environ.get(_ENV_ADDR)
        token = os.environ.get(_ENV_TOKEN)
        try:
            client = _build_client(addr, token)
            # read_secret_version returns {'data': {'data': {<field>: <value>, ...}, 'metadata': {...}}}.
            response: Any = client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount)
            data = response["data"]["data"]
        except SecretProviderError:
            raise
        except Exception as exc:
            # Fail closed on ANY KV/transport/shape failure. Include ONLY the exception TYPE + the
            # reference path (not the value) — a backend error could otherwise echo secret material.
            raise SecretProviderError(
                f"[secrets].provider={_EXTRA!r} could not read secret {path!r} (field {field!r}) from "
                f"Vault KV: {type(exc).__name__}."
            ) from exc
        if not isinstance(data, dict) or field not in data:
            raise SecretProviderError(
                f"[secrets].provider={_EXTRA!r}: Vault KV secret {path!r} has no field {field!r}."
            )
        value = data[field]
        if not isinstance(value, str) or not value:
            raise SecretProviderError(
                f"[secrets].provider={_EXTRA!r}: Vault KV secret {path!r} field {field!r} is empty or "
                f"not a string."
            )
        return value


def build_provider(settings: SecretsSettings) -> VaultSecretProvider:
    """The dispatch entrypoint ``secretprovider._load_external_provider`` imports and calls by name."""
    return VaultSecretProvider(settings)
