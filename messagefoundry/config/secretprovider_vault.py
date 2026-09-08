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
from messagefoundry.config.tls_policy import vault_client_verify_kwargs

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
#: PEM path to the CA that issued the Vault server's certificate (#1180, ASVS 12.3.4). A PATH, not a
#: secret. The twin of the store KeyProvider's ``MEFOR_STORE_VAULT_CA_FILE``, kept separate for the
#: same reason the address and token are: the two providers may point at different Vaults. Unset =
#: hvac's own default, which is ``requests``' PUBLIC certifi bundle.
#: (:func:`~messagefoundry.config.tls_policy.vault_client_verify_kwargs` records why ``[tls]`` does
#: not reach this hop yet.)
_ENV_CA_FILE = "MEFOR_SECRETS_VAULT_CA_FILE"

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


def _vault_ca_kwargs(addr: str | None) -> dict[str, str]:
    """This Vault hop's ``verify=`` keyword arguments — ``{}`` when no anchor is configured.

    #1180 (ASVS 12.3.4) — the twin of ``store/keyprovider_vault.py``'s, sharing
    :func:`~messagefoundry.config.tls_policy.vault_client_verify_kwargs`. This client reads connector
    credentials out of Vault KV, so the anchor that verifies the server is the only thing standing
    between a spoofed Vault and every partner credential the engine holds.

    Fails closed here rather than in the shared helper, because the error type and cell name are this
    module's: ``requests`` would otherwise raise deep inside the first KV read, surfacing as an opaque
    resolution failure that names no cause."""
    ca = os.environ.get(_ENV_CA_FILE) or None
    if ca is not None and not os.path.isfile(ca):
        raise SecretProviderError(
            f"[secrets].provider={_EXTRA!r}: {_ENV_CA_FILE} names {ca!r}, which is not a readable "
            f"file — point it at the PEM of the CA that issued the Vault server certificate."
        )
    return vault_client_verify_kwargs(ca_file=ca, addr=addr, cell=f"[secrets].provider={_EXTRA!r}")


def _build_client(addr: str | None, token: str | None) -> Any:
    """Construct an ``hvac.Client``. Factored out so tests can substitute a fake KV backend without a live
    Vault. ``addr``/``token`` pass through; when ``None``, hvac falls back to its own VAULT_ADDR/VAULT_TOKEN
    environment conventions."""
    hvac = _import_hvac()
    # allow_redirects=False (BACKLOG #1042, ASVS 15.3.2/1.3.6): hvac's default is True, and this was
    # one of the three clients that did not carry the no-redirect policy every other shipped HTTP
    # egress does. `token` rides as an `X-Vault-Token` header on every KV read, so a 3xx from an
    # on-path attacker (absent TLS integrity) or a spoofed Vault would otherwise relocate the
    # request carrying it. See store/keyprovider_vault.py's twin for the measurement.
    # #1180 (ASVS 12.3.4): narrow the trust anchor when the operator named one. The keyword is OMITTED
    # when they did not, so the stock construction is unchanged rather than passed an explicit default.
    client: Any = hvac.Client(
        url=addr, token=token, allow_redirects=False, **_vault_ca_kwargs(addr)
    )
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
