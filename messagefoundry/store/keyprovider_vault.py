# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``vault`` KeyProvider — HashiCorp Vault **Transit** envelope-decrypt of the store DEK (ADR 0019 §3).

The seam designed in [ADR 0019](../../docs/adr/0019-pluggable-keyprovider-hsm-kms-vault.md): a per-
provider follow-on that the base ``keyprovider.py`` dispatch picks up **by name** (``_load_external_
provider`` imports ``messagefoundry.store.keyprovider_<name>`` and calls its ``build_provider``), with
**no edit to keyprovider.py**. This module supplies the ``vault`` provider.

**Two-tier model (ADR 0019 §3):** a root **Key-Encryption-Key (KEK)** is held *non-extractable* inside
Vault's Transit engine; only the **wrapped DEK** (KEK-encrypted ciphertext, ``vault:v1:…``) sits at rest.
At startup we ask Transit to ``decrypt`` the wrapped DEK — the unwrap runs **inside** Vault against the
non-extractable KEK — and Vault returns the plaintext as **base64**. Because the canonical sealed form is
the **raw 32 DEK bytes** (ADR 0019 §3 "avoid double-base64"), ``response['data']['plaintext']`` is
already ``base64(raw32)`` — exactly the ``active_key()`` contract ``make_cipher`` consumes, with **no
re-encoding here**.

**Fail-closed (ADR 0019 §4):** a missing ``hvac`` extra, missing config, or any Transit/transport failure
raises :class:`~messagefoundry.store.keyprovider.KeyProviderError` — ``open_store`` propagates it so
``serve`` refuses to start rather than degrading to the identity (plaintext) cipher. **Key material is
NEVER logged or placed in an exception message** (neither the wrapped nor the plaintext DEK), consistent
with the opaque-``CipherError`` no-oracle contract and PHI.md never-log-key rules.

``hvac`` (the official HashiCorp client, Apache-2.0) is **lazy-imported** inside :func:`_import_hvac`, so
the base install pulls zero Vault SDK; it lives behind the optional ``[vault]`` extra. It ships **no type
stubs**, so the client is contained as a typed ``Any`` local here — never a repo-wide ignore.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from messagefoundry.config.tls_policy import vault_client_verify_kwargs
from messagefoundry.store.keyprovider import KeyProviderError, _split_retired

if TYPE_CHECKING:
    from messagefoundry.config.settings import StoreSettings

#: The optional extra that carries ``hvac`` — named in every fail-closed message so the operator knows
#: exactly what to install.
_EXTRA = "vault"

# Vault connection + envelope config comes from the environment (never the config file): the Vault
# address/token are secrets/host-specific and the wrapped DEK + Transit KEK name are per-deployment
# provisioning outputs. Address/token fall back to hvac's own ``VAULT_ADDR``/``VAULT_TOKEN`` conventions
# when the MEFOR_* overrides are unset, so a standard Vault agent environment works unchanged.
_ENV_ADDR = "MEFOR_STORE_VAULT_ADDR"
_ENV_TOKEN = "MEFOR_STORE_VAULT_TOKEN"  # nosec B105 — this is the env-var NAME, not a token value
#: The Transit key name (the KEK) the wrapped DEK was sealed under.
_ENV_TRANSIT_KEY = "MEFOR_STORE_VAULT_TRANSIT_KEY"
#: The wrapped DEK ciphertext (``vault:v1:…``). Not itself a secret (it is KEK-encrypted), but supplied
#: via env alongside the token so a deployment keeps all Vault wiring in one place.
_ENV_WRAPPED_DEK = "MEFOR_STORE_VAULT_WRAPPED_DEK"
#: PEM path to the CA that issued the Vault server's certificate (#1180, ASVS 12.3.4). A PATH, not a
#: secret — the same status as ``[tls].internal_ca_file`` and ``tls_cert_file``. Env-fed, beside the
#: address and token it belongs with; ``[tls].internal_ca_file`` cannot reach this hop yet, and
#: :func:`~messagefoundry.config.tls_policy.vault_client_verify_kwargs` records what that would take.
#: Unset = hvac's own default, which is ``requests``' PUBLIC certifi bundle.
_ENV_CA_FILE = "MEFOR_STORE_VAULT_CA_FILE"


def _import_hvac() -> Any:
    """Lazily import ``hvac`` (the optional ``[vault]`` extra), failing closed with a
    :class:`KeyProviderError` that names the extra — mirrors ``keyprovider.py``'s not-built-yet message.
    ``ImportError`` (not just ``ModuleNotFoundError``) is caught so a partially-broken install also fails
    closed rather than surfacing a bare import error out of ``open_store``."""
    try:
        # hvac ships no type stubs; the targeted ignore contains that here (never a repo-wide ignore).
        import hvac  # type: ignore[import-untyped]  # noqa: PLC0415  (lazy — base install pulls no SDK)
    except ImportError as exc:
        raise KeyProviderError(
            f"[store].key_provider={_EXTRA!r} requires the optional {_EXTRA!r} extra (hvac not "
            f"importable): install 'messagefoundry[{_EXTRA}]'."
        ) from exc
    return hvac


def _vault_ca_kwargs(addr: str | None) -> dict[str, str]:
    """This Vault hop's ``verify=`` keyword arguments — ``{}`` when no anchor is configured.

    #1180 (ASVS 12.3.4): the client that hands out the store's data-encryption key took no CA argument
    at all, so an operator running Vault behind their own PKI could not say so. The env-supplied CA is
    this hop's own anchor and so wins verbatim — trust ONLY it, no public bundle — exactly as a
    connection's ``tls_ca_file`` does; see
    :func:`~messagefoundry.config.tls_policy.vault_client_verify_kwargs` for the shared resolution and
    for what still has to be threaded before ``[tls].internal_ca_file`` can reach this hop.

    Fails closed here rather than there, because the error type and cell name are this module's:
    ``requests`` would otherwise raise deep inside the first Transit call, surfacing as an opaque
    store-open failure that names no cause."""
    ca = os.environ.get(_ENV_CA_FILE) or None
    if ca is not None and not os.path.isfile(ca):
        raise KeyProviderError(
            f"[store].key_provider={_EXTRA!r}: {_ENV_CA_FILE} names {ca!r}, which is not a readable "
            f"file — point it at the PEM of the CA that issued the Vault server certificate."
        )
    return vault_client_verify_kwargs(
        ca_file=ca, addr=addr, cell=f"[store].key_provider={_EXTRA!r}"
    )


def _build_client(addr: str | None, token: str | None) -> Any:
    """Construct an ``hvac.Client``. Factored out so tests can substitute a fake Transit backend without
    a live Vault. ``addr``/``token`` are passed through; when ``None``, hvac falls back to its own
    ``VAULT_ADDR``/``VAULT_TOKEN`` environment conventions."""
    hvac = _import_hvac()
    # ASVS 4.2.5: ``token`` ships as an ``X-Vault-Token`` request header on EVERY Transit
    # encrypt/decrypt/HMAC call, and ``addr`` becomes the request URL -- both from MEFOR_* env, and
    # neither was ever measured (the outbound length gate lived only in transports/). An env value
    # that resolved to an unexpected blob is exactly the misconfiguration the bound exists to surface
    # early, and here it would otherwise surface as an opaque Vault-side failure on the first
    # store read. Imported lazily so store/ does not take a transports/ import at module scope.
    from messagefoundry.transports.rest import enforce_outbound_length_limits

    enforce_outbound_length_limits(addr or "", {"X-Vault-Token": token} if token else {})
    # hvac.Client() reads VAULT_ADDR/VAULT_TOKEN from the environment when url/token are None.
    #
    # allow_redirects=False (BACKLOG #1042, ASVS 15.3.2/1.3.6): every other shipped HTTP egress
    # refuses redirects (transports/rest.py's _NO_REDIRECT_OPENER, auth/oidc_http.py's local twin),
    # and this client was the exception -- hvac's default is True. `token` rides as an
    # `X-Vault-Token` header on EVERY Transit call, so a 3xx from an on-path attacker (absent TLS
    # integrity) or a spoofed Vault would otherwise relocate the request, and requests re-sends the
    # header on a same-host redirect. Measured against hvac 2.4.0: the kwarg lands on the adapter,
    # which passes it to requests.Session.request. Shared with crypto_transit.py, so the Transit
    # cipher inherits the policy from this one construction point.
    # #1180 (ASVS 12.3.4): narrow the trust anchor when the operator named one. The keyword is OMITTED
    # when they did not, so the stock construction is unchanged rather than passed an explicit default.
    client: Any = hvac.Client(
        url=addr, token=token, allow_redirects=False, **_vault_ca_kwargs(addr)
    )
    return client


class VaultKeyProvider:
    """``vault`` — envelope-decrypt the wrapped store DEK via Vault Transit (ADR 0019 §3).

    ``active_key()`` returns the base64 32-byte DEK Vault Transit hands back; ``retired_keys()`` surfaces
    the built-in ``[store].encryption_keys_retired`` decrypt-only window (operator-supplied plaintext
    retired keys), so a rotation still bridges old ``mfenc:v1`` rows exactly as the built-in providers do.
    """

    def __init__(self, settings: StoreSettings) -> None:
        self._settings = settings

    def active_key(self) -> str | None:
        transit_key = os.environ.get(_ENV_TRANSIT_KEY)
        wrapped_dek = os.environ.get(_ENV_WRAPPED_DEK)
        if not transit_key or not wrapped_dek:
            # Fail closed: selecting `vault` without the KEK name + wrapped DEK is a misconfiguration, not
            # a "no key" (identity-cipher) degrade. The message names the missing env vars — no secrets.
            missing = [
                name
                for name, value in (
                    (_ENV_TRANSIT_KEY, transit_key),
                    (_ENV_WRAPPED_DEK, wrapped_dek),
                )
                if not value
            ]
            raise KeyProviderError(
                f"[store].key_provider={_EXTRA!r} is selected but {', '.join(missing)} is not set — "
                f"supply the Transit KEK name and the wrapped DEK via the environment."
            )
        addr = os.environ.get(_ENV_ADDR)
        token = os.environ.get(_ENV_TOKEN)
        try:
            client = _build_client(addr, token)
            # transit.decrypt_data unwraps the DEK inside Vault against the non-extractable KEK and
            # returns response['data']['plaintext'] — already base64 of the sealed raw-32 DEK bytes, so
            # it IS the active_key() contract with no re-encoding (ADR 0019 §3, no double-base64).
            response: Any = client.secrets.transit.decrypt_data(
                name=transit_key, ciphertext=wrapped_dek
            )
            plaintext = response["data"]["plaintext"]
        except KeyProviderError:
            raise
        except Exception as exc:
            # Fail closed on ANY Transit/transport/shape failure. Include ONLY the exception TYPE, never
            # its value — a Transit error can echo ciphertext, and we must never surface key material.
            raise KeyProviderError(
                f"[store].key_provider={_EXTRA!r} could not envelope-decrypt the store DEK via Vault "
                f"Transit (key {transit_key!r}): {type(exc).__name__}."
            ) from exc
        if not isinstance(plaintext, str) or not plaintext:
            raise KeyProviderError(
                f"[store].key_provider={_EXTRA!r} got an empty/non-string plaintext from Vault Transit "
                f"(key {transit_key!r}); expected a base64 32-byte DEK."
            )
        return plaintext

    def retired_keys(self) -> Sequence[str]:
        return _split_retired(self._settings.encryption_keys_retired)


def build_provider(settings: StoreSettings) -> VaultKeyProvider:
    """The dispatch entrypoint ``keyprovider._load_external_provider`` imports and calls by name."""
    return VaultKeyProvider(settings)
