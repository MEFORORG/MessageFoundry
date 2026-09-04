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

from messagefoundry.config.tls_policy import assert_hvac_tls_suites
from messagefoundry.store.keyprovider import KeyProviderError, _split_retired

if TYPE_CHECKING:
    from messagefoundry.config.settings import StoreSettings

#: The optional extra that carries ``hvac`` — named in every fail-closed message so the operator knows
#: exactly what to install.
_EXTRA = "vault"

#: Operator-recognisable label for this hop, carried into the TLS suite assertion's error. Distinct
#: from the KV secret provider's label so a refusal names which Vault client refused.
_VAULT_TRANSIT_CONNECTOR = "Vault Transit key provider"

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
    #
    # ONE dict feeds both the assertion and the construction, deliberately. The LDAPS site had to
    # grow a second test to prove its asserted arguments were the ones its bind used, because the two
    # lived in different methods; here they cannot drift, because they are the same object.
    kwargs: dict[str, object] = {"url": addr, "token": token, "allow_redirects": False}
    # ASVS 12.1.2 (BACKLOG #1317, ADR 0180): hvac exposes no SSLContext, so this asserts the context
    # urllib3 will build for this hop. Raises ValueError at construction. Shared with
    # crypto_transit.py, so the Transit cipher's client inherits the assertion from here too — the
    # two construction points cover all THREE hvac clients the engine builds.
    assert_hvac_tls_suites(kwargs, connector=_VAULT_TRANSIT_CONNECTOR)
    client: Any = hvac.Client(**kwargs)
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
        # OUTSIDE the try on purpose. The TLS suite assertion inside `_build_client` raises
        # ValueError, and the `except Exception` below would relabel it "could not envelope-decrypt
        # the store DEK" — turning a configuration refusal into what reads as a Vault-side failure,
        # the same mistake ADR 0180 records for the LDAPS site. Fail-closed is unchanged either way:
        # both paths propagate out of open_store and serve refuses to start.
        client = _build_client(addr, token)
        try:
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
