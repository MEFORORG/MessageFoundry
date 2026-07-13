# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pluggable **SecretProvider** seam for connector credentials (ADR 0019 §5, BACKLOG #196 residual).

This is the connector-secret twin of the store-DEK :class:`~messagefoundry.store.keyprovider.KeyProvider`
seam (ADR 0019 §1-§4). Where the KeyProvider changes **how the store's at-rest DEK bytes are
provisioned**, the SecretProvider changes **how a named *connector* credential is sourced** — an AD LDAP
bind password, an SMTP password, a SQL Server auth password — resolving it from an external secrets
backend (HashiCorp Vault KV today) **instead of** a ``MEFOR_*`` environment variable.

**Mirrors the KeyProvider pattern deliberately** (§5 promised the generalization):

* A small ``@runtime_checkable`` :class:`SecretProvider` protocol — ``resolve(ref) -> str`` returns the
  secret **value** for a logical reference, or raises :class:`SecretProviderError` (fail-closed: a
  missing/erroring secret is **never** a silent no-credential).
* The provider is **selected by name** via ``[secrets].provider`` (:func:`resolve_secret_provider`):
  ``none`` (the default → env-sourced, **byte-identical** to today), the ``env`` built-in, and the
  external ``vault`` provider behind the lazy-imported ``[vault]`` extra (the **same** ``hvac`` dependency
  the store's Vault KeyProvider already uses — **no new dependency**).
* External providers are **lazy optional extras** (:func:`_load_external_provider` imports
  ``messagefoundry.config.secretprovider_<name>`` and calls its ``build_provider``), so the base install
  pulls **zero** Vault SDK; selecting one without its extra **fails closed** naming the extra.

**Default is byte-identical.** With ``[secrets].provider`` unset/``none`` there is **no** provider: each
credential point keeps reading its ``MEFOR_*`` env-sourced settings value exactly as before. A provider is
consulted **only** for a credential whose per-credential ``*_secret`` reference is set (e.g.
``[auth].ad_bind_password_secret``); an unset reference always falls through to the env literal.

**Fail-closed contract (mirrors ADR 0019 §4).** :func:`resolve_connector_secret` raises
:class:`SecretProviderError` when a secret reference is configured but no provider is (a misconfiguration,
never a blank credential), and any backend/transport failure inside a provider raises the same — the
credential point propagates it so the affected subsystem refuses to come up rather than binding
anonymously. **A secret value is NEVER logged or placed in an exception message** (consistent with the
KeyProvider's no-oracle contract and PHI.md never-log rules).
"""

from __future__ import annotations

import importlib
import os
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from messagefoundry.config.settings import SecretsSettings

__all__ = [
    "SecretProvider",
    "SecretProviderError",
    "EnvSecretProvider",
    "KNOWN_PROVIDERS",
    "resolve_secret_provider",
    "resolve_connector_secret",
]


class SecretProviderError(RuntimeError):
    """The configured ``[secrets].provider`` could not provision a connector secret — an unknown provider
    name, an external provider selected without its extra, a reference configured with no provider, or a
    backend/transport failure resolving the reference. Raised out of :func:`resolve_secret_provider` /
    :func:`resolve_connector_secret` (and thus out of the credential point that consumes it) so the
    affected subsystem **fails closed** rather than proceeding with a blank credential — mirroring the
    store KeyProvider's :class:`~messagefoundry.store.keyprovider.KeyProviderError`."""


@runtime_checkable
class SecretProvider(Protocol):
    """How a named connector credential is sourced (ADR 0019 §5).

    ``resolve(ref)`` returns the secret **value** for a logical reference string, or raises
    :class:`SecretProviderError`. The reference syntax is provider-specific (an env var name for
    :class:`EnvSecretProvider`; a Vault KV ``path#field`` for the ``vault`` provider). A provider **must
    never** return an empty string as "resolved" and must **never** log or embed the value in an error."""

    def resolve(self, ref: str) -> str: ...


class EnvSecretProvider:
    """``env`` — resolve a reference as the name of a ``MEFOR_*`` environment variable.

    A degenerate-but-useful built-in: it keeps the env as the source of truth while still routing through
    the provider seam (so a deployment can standardize on ``[secrets].provider = env`` and per-credential
    ``*_secret`` references without an external backend). Fail-closed: an unset/blank env var raises rather
    than yielding a blank credential."""

    def resolve(self, ref: str) -> str:
        value = os.environ.get(ref)
        if not value:
            # Name the env var (not a value) so the operator can fix it; a blank/unset secret is a
            # misconfiguration, never a silent anonymous credential.
            raise SecretProviderError(
                f"[secrets].provider='env': secret reference {ref!r} names an environment variable that "
                f"is unset or empty — set it, or correct the reference."
            )
        return value


#: Built-in providers — no external dependency.
_BUILTIN_PROVIDERS = ("env",)

#: External provider name → optional ``pyproject`` extra carrying its SDK. ``vault`` reuses the SAME
#: ``[vault]`` / ``hvac`` extra the store's Vault KeyProvider already declares — no new dependency lands.
#: NOT built into this module — see :func:`_load_external_provider`. ``provider`` is **not** a secret: it
#: names a backend, not credential material, so it must never be treated as one.
_EXTERNAL_PROVIDERS: dict[str, str] = {
    "vault": "vault",
}

#: Every accepted ``[secrets].provider`` value (``none`` + built-in + external), for validation + errors.
KNOWN_PROVIDERS: tuple[str, ...] = ("none", *_BUILTIN_PROVIDERS, *tuple(_EXTERNAL_PROVIDERS))


def _load_external_provider(name: str, settings: SecretsSettings) -> SecretProvider:
    """Lazy hook for an external secrets backend (mirrors ``keyprovider._load_external_provider``).

    The seam: a per-provider module ``messagefoundry/config/secretprovider_<name>.py`` exposes
    ``build_provider(settings) -> SecretProvider`` behind an optional extra; this dispatch imports it by
    name with **no edit here**. A missing provider module or a missing backend SDK **fails closed** naming
    the extra — the base install pulls **zero** external SDK."""
    extra = _EXTERNAL_PROVIDERS[name]
    module_name = f"{__name__}_{name}"
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name:
            # The provider module itself isn't present (should not happen for a shipped provider).
            raise SecretProviderError(
                f"[secrets].provider={name!r} is not available — its provider module did not import."
            ) from exc
        # The provider module shipped but its backend SDK (e.g. hvac) is missing — install the extra.
        raise SecretProviderError(
            f"[secrets].provider={name!r} could not load its backend ({exc.name!r} is missing) — "
            f"install the optional {extra!r} extra ('messagefoundry[{extra}]')."
        ) from exc
    provider: SecretProvider = module.build_provider(settings)
    return provider


def resolve_secret_provider(settings: SecretsSettings) -> SecretProvider | None:
    """Build the :class:`SecretProvider` selected by ``[secrets].provider``, or ``None`` for ``none``.

    ``none`` (the default) returns ``None`` → the **env-sourced default path**, byte-identical to today
    (no provider is ever consulted). ``env`` is the built-in; ``vault`` is the lazy optional extra. An
    unknown name **fails closed** with :class:`SecretProviderError`."""
    name = settings.provider
    if name in ("", "none"):
        return None
    if name == "env":
        return EnvSecretProvider()
    if name in _EXTERNAL_PROVIDERS:
        return _load_external_provider(name, settings)
    raise SecretProviderError(
        f"unknown [secrets].provider {name!r}; valid values are {', '.join(KNOWN_PROVIDERS)}"
    )


def resolve_connector_secret(
    provider: SecretProvider | None,
    *,
    ref: str | None,
    literal: str | None,
    label: str,
) -> str | None:
    """Resolve one connector credential: the provider-sourced value when ``ref`` is set, else the
    env-sourced ``literal`` (byte-identical to today).

    * ``ref`` **unset** → return ``literal`` unchanged (the ``MEFOR_*`` env value the credential point
      already loads). No provider is consulted — the default path.
    * ``ref`` **set**, ``provider`` **None** → **fail closed** (:class:`SecretProviderError`): a reference
      is meaningless without a provider, and silently using the ``literal`` would mask the misconfiguration.
    * ``ref`` **set**, ``provider`` present → return ``provider.resolve(ref)`` (which itself fails closed
      on a missing/erroring secret).

    ``label`` names the credential (e.g. ``"[auth].ad_bind_password"``) for the error only — never a value.
    """
    if not ref:
        return literal
    if provider is None:
        raise SecretProviderError(
            f"{label}: a secret reference is configured ({label}_secret) but [secrets].provider is unset "
            f"('none'). Set [secrets].provider (e.g. 'vault'), or remove the reference to use the "
            f"environment-sourced value."
        )
    return provider.resolve(ref)
