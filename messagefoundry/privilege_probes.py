# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The read-only Vault and LDAP probes behind ``messagefoundry check-privileges`` (BACKLOG #305,
ASVS 13.2.2).

:mod:`messagefoundry.privilege_check` is pure and judges what these return; this module is the half
that touches the network. Each probe goes through the client the engine already builds for that hop,
so it carries the same TLS narrowing, trust anchor, redirect refusal and cleartext refusal, and adds
no client of its own:

* **Vault**, per token: ``GET /v1/auth/token/lookup-self`` for the token's policies, TTL and
  renewability, then one ``POST /v1/sys/capabilities-self`` for the exact paths the engine calls
  plus the paths it never needs (:func:`~messagefoundry.privilege_check.vault_admin_paths`). Both
  are calls a token's ``default`` policy allows, and both only read. Only the token named in the
  hop's own ``MEFOR_*_VAULT_TOKEN`` is read, never one hvac would fall back to.
* **LDAP**: the RFC 4532 "Who am I?" extended operation on the service-account bind, then a read of
  that account's own groups (:meth:`~messagefoundry.auth.ldap.LdapAuthenticator.read_bind_account`).

**A probe never raises.** Anything that stops it -- no extra, no address, a refused cleartext
address, an unreachable server, a 403 on the lookup -- comes back as a problem string, which the
read-out reports as ``unobservable``. **Nothing secret is kept:** never the token, its accessor or
its id, and never a bind password. A problem names the exception type, or the engine's own fixed
refusal text, never a server's error body.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from messagefoundry.controlchars import strip_control_chars
from messagefoundry.privilege_check import printable, vault_admin_paths

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from messagefoundry.auth.ldap import BindAccountReading
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.config.tls_policy import HopPosture
    from messagefoundry.privilege_check import VaultConsumer

__all__ = [
    "VaultTokenReading",
    "probe_vault",
    "read_ldap_bind",
    "read_vault_token",
]


@dataclass(frozen=True, slots=True)
class VaultTokenReading:
    """What one Vault token said about itself. Holds no part of the token.

    ``required`` is each path the engine calls with the capabilities that call needs; it is empty
    when the paths could not be named. ``admin_paths`` is every path asked about that the engine
    never calls (:func:`~messagefoundry.privilege_check.vault_admin_paths`). ``capabilities`` is
    Vault's answer for both sets. ``problems`` names every part that could not be read.

    ``token_ref`` is a SHA-256 digest of the token, kept only so :meth:`same_token_as` can tell
    when two hops hold one token, whatever the token type and whether or not lookup-self answered.
    It is never printed: it is out of ``repr`` and out of every hop's text. A digest of a
    high-entropy token gives nothing back to a reader, but it is still not shown."""

    looked_up: bool = False
    policies: tuple[str, ...] = ()
    ttl: int | None = None
    renewable: bool | None = None
    required: Mapping[str, frozenset[str]] = field(default_factory=dict)
    admin_paths: tuple[str, ...] = ()
    capabilities: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    problems: tuple[str, ...] = ()
    token_ref: str | None = field(default=None, repr=False, compare=False)

    def same_token_as(self, other: VaultTokenReading) -> bool:
        """Whether both readings were taken with the same token. ``False`` when either has no
        token to compare, because its token variable was unset."""
        return self.token_ref is not None and self.token_ref == other.token_ref


def _problem(text: str) -> str:
    """Log one probe problem and return it. The text is already secret-free (:func:`_why`), and
    is logged without control or format characters, as it is printed."""
    logger.warning("check-privileges: %s", printable(text))
    return text


def _why(exc: BaseException) -> str:
    """A problem text that cannot carry a secret or a server's error body."""
    from messagefoundry.auth.ldap import LdapError
    from messagefoundry.config.secretprovider import SecretProviderError
    from messagefoundry.config.tls_policy import InsecureHopRefused
    from messagefoundry.store.keyprovider import KeyProviderError

    # The engine's own fail-closed types carry fixed, secret-free text by contract; the cleartext
    # refusal (BACKLOG #2317) arrives wrapped in one of them. An LdapError from a failed bind carries
    # ldap3's result line, which names no password. A directory may supply control characters.
    if isinstance(exc, (KeyProviderError, SecretProviderError, LdapError, InsecureHopRefused)):
        return strip_control_chars(str(exc))
    name = type(exc).__name__
    # hvac maps a 403 to Forbidden; say what it means without importing hvac here.
    if name == "Forbidden":
        return f"permission denied ({name})"
    if type(exc) is ValueError:
        # Exactly ValueError, not a subclass: the probe's own shape refusals and the TLS-suite
        # assertion raise it with engine-written text. A subclass, such as a JSON decode error,
        # can quote what the server sent, so it keeps the type name alone.
        return f"{name}: {strip_control_chars(str(exc))[:200]}"
    return name


def _strings(value: object) -> tuple[str, ...]:
    """The string members of a Vault list, kept EXACTLY as Vault sent them. A policy name is also
    a path the probe asks about, so altering it here would ask about a different policy. Every
    printed or logged text goes through ``printable()`` at the output boundary instead."""
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(v for v in value if isinstance(v, str))


def read_vault_token(
    token: Callable[[], str],
    build_client: Callable[[str], Any],
    required: Callable[[], Mapping[str, frozenset[str]]],
) -> VaultTokenReading:
    """Read one token's own policies and capabilities through the engine's client for that hop.

    ``token`` returns the token named in the hop's own variable and refuses when it is unset, so
    hvac never substitutes ``VAULT_TOKEN``. ``build_client`` is the hop's own constructor, and
    ``required`` names the paths the engine calls on it; all three live beside the calls they
    describe (``store/keyprovider_vault.py``, ``store/crypto_transit.py``,
    ``config/secretprovider_vault.py``)."""
    problems: list[str] = []
    try:
        named = token()
        client = build_client(named)
    except Exception as exc:  # an unset token or a refused client: reported, never raised
        return VaultTokenReading(problems=(_problem(f"no Vault client: {_why(exc)}"),))
    token_ref = hashlib.sha256(named.encode("utf-8")).hexdigest()
    try:
        needed = dict(required())
    except Exception as exc:  # an unset key name or a malformed reference
        needed = {}
        problems.append(_problem(_why(exc)))

    looked_up = False
    policies: tuple[str, ...] = ()
    ttl: int | None = None
    renewable: bool | None = None
    try:
        response: Any = client.auth.token.lookup_self()
        data = response.get("data") if isinstance(response, Mapping) else None
        if not isinstance(data, Mapping):
            raise ValueError("lookup-self returned no data")
        looked_up = True
        # Policies attached to the token and those reaching it through an identity entity or group.
        policies = tuple(
            sorted({*_strings(data.get("policies")), *_strings(data.get("identity_policies"))})
        )
        raw_ttl = data.get("ttl")
        ttl = raw_ttl if isinstance(raw_ttl, int) and not isinstance(raw_ttl, bool) else None
        raw_renewable = data.get("renewable")
        renewable = raw_renewable if isinstance(raw_renewable, bool) else None
    except OSError as exc:
        # A transport failure (requests' errors are OSErrors): the capabilities read would wait out
        # the same timeout against the same server, so it is not sent.
        problems.append(_problem(f"token lookup-self failed: {_why(exc)}"))
        return VaultTokenReading(required=needed, problems=tuple(problems), token_ref=token_ref)
    except Exception as exc:  # Vault answered and refused, or answered in an unexpected shape
        problems.append(_problem(f"token lookup-self failed: {_why(exc)}"))

    from messagefoundry.store.keyprovider_vault import TRANSIT_MOUNT

    admin = vault_admin_paths(needed, policies, transit_mount=TRANSIT_MOUNT)
    capabilities: dict[str, tuple[str, ...]] = {}
    paths = [*needed, *admin]
    try:
        answer: Any = client.sys.get_capabilities(paths=paths)
        # Vault answers each path at the top level and again under "data"; read the "data" copy.
        body = answer.get("data") if isinstance(answer, Mapping) else None
        if not isinstance(body, Mapping):
            body = answer if isinstance(answer, Mapping) else {}
        for path in paths:
            caps = body.get(path)
            if isinstance(caps, list):
                capabilities[path] = _strings(caps)
            else:
                problems.append(_problem(f"capabilities-self returned nothing for {path}"))
    except Exception as exc:  # Vault refused or could not be reached: reported, never raised
        problems.append(_problem(f"capabilities-self failed: {_why(exc)}"))

    return VaultTokenReading(
        looked_up=looked_up,
        policies=policies,
        ttl=ttl,
        renewable=renewable,
        required=needed,
        admin_paths=admin,
        capabilities=capabilities,
        problems=tuple(problems),
        token_ref=token_ref,
    )


def probe_vault(consumer: VaultConsumer) -> VaultTokenReading:
    """Read the token behind one Vault consumer, with the client and paths of the provider that
    uses it. Imports lazily, as the providers do, so the command stays light without Vault."""
    kind = consumer.kind
    if kind == "kv":
        from messagefoundry.config.secretprovider_vault import (
            kv_required_capabilities,
            secrets_vault_client,
            secrets_vault_token,
        )

        return read_vault_token(
            secrets_vault_token,
            secrets_vault_client,
            lambda: kv_required_capabilities(consumer.refs),
        )
    from messagefoundry.store.keyprovider_vault import (
        kek_required_capabilities,
        store_vault_client,
        store_vault_token,
    )

    if kind == "transit":
        from messagefoundry.store.crypto_transit import transit_cipher_required_capabilities

        return read_vault_token(
            store_vault_token, store_vault_client, transit_cipher_required_capabilities
        )
    if kind == "kek":
        return read_vault_token(store_vault_token, store_vault_client, kek_required_capabilities)
    # Unreachable while VaultKind has three members; a fourth must be routed here, not defaulted.
    raise ValueError(f"no Vault probe for consumer kind {kind!r}")


def read_ldap_bind(settings: ServiceSettings, posture: HopPosture | None) -> BindAccountReading:
    """Build the AD authenticator with the arguments ``AuthService`` gives it and read its bind
    account. The bind password resolves through ``[secrets]`` as it does under ``serve``, except
    that a Vault-held password is read only with the token in ``MEFOR_SECRETS_VAULT_TOKEN`` from the
    Vault in ``MEFOR_SECRETS_VAULT_ADDR``, never ones hvac would substitute. Any failure comes back in ``problem``; this never raises."""
    from messagefoundry.auth.ldap import BindAccountReading, LdapAuthenticator
    from messagefoundry.config.secretprovider import resolve_secret_provider
    from messagefoundry.config.settings import SecurityEnforcement

    try:
        if settings.auth.ad_bind_password_secret and settings.secrets.provider == "vault":
            from messagefoundry.config.secretprovider_vault import (
                secrets_vault_address,
                secrets_vault_token,
            )

            # Refuse before any read when the engine's token or address is unset, so hvac never
            # substitutes VAULT_TOKEN, or sends the engine's token to VAULT_ADDR.
            secrets_vault_token()
            secrets_vault_address()
        authenticator = LdapAuthenticator(
            settings.auth,
            secret_provider=resolve_secret_provider(settings.secrets),
            posture=posture,
            enforcing=settings.security.enforcement is SecurityEnforcement.ENFORCE,
        )
    except Exception as exc:  # no extra, no CA file, an unset token: reported, never raised
        return BindAccountReading(
            None, problem=_problem(f"AD bind probe not run: {_why(exc)}"), bound=False
        )
    try:
        return authenticator.read_bind_account()
    except Exception as exc:  # the bind itself failed: reported, never raised
        return BindAccountReading(
            None, problem=_problem(f"AD bind probe: {_why(exc)}"), bound=False
        )
