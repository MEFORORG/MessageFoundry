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
  plus :data:`~messagefoundry.privilege_check.VAULT_ADMIN_PATHS`. Both are calls a token's
  ``default`` policy allows, and both only read.
* **LDAP**: the RFC 4532 "Who am I?" extended operation on the service-account bind, then a read of
  that account's own groups (:meth:`~messagefoundry.auth.ldap.LdapAuthenticator.read_bind_account`).

**A probe never raises.** Anything that stops it -- no extra, no address, a refused cleartext
address, an unreachable server, a 403 on the lookup -- comes back as a problem string, which the
read-out reports as ``unobservable``. **Nothing secret is kept:** never the token, its accessor or
its id, and never a bind password. A problem names the exception type, or the engine's own fixed
refusal text, never a server's error body.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from messagefoundry.controlchars import strip_control_chars
from messagefoundry.privilege_check import VAULT_ADMIN_PATHS

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
    when the paths could not be named. ``capabilities`` is Vault's answer for those paths and for
    the administrative ones. ``problems`` names every part that could not be read.

    ``token_ref`` is the token's ACCESSOR, as lookup-self reported it. It is kept only so
    :meth:`same_token_as` can tell when two hops hold one token, and it is never printed: it is out
    of ``repr`` and out of every hop's text. An accessor cannot authenticate, but with the right
    policy it can look up or revoke the token, so it is treated as a value not to show."""

    looked_up: bool = False
    policies: tuple[str, ...] = ()
    ttl: int | None = None
    renewable: bool | None = None
    required: Mapping[str, frozenset[str]] = field(default_factory=dict)
    capabilities: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    problems: tuple[str, ...] = ()
    token_ref: str | None = field(default=None, repr=False, compare=False)

    def same_token_as(self, other: VaultTokenReading) -> bool:
        """Whether lookup-self named the same token for both readings. ``False`` when either could
        not name its token."""
        return self.token_ref is not None and self.token_ref == other.token_ref


def _problem(text: str) -> str:
    """Log one probe problem and return it. The text is already secret-free (:func:`_why`)."""
    logger.warning("check-privileges: %s", text)
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
    return f"permission denied ({name})" if name == "Forbidden" else name


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(strip_control_chars(v) for v in value if isinstance(v, str))


def read_vault_token(
    build_client: Callable[[], Any], required: Callable[[], Mapping[str, frozenset[str]]]
) -> VaultTokenReading:
    """Read one token's own policies and capabilities through the engine's client for that hop.

    ``build_client`` is the hop's own constructor, and ``required`` names the paths the engine calls
    on it; both live beside the calls they describe (``store/keyprovider_vault.py``,
    ``store/crypto_transit.py``, ``config/secretprovider_vault.py``)."""
    problems: list[str] = []
    try:
        client = build_client()
    except Exception as exc:  # any build failure is this hop's finding, reported, never raised
        return VaultTokenReading(problems=(_problem(f"no Vault client: {_why(exc)}"),))
    try:
        needed = dict(required())
    except Exception as exc:  # an unset key name or a malformed reference
        needed = {}
        problems.append(_problem(_why(exc)))

    looked_up = False
    policies: tuple[str, ...] = ()
    ttl: int | None = None
    renewable: bool | None = None
    token_ref: str | None = None
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
        raw_ref = data.get("accessor")
        token_ref = raw_ref if isinstance(raw_ref, str) and raw_ref else None
    except OSError as exc:
        # A transport failure (requests' errors are OSErrors): the capabilities read would wait out
        # the same timeout against the same server, so it is not sent.
        problems.append(_problem(f"token lookup-self failed: {_why(exc)}"))
        return VaultTokenReading(required=needed, problems=tuple(problems))
    except Exception as exc:  # Vault answered and refused, or answered in an unexpected shape
        problems.append(_problem(f"token lookup-self failed: {_why(exc)}"))

    capabilities: dict[str, tuple[str, ...]] = {}
    paths = [*needed, *VAULT_ADMIN_PATHS]
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
        )

        return read_vault_token(
            secrets_vault_client, lambda: kv_required_capabilities(consumer.refs)
        )
    from messagefoundry.store.keyprovider_vault import (
        kek_required_capabilities,
        store_vault_client,
    )

    if kind == "transit":
        from messagefoundry.store.crypto_transit import transit_cipher_required_capabilities

        return read_vault_token(store_vault_client, transit_cipher_required_capabilities)
    if kind == "kek":
        return read_vault_token(store_vault_client, kek_required_capabilities)
    # Unreachable while VaultKind has three members; a fourth must be routed here, not defaulted.
    raise ValueError(f"no Vault probe for consumer kind {kind!r}")


def read_ldap_bind(settings: ServiceSettings, posture: HopPosture | None) -> BindAccountReading:
    """Build the AD authenticator with the arguments ``AuthService`` gives it and read its bind
    account. The bind password resolves through ``[secrets]`` as it does under ``serve``. Any
    failure comes back in ``problem``; this never raises."""
    from messagefoundry.auth.ldap import BindAccountReading, LdapAuthenticator
    from messagefoundry.config.secretprovider import resolve_secret_provider
    from messagefoundry.config.settings import SecurityEnforcement

    try:
        authenticator = LdapAuthenticator(
            settings.auth,
            secret_provider=resolve_secret_provider(settings.secrets),
            posture=posture,
            enforcing=settings.security.enforcement is SecurityEnforcement.ENFORCE,
        )
        return authenticator.read_bind_account()
    except Exception as exc:  # no extra, no CA file, a failed bind: reported, never raised
        return BindAccountReading(None, problem=_problem(f"AD bind probe: {_why(exc)}"))
