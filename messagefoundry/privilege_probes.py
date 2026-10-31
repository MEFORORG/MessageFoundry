# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The read-only Vault and LDAP probes behind ``messagefoundry check-privileges`` (BACKLOG #305,
ASVS 13.2.2).

:mod:`messagefoundry.privilege_check` is pure and judges what these return; this module is the half
that touches the network. Each probe goes through the client the engine already builds for that hop,
so it carries the same TLS narrowing, trust anchor, redirect refusal and cleartext refusal, and adds
no client of its own. A Vault probe is also held to that hop's revocation rule, with the hop's own
attestation and the command's posture (vault BACKLOG #2983):

* **Vault**, per token: ``GET /v1/auth/token/lookup-self`` for the token's policies, TTL and
  renewability, then one ``POST /v1/sys/capabilities-self`` for the exact paths the engine calls
  plus the paths it never needs (:func:`~messagefoundry.privilege_check.vault_admin_paths`). Both
  are calls a token's ``default`` policy allows, and both only read. Only the token named in the
  hop's own ``MEFOR_*_VAULT_TOKEN`` is read, never one hvac would fall back to.
* **LDAP**: the RFC 4532 "Who am I?" extended operation on the service-account bind, then a read of
  that account's own groups (:meth:`~messagefoundry.auth.ldap.LdapAuthenticator.read_bind_account`).

**A probe never raises.** Anything that stops it -- no extra, no address, a refused cleartext
address, an unreachable server, a 403 on the lookup -- comes back as a problem string, which the
read-out reports as ``unobservable``. Only a network failure, a timeout or a 403 is excused
(:func:`excused_failure`, ADR 0216); a Vault reading also names every other failure, so the
startup preflight can refuse on one under ``enforce``. **Nothing secret is kept:** never the
token, its accessor or its id, and never a bind password. A problem names the exception type, or
the engine's own fixed refusal text, or the first 200 characters of a plain ``ValueError`` raised
from engine code (the probe's own shape checks and the TLS-suite assertion raise those). It never
carries a server's error body: a subclass of ``ValueError``, such as a JSON decode error, keeps
its type name alone, and so does a plain ``ValueError`` a library raised, such as a URL parser's
(vault BACKLOG #3454).
"""

from __future__ import annotations

import functools
import hashlib
import logging
import socket
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from messagefoundry.controlchars import scrub_log_argument, strip_control_chars
from messagefoundry.privilege_check import vault_admin_paths
from messagefoundry.transports.bounded_read import TruncatedResponseError

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from messagefoundry.auth.ldap import BindAccountReading
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.config.tls_policy import HopPosture
    from messagefoundry.privilege_check import VaultConsumer

__all__ = [
    "VaultTokenReading",
    "excused_failure",
    "probe_vault",
    "read_ldap_bind",
    "read_vault_token",
    "unexcused_cause",
]


@dataclass(frozen=True, slots=True)
class VaultTokenReading:
    """What one Vault token said about itself. Holds no part of the token.

    ``required`` is each path the engine calls with the capabilities that call needs; it is empty
    when the paths could not be named. ``admin_paths`` is every path asked about that the engine
    never calls (:func:`~messagefoundry.privilege_check.vault_admin_paths`). ``capabilities`` is
    Vault's answer for both sets. ``problems`` names every part that could not be read.
    ``unexcused`` names each failure behind a problem that :func:`excused_failure` does not
    excuse, by the exception's type name, or in words for an answer that named no capabilities for
    a path; the startup preflight refuses on one under ``enforce``.

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
    unexcused: tuple[str, ...] = ()
    token_ref: str | None = field(default=None, repr=False, compare=False)

    def same_token_as(self, other: VaultTokenReading) -> bool:
        """Whether both readings were taken with the same token. ``False`` when either has no
        token to compare, because its token variable was unset."""
        return self.token_ref is not None and self.token_ref == other.token_ref


def _problem(text: str) -> str:
    """Log one probe problem and return it. The text is already secret-free (:func:`_why`), and
    is logged with every character in ``CONTROL_CATEGORIES`` escaped visibly, by the log's own
    rule, as the terminal escapes them (``privilege_check.render_text``), so neither deletes a
    character the server sent (BACKLOG #2891)."""
    # Not "check-privileges:": serve runs these probes at every start too (BACKLOG #2903).
    logger.warning("privilege probe: %s", scrub_log_argument(text))
    return text


def _is_forbidden(exc: BaseException) -> bool:
    """Whether ``exc`` is Vault's 403. hvac maps a 403 to ``Forbidden``; it is read by name so this
    module never imports hvac."""
    return type(exc).__name__ == "Forbidden"


def excused_failure(exc: BaseException) -> bool:
    """Whether a Vault probe failure is one the owner ruling of 2026-10-04 lets only warn (ADR
    0216): a network failure, a timeout, or a 403 (:func:`_is_forbidden`).

    A network failure or a timeout is a refused, reset or dropped connection, a name that did not
    resolve, a connect or read timeout, a TLS handshake the peer cut off, or a reply cut short of
    its declared length. That is the builtin ``ConnectionError`` and ``TimeoutError``,
    ``socket.gaierror``, requests' ``ConnectionError``, ``Timeout`` and ``ChunkedEncodingError``,
    and the strict reply adapter's ``TruncatedResponseError``. It is not every ``OSError``:
    requests' ``InvalidHeader`` and ``InvalidURL``, a missing CA file and a TLS failure other than
    a cut-off handshake are configuration. A TLS failure is looked for in the whole chain, because
    requests reports one on the proxy leg as a ``ProxyError``, and on either leg the wrapped
    ``ssl.SSLError`` is what tells a verification failure from a dropped handshake.

    Any other failure left the token unjudged for a reason the ruling does not excuse. At least
    these are in that class: a ``TypeError`` or ``AttributeError`` after an hvac rename or a
    signature drift, an engine refusal such as an unset token variable, and any other Vault error
    status. The startup preflight refuses on one under ``enforce``
    (:func:`~messagefoundry.privilege_check.vault_preflight_outcome`)."""
    if _is_forbidden(exc):
        return True
    chain = list(_chain(exc))
    if any(_is_ssl(e, "SSLError") and not _is_ssl(e, "SSLEOFError") for e in chain):
        return False
    if isinstance(exc, (ConnectionError, TimeoutError, socket.gaierror, TruncatedResponseError)):
        return True
    try:
        from requests import exceptions as rex
    except ImportError:  # no requests, so none of its errors can be the one raised
        return False
    if isinstance(exc, rex.SSLError):
        # Excused only where the chain shows a handshake the peer cut off.
        return any(_is_ssl(e, "SSLEOFError") for e in chain)
    return isinstance(exc, (rex.ConnectionError, rex.Timeout, rex.ChunkedEncodingError))


def _is_ssl(exc: BaseException, name: str) -> bool:
    """Whether ``exc`` is the stdlib ``ssl`` module's class ``name`` or a subclass of it. Read off
    the class's MRO, so this module reads an exception's type without importing ``ssl``, which the
    crypto inventory gate counts as a crypto use (``scripts/security/crypto_inventory_check.py``)."""
    return any(c.__module__ == "ssl" and c.__name__ == name for c in type(exc).__mro__)


def _chain(exc: BaseException) -> Iterator[BaseException]:
    """``exc`` and every exception it wraps: its cause and context, and the exceptions urllib3 and
    requests keep in ``args``, ``reason`` and ``original_error``. Each is visited once."""
    seen: set[int] = set()
    todo: list[BaseException] = [exc]
    while todo:
        e = todo.pop()
        if id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        inner: list[object] = [e.__cause__, e.__context__, *e.args]
        inner += [getattr(e, "reason", None), getattr(e, "original_error", None)]
        todo += [i for i in inner if isinstance(i, BaseException)]


def unexcused_cause(exc: BaseException) -> str | None:
    """How a reading names ``exc`` in ``unexcused``: its type name, or ``None`` when
    :func:`excused_failure` excuses it. The one spelling for a failure the probe caught and one
    the preflight caught."""
    return None if excused_failure(exc) else type(exc).__name__


def _why(exc: BaseException) -> str:
    """A problem text that cannot carry a secret or a server's error body."""
    from messagefoundry.auth.ldap import LdapError
    from messagefoundry.config.secretprovider import SecretProviderError
    from messagefoundry.config.tls_policy import is_vault_hop_refusal
    from messagefoundry.store.keyprovider import KeyProviderError

    # The engine's own fail-closed types carry fixed, secret-free text by contract; the cleartext
    # refusal (BACKLOG #2317) arrives wrapped in one of them. An LdapError from a failed bind
    # names the result code or ldap3's error type (BACKLOG #3017), never a password. Control
    # characters are stripped from every one of these texts all the same.
    #
    # A hop refusal keeps its text only when it is exactly the Vault hop's marked one, built from
    # fixed text (BACKLOG #3471), as `vault_failure_text` reads it. Any other `InsecureHopRefused`
    # falls through to its type name: the base type promises no fixed text. `_ad_why` keeps the
    # LDAPS guard's for the AD probe.
    fail_closed = (KeyProviderError, SecretProviderError, LdapError)
    if isinstance(exc, fail_closed) or is_vault_hop_refusal(exc):
        return strip_control_chars(str(exc))
    name = type(exc).__name__
    if _is_forbidden(exc):
        return f"permission denied ({name})"
    # Exactly ValueError, not a subclass: the probe's own shape refusals and the TLS-suite
    # assertion raise it with engine-written text. A subclass, such as a JSON decode error, can
    # quote what the server sent, so it keeps the type name alone. So does a ValueError a library
    # raised (vault BACKLOG #3454): urllib.parse's quotes a whole proxy URL. The rule reads the
    # innermost frame, not who wrote the text, so it does not catch a ValueError a C builtin such
    # as int() raises inside engine code, nor engine code that copies a library's text. An
    # exception never raised has no frame, and keeps its type name alone.
    if type(exc) is ValueError and _raised_by_the_engine(exc):
        return f"{name}: {strip_control_chars(str(exc))[:200]}"
    return name


def _ad_why(exc: BaseException) -> str:
    """:func:`_why` for the AD bind probe, which keeps an ``InsecureHopRefused``'s text whole.

    On that probe one comes from building the LDAPS bind: the revocation guard of BACKLOG #2193,
    whose text names the hop, the domain controller's host and the setting that clears it, and
    reads no password. ``provision-admin`` and ``serve`` print the same refusal whole. The Vault
    probe does not take this rule (BACKLOG #3471)."""
    from messagefoundry.config.tls_policy import InsecureHopRefused

    if isinstance(exc, InsecureHopRefused):
        return strip_control_chars(str(exc))
    return _why(exc)


def _raised_by_the_engine(exc: BaseException) -> bool:
    """Whether the innermost frame of ``exc``'s traceback is in a ``messagefoundry`` module (vault
    BACKLOG #3454), the rule ``config.wiring`` and ``__main__._is_engine_refusal`` apply too. A
    copy, not an import of ``config.wiring``'s, so the probe neither loads that module nor imports
    anything inside its exception handlers, where a failed import would raise."""
    tb = exc.__traceback__
    if tb is None:
        return False
    while tb.tb_next is not None:
        tb = tb.tb_next
    module = tb.tb_frame.f_globals.get("__name__", "")
    return isinstance(module, str) and module.split(".")[0] == "messagefoundry"


def _strings(value: object) -> tuple[str, ...]:
    """The string members of a Vault list, kept EXACTLY as Vault sent them. A policy name is also
    a path the probe asks about, so altering it here would ask about a different policy. A
    printed line is escaped at ``privilege_check.render_text``, and a logged one by
    ``scrub_log_argument``, each at its output boundary instead."""
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(v for v in value if isinstance(v, str))


def _unset(*sources: Callable[[], object], why: Callable[[BaseException], str] = _why) -> list[str]:
    """Ask each source, and return why each one that refused did. Asking all of them before
    returning means one run names every missing variable, not the first."""
    out: list[str] = []
    for source in sources:
        try:
            source()
        except Exception as exc:  # a refusal is this hop's finding, reported, never raised
            out.append(why(exc))
    return out


def read_vault_token(
    token: Callable[[], str],
    address: Callable[[], str],
    build_client: Callable[[str, str], Any],
    required: Callable[[], Mapping[str, frozenset[str]]],
) -> VaultTokenReading:
    """Read one token's own policies and capabilities through the engine's client for that hop.

    ``token`` returns the token named in the hop's own variable and refuses when it is unset, so
    hvac never substitutes ``VAULT_TOKEN``; ``address`` does the same for ``VAULT_ADDR``, and the
    client is built from exactly the two values they returned. ``build_client`` is the hop's own
    constructor, and ``required`` names the paths the engine calls on it; all of them live beside
    the calls they describe (``store/keyprovider_vault.py``, ``store/crypto_transit.py``,
    ``config/secretprovider_vault.py``). The variables and the paths are all read before anything
    is returned, so one run names every one that is missing.

    Every failure is recorded as a problem. One that :func:`excused_failure` does not excuse is
    also named in ``unexcused``, so a code defect swallowed here still refuses an enforcing start."""
    problems: list[str] = []
    unexcused: list[str] = []

    def unjudged(cause: str) -> None:
        if cause not in unexcused:
            unexcused.append(cause)

    def why(exc: BaseException) -> str:
        if (cause := unexcused_cause(exc)) is not None:
            unjudged(cause)
        return _why(exc)

    needed: dict[str, frozenset[str]] = {}
    try:
        needed = dict(required())
    except Exception as exc:  # an unset key name or a malformed reference
        problems.append(why(exc))
    unset = _unset(token, address, why=why)
    if unset:
        return VaultTokenReading(
            required=needed,
            problems=tuple(
                _problem(p) for p in [*(f"no Vault client: {u}" for u in unset), *problems]
            ),
            unexcused=tuple(unexcused),
        )
    named = token()
    try:
        client = build_client(address(), named)
    except Exception as exc:  # a refused client: reported, never raised
        return VaultTokenReading(
            required=needed,
            problems=tuple(_problem(p) for p in [f"no Vault client: {why(exc)}", *problems]),
            unexcused=tuple(unexcused),
        )
    for p in problems:
        _problem(p)
    token_ref = hashlib.sha256(named.encode("utf-8")).hexdigest()

    from messagefoundry.config.tls_policy import InsecureHopRefused

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
    except (OSError, InsecureHopRefused) as exc:
        # A transport failure (requests' errors are OSErrors): the capabilities read would wait out
        # the same timeout against the same server, so it is not sent. A refusal of the hop itself,
        # such as a proxy-leg CA the TLS library would not load (BACKLOG #3090), would refuse that
        # read the same way, so it is not sent either.
        problems.append(_problem(f"token lookup-self failed: {why(exc)}"))
        return VaultTokenReading(
            required=needed,
            problems=tuple(problems),
            unexcused=tuple(unexcused),
            token_ref=token_ref,
        )
    except Exception as exc:  # Vault answered and refused, or answered in an unexpected shape
        problems.append(_problem(f"token lookup-self failed: {why(exc)}"))

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
                # Kept exactly as sent: a value that is not exactly a capability the engine needs,
                # or exactly "deny", counts as excess. Normalising would let "deny" plus an
                # invisible character read as deny, and so err toward a clean result.
                capabilities[path] = _strings(caps)
            else:
                # Not a network, timeout or 403 failure either: this path went unjudged.
                unjudged("an answer naming no capabilities for a path")
                problems.append(_problem(f"capabilities-self returned nothing for {path}"))
    except Exception as exc:  # Vault refused or could not be reached: reported, never raised
        problems.append(_problem(f"capabilities-self failed: {why(exc)}"))

    return VaultTokenReading(
        looked_up=looked_up,
        policies=policies,
        ttl=ttl,
        renewable=renewable,
        required=needed,
        admin_paths=admin,
        capabilities=capabilities,
        problems=tuple(problems),
        unexcused=tuple(unexcused),
        token_ref=token_ref,
    )


def probe_vault(
    consumer: VaultConsumer, settings: ServiceSettings, *, posture: HopPosture | None = None
) -> VaultTokenReading:
    """Read the token behind one Vault consumer, with the client and paths of the provider that
    uses it. Imports lazily, as the providers do, so the command stays light without Vault.

    Each client is held to its hop's revocation rule, as the provider's own client is (vault
    BACKLOG #2983). ``settings`` supplies the hop's own attestation: the ``[secrets]`` pair for
    the connector-secret client and the ``[store]`` pair for the store client. ``posture`` is
    the instance posture, and ``None`` counts as enforcing. So the probe reaches an off-box
    ``https://`` Vault exactly where ``serve`` would, and a refusal names a setting this path
    reads."""
    kind = consumer.kind
    if kind == "kv":
        from messagefoundry.config.secretprovider_vault import (
            kv_required_capabilities,
            secrets_vault_address,
            secrets_vault_client,
            secrets_vault_token,
        )

        return read_vault_token(
            secrets_vault_token,
            secrets_vault_address,
            functools.partial(
                secrets_vault_client,
                revocation_attested=settings.secrets.vault_revocation_attested,
                revocation_reason=settings.secrets.vault_revocation_attested_reason,
                posture=posture,
            ),
            lambda: kv_required_capabilities(consumer.refs),
        )
    from messagefoundry.store.keyprovider_vault import (
        kek_required_capabilities,
        store_vault_address,
        store_vault_client,
        store_vault_token,
    )

    store_client = functools.partial(
        store_vault_client,
        revocation_attested=settings.store.vault_revocation_attested,
        revocation_reason=settings.store.vault_revocation_attested_reason,
        posture=posture,
    )
    if kind == "transit":
        from messagefoundry.store.crypto_transit import transit_cipher_required_capabilities

        return read_vault_token(
            store_vault_token,
            store_vault_address,
            store_client,
            transit_cipher_required_capabilities,
        )
    if kind == "kek":
        return read_vault_token(
            store_vault_token, store_vault_address, store_client, kek_required_capabilities
        )
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
            # substitutes VAULT_TOKEN, or sends the engine's token to VAULT_ADDR. No bind is made
            # either way; asking both names both in one run.
            unset = _unset(secrets_vault_token, secrets_vault_address)
            if unset:
                return BindAccountReading(
                    None,
                    problem=_problem("AD bind probe not run: " + "; ".join(unset)),
                    bound=False,
                )
        authenticator = LdapAuthenticator(
            settings.auth,
            secret_provider=resolve_secret_provider(settings.secrets, posture=posture),
            enforcing=settings.security.enforcement is SecurityEnforcement.ENFORCE,
            hop_posture=posture,  # BACKLOG #2193: the LDAPS revocation guard, as AuthService passes
        )
    except Exception as exc:  # no extra, no CA file, an unset token: reported, never raised
        return BindAccountReading(
            None, problem=_problem(f"AD bind probe not run: {_ad_why(exc)}"), bound=False
        )
    try:
        return authenticator.read_bind_account()
    except Exception as exc:  # the bind itself failed: reported, never raised
        return BindAccountReading(
            None, problem=_problem(f"AD bind probe: {_ad_why(exc)}"), bound=False
        )
