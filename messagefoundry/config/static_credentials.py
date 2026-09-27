# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The static-credential backend-hop inventory, and the evaluation behind its opt-in gate (BACKLOG
#1182, ASVS 13.2.1).

ASVS 13.2.1 asks that backend component communications authenticate with individual service accounts,
short-term tokens or certificates, and not with unchanging credentials. This module answers one
question for the whole engine: **which backend hops that the engine opens do not meet that verb, and
does the product offer a compliant credential kind for each?** It widens
:func:`~messagefoundry.config.wiring.static_credential_db_hops`, which covers database hops only, to
the classification the owner ruled on 2026-08-22 and funded on 2026-09-22.

**One reader.** :func:`static_credential_hops` is the SINGLE reader of the set, on the contract of
:func:`~messagefoundry.config.wiring.accepted_cleartext_hops` and its siblings: every surface that
reports or gates the set calls it, so no two of them can disagree. It has two halves because the engine
keeps its hops in two places: the connection graph (a ``Registry``) and the service settings
(``[store]``, ``[secrets]``, ``[alerts]``, ``[ai]``, ``[auth]`` and ``[logging]``). A caller passes
``None`` for a half it cannot see, and must then say so in its own output rather than report a subset as if it were
everything.

**What counts as a hop here.** A hop the engine DIALS, where the engine is the party that would have to
present the credential, and only when the engine would actually open it (a connection declared with
``deployed=False`` is never built, so it is not a hop). Two shapes are reported:

* ``credential="static"``: the hop presents an unchanging credential (a password, API key, static
  bearer token, or a Vault token read from the environment).
* ``credential="none"``: the hop presents no credential at all. It is reported because a gate that
  refused a static password but passed the same hop with the password deleted would reward making the
  hop weaker.

A hop that presents a compliant credential and no static one is not reported. The compliant kinds are
a client certificate (mTLS), an SSH private key, SMART Backend Services (a signed assertion), OAuth2
client credentials (a short-term bearer token), and a delegated database identity (Windows Integrated
or Entra). OAuth2 client credentials count as compliant by the 2026-08-22 owner ruling, which
classified the SMART and OAuth2 composition helpers as giving ``Rest()``, ``FHIR()`` and
``FhirLookup()`` a compliant kind. The OAuth2 token request itself still carries a static
``client_secret``; that token hop is not enumerated separately. A ``FhirLookup`` can take SMART only:
the lookup executor builds no OAuth2 provider.

**``compliant_kind`` on each hop** says whether the product offers ANY compliant credential kind for
that hop today. Where it is ``False`` no operator configuration clears the hop, so with the gate on the
only way through is an explicit, audited opt-out. The owner accepted that when the gate was ruled
opt-in and off by default (2026-09-23).

**Classification reads settings keys, not the built connector**, so each rule below mirrors what the
connector does with those keys: a client certificate counts only with ``tls`` on, HTTP Basic only when
both halves are set, a WS-Security UsernameToken only with ``ws_security`` on, and a static
``Authorization`` credential not at all when SMART or OAuth2 replaces that header with a minted token.

**Out of scope, stated so the silence is not read as coverage.**

* LISTENERS (inbound MLLP, TCP, X12, DICOM, HTTP). There the partner presents a credential to the
  engine, not the other way round. Whether a trading partner is a backend component is a question the
  record declines to settle, and the HTTP listener has its own intake-authentication gate
  (``check_http_intake_auth``).
* Plugin connector types this module does not know. They are not guessed at.
* A generic-ODBC database hop that sets no top-level ``username``/``password``: the credential, if
  any, sits under a driver keyword the engine cannot enumerate. See ``static_credential_db_hops``.
* A forward-proxy URL the engine cannot read: a connection's ``proxy_url`` written as an ``env()``
  reference, whose value is resolved only when the connector is built, and ``proxy_url='default'``,
  where the operating system's proxy settings carry any credential. Userinfo in either is sent and
  not listed. A ``proxy_user``/``proxy_password`` pair beside an ``env()`` URL is still listed.

Pure apart from :func:`apply_static_credential_gate`, which also logs: every function reads its
arguments and touches nothing else.

**A detail cannot carry a secret, by construction.** Every detail is fixed text chosen from a closed
set, plus at most one peer label. The peer label (:func:`~messagefoundry.config.wiring._peer_label`) is built from parsed parts, so it holds
a scheme, a host and a port and nothing else; userinfo, path, query and fragment are never copied, and
an address that does not parse is withheld behind fixed text. Where a detail names a credential it
names the SETTING that holds it, never the value."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from messagefoundry.config.ai_policy import AiMode
from messagefoundry.config.models import ConnectorType, remote_file_protocol
from messagefoundry.config.settings import (
    ServiceSettings,
    SqlAuth,
    StoreBackend,
    SyslogProtocol,
)
from messagefoundry.config.wiring import (
    Registry,
    WiringError,
    _peer_label,
    static_credential_db_hops,
)

__all__ = [
    "SETTINGS_PREFIX",
    "StaticCredentialHop",
    "StaticCredentialVerdict",
    "apply_static_credential_gate",
    "evaluate_static_credential_gate",
    "make_static_credential_guard",
    "static_credential_hops",
]

Credential = Literal["static", "none"]

#: The prefix every settings-scoped hop name carries, so it cannot collide with a connection name.
SETTINGS_PREFIX = "settings:"


@dataclass(frozen=True, slots=True)
class StaticCredentialHop:
    """One backend hop that does not meet ASVS 13.2.1's credential verb.

    ``name`` is the hop's identity: the key an operator opts it out with. ``detail`` names what the hop
    presents and its peer as scheme, host and port; the module docstring says why it cannot carry a
    secret. ``compliant_kind`` says whether the
    product offers a compliant credential kind for this hop in any configuration."""

    name: str
    credential: Credential
    detail: str
    compliant_kind: bool


# --- the graph half ---------------------------------------------------------------------------------

#: The HTTP-family connector types. Each may dial through a forward proxy (ADR 0126). The same four
#: types as ``pipeline.wiring_runner._HTTP_FAMILY_DEST_TYPES``, which ``config`` cannot import; a test
#: pins the two equal.
_HTTP_FAMILY = frozenset(
    {ConnectorType.REST, ConnectorType.FHIR, ConnectorType.SOAP, ConnectorType.DICOMWEB}
)


def _smart(settings: Mapping[str, Any]) -> bool:
    # Lazy: ``config`` takes no module-import dependency on ``transports`` (the one-way rule the sibling
    # readers in ``wiring`` follow). Both predicates are the single definitions the providers use.
    from messagefoundry.transports.smart import smart_auth_configured

    return smart_auth_configured(settings)


def _oauth2(settings: Mapping[str, Any]) -> bool:
    from messagefoundry.transports.http_auth import oauth2_auth_configured

    return oauth2_auth_configured(settings)


def _http_static(ctype: ConnectorType, settings: Mapping[str, Any], token: bool) -> list[str]:
    """The static credentials an HTTP-family hop actually puts on the wire.

    A minted SMART or OAuth2 bearer replaces the ``Authorization`` header, so a static bearer or
    Basic credential configured beside it never leaves the engine. Basic needs both halves (the
    connector sends nothing on one). A WS-Security UsernameToken rides in the SOAP body, so token auth
    does not displace it, but it is stamped only with ``ws_security`` on; its user and password fall
    back to the Basic pair. ``Soap()`` hoists ``body_secrets`` into ``body_secret_tokens``."""
    out: list[str] = []
    if not token:
        if settings.get("bearer_token"):
            out.append("static bearer token")
        if settings.get("basic_user") and settings.get("basic_password"):
            out.append("HTTP Basic")
    # The connector answers a Digest challenge only in http_auth='digest' mode, and refuses to build
    # in that mode with either half missing, so the mode is the predicate, not the credential keys.
    if str(settings.get("http_auth") or "").lower() == "digest":
        out.append("HTTP Digest")
    if ctype is ConnectorType.SOAP:
        ws_user = settings.get("ws_username") or settings.get("basic_user")
        ws_password = settings.get("ws_password") or settings.get("basic_password")
        if settings.get("ws_security") and (ws_user or ws_password):
            out.append("WS-Security UsernameToken")
        if settings.get("body_secret_tokens"):
            out.append("body secrets")
    return out


def _http_hop(
    name: str,
    ctype: ConnectorType,
    settings: Mapping[str, Any],
    peer: str,
    *,
    lookup: bool = False,
) -> StaticCredentialHop | None:
    """One HTTP-family hop. DICOMweb cannot take the SMART or OAuth2 composition and has no
    client-certificate arm, so it alone has no compliant kind. A ``FhirLookup`` takes SMART only."""
    compliant_kind = ctype is not ConnectorType.DICOMWEB
    token = compliant_kind and (_smart(settings) or (not lookup and _oauth2(settings)))
    static = _http_static(ctype, settings, token)
    if static:
        return StaticCredentialHop(
            name, "static", f"presents {' + '.join(static)} ({peer})", compliant_kind
        )
    if token or (ctype is ConnectorType.SOAP and settings.get("client_cert_file")):
        return None
    return StaticCredentialHop(name, "none", f"presents no credential ({peer})", compliant_kind)


def _proxy_url_sends_userinfo(url: object) -> bool:
    # Lazy, like ``_smart``: the transport owns what its proxy handler sends.
    from messagefoundry.transports.rest import proxy_url_sends_userinfo

    return proxy_url_sends_userinfo(url)


def _proxy_hop(
    name: str, settings: Mapping[str, Any], site_proxy: str | None
) -> StaticCredentialHop | None:
    """The forward-proxy hop an HTTP-family connection dials through, when it carries a credential.

    It is its own hop with its own peer: the proxy receives a ``Proxy-Authorization`` credential, and
    ``proxy_auth_type`` offers only static Basic or Digest (NTLM and Negotiate are refused, ADR 0126).
    So no compliant kind exists for it. The proxy is the connection's own ``proxy_url``, else the
    inherited ``[egress].proxy_url``. ``site_proxy`` is that inherited value, or ``None`` when the
    caller has no settings to read; the hop is then reported, because a credential written on a
    connection is written to be used. A proxy with no credential has nothing presented to it.

    The credential is the ``proxy_user``/``proxy_password`` pair, or a user and password in the
    proxy URL itself (:func:`_proxy_url_sends_userinfo`). The label is built from parsed parts, so the
    userinfo never reaches it."""
    proxy_url = settings.get("proxy_url") or site_proxy
    in_url = _proxy_url_sends_userinfo(proxy_url)
    if not in_url and not (settings.get("proxy_user") or settings.get("proxy_password")):
        return None
    if site_proxy is not None and not proxy_url:
        return None  # no proxy at all: the credential is never sent
    # From a closed set, not echoed: only a known scheme name reaches the detail. URL userinfo is
    # always Basic: the handler sends it pre-emptively and it replaces the engine's own header,
    # whatever proxy_auth_type says. Otherwise the type is read the way the transport reads it.
    kind = "basic" if in_url else str(settings.get("proxy_auth_type") or "basic").strip().lower()
    if kind not in ("basic", "digest"):
        kind = "static"
    return StaticCredentialHop(
        f"proxy:{name}",
        "static",
        f"forward-proxy {kind} credential ({_peer_label({'url': proxy_url})})",
        False,
    )


def _remote_file_hop(
    name: str, settings: Mapping[str, Any], peer: str
) -> StaticCredentialHop | None:
    """SFTP can present an SSH private key, which is compliant. FTP and FTPS cannot: the FTPS client
    certificate exists in the transport, but ``Ftp()`` exposes no setting that selects it.

    The protocol is read through the normalisation the transport uses (lowercased, SFTP when unset), so
    the classifier cannot call a hop FTP that the transport dials as SFTP."""
    if remote_file_protocol(settings) == "sftp":
        if settings.get("password"):
            return StaticCredentialHop(name, "static", f"SFTP password ({peer})", True)
        if settings.get("private_key"):
            return None
        return StaticCredentialHop(name, "none", f"SFTP, no credential ({peer})", True)
    if settings.get("username") or settings.get("password"):
        return StaticCredentialHop(name, "static", f"FTP password ({peer})", False)
    return StaticCredentialHop(name, "none", f"anonymous FTP ({peer})", False)


def _connection_hop(
    name: str, ctype: ConnectorType, settings: Mapping[str, Any]
) -> StaticCredentialHop | None:
    """Classify one dialled connection's own hop. DATABASE is not here: the database arm owns it."""
    peer = _peer_label(settings)
    if ctype in (ConnectorType.MLLP, ConnectorType.DIMSE):
        # The client certificate is loaded only into a TLS context; with tls off it is never sent.
        if settings.get("tls") and settings.get("tls_cert_file"):
            return None
        return StaticCredentialHop(
            name, "none", f"presents no client certificate; set tls + tls_cert_file ({peer})", True
        )
    if ctype in (ConnectorType.TCP, ConnectorType.X12):
        return StaticCredentialHop(
            name,
            "none",
            f"raw socket; the factory offers no credential of any kind ({peer})",
            False,
        )
    if ctype in _HTTP_FAMILY:
        return _http_hop(name, ctype, settings, peer)
    if ctype in (ConnectorType.EMAIL, ConnectorType.DIRECT):
        # SMTP AUTH is a static username/password; no certificate or token arm is built.
        if settings.get("username") or settings.get("password"):
            return StaticCredentialHop(name, "static", f"SMTP AUTH password ({peer})", False)
        return StaticCredentialHop(name, "none", f"SMTP relay, no AUTH ({peer})", False)
    if ctype is ConnectorType.REMOTEFILE:
        return _remote_file_hop(name, settings, peer)
    # FILE: only the ADR 0132 alternate-share credential is a hop credential. Without it the connector
    # runs as the service's own identity, which is a machine or gMSA principal.
    if ctype is ConnectorType.FILE and (
        settings.get("credential_username") or settings.get("credential_password")
    ):
        return StaticCredentialHop(name, "static", "alternate-share password", False)
    return None


#: Inbound connection types that DIAL their peer. Every other inbound type is a listener or has no
#: peer at all. DATABASE (``DatabasePoll``) dials too, and the database arm covers it.
_DIALLED_INBOUND = frozenset({ConnectorType.REMOTEFILE, ConnectorType.FILE})


def _graph_hops(registry: Registry, site_proxy: str | None) -> list[StaticCredentialHop]:
    undeployed = {oc.name for oc in registry.outbound.values() if not oc.deployed} | {
        f"inbound:{ic.name}" for ic in registry.inbound.values() if not ic.deployed
    }
    # The database arm is the shipped reader, reused rather than restated. Every database hop has a
    # compliant kind: auth='integrated'/'entra' on the SQL Server preset, a driver keyword on generic.
    out = [
        StaticCredentialHop(name, "static", reason, True)
        for name, reason in static_credential_db_hops(registry)
        if name not in undeployed
    ]
    dialled = [(oc.name, oc.spec) for oc in registry.outbound.values() if oc.deployed] + [
        (f"inbound:{ic.name}", ic.spec)
        for ic in registry.inbound.values()
        if ic.deployed and ic.spec.type in _DIALLED_INBOUND
    ]
    for name, spec in dialled:
        hop = _connection_hop(name, spec.type, spec.settings)
        if hop is not None:
            out.append(hop)
        if spec.type in _HTTP_FAMILY and (proxy := _proxy_hop(name, spec.settings, site_proxy)):
            out.append(proxy)
    for lk in registry.fhir_lookups.values():
        name = f"fhir_lookup:{lk.name}"
        hop = _http_hop(
            name, ConnectorType.FHIR, lk.settings, _peer_label(lk.settings), lookup=True
        )
        if hop is not None:
            out.append(hop)
        if proxy := _proxy_hop(name, lk.settings, site_proxy):
            out.append(proxy)
    return out


# --- the settings half ------------------------------------------------------------------------------


def _settings_hops(settings: ServiceSettings) -> list[StaticCredentialHop]:
    out: list[StaticCredentialHop] = []

    def add(name: str, credential: Credential, detail: str, compliant_kind: bool) -> None:
        out.append(StaticCredentialHop(SETTINGS_PREFIX + name, credential, detail, compliant_kind))

    store = settings.store
    if store.backend is StoreBackend.SQLSERVER and store.auth not in (
        SqlAuth.INTEGRATED,
        SqlAuth.ENTRA,
    ):
        add("store", "static", "SQL Server store: static SQL login ([store].auth='sql')", True)
    elif store.backend is StoreBackend.POSTGRES:
        # The Postgres backend's own validator accepts only auth='sql'.
        add("store", "static", "Postgres store: static username/password", False)
    # Every Vault construction site reads a static token from the environment; no AppRole or platform
    # login with lease renewal is built. Transit replaces the key provider rather than adding to it.
    if store.cipher_provider == "vault_transit":
        add("vault.store_transit", "static", "Vault token from MEFOR_STORE_VAULT_TOKEN", False)
    elif store.key_provider == "vault":
        add("vault.store_key", "static", "Vault token from MEFOR_STORE_VAULT_TOKEN", False)
    auth, alerts = settings.auth, settings.alerts
    # The connector secret provider is consulted only for a credential whose *_secret reference is set.
    if settings.secrets.provider == "vault" and (
        auth.ad_bind_password_secret or auth.oidc_client_secret_ref or alerts.email_password_secret
    ):
        add("vault.secrets", "static", "Vault token from MEFOR_SECRETS_VAULT_TOKEN", False)
    if alerts.webhook_url:
        add("alerts.webhook", "none", "the alert webhook sink has no credential field", False)
    # Both SMTP consumers (the alert sinks and the security notifier) need a host and a sender.
    if alerts.email_smtp_host and alerts.email_from:
        if alerts.email_username or alerts.email_password or alerts.email_password_secret:
            add("alerts.smtp", "static", "alert SMTP AUTH password", False)
        else:
            add("alerts.smtp", "none", "alert SMTP relay, no AUTH", False)
    if settings.ai.mode is AiMode.MANAGED_ENDPOINT:
        add("ai.broker", "static", "AI broker x-api-key from [ai].api_key", False)
    if auth.ad_enabled:
        add("auth.ad_bind", "static", "LDAP SIMPLE bind with a static ad_bind_password", False)
    if auth.oidc_enabled:
        add("auth.oidc", "static", "OIDC token request with a static client_secret", False)
    # The syslog/SIEM forwarder dials the collector. Only TLS with a client certificate authenticates
    # the engine to it; UDP, TCP and server-only TLS present nothing.
    log = settings.logging
    if log.forward_enabled and log.forward_host:
        protocol = log.forward_protocol
        if not (protocol is SyslogProtocol.TLS and log.forward_tls_client_cert):
            detail = f"syslog forwarder over {protocol.value}, no client certificate"
            add("logging.forward", "none", detail, True)
    return out


# --- the single reader ------------------------------------------------------------------------------


def static_credential_hops(
    *, registry: Registry | None, settings: ServiceSettings | None
) -> list[StaticCredentialHop]:
    """Every backend hop that presents an unchanging credential or none, sorted by name.

    The SINGLE reader of the set; the module docstring says what it counts and what it leaves out.
    Pass ``None`` for a half the caller cannot see: ``registry=None`` reads the service settings only,
    and ``settings=None`` reads the connection graph only. A caller that passes ``None`` must say so in
    its own output. With both, the graph half also reads ``[egress].proxy_url`` to decide whether a
    connection's proxy credential is ever sent."""
    out: list[StaticCredentialHop] = []
    if registry is not None:
        site_proxy = None if settings is None else (settings.egress.proxy_url or "")
        out += _graph_hops(registry, site_proxy)
    if settings is not None:
        out += _settings_hops(settings)
    return sorted(out, key=lambda hop: hop.name)


# --- the gate ---------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StaticCredentialVerdict:
    """What the opt-in gate decides over one enumeration.

    ``refused`` lists the hops with no opt-out. ``accepted`` pairs each opted-out hop with the
    operator's recorded reason. ``unmatched`` names opt-outs that match no enumerated hop in scope,
    which is usually a typo or a hop that has since been fixed."""

    refused: tuple[StaticCredentialHop, ...]
    accepted: tuple[tuple[StaticCredentialHop, str], ...]
    unmatched: tuple[str, ...]


def evaluate_static_credential_gate(
    hops: Iterable[StaticCredentialHop],
    accepted: Mapping[str, str],
    *,
    settings_half: bool | None = None,
) -> StaticCredentialVerdict:
    """Split ``hops`` into refused and opted-out, against the ``accepted`` opt-out table.

    ``settings_half`` scopes the whole verdict, hops and opt-outs alike, because the serve path
    evaluates the two halves at different moments. ``True``: only ``settings:`` names. ``False``: only
    graph names. ``None``: everything."""

    def in_scope(name: str) -> bool:
        return settings_half is None or name.startswith(SETTINGS_PREFIX) == settings_half

    refused: list[StaticCredentialHop] = []
    taken: list[tuple[StaticCredentialHop, str]] = []
    seen: set[str] = set()
    for hop in hops:
        if not in_scope(hop.name):
            continue
        seen.add(hop.name)
        if hop.name in accepted:
            taken.append((hop, accepted[hop.name]))
        else:
            refused.append(hop)
    unmatched = sorted(name for name in accepted if name not in seen and in_scope(name))
    return StaticCredentialVerdict(tuple(refused), tuple(taken), tuple(unmatched))


def apply_static_credential_gate(
    settings: ServiceSettings, *, registry: Registry | None, log: logging.Logger
) -> str | None:
    """Run the opt-in ``[security].require_nonstatic_credentials`` gate over one half of the set.

    ``registry=None`` judges the settings half, which ``serve`` does before anything starts; a
    registry judges that graph's hops only, which is what the registry guard does at every load.
    Returns the refusal message when a hop in that half has no opt-out, else ``None``; the caller
    refuses or warns on ``[security].enforcement``. Logs, at WARNING, one line per honoured opt-out
    (hop name and the operator's reason: this is the startup audit of every opt-out) and one line per
    opt-out that matches no hop in this half. The lines carry hop names, the operator's own reasons
    and details, and a detail cannot carry a secret (see the module docstring). Returns ``None`` without reading or logging anything when the gate is off."""
    security = settings.security
    if not security.require_nonstatic_credentials:
        return None
    verdict = evaluate_static_credential_gate(
        static_credential_hops(registry=registry, settings=settings),
        security.static_credential_accepted,
        settings_half=registry is None,
    )
    for hop, reason in verdict.accepted:
        log.warning(
            "[security].static_credential_accepted: hop %s runs on a %s credential by opt-out "
            "(compliant kind available: %s): %s",
            hop.name,
            hop.credential,
            "yes" if hop.compliant_kind else "no",
            reason,
        )
    for name in verdict.unmatched:
        log.warning(
            "[security].static_credential_accepted names %s, which is not a static-credential hop "
            "of this instance; the opt-out does nothing",
            name,
        )
    if not verdict.refused:
        return None
    listed = "; ".join(f"{hop.name} ({hop.detail})" for hop in verdict.refused)
    return (
        f"[security].require_nonstatic_credentials is set but {len(verdict.refused)} backend hop(s) "
        f"present an unchanging credential or none, with no opt-out: {listed}. Move each to a "
        "compliant credential kind where one exists, or name it in "
        "[security].static_credential_accepted with the reason (see docs/SECURITY.md)"
    )


def make_static_credential_guard(
    settings: ServiceSettings, *, enforcing: bool, log: logging.Logger
) -> Callable[[Registry], None] | None:
    """The engine registry guard for the graph half, or ``None`` when the gate is off.

    It raises ``WiringError`` on a refused graph when ``enforcing`` (so a first load fails the start
    and a ``/config/reload`` is refused with the running graph kept), and only warns otherwise."""
    if not settings.security.require_nonstatic_credentials:
        return None

    def guard(registry: Registry) -> None:
        reason = apply_static_credential_gate(settings, registry=registry, log=log)
        if reason is None:
            return
        if enforcing:
            raise WiringError(reason)
        log.warning("%s", reason)

    return guard
