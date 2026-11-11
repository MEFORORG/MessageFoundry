# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pluggable outbound HTTP auth for the REST/SOAP/FHIR destinations (BACKLOG #65, ADR 0024 amendment).

Before #65 the HTTP destinations shipped: a static ``bearer_token`` / HTTP ``Basic``, and the SMART
Backend Services **asymmetric-JWT** OAuth2 token provider (ADR 0024). #65 adds two more **generic**
outbound auth modes, selected per connection and **additive** (off by default → byte-identical):

* **OAuth2 client-credentials with a SYMMETRIC ``client_secret``** — the common OAuth2 machine-to-machine
  grant (``grant_type=client_credentials`` with ``client_secret_basic`` / ``client_secret_post``). It is
  a :class:`BearerTokenProvider`, exactly like the SMART provider, so it slots into the destinations'
  **existing per-request bearer-injection seam** with no new plumbing — mint + cache a short-lived bearer,
  inject ``Authorization: Bearer …`` per request off-loop past the queue boundary (a retry re-mints).
* **HTTP Digest (RFC 7616)** — a challenge/response auth handled by the stdlib
  :class:`urllib.request.HTTPDigestAuthHandler`, which answers the endpoint's ``401`` challenge and
  retries within a single ``opener.open()`` (Digest is request-oriented, so no connection pinning needed).
  Exposed as an opener handler the destination folds into its per-connection opener.

**No new dependency.** OAuth2-CC reuses rest.py's hardened, TLS-verifying, no-redirect opener + URL
redaction; Digest is pure stdlib ``urllib``.

**Secrets / PHI.** ``oauth2_client_secret`` / ``http_auth_password`` are secrets — kept in ``env()``
(both are in ``_SECRET_SETTING_KEYS``, redacted in ``/metadata``), never logged, and the minted bearer /
digest response are runtime-only (never persisted). A token-endpoint or auth failure surfaces only the
redacted host + HTTP status — never the credential or the response body (which may echo the token).

**NTLM / Negotiate (deferred).** NTLM's handshake is **connection-bound** (the type1/type2/type3 legs
must ride one keep-alive TCP connection), which ``urllib.request`` — a new connection per ``open()`` —
cannot satisfy; a correct implementation needs a keep-alive HTTP client driven by ``pyspnego`` (already
in ``requirements.lock``, backing the AD/SSO server path). It is a scoped follow-up; the provider seam
here is shaped to admit it. See ADR 0024 amendment.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.tls_policy import (
    CREDENTIAL_HOP_WAYS_ACROSS,
    MIRRORED_CONNECTION_SETTING,
    SYSTEM_TRUST_ANCHOR,
    InsecureHopRefused,
    TrustAnchor,
    TrustAnchorPolicy,
    hop_name_prefix,
)
from messagefoundry.transports.base import float_setting
from messagefoundry.transports.rest import (
    HttpAuthError,
    ProxyConfig,
    _ApprovedDigestMixin,
    enforce_outbound_length_limits,
    hop_declarations_from_settings,
    http_family_trust_anchor,
    proxy_auth_handler_from_settings,
    refuse_cleartext_credential_hop,
)
from messagefoundry.transports.smart import (
    _TokenEndpointProvider,
    smart_auth_configured,
    token_provider_from_settings,
)

if TYPE_CHECKING:  # avoid importing heavy wiring at module import (transports <- config cycle)
    from messagefoundry.config.wiring import ConnectionSpec

__all__ = [
    "BearerTokenProvider",
    "HttpAuthError",
    "OAuth2ClientCredentialsProvider",
    "bearer_provider_from_settings",
    "digest_handler_from_settings",
    "http_digest_selected",
    "is_authorization_header_name",
    "refuse_http_digest_conflicts",
    "oauth2_auth_configured",
    "oauth2_cc_provider_from_settings",
    "proxy_auth_handler_from_settings",
    "with_http_digest",
    "with_oauth2_client_credentials",
]

# The HTTP destinations these auth modes apply to (REST/SOAP/FHIR share rest.py's HTTP plumbing).
_HTTP_CONNECTOR_TYPES = (ConnectorType.REST, ConnectorType.SOAP, ConnectorType.FHIR)


def oauth2_auth_configured(s: Mapping[str, Any]) -> bool:
    """Whether a settings mapping has OAuth2 client-credentials auth turned ON.

    ON means ``oauth2_token_url`` is present and ``oauth2_enabled`` is not switched off. The SINGLE
    definition, shared by at least :func:`oauth2_cc_provider_from_settings` (which builds the provider),
    the mutual-exclusion screen in :func:`bearer_provider_from_settings`, the static-credential hop
    reader (BACKLOG #1182) and :func:`~messagefoundry.config.wiring.oauth_request_advisories`.
    Before it existed the builder treated any falsy ``oauth2_enabled`` as off while the screen treated
    only a literal ``False`` as off. Off is the conservative reading, so a falsy value is off, the same
    rule :func:`~messagefoundry.transports.smart.smart_auth_configured` states."""
    return bool(s.get("oauth2_token_url")) and bool(s.get("oauth2_enabled", True))


# Renew this many seconds before the server's stated expiry so a token never expires mid-flight.
_DEFAULT_EXPIRY_SKEW = 60.0
_DEFAULT_TOKEN_TIMEOUT = 30.0


@runtime_checkable
class BearerTokenProvider(Protocol):
    """The structural interface the HTTP destinations already drive for per-request bearer injection
    (ADR 0024): :meth:`access_token` returns a valid (cached) token, :meth:`invalidate` drops the cache on
    a ``401``. Both :class:`~messagefoundry.transports.smart.SmartBackendTokenProvider` (asymmetric JWT)
    and :class:`OAuth2ClientCredentialsProvider` (symmetric secret) satisfy it, so the connector is
    provider-agnostic."""

    def access_token(self) -> str: ...

    def invalidate(self) -> None: ...


class OAuth2ClientCredentialsProvider(_TokenEndpointProvider):
    """Acquire + cache an OAuth2 ``client_credentials`` bearer using a **symmetric ``client_secret``**
    (BACKLOG #65) — the classic machine-to-machine grant (contrast the SMART provider's asymmetric signed
    ``client_assertion``, ADR 0024).

    Built once at connector construction (the token endpoint + secret are validated here). At delivery the
    connector calls :meth:`access_token` from its off-loop ``send()`` worker; the provider returns a cached
    token until it nears expiry, else POSTs the grant to the token endpoint. :meth:`invalidate` drops the
    cache so the next call re-mints (the connector calls it on a ``401`` — a token that expired between
    mint and use). ``auth_style`` selects RFC 6749 §2.3.1 ``client_secret_basic`` (the credential rides an
    HTTP ``Basic`` header, the default) or ``client_secret_post`` (in the form body). Why ``basic`` is
    the default, and what that does not claim about the header, is recorded on
    :func:`with_oauth2_client_credentials` (vault BACKLOG #2206).

    The token hop and the cache are the SMART provider's own, through the shared base (BACKLOG #2115):
    the cleartext refusal, the #2112 revocation guard, the proxy, ECH and trust-anchor routing, and the
    #2054 cache ceiling. Its hop parameters are documented on ``_open_token_hop``."""

    _LABEL = "OAuth2"
    _MISSING_URL = "OAuth2 client-credentials requires an 'oauth2_token_url' setting"
    _URL_SETTING = "oauth2_token_url"
    _CREDENTIAL_SETTINGS = "oauth2_client_id/oauth2_client_secret"
    _CREDENTIAL_NAME = "client_secret"
    _ERROR = HttpAuthError

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
        auth_style: str = "basic",
        audience: str | None = None,
        expiry_skew_seconds: float = _DEFAULT_EXPIRY_SKEW,
        timeout_seconds: float = _DEFAULT_TOKEN_TIMEOUT,
        # BACKLOG #2112 (ADR 0173 section 4.3): the per-connection `tls_revocation_attested`, read from
        # the resolved settings exactly as the SMART sibling reads it. No cleartext declaration is
        # taken: none lets the token request cross cleartext http off-box (vault BACKLOG #3533 item 4).
        revocation_attested: bool = False,
        revocation_attested_reason: str | None = None,
        # The connection the refusals and the revocation record name.
        connection: str | None = None,
        # The connection that declared `revocation_attested`, named in the revocation guard's audit
        # line. Both readers fill it from the same `connection_name` mirror as `connection`.
        revocation_connection: str | None = None,
        proxy: ProxyConfig | None = None,
        # #1176 (ADR 0139): this connection's loopback ECH sidecar, when it has one; the token POST is
        # re-addressed to it (see ``_post_token``). Mutually exclusive with ``proxy`` (refused at
        # connector construction). None (default) -> byte-identical.
        ech_sidecar: str | None = None,
        # #1660 (#1180, ADR 0093): the client trust anchor for the TOKEN hop, already resolved against
        # the token host by :func:`oauth2_cc_provider_from_settings`. Identical reasoning to the SMART
        # sibling in smart.py -- the data hop has carried one since #1180 and the hop that carries the
        # client_secret did not. The default is the OS trust store, so a direct test construction and
        # an unconfigured instance are byte-identical.
        trust_anchor: TrustAnchor = SYSTEM_TRUST_ANCHOR,
    ) -> None:
        scheme = self._check_token_url(
            token_url,
            connection=connection,
        )
        if not client_id:
            raise HttpAuthError("OAuth2 client-credentials requires an 'oauth2_client_id' setting")
        if not client_secret:
            raise HttpAuthError(
                "OAuth2 client-credentials requires an 'oauth2_client_secret' setting (via env())"
            )
        if auth_style not in ("basic", "post"):
            raise HttpAuthError(f"oauth2_auth_style must be 'basic' or 'post', got {auth_style!r}")
        self.client_id = client_id
        self._client_secret = client_secret
        self.scope = scope or None
        self.audience = audience or None
        self.auth_style = auth_style
        self._open_token_hop(
            scheme,
            token_url,
            expiry_skew_seconds=expiry_skew_seconds,
            timeout_seconds=timeout_seconds,
            revocation_attested=revocation_attested,
            revocation_attested_reason=revocation_attested_reason,
            revocation_connection=revocation_connection,
            proxy=proxy,
            ech_sidecar=ech_sidecar,
            trust_anchor=trust_anchor,
        )

    def _fetch_token(self) -> tuple[str, float]:
        """POST the ``client_credentials`` grant and return ``(access_token, ttl)``. PHI/secret-safe: a
        failure names only the redacted token host + HTTP status — never the secret or the response body
        (which carries the bearer)."""
        form: dict[str, str] = {"grant_type": "client_credentials"}
        if self.scope:
            form["scope"] = self.scope
        if self.audience:
            form["audience"] = self.audience
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            **self._proxy_auth,  # ADR 0126: pre-emptive Proxy-Authorization when behind an auth proxy
        }
        if self.auth_style == "basic":
            raw = f"{self.client_id}:{self._client_secret}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        else:  # client_secret_post
            form["client_id"] = self.client_id
            form["client_secret"] = self._client_secret
        data = urllib.parse.urlencode(form).encode("ascii")
        # ASVS 4.2.5: the token URL and the Basic client-credential header are operator-supplied via
        # env(), so an env value that resolved to an unexpected blob would otherwise surface as an
        # opaque IdP-side failure on the first mint rather than as a clear config error.
        enforce_outbound_length_limits(self.token_url, dict(headers))
        return self._post_token(data, headers)


def oauth2_cc_provider_from_settings(
    s: Mapping[str, Any],
    *,
    proxy: ProxyConfig | None = None,
    ech_sidecar: str | None = None,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
) -> OAuth2ClientCredentialsProvider | None:
    """The :class:`OAuth2ClientCredentialsProvider` for an ``env()``-resolved settings mapping, or ``None``
    when symmetric OAuth2-CC auth is off (``oauth2_token_url`` absent, or ``oauth2_enabled`` is False) — so
    any connection that didn't configure it is byte-identical. ``proxy`` (ADR 0126) routes the
    token-endpoint POST through the connection's forward proxy; ``ech_sidecar`` (#1176, ADR 0139)
    re-addresses it to the connection's loopback ECH sidecar instead. The two are mutually exclusive by
    construction.

    ``trust_anchor_policy`` (#1660) is the instance-wide ``[tls]`` policy the caller already holds, off
    its ``Destination``. ``None`` resolves to the OS trust store, byte-identical."""
    if not oauth2_auth_configured(s):
        return None
    # Read strictly for the flag check (vault BACKLOG #2232) and the mirrored connection name.
    _, (_, _, connection), revocation = hop_declarations_from_settings(s, HttpAuthError)
    token_url = str(s.get("oauth2_token_url") or "")
    return OAuth2ClientCredentialsProvider(
        token_url=token_url,
        client_id=str(s.get("oauth2_client_id") or ""),
        client_secret=str(s.get("oauth2_client_secret") or ""),
        scope=(str(s["oauth2_scope"]) if s.get("oauth2_scope") else None),
        auth_style=str(s.get("oauth2_auth_style", "basic")),
        audience=(str(s["oauth2_audience"]) if s.get("oauth2_audience") else None),
        expiry_skew_seconds=float_setting(
            s.get("oauth2_expiry_skew_seconds", _DEFAULT_EXPIRY_SKEW),
            knob="oauth2_expiry_skew_seconds",
            transport="OAuth2",
        ),
        timeout_seconds=float_setting(
            s.get("oauth2_timeout_seconds", _DEFAULT_TOKEN_TIMEOUT),
            knob="oauth2_timeout_seconds",
            transport="OAuth2",
        ),
        # BACKLOG #2112 (ADR 0173 section 4.3): the revocation attestation `_dest_config` mirrors from
        # the connection's top-level declaration, through the reader the SMART sibling uses.
        revocation_attested=revocation[0],
        revocation_attested_reason=revocation[1],
        connection=connection,
        revocation_connection=revocation[2],
        proxy=proxy,  # ADR 0126: forward-proxy the token-endpoint POST
        ech_sidecar=ech_sidecar,  # #1176: ...or re-address it to the ECH sidecar (ADR 0139)
        # #1660: resolved against the TOKEN url, not the connection's data url -- the authorization
        # server is frequently a different host from the REST/SOAP endpoint, and both the loopback
        # exemption and the internal-vs-public decision key on the host actually being dialled. The
        # connection's own ``tls_ca_file`` still wins verbatim, exactly as it does on the data hop.
        trust_anchor=http_family_trust_anchor(
            s, url=token_url, trust_anchor_policy=trust_anchor_policy, cell="oauth2_token_url"
        ),
    )


def bearer_provider_from_settings(
    s: Mapping[str, Any],
    *,
    proxy: ProxyConfig | None = None,
    ech_sidecar: str | None = None,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
) -> BearerTokenProvider | None:
    """The active bearer-token provider for an HTTP destination, or ``None`` when none is configured
    (byte-identical). Unifies the SMART Backend Services provider (ADR 0024, asymmetric JWT) and the
    OAuth2 client-credentials provider (#65, symmetric secret) behind the one bearer seam the connector
    drives. The two are **mutually exclusive** on one connection — configuring both is a loud
    :class:`HttpAuthError` (a connection has exactly one identity). ``proxy`` (ADR 0126) routes whichever
    provider's token-endpoint call through the connection's forward proxy; ``ech_sidecar`` (#1176,
    ADR 0139) re-addresses it to the connection's loopback ECH sidecar instead, so the ECH connection's
    token hop stops leaking the authorization server's SNI while its payload hop is routed.
    ``trust_anchor_policy`` (#1660) likewise reaches whichever provider is built, so the token hop
    verifies against the same instance ``[tls]`` anchor the delivery hop has used since #1180."""
    # Detect the conflict from settings PRESENCE before constructing either provider, so a "both
    # configured" mistake reports the mutual-exclusion error rather than whichever provider's own
    # validation happens to fire first on partial config.
    has_smart = smart_auth_configured(s)
    has_oauth = oauth2_auth_configured(s)
    if has_smart and has_oauth:
        raise HttpAuthError(
            "a connection cannot use both SMART backend services and OAuth2 client-credentials auth "
            "(mutually exclusive — configure exactly one)"
        )
    return token_provider_from_settings(
        s, proxy=proxy, ech_sidecar=ech_sidecar, trust_anchor_policy=trust_anchor_policy
    ) or oauth2_cc_provider_from_settings(
        s, proxy=proxy, ech_sidecar=ech_sidecar, trust_anchor_policy=trust_anchor_policy
    )


class _ApprovedDigestAuthHandler(_ApprovedDigestMixin, urllib.request.HTTPDigestAuthHandler):
    """urllib's Digest handler, answering an endpoint's 401 with SHA-256 or refusing it (BACKLOG #1171,
    ASVS 11.4.1). The check lives in :class:`~messagefoundry.transports.rest._ApprovedDigestMixin`,
    which the proxy 407 handler shares, so the origin and proxy paths cannot drift apart."""


#: RFC 9110 ``tchar``: the characters a field name can hold. The same set as
#: ``bounded_read._TCHARS``, which reads ``Proxy-Authorization`` by this rule.
_TCHARS = r"!#$%&'*+\-.^_`|~0-9A-Za-z"
#: ``Authorization`` in any ASCII letter case, with any run of characters no field name can hold
#: before it, and after it either nothing or such a character and then anything (the rule
#: ``bounded_read.is_proxy_credential_header_name`` applies to ``Proxy-Authorization``).
_AUTHORIZATION_NAME = re.compile(
    rf"[^{_TCHARS}]*authorization(?:[^{_TCHARS}].*)?", re.ASCII | re.IGNORECASE | re.DOTALL
)


def is_authorization_header_name(name: str) -> bool:
    """Whether ``name`` is the ``Authorization`` header, however it is spelled (BACKLOG #5529).
    ``http.client`` sends a name ending in a space, a tab, a NUL or a DEL, or starting with a NUL or
    a DEL, as it is written, and a peer may read each as the plain name, so a bare ``lower()``
    comparison is not enough."""
    return _AUTHORIZATION_NAME.fullmatch(name) is not None


def http_digest_selected(s: Mapping[str, Any]) -> bool:
    """Whether ``http_auth`` selects HTTP Digest. The SINGLE definition, shared by the connectors
    and the static-credential census so the two agree.

    Off for an unset or falsy value, or a string that is blank once stripped. Any other value than
    ``digest`` (any case, any padding) raises :class:`HttpAuthError` (BACKLOG #5529 limb 1): a typo
    used to read as auth off, so the connection built and delivered with no auth. The message does
    not echo the value."""
    raw = s.get("http_auth")
    mode = str(raw).strip().lower() if raw else ""
    if not mode:
        return False
    if mode == "digest":
        return True
    connection = s.get(MIRRORED_CONNECTION_SETTING)
    raise HttpAuthError(
        f"{hop_name_prefix(None if connection is None else str(connection))}http_auth names a "
        "mode this engine does not offer; the only value is 'digest' "
        "(with_http_digest), or leave it unset for no HTTP auth"
    )


def refuse_http_digest_conflicts(s: Mapping[str, Any]) -> bool:
    """Whether Digest is selected, after refusing what cannot stand beside it (BACKLOG #5529).

    The connectors call this at the top of construction, so a connection that will not build logs
    no insecure-hop crossing or warning first; :func:`digest_handler_from_settings` calls it again.
    Refuses an unrecognised ``http_auth`` (:func:`http_digest_selected`), and with Digest selected,
    a static ``bearer_token``, ``basic_user``, ``basic_password``, ``Authorization`` entry in
    ``headers`` or signing header named ``Authorization``: a connection configures exactly one HTTP
    credential. Where such a credential is sent it would replace the Digest response on the wire,
    because urllib lets a request header override the one the Digest handler adds; a lone Basic
    half sends nothing, and is refused under the same rule. Also refuses, here rather than late, a
    SMART or OAuth2 bearer provider beside Digest and a missing Digest user or password. Names
    settings, never a value."""
    if not http_digest_selected(s):
        return False
    # Read strictly: a non-bool flag raises HttpAuthError naming the connection (#2232).
    _, (_, _, conn), _ = hop_declarations_from_settings(s, HttpAuthError)
    prefix = hop_name_prefix(conn)
    static = [name for name in ("bearer_token", "basic_user", "basic_password") if s.get(name)]
    extra = s.get("headers")
    if isinstance(extra, Mapping) and any(is_authorization_header_name(str(k)) for k in extra):
        static.append("an Authorization entry in headers")
    # A detached JWS written under the Authorization name (with_signing's header_name) is a header
    # _post sets per request, so it would replace the Digest response the same way.
    signing = s.get("sign_private_key") and s.get("sign_enabled", True)
    if signing and is_authorization_header_name(str(s.get("sign_header") or "")):
        static.append("a signing header named Authorization")
    if static:
        raise HttpAuthError(
            f"{prefix}HTTP Digest cannot be configured beside a static credential "
            f"({', '.join(static)}); configure exactly one"
        )
    if smart_auth_configured(s) or oauth2_auth_configured(s):
        raise HttpAuthError(
            f"{prefix}a connection cannot use BOTH a bearer-token provider and HTTP Digest auth "
            "(mutually exclusive — configure exactly one)"
        )
    if not str(s.get("http_auth_user") or "") or not str(s.get("http_auth_password") or ""):
        raise HttpAuthError(
            f"{prefix}HTTP Digest auth requires 'http_auth_user' and 'http_auth_password' "
            "(password via env())"
        )
    return True


def digest_handler_from_settings(
    s: Mapping[str, Any], *, url: str
) -> urllib.request.HTTPDigestAuthHandler | None:
    """An :class:`urllib.request.HTTPDigestAuthHandler` pre-loaded with the connection's credentials
    (BACKLOG #65, RFC 7616), or ``None`` when HTTP Digest auth is off (``http_auth`` unset, falsy
    or blank) — byte-identical. Any other value than ``digest`` raises, as do the conflicts
    :func:`refuse_http_digest_conflicts` names. The connector folds the returned handler into its
    per-connection opener; urllib then answers the endpoint's ``401`` Digest challenge and retries
    within one ``opener.open()``.

    Refuses to run over cleartext ``http`` to an off-box host (the digest response is a credential),
    through the rule the delivery cells' credentials share (``refuse_cleartext_credential_hop``): only
    a loopback host lifts it, never ``tls_hop_attested`` or ``cleartext_accepted`` (vault BACKLOG #3533
    item 4). A missing user/password is a loud :class:`HttpAuthError` (fail-closed, never a silent
    no-auth request)."""
    if not refuse_http_digest_conflicts(s):
        return None
    # The declarations are read strictly: a non-bool flag raises HttpAuthError naming the connection
    # (vault BACKLOG #2232), and the mirrored connection name heads the refusal below.
    _, (_, _, accept_conn), _ = hop_declarations_from_settings(s, HttpAuthError)
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    # The digest response is a credential, so an off-box cleartext hop is refused with no escape
    # (``refuse_cleartext_credential_hop``, vault BACKLOG #3533 item 4). It raises
    # ``InsecureHopRefused``; re-raise as ``HttpAuthError`` to keep this seam's error contract (both are
    # ``ValueError``s, so the loader surfaces either identically).
    try:
        refuse_cleartext_credential_hop(
            scheme,
            url,
            credential="digest credential",
            connection=accept_conn,
        )
    except InsecureHopRefused as exc:
        raise HttpAuthError(
            f"{hop_name_prefix(accept_conn)}HTTP Digest over cleartext http would expose the digest "
            f"credential; refused ({CREDENTIAL_HOP_WAYS_ACROSS})"
        ) from exc
    # Both are non-empty: refuse_http_digest_conflicts refused a missing one above.
    user = str(s.get("http_auth_user") or "")
    password = str(s.get("http_auth_password") or "")
    pwmgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    # A default-realm entry keyed on the endpoint URL: urllib matches by URL prefix, so the same
    # credential answers whatever realm the server names in its 401 challenge.
    pwmgr.add_password(None, url, user, password)
    return _ApprovedDigestAuthHandler(pwmgr)


def _require_http_spec(spec: ConnectionSpec, mode: str) -> None:
    if spec.type not in _HTTP_CONNECTOR_TYPES:
        raise HttpAuthError(
            f"{mode} auth applies to REST/SOAP/FHIR outbound only, not {spec.type.value!r} (#65)"
        )


def with_oauth2_client_credentials(
    spec: ConnectionSpec,
    *,
    token_url: object,
    client_id: object,
    client_secret: object,
    scope: str | None = None,
    auth_style: str = "basic",
    audience: object | None = None,
    expiry_skew_seconds: float = _DEFAULT_EXPIRY_SKEW,
    timeout_seconds: float = _DEFAULT_TOKEN_TIMEOUT,
    enabled: bool = True,
) -> ConnectionSpec:
    """Enable **OAuth2 client-credentials** auth (symmetric ``client_secret``) on a REST/SOAP/FHIR outbound
    spec (BACKLOG #65). Compose it over the ``Rest()`` / ``FHIR()`` / ``Soap()`` factory — auth is one
    code-first call and nothing else about the connector changes::

        outbound("OB_PARTNER", with_oauth2_client_credentials(
            Rest(url=env("partner_url"), capture_response=True),
            token_url=env("partner_token_url"),
            client_id=env("partner_client_id"),
            client_secret=env("partner_client_secret"),   # secret — keep in env()
            scope="claims.write",
        ))

    ``token_url`` / ``client_id`` / ``client_secret`` / ``audience`` may be
    :func:`~messagefoundry.config.wiring.env` references — keep the secret in ``env()``. The minted bearer
    **overrides** any static ``bearer_token``; it is mutually exclusive with SMART auth and HTTP Digest
    (a loud error at construction otherwise). Mutates ``spec`` in place and returns it.

    **What this mode does not give you, and where the stronger one already is** (BACKLOG #1158, ASVS
    10.2.2). Both ``auth_style`` values send the ``client_secret`` itself — ``basic`` in an
    ``Authorization`` header, ``post`` in the form body — so the credential a token endpoint receives is
    **reusable**: nothing in it names the endpoint it was sent to or bounds its lifetime, and the same
    secret registered at a second authorization server authenticates there too. Where your
    authorization server will register a **public key**, compose
    :func:`~messagefoundry.transports.smart.with_smart_backend` over the same ``Rest()`` spec instead.
    Despite the name it is a plain **RFC 7523 section 2.2 ``private_key_jwt``** client —
    ``grant_type=client_credentials`` plus a signed assertion whose ``aud`` is this connection's pinned
    token endpoint, with nothing FHIR- or SMART-specific on the wire — so a partner validating ``aud``
    (RFC 7523 section 3) rejects a replayed assertion and the key never leaves this process. Pass
    ``algorithm="RS256"`` for a generic partner; the ``RS384`` default is SMART's own requirement.

    A symmetric ``client_secret_jwt`` (RFC 7523 with an HMAC) is **deliberately not offered**: the
    authorization server must hold the same secret to verify such an assertion, so it can mint one for
    any other audience. It would stop transmitting the secret without restoring the property above.
    ``tests/test_oauth2_destination_binding.py`` holds both halves of this paragraph.

    **Why ``auth_style`` defaults to ``"basic"``** (vault BACKLOG #2206, decided 2026-10-04: the default
    stays, and no behaviour changed). Two reasons. Of the two symmetric styles, RFC 6749 section 2.3.1
    says an authorization server MUST support HTTP Basic for a client issued a client password, and
    that sending the credentials in the request body is NOT RECOMMENDED. So ``basic`` is the style a
    server is required to accept. And a public-key style cannot be a default: it needs key material,
    which ``with_smart_backend`` requires as ``private_key`` and which no default can supply. The
    stronger option is therefore a choice you make, named in the paragraph above.

    That is a statement about WHICH style is the default. It is not a claim that the header this
    provider builds follows that section's encoding rule. ``_fetch_token`` base64-encodes the client
    id and secret as written. The section also asks for each to be form-encoded first, and that step
    is not applied. The two forms are the same for an id and secret with no reserved character."""
    _require_http_spec(spec, "OAuth2 client-credentials")
    spec.settings.update(
        {
            "oauth2_enabled": enabled,
            "oauth2_token_url": token_url,
            "oauth2_client_id": client_id,
            "oauth2_client_secret": client_secret,
            "oauth2_scope": scope,
            "oauth2_auth_style": auth_style,
            "oauth2_audience": audience,
            "oauth2_expiry_skew_seconds": expiry_skew_seconds,
            "oauth2_timeout_seconds": timeout_seconds,
        }
    )
    return spec


def with_http_digest(
    spec: ConnectionSpec,
    *,
    user: object,
    password: object,
) -> ConnectionSpec:
    """Enable **HTTP Digest** auth (RFC 7616) on a REST/SOAP/FHIR outbound spec (BACKLOG #65). urllib
    answers the endpoint's ``401`` Digest challenge and retries within one request::

        outbound("OB_LEGACY", with_http_digest(
            Rest(url=env("legacy_url")),
            user=env("legacy_user"),
            password=env("legacy_password"),   # secret — keep in env()
        ))

    ``user`` / ``password`` may be :func:`~messagefoundry.config.wiring.env` references. Mutually exclusive
    with a bearer provider (SMART / OAuth2-CC), with a static ``bearer_token``, ``basic_user`` or
    ``basic_password``, with an ``Authorization`` entry in ``headers`` or a signing header named
    ``Authorization`` (#5529), and on REST with ``ech_egress``; refused over cleartext ``http`` to a
    host off this machine, with no escape (vault BACKLOG #3533 item 4). Mutates ``spec`` in place
    and returns it."""
    _require_http_spec(spec, "HTTP Digest")
    spec.settings.update(
        {"http_auth": "digest", "http_auth_user": user, "http_auth_password": password}
    )
    return spec
