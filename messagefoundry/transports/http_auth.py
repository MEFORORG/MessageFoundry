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
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.tls_policy import (
    CREDENTIAL_HOP_WAYS_ACROSS,
    SYSTEM_TRUST_ANCHOR,
    InsecureHopRefused,
    TrustAnchor,
    TrustAnchorPolicy,
    hop_name_prefix,
)
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
        attested: bool = False,
        # BACKLOG #2112 (ADR 0173 section 4.3): the per-connection `tls_revocation_attested`, read from
        # the resolved settings exactly as the SMART sibling reads it. DISTINCT from `attested` above.
        revocation_attested: bool = False,
        revocation_attested_reason: str | None = None,
        # ADR 0153: the same per-connection cleartext declaration the delivery hop carries. Without it
        # the token-endpoint hop would refuse a connection whose delivery hop was declared, leaving the
        # operator no honest way to describe a legacy peer.
        cleartext_accepted: bool = False,
        cleartext_reason: str | None = None,
        connection: str | None = None,
        # The connection that declared `revocation_attested`, named in the revocation guard's audit
        # line. Kept apart from `connection`, the cleartext declaration's name.
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
            attested=attested,
            cleartext_accepted=cleartext_accepted,
            cleartext_reason=cleartext_reason,
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
    attested, _accepted, revocation = hop_declarations_from_settings(s, HttpAuthError)
    token_url = str(s.get("oauth2_token_url") or "")
    return OAuth2ClientCredentialsProvider(
        token_url=token_url,
        client_id=str(s.get("oauth2_client_id") or ""),
        client_secret=str(s.get("oauth2_client_secret") or ""),
        scope=(str(s["oauth2_scope"]) if s.get("oauth2_scope") else None),
        auth_style=str(s.get("oauth2_auth_style", "basic")),
        audience=(str(s["oauth2_audience"]) if s.get("oauth2_audience") else None),
        expiry_skew_seconds=float(s.get("oauth2_expiry_skew_seconds", _DEFAULT_EXPIRY_SKEW)),
        timeout_seconds=float(s.get("oauth2_timeout_seconds", _DEFAULT_TOKEN_TIMEOUT)),
        # #200: the per-connection insecure-hop attestation keys the posture-keyed cleartext refusal in
        # __init__ (read from settings exactly as _dest_config / FhirLookup do). Default False → the hop
        # decides purely on posture.
        attested=attested,
        # BACKLOG #2112 (ADR 0173 section 4.3): the revocation attestation `_dest_config` mirrors from
        # the connection's top-level declaration, through the reader the SMART sibling uses.
        revocation_attested=revocation[0],
        revocation_attested_reason=revocation[1],
        # ADR 0153: the sibling cleartext-acceptance declaration, mirrored into these resolved settings
        # by the runner's _dest_config for exactly this kind of settings-driven seam (the connection name
        # rides with it so the acceptance audit record can name the declaration that produced it).
        cleartext_accepted=_accepted[0],
        cleartext_reason=_accepted[1],
        connection=_accepted[2],
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


def digest_handler_from_settings(
    s: Mapping[str, Any], *, url: str
) -> urllib.request.HTTPDigestAuthHandler | None:
    """An :class:`urllib.request.HTTPDigestAuthHandler` pre-loaded with the connection's credentials
    (BACKLOG #65, RFC 7616), or ``None`` when HTTP Digest auth is off (``http_auth`` != ``"digest"``) —
    byte-identical. The connector folds the returned handler into its per-connection opener; urllib then
    answers the endpoint's ``401`` Digest challenge and retries within one ``opener.open()``.

    Refuses to run over cleartext ``http`` (the digest response is a credential) via the SAME
    posture-keyed authority the REST/SOAP/FHIR delivery cells use (#200, ADR 0092): a production-PHI hop
    is REFUSED even with the global escape set (inert for prod-PHI), while a non-prod / non-PHI /
    per-hop-attested / loopback hop decides exactly as the delivery cells do. A missing user/password is a
    loud :class:`HttpAuthError` (fail-closed, never a silent no-auth request)."""
    if str(s.get("http_auth") or "").lower() != "digest":
        return None
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    # The digest response is a credential — refuse the cleartext hop through the ONE posture-keyed
    # authority (``refuse_cleartext_credential_hop``) instead of the blunt global escape, so prod-PHI is
    # refused even with the escape set (matching the delivery cells). ``url`` is the delivery URL (same
    # host as the delivery hop), so the connection's ``tls_hop_attested`` applies directly. It raises
    # ``InsecureHopRefused`` on REFUSE; re-raise as ``HttpAuthError`` to keep this seam's error contract
    # (both are ``ValueError``s → the loader surfaces either identically). Runs at connector construction
    # under the gate's stamped posture (fail-closing to prod-PHI when unstamped).
    # ADR 0153: the sibling cleartext-acceptance declaration, mirrored into these resolved settings by
    # the runner's _dest_config for exactly this kind of settings-driven seam. A non-bool flag raises
    # HttpAuthError naming the connection, inside this seam's contract (vault BACKLOG #2232).
    attested, (accepted, accept_reason, accept_conn), _ = hop_declarations_from_settings(
        s, HttpAuthError
    )
    try:
        refuse_cleartext_credential_hop(
            scheme,
            url,
            credential="digest credential",
            attested=attested,
            cleartext_accepted=accepted,
            cleartext_reason=accept_reason,
            connection=accept_conn,
        )
    except InsecureHopRefused as exc:
        raise HttpAuthError(
            f"{hop_name_prefix(accept_conn)}HTTP Digest over cleartext http would expose the digest "
            "credential; refused by the "
            f"instance security posture ({CREDENTIAL_HOP_WAYS_ACROSS})"
        ) from exc
    user = str(s.get("http_auth_user") or "")
    password = str(s.get("http_auth_password") or "")
    if not user or not password:
        raise HttpAuthError(
            "HTTP Digest auth requires 'http_auth_user' and 'http_auth_password' (password via env())"
        )
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
    with a bearer provider (SMART / OAuth2-CC); refused over cleartext ``http`` by the instance security
    posture (a production-PHI hop cannot be escaped — #200). Mutates ``spec`` in place and returns it."""
    _require_http_spec(spec, "HTTP Digest")
    spec.settings.update(
        {"http_auth": "digest", "http_auth_user": user, "http_auth_password": password}
    )
    return spec
