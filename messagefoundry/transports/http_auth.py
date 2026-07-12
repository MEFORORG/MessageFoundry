# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.tls_policy import InsecureHopRefused
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.rest import (
    _NO_REDIRECT_OPENER,
    _redact_url,
    refuse_cleartext_credential_hop,
)
from messagefoundry.transports.smart import token_provider_from_settings

if TYPE_CHECKING:  # avoid importing heavy wiring at module import (transports <- config cycle)
    from messagefoundry.config.wiring import ConnectionSpec

__all__ = [
    "BearerTokenProvider",
    "HttpAuthError",
    "OAuth2ClientCredentialsProvider",
    "bearer_provider_from_settings",
    "digest_handler_from_settings",
    "oauth2_cc_provider_from_settings",
    "with_http_digest",
    "with_oauth2_client_credentials",
]

# The HTTP destinations these auth modes apply to (REST/SOAP/FHIR share rest.py's HTTP plumbing).
_HTTP_CONNECTOR_TYPES = (ConnectorType.REST, ConnectorType.SOAP, ConnectorType.FHIR)

# Renew this many seconds before the server's stated expiry so a token never expires mid-flight.
_DEFAULT_EXPIRY_SKEW = 60.0
_DEFAULT_TOKEN_TIMEOUT = 30.0
# If the token response omits expires_in, assume a short lifetime and re-mint soon.
_FALLBACK_TOKEN_TTL = 300.0


class HttpAuthError(ValueError):
    """A generic outbound-HTTP-auth configuration is invalid (missing secret, a cleartext token endpoint,
    two mutually-exclusive auth modes on one connection). Raised **loud at connector construction** — like
    a bad TLS cert — so it fails at ``check`` / dry-run / start, never as a wire-time surprise. The message
    never contains a secret value."""


@runtime_checkable
class BearerTokenProvider(Protocol):
    """The structural interface the HTTP destinations already drive for per-request bearer injection
    (ADR 0024): :meth:`access_token` returns a valid (cached) token, :meth:`invalidate` drops the cache on
    a ``401``. Both :class:`~messagefoundry.transports.smart.SmartBackendTokenProvider` (asymmetric JWT)
    and :class:`OAuth2ClientCredentialsProvider` (symmetric secret) satisfy it, so the connector is
    provider-agnostic."""

    def access_token(self) -> str: ...

    def invalidate(self) -> None: ...


class OAuth2ClientCredentialsProvider:
    """Acquire + cache an OAuth2 ``client_credentials`` bearer using a **symmetric ``client_secret``**
    (BACKLOG #65) — the classic machine-to-machine grant (contrast the SMART provider's asymmetric signed
    ``client_assertion``, ADR 0024).

    Built once at connector construction (the token endpoint + secret are validated here). At delivery the
    connector calls :meth:`access_token` from its off-loop ``send()`` worker; the provider returns a cached
    token until it nears expiry, else POSTs the grant to the token endpoint. :meth:`invalidate` drops the
    cache so the next call re-mints (the connector calls it on a ``401`` — a token that expired between
    mint and use). ``auth_style`` selects RFC 6749 §2.3.1 ``client_secret_basic`` (the credential rides an
    HTTP ``Basic`` header, the default) or ``client_secret_post`` (in the form body)."""

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
    ) -> None:
        if not token_url:
            raise HttpAuthError("OAuth2 client-credentials requires an 'oauth2_token_url' setting")
        scheme = urllib.parse.urlsplit(token_url).scheme.lower()
        if scheme not in ("http", "https"):
            raise HttpAuthError(f"oauth2_token_url must be http or https, got scheme {scheme!r}")
        # The client_secret / minted bearer is a credential — the token-endpoint hop must not carry it
        # over cleartext http. Re-keyed (#200, ADR 0092) onto the SAME posture-keyed authority the
        # REST/SOAP/FHIR delivery cells consume (``refuse_cleartext_credential_hop``) so a production-PHI
        # hop is REFUSED even with the blunt global escape set (the escape is INERT for prod-PHI — the
        # delivery URL already had this invariant, the token-endpoint host did not), while a non-prod /
        # non-PHI / per-hop-attested / loopback hop decides exactly as the delivery cells do. The posture
        # is the one stamped by the construction gate (this provider is built inside the destination's
        # __init__, under ``build_check_registry``'s ``active_hop_posture`` scope), fail-closing to
        # prod-PHI when unstamped. ``refuse_cleartext_credential_hop`` raises ``InsecureHopRefused`` (a
        # ``tls_policy`` ``ValueError``) on REFUSE and returns on WARN/ALLOW; re-raise as ``HttpAuthError``
        # to preserve THIS seam's error contract (its callers/tests expect it) — both are ``ValueError``
        # subclasses, so the loader surfaces either identically. The message never carries the secret.
        try:
            refuse_cleartext_credential_hop(
                scheme, token_url, credential="OAuth2 client_secret", attested=attested
            )
        except InsecureHopRefused as exc:
            raise HttpAuthError(
                "OAuth2 token endpoint over cleartext http would expose the client_secret; refused by "
                "the instance security posture — a production-PHI hop cannot be escaped (use https, or "
                "attest the hop as secure via tls_hop_attested)"
            ) from exc
        if not client_id:
            raise HttpAuthError("OAuth2 client-credentials requires an 'oauth2_client_id' setting")
        if not client_secret:
            raise HttpAuthError(
                "OAuth2 client-credentials requires an 'oauth2_client_secret' setting (via env())"
            )
        if auth_style not in ("basic", "post"):
            raise HttpAuthError(f"oauth2_auth_style must be 'basic' or 'post', got {auth_style!r}")
        self.token_url = token_url
        self.client_id = client_id
        self._client_secret = client_secret
        self.scope = scope or None
        self.audience = audience or None
        self.auth_style = auth_style
        self.expiry_skew_seconds = max(0.0, expiry_skew_seconds)
        self.timeout_seconds = timeout_seconds
        self._opener: urllib.request.OpenerDirector = _NO_REDIRECT_OPENER
        self._lock = threading.Lock()
        self._cached_token: str | None = None
        self._cached_expiry_monotonic = 0.0

    def access_token(self) -> str:
        """A valid bearer token — cached until it nears expiry, else freshly acquired. Blocking (a token
        ``POST``); called inside the connector's off-loop ``send()`` worker. Raises
        :class:`~messagefoundry.transports.base.DeliveryError` (transient) if acquisition fails."""
        with self._lock:
            if self._cached_token is not None and time.monotonic() < self._cached_expiry_monotonic:
                return self._cached_token
            token, ttl = self._fetch_token()
            self._cached_expiry_monotonic = time.monotonic() + max(
                0.0, ttl - self.expiry_skew_seconds
            )
            self._cached_token = token
            return token

    def invalidate(self) -> None:
        """Drop the cached token so the next :meth:`access_token` re-mints (called on a ``401``)."""
        with self._lock:
            self._cached_token = None
            self._cached_expiry_monotonic = 0.0

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
        }
        if self.auth_style == "basic":
            raw = f"{self.client_id}:{self._client_secret}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        else:  # client_secret_post
            form["client_id"] = self.client_id
            form["client_secret"] = self._client_secret
        data = urllib.parse.urlencode(form).encode("ascii")
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) above
            self.token_url, data=data, headers=headers, method="POST"
        )
        try:
            with self._opener.open(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise DeliveryError(
                f"OAuth2 token endpoint {_redact_url(self.token_url)} returned HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise DeliveryError(
                f"OAuth2 token endpoint {_redact_url(self.token_url)} unreachable: {exc.reason}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(
                f"OAuth2 token endpoint {_redact_url(self.token_url)} failed: {exc}"
            ) from exc
        return self._parse_token_response(body)

    def _parse_token_response(self, body: str) -> tuple[str, float]:
        """Extract ``(access_token, ttl)`` from the token JSON. Never echoes ``body`` (it carries the
        bearer)."""
        try:
            payload = json.loads(body)
            token = payload["access_token"]
            if not isinstance(token, str) or not token:
                raise ValueError("missing access_token")
        except (ValueError, KeyError, TypeError) as exc:
            raise DeliveryError(
                f"OAuth2 token endpoint {_redact_url(self.token_url)} returned an unparseable or "
                "incomplete token response"
            ) from exc
        expires_in = payload.get("expires_in", _FALLBACK_TOKEN_TTL)
        ttl = float(expires_in) if isinstance(expires_in, (int, float)) else _FALLBACK_TOKEN_TTL
        return token, ttl


def oauth2_cc_provider_from_settings(
    s: Mapping[str, Any],
) -> OAuth2ClientCredentialsProvider | None:
    """The :class:`OAuth2ClientCredentialsProvider` for an ``env()``-resolved settings mapping, or ``None``
    when symmetric OAuth2-CC auth is off (``oauth2_token_url`` absent, or ``oauth2_enabled`` is False) — so
    any connection that didn't configure it is byte-identical."""
    if not s.get("oauth2_token_url"):
        return None
    if not s.get("oauth2_enabled", True):
        return None
    return OAuth2ClientCredentialsProvider(
        token_url=str(s.get("oauth2_token_url") or ""),
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
        attested=bool(s.get("tls_hop_attested", False)),
    )


def bearer_provider_from_settings(s: Mapping[str, Any]) -> BearerTokenProvider | None:
    """The active bearer-token provider for an HTTP destination, or ``None`` when none is configured
    (byte-identical). Unifies the SMART Backend Services provider (ADR 0024, asymmetric JWT) and the
    OAuth2 client-credentials provider (#65, symmetric secret) behind the one bearer seam the connector
    drives. The two are **mutually exclusive** on one connection — configuring both is a loud
    :class:`HttpAuthError` (a connection has exactly one identity)."""
    # Detect the conflict from settings PRESENCE before constructing either provider, so a "both
    # configured" mistake reports the mutual-exclusion error rather than whichever provider's own
    # validation happens to fire first on partial config.
    has_smart = bool(s.get("smart_token_url")) and s.get("smart_enabled", True) is not False
    has_oauth = bool(s.get("oauth2_token_url")) and s.get("oauth2_enabled", True) is not False
    if has_smart and has_oauth:
        raise HttpAuthError(
            "a connection cannot use BOTH SMART Backend Services and OAuth2 client-credentials auth "
            "(mutually exclusive — configure exactly one)"
        )
    return token_provider_from_settings(s) or oauth2_cc_provider_from_settings(s)


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
    attested = bool(s.get("tls_hop_attested", False))
    try:
        refuse_cleartext_credential_hop(
            scheme, url, credential="digest credential", attested=attested
        )
    except InsecureHopRefused as exc:
        raise HttpAuthError(
            "HTTP Digest over cleartext http would expose the digest credential; refused by the "
            "instance security posture — a production-PHI hop cannot be escaped (use https, or attest "
            "the hop as secure via tls_hop_attested)"
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
    return urllib.request.HTTPDigestAuthHandler(pwmgr)


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
    (a loud error at construction otherwise). Mutates ``spec`` in place and returns it."""
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
