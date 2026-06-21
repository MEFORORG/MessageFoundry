# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SMART Backend Services token provider for the FHIR/REST outbound (ADR 0024).

A real SMART-secured FHIR server (Epic, Oracle Health) does **not** accept a long-lived static
``bearer_token``: it requires **SMART Backend Services** authorization — OAuth2 ``client_credentials``
with an **asymmetric, signed ``client_assertion`` JWT** (``RS384``/``ES384``), returning a short-lived
bearer (~5 min, **no** refresh token). This module mints that assertion, exchanges it at the
authorization server's **token endpoint**, caches the bearer with expiry awareness, and hands it to the
FHIR/REST destination, which injects it **per request** in ``send()`` (past the staged-queue boundary —
the value-placement contract of ADR 0015/0024, so a retry re-mints and routers/transforms stay pure).

**No new dependency.** The JWT is signed with the ADR 0018 core-``cryptography`` signer
(:class:`~messagefoundry.transports.signing.CompactJwtSigner`); the token ``POST`` reuses rest.py's
hardened, TLS-verifying, no-redirect opener.

**Secrets / PHI.** The signing key and minted credentials are secrets: the access token and the
``client_assertion`` are **never** logged or persisted, and a token-endpoint failure surfaces only the
HTTP status + a redacted host (the response body may echo the token). The private key stays in
``env()`` (``smart_private_key`` is in ``_SECRET_SETTING_KEYS``); only the public-verifiable signature
and the registered ``kid`` leave the box.

**Out of scope (ADR 0024):** SMART App Launch (the human-user browser flow), the SMART
authorization/resource server, JWKS hosting, ``.well-known`` discovery (the MVP takes an explicit
``token_url``), and Bulk Data ``$export`` (a later read client that reuses this same provider).
"""

from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING

from messagefoundry.config.models import ConnectorType, Destination, SignatureAlgorithm
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.transports.base import DeliveryError

# Reuse rest.py's hardened opener + URL redaction (no new HTTP plumbing) — exactly as fhir.py/soap.py
# do. rest.py imports this module's provider LAZILY (inside __init__) so there is no import cycle.
from messagefoundry.transports.rest import _NO_REDIRECT_OPENER, _redact_url
from messagefoundry.transports.signing import CompactJwtSigner

if TYPE_CHECKING:  # only for the with_smart_backend() annotation — avoid importing heavy wiring
    from messagefoundry.config.wiring import ConnectionSpec

__all__ = [
    "SmartAuthError",
    "SmartBackendTokenProvider",
    "token_provider_from_destination",
    "with_smart_backend",
]

# RFC 7523 / SMART Backend Services constants.
_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# The client_assertion lifetime. SMART caps exp at 5 min after iat; 4 min stays comfortably under the
# ceiling while tolerating moderate clock skew. The assertion is one-time (consumed at the token POST).
_CLIENT_ASSERTION_TTL = 240
# Renew this many seconds before the server's stated expiry, so a token never expires mid-flight.
_DEFAULT_EXPIRY_SKEW = 60.0
_DEFAULT_TOKEN_TIMEOUT = 30.0
# If the token response omits expires_in, assume a short, conservative lifetime and re-mint soon.
_FALLBACK_TOKEN_TTL = 300.0


class SmartAuthError(ValueError):
    """A SMART Backend Services auth configuration is invalid (missing/malformed field, bad key/curve,
    a cleartext token endpoint). Raised loud at connector construction — like a bad TLS cert — so it
    fails at ``check``/dry-run/start, never as a wire-time surprise."""


class SmartBackendTokenProvider:
    """Acquire + cache a SMART Backend Services bearer token for one outbound connection (ADR 0024).

    Built once at connector construction (the signing key + algorithm are validated here). At delivery
    time the connector calls :meth:`access_token` from its off-loop ``send()`` worker; the provider
    returns a cached token until it nears expiry, otherwise mints a fresh ``client_assertion`` and
    exchanges it at the token endpoint. :meth:`invalidate` drops the cache so the next call re-mints
    (the connector calls it on a ``401`` — a token that expired between mint and use)."""

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        private_key: str,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.RS384,
        scope: str | None = None,
        audience: str | None = None,
        key_id: str | None = None,
        private_key_password: str | None = None,
        expiry_skew_seconds: float = _DEFAULT_EXPIRY_SKEW,
        timeout_seconds: float = _DEFAULT_TOKEN_TIMEOUT,
    ) -> None:
        if not token_url:
            raise SmartAuthError("SMART Backend Services requires a 'smart_token_url' setting")
        scheme = urllib.parse.urlsplit(token_url).scheme.lower()
        if scheme not in ("http", "https"):
            raise SmartAuthError(f"smart_token_url must be http or https, got scheme {scheme!r}")
        if scheme == "http" and not insecure_tls_allowed():
            # The client_assertion JWT is a credential — refuse to send it over cleartext.
            raise SmartAuthError(
                "SMART token endpoint over cleartext http would expose the client_assertion; "
                f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set (dev/trusted-network only) — use https"
            )
        if not client_id:
            raise SmartAuthError("SMART Backend Services requires a 'smart_client_id' setting")
        if not private_key:
            raise SmartAuthError(
                "SMART Backend Services requires a 'smart_private_key' setting (PEM via env())"
            )
        self.token_url = token_url
        self.client_id = client_id
        self.scope = scope or None
        # SMART: aud = the token endpoint URL unless the server documents another audience.
        self.audience = audience or token_url
        self.expiry_skew_seconds = max(0.0, expiry_skew_seconds)
        self.timeout_seconds = timeout_seconds
        # Loads + validates the key/curve for the algorithm — a bad key fails loud here.
        self._signer = CompactJwtSigner(
            private_key=private_key,
            algorithm=algorithm,
            private_key_password=private_key_password,
            key_id=key_id,
        )
        self._opener: urllib.request.OpenerDirector = _NO_REDIRECT_OPENER
        self._lock = threading.Lock()
        self._cached_token: str | None = None
        self._cached_expiry_monotonic = 0.0

    def access_token(self) -> str:
        """A valid bearer token — cached until it nears expiry, otherwise freshly acquired. Blocking
        (a token ``POST``); the connector calls it inside its off-loop ``send()`` worker. Raises
        :class:`~messagefoundry.transports.base.DeliveryError` (transient) if acquisition fails."""
        with self._lock:
            if self._cached_token is not None and time.monotonic() < self._cached_expiry_monotonic:
                return self._cached_token
            token, ttl = self._fetch_token()
            # Cache until `skew` seconds before the server's stated expiry (never negative).
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

    def _assertion_claims(self) -> dict[str, object]:
        """The five SMART-mandated client_assertion claims (iss=sub=client_id, aud, exp, jti)."""
        return {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.audience,
            "exp": int(time.time()) + _CLIENT_ASSERTION_TTL,
            "jti": secrets.token_urlsafe(32),
        }

    def _fetch_token(self) -> tuple[str, float]:
        """Mint a client_assertion, POST it to the token endpoint, and return ``(access_token, ttl)``.

        PHI/secret-safe: a failure names only the redacted token host + HTTP status — never the
        request (the assertion) or the response body (which carries the bearer token)."""
        form = {
            "grant_type": "client_credentials",
            "client_assertion_type": _CLIENT_ASSERTION_TYPE,
            "client_assertion": self._signer.sign(self._assertion_claims()),
        }
        if self.scope:
            form["scope"] = self.scope
        data = urllib.parse.urlencode(form).encode("ascii")
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.token_url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener.open(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise DeliveryError(
                f"SMART token endpoint {_redact_url(self.token_url)} returned HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise DeliveryError(
                f"SMART token endpoint {_redact_url(self.token_url)} unreachable: {exc.reason}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(
                f"SMART token endpoint {_redact_url(self.token_url)} failed: {exc}"
            ) from exc
        return self._parse_token_response(body)

    def _parse_token_response(self, body: str) -> tuple[str, float]:
        """Extract ``(access_token, ttl)`` from the token response JSON. Never echoes ``body`` in an
        error — it carries the bearer token."""
        try:
            payload = json.loads(body)
            token = payload["access_token"]
            if not isinstance(token, str) or not token:
                raise ValueError("missing access_token")
        except (ValueError, KeyError, TypeError) as exc:
            raise DeliveryError(
                f"SMART token endpoint {_redact_url(self.token_url)} returned an unparseable or "
                "incomplete token response"
            ) from exc
        expires_in = payload.get("expires_in", _FALLBACK_TOKEN_TTL)
        ttl = float(expires_in) if isinstance(expires_in, (int, float)) else _FALLBACK_TOKEN_TTL
        return token, ttl


def token_provider_from_destination(config: Destination) -> SmartBackendTokenProvider | None:
    """The :class:`SmartBackendTokenProvider` for an outbound, or ``None`` when SMART auth is off.

    SMART auth is OFF (``None``) unless ``smart_token_url`` is present (and ``smart_enabled`` is not
    ``False``), so every existing outbound is byte-identical. Settings arrive already ``env()``-resolved
    (the runner substitutes them before building the connector), exactly like the ``sign_*`` path."""
    s = config.settings
    if not s.get("smart_token_url"):
        return None
    if not s.get("smart_enabled", True):
        return None
    return SmartBackendTokenProvider(
        token_url=str(s.get("smart_token_url") or ""),
        client_id=str(s.get("smart_client_id") or ""),
        private_key=str(s.get("smart_private_key") or ""),
        algorithm=SignatureAlgorithm(str(s.get("smart_algorithm", "RS384"))),
        scope=(str(s["smart_scope"]) if s.get("smart_scope") else None),
        audience=(str(s["smart_audience"]) if s.get("smart_audience") else None),
        key_id=(str(s["smart_key_id"]) if s.get("smart_key_id") else None),
        private_key_password=(
            str(s["smart_private_key_password"]) if s.get("smart_private_key_password") else None
        ),
        expiry_skew_seconds=float(s.get("smart_expiry_skew_seconds", _DEFAULT_EXPIRY_SKEW)),
        timeout_seconds=float(s.get("smart_timeout_seconds", _DEFAULT_TOKEN_TIMEOUT)),
    )


def with_smart_backend(
    spec: ConnectionSpec,
    *,
    token_url: object,
    client_id: object,
    private_key: object,
    scope: str | None = None,
    algorithm: SignatureAlgorithm | str = SignatureAlgorithm.RS384,
    key_id: str | None = None,
    audience: object | None = None,
    private_key_password: object | None = None,
    expiry_skew_seconds: float = _DEFAULT_EXPIRY_SKEW,
    timeout_seconds: float = _DEFAULT_TOKEN_TIMEOUT,
    enabled: bool = True,
) -> ConnectionSpec:
    """Enable SMART Backend Services client auth on a **REST/FHIR** outbound spec (ADR 0024).

    Compose it over the ``Rest()`` / ``FHIR()`` factory — which supplies every transport default — so
    SMART auth is one code-first call and nothing else about the connector changes::

        from messagefoundry import FHIR, env, outbound
        from messagefoundry.transports.smart import with_smart_backend

        outbound("OB_EPIC_FHIR", with_smart_backend(
            FHIR(url=env("epic_fhir_base"), interaction="create"),
            token_url=env("epic_token_url"),      # the authorization server token endpoint
            client_id=env("epic_client_id"),
            scope="system/*.rs",                  # SMART v2 system scopes (no human)
            private_key=env("epic_smart_key"),    # inline PEM via env(), or a PEM file path
            algorithm="RS384",                    # SMART SHALL: RS384 (default) | ES384
            key_id="epic-2026",                   # kid → the public key registered with the server
        ))

    ``token_url`` / ``client_id`` / ``private_key`` / ``audience`` / ``private_key_password`` may be
    :func:`~messagefoundry.config.wiring.env` references — keep every secret in ``env()``. The minted
    bearer **overrides** any static ``bearer_token`` on the spec. Mutates ``spec`` in place and returns
    it; SMART auth is OFF on any spec this was not called on."""
    if spec.type not in (ConnectorType.REST, ConnectorType.FHIR):
        raise SmartAuthError(
            f"SMART Backend Services auth applies to REST/FHIR outbound only, not "
            f"{spec.type.value!r} (ADR 0024)"
        )
    spec.settings.update(
        {
            "smart_enabled": enabled,
            "smart_token_url": token_url,
            "smart_client_id": client_id,
            "smart_private_key": private_key,
            "smart_private_key_password": private_key_password,
            "smart_scope": scope,
            "smart_algorithm": SignatureAlgorithm(algorithm).value,
            "smart_key_id": key_id,
            "smart_audience": audience,
            "smart_expiry_skew_seconds": expiry_skew_seconds,
            "smart_timeout_seconds": timeout_seconds,
        }
    )
    return spec
