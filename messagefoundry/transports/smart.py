# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

**Trust boundary (ASVS 10.4.16).** The authorization server named by ``token_url`` is **trusted and
operator-pinned** — the engine takes an explicit ``token_url`` (no ``.well-known`` discovery, so it can't
be redirected to a rogue AS), gates it through the fail-closed ``[egress].allowed_http`` allowlist (the
signed ``client_assertion`` only ever POSTs to an allow-listed host), and — per RFC 7523 / SMART — sets
the assertion ``aud`` to that same ``token_url`` by default (:attr:`SmartBackendTokenProvider.audience`),
so the credential is bound to the pinned endpoint and is not replayable at another AS.

**Out of scope (ADR 0024):** SMART App Launch (the human-user browser flow), the SMART
authorization/resource server, JWKS hosting, ``.well-known`` discovery (the MVP takes an explicit
``token_url``), and Bulk Data ``$export`` (a later read client that reuses this same provider).
"""

from __future__ import annotations

import abc
import http.client
import math
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar

from messagefoundry.config.models import ConnectorType, Destination, SignatureAlgorithm
from messagefoundry.config.tls_policy import (
    CREDENTIAL_HOP_WAYS_ACROSS,
    MIRRORED_CONNECTION_SETTING,
    SYSTEM_TRUST_ANCHOR,
    InsecureHopRefused,
    TrustAnchor,
    TrustAnchorPolicy,
    hop_name_prefix,
)
from messagefoundry.redaction import json_loads_or_refusal
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.bounded_read import (
    MAX_TOKEN_RESPONSE_BYTES,
    EgressReplyError,
    read_bounded_text,
)

# Reuse rest.py's hardened opener + URL redaction (no new HTTP plumbing) — exactly as fhir.py/soap.py
# do. rest.py imports this module's provider LAZILY (inside __init__) so there is no import cycle.
from messagefoundry.transports.rest import (
    _NO_REDIRECT_OPENER,
    ECH_HOP_WAYS_ACROSS,
    HttpAuthError,
    ProxyConfig,
    _no_redirect_opener,
    _redact_url,
    cleartext_acceptance_from_settings,
    ech_readdressed_request,
    enforce_outbound_length_limits,
    http_family_trust_anchor,
    refuse_cleartext_credential_hop,
    refuse_unrevoked_verified_hop,
    refuse_url_credentials,
)
from messagefoundry.transports.signing import (
    CLIENT_ASSERTION_TYPE,
    CompactJwtSigner,
    client_assertion_claims,
)

if TYPE_CHECKING:  # only for the with_smart_backend() annotation — avoid importing heavy wiring
    from messagefoundry.config.wiring import ConnectionSpec, FhirLookupSpec

__all__ = [
    "SmartAuthError",
    "SmartBackendTokenProvider",
    "request_token",
    "revocation_attestation_from_settings",
    "token_cache_seconds",
    "token_provider_from_destination",
    "token_provider_from_settings",
    "with_smart_backend",
]

# RFC 7523 / SMART Backend Services constants.
# The client_assertion lifetime. SMART caps exp at 5 min after iat; 4 min stays comfortably under the
# ceiling while tolerating moderate clock skew. The assertion is one-time (consumed at the token POST).
_CLIENT_ASSERTION_TTL = 240
# Renew this many seconds before the server's stated expiry, so a token never expires mid-flight.
_DEFAULT_EXPIRY_SKEW = 60.0
_DEFAULT_TOKEN_TIMEOUT = 30.0
# If the token response omits expires_in, assume a short, conservative lifetime and re-mint soon.
_FALLBACK_TOKEN_TTL = 300.0
# The longest time a token provider will cache a token for, after the expiry skew, whatever
# expires_in claims. SMART Backend Services expects tokens of about five minutes, so an hour is
# generous. Clamping only makes the next mint come sooner. Without it, an expires_in of 1e999 (read
# as inf) would cache the token for good (BACKLOG #1980, and #2054 for the OAuth2 provider).
_MAX_TOKEN_CACHE_SECONDS = 3600.0
# Visible ASCII only (RFC 9110 VCHAR): no control character, no space, nothing outside ASCII.
_BEARER_TOKEN_CHARS = re.compile(r"[\x21-\x7e]+")


# The token-endpoint helpers below serve both bearer providers through _TokenEndpointProvider
# (BACKLOG #2054, #2115). ``endpoint`` is the caller's label, built from the REDACTED token URL, so
# no helper ever sees the credential or the query string.


def request_token(
    opener: urllib.request.OpenerDirector,
    req: urllib.request.Request,
    *,
    timeout: float,
    endpoint: str,
    connector: str,
) -> tuple[str, float]:
    """Send the token request and return ``(access_token, ttl)``, raising
    :class:`~messagefoundry.transports.base.DeliveryError` for a transport failure or a bad reply.
    A failure names ``endpoint`` and a status, reason or error class, never the request or the reply
    body, because the body carries the bearer token. A request that cannot be encoded for the wire
    still raises its own ``ValueError``, as it did before BACKLOG #2054. ``connector`` names the hop
    in a refusal of the reply body, and holds no URL (BACKLOG #2060)."""
    body = _read_token_reply(opener, req, timeout=timeout, endpoint=endpoint, connector=connector)
    return _parse_token_reply(body, endpoint=endpoint)


def _read_token_reply(
    opener: urllib.request.OpenerDirector,
    req: urllib.request.Request,
    *,
    timeout: float,
    endpoint: str,
    connector: str,
) -> str:
    try:
        with opener.open(req, timeout=timeout) as resp:
            # ASVS 15.2.2: bounded on the socket read, at the tighter token ceiling. A
            # client-credentials token response is a bearer, a TTL and a scope list; anything past
            # 256 KiB is not one. Over-cap raises ResponseTooLargeError, already a DeliveryError,
            # so it takes the provider's normal mint-failure path.
            return read_bounded_text(
                resp, limit=MAX_TOKEN_RESPONSE_BYTES, connector=connector, encoding="utf-8"
            )
    except urllib.error.HTTPError as exc:
        raise DeliveryError(f"{endpoint} returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
        raise DeliveryError(f"{endpoint} unreachable: {exc.reason}") from exc
    except (TimeoutError, OSError) as exc:
        raise DeliveryError(f"{endpoint} failed: {exc}") from exc
    except HttpAuthError as exc:
        # BACKLOG #1171: this opener carries the web proxy's Digest handler, which refuses a 407 it will
        # not answer (a hash other than SHA-256, or a challenge it cannot parse) with an HttpAuthError.
        # That is a ValueError, and it escaped this function's DeliveryError contract. Fixed text: the
        # refusal names the peer's own algorithm token, which stays on the cause only.
        raise DeliveryError(
            f"{endpoint} was not reached: the web proxy's authentication challenge was refused"
        ) from exc
    except EgressReplyError:
        # A bare CR in the reply head raises MalformedReplyHeadError, which is an HTTPException as
        # well (BACKLOG #2052). It is already a retryable DeliveryError with a fixed reason, so it
        # passes through unchanged rather than being retyped by the arm below.
        raise
    except http.client.HTTPException as exc:
        # A malformed status or header line (BadStatusLine, LineTooLong) is neither an OSError nor
        # a URLError, so it once escaped the providers' DeliveryError contract (BACKLOG #1980,
        # #2054). Named by class only: the exception text can echo the endpoint's own bytes, so it
        # is kept off the chain too, and the refusal is raised outside the handler (BACKLOG #2048).
        malformed = type(exc).__name__
    raise DeliveryError(f"{endpoint} sent a malformed HTTP reply ({malformed})")


def _parse_token_reply(body: str, *, endpoint: str) -> tuple[str, float]:
    refused = f"{endpoint} returned an unparseable or incomplete token response"
    # Decoded outside any handler (BACKLOG #2048): a JSONDecodeError holds the WHOLE reply, bearer
    # included, and ``from exc`` would chain it onto the DeliveryError. The helper also catches
    # json's depth-limit RecursionError, which once escaped this contract (BACKLOG #1980, #2054).
    payload, refusal = json_loads_or_refusal(body)
    if refusal is not None:
        raise DeliveryError(refused)
    try:
        token = payload["access_token"]
        if not isinstance(token, str) or not token:
            raise ValueError("missing access_token")
        expires_in = payload.get("expires_in", _FALLBACK_TOKEN_TTL)
        # A JSON true or false is an int to isinstance, but it is no lifetime: use the fallback.
        is_number = isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool)
        ttl = float(expires_in) if is_number else _FALLBACK_TOKEN_TTL
        # json.loads reads 1e999 as inf and accepts the NaN literal. NaN is treated as a missing
        # expires_in. An infinite one is left for token_cache_seconds' ceiling to clamp.
        if math.isnan(ttl):
            ttl = _FALLBACK_TOKEN_TTL
    # OverflowError (an integer expires_in too large for a float) is not a ValueError, and once
    # escaped the providers' DeliveryError contract (BACKLOG #1980, #2054).
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        raise DeliveryError(refused) from exc
    # A token the Authorization header cannot carry is refused here, before it is cached (BACKLOG
    # #2114). Cached, http.client would refuse it in putheader on every send, and the destinations
    # read that ValueError as a permanent bad request, so each message would dead-letter until the
    # cache lapsed. The test is visible ASCII, a superset of RFC 6750's b64token, so an opaque token
    # with other printable characters still works. The token is never named in the message.
    if _BEARER_TOKEN_CHARS.fullmatch(token) is None:
        raise DeliveryError(f"{endpoint} returned an access_token an HTTP header cannot carry")
    return token, ttl


def token_cache_seconds(ttl: float, skew: float) -> float:
    """How long to cache a token that the server says lives ``ttl`` seconds: until ``skew`` seconds
    before that expiry, never negative and never past the ceiling. The ceiling applies after the
    skew, so a large skew still caches."""
    return min(_MAX_TOKEN_CACHE_SECONDS, max(0.0, ttl - skew))


class SmartAuthError(ValueError):
    """A SMART Backend Services auth configuration is invalid (missing/malformed field, bad key/curve,
    a cleartext token endpoint). Raised loud at connector construction — like a bad TLS cert — so it
    fails at ``check``/dry-run/start, never as a wire-time surprise."""


class _TokenEndpointProvider(abc.ABC):
    """The token hop and the token cache, shared by :class:`SmartBackendTokenProvider` and the
    symmetric-secret ``OAuth2ClientCredentialsProvider`` in http_auth.py (BACKLOG #2115).

    The two once carried copies of all of this, and each fix reached one and drifted from the
    other: #1980's cache cap reached SMART only, and #1498's revocation guard missed OAuth2 until
    #2112. A subclass supplies the words its messages use, validates its own grant fields, and
    implements :meth:`_fetch_token`. Its constructor calls :meth:`_check_token_url` first and
    :meth:`_open_token_hop` last, so each provider refuses a bad config in the order it always did.
    """

    #: ``SMART`` or ``OAuth2``: names the endpoint, the credential and the refusals.
    _LABEL: ClassVar[str]
    #: The refusal for a missing token URL, verbatim: the two providers' articles differ.
    _MISSING_URL: ClassVar[str]
    #: The setting that holds the token URL.
    _URL_SETTING: ClassVar[str]
    #: Where a credential found in the token URL belongs instead.
    _CREDENTIAL_SETTINGS: ClassVar[str]
    #: What the token POST carries that cleartext http would expose.
    _CREDENTIAL_NAME: ClassVar[str]
    #: The provider's configuration error type. Both are ``ValueError`` subclasses.
    _ERROR: ClassVar[type[ValueError]]

    token_url: str
    expiry_skew_seconds: float
    timeout_seconds: float

    def _check_token_url(
        self,
        token_url: str,
        *,
        attested: bool,
        cleartext_accepted: bool,
        cleartext_reason: str | None,
        connection: str | None,
    ) -> str:
        """Validate the token URL and refuse a cleartext hop; return its lower-cased scheme."""
        if not token_url:
            raise self._ERROR(self._MISSING_URL)
        scheme = urllib.parse.urlsplit(token_url).scheme.lower()
        if scheme not in ("http", "https"):
            raise self._ERROR(f"{self._URL_SETTING} must be http or https, got scheme {scheme!r}")
        refuse_url_credentials(
            token_url, self._URL_SETTING, use=self._CREDENTIAL_SETTINGS, error=self._ERROR
        )
        # The token POST carries a credential, so this hop goes through the ONE posture-keyed
        # authority the REST/SOAP/FHIR delivery cells consume (#200, ADR 0092). A production-PHI
        # hop is refused whatever the process environment says, while a non-prod, non-PHI,
        # per-hop-attested, declared (ADR 0153) or loopback hop decides as the delivery cells do.
        # The posture is the one the construction gate stamped, fail-closing to production-PHI
        # when unstamped. InsecureHopRefused is re-raised as the provider's own error to keep each seam's contract;
        # both are ValueError subclasses, so the loader surfaces either identically. The message
        # never carries the credential.
        try:
            refuse_cleartext_credential_hop(
                scheme,
                token_url,
                credential=f"{self._LABEL} {self._CREDENTIAL_NAME}",
                attested=attested,
                cleartext_accepted=cleartext_accepted,
                cleartext_reason=cleartext_reason,
                connection=connection,
            )
        except InsecureHopRefused as exc:
            raise self._ERROR(
                f"{hop_name_prefix(connection)}{self._LABEL} token endpoint over cleartext http "
                "would expose the "
                f"{self._CREDENTIAL_NAME}; refused by the instance security posture ({CREDENTIAL_HOP_WAYS_ACROSS})"
            ) from exc
        return scheme

    def _open_token_hop(
        self,
        scheme: str,
        token_url: str,
        *,
        expiry_skew_seconds: float,
        timeout_seconds: float,
        revocation_attested: bool,
        revocation_attested_reason: str | None,
        revocation_connection: str | None,
        proxy: ProxyConfig | None,
        ech_sidecar: str | None,
        trust_anchor: TrustAnchor,
    ) -> None:
        """Build the token hop's opener, refuse it if it verifies with no revocation check, and set
        up the empty cache."""
        self.token_url = token_url
        self.expiry_skew_seconds = max(0.0, expiry_skew_seconds)
        self.timeout_seconds = timeout_seconds
        # ADR 0126: route the token-endpoint POST through the connection's forward proxy — resolved
        # for the TOKEN host (its own bypass decision, #128). None / bypassed → the shared opener and
        # no Proxy-Authorization (byte-identical).
        token_proxy = (
            proxy.for_host(urllib.parse.urlsplit(token_url).hostname or "") if proxy else None
        )
        # #1660: a PER-PROVIDER opener whenever the token hop needs a handler the shared one lacks (a
        # forward proxy) OR a trust anchor that ``narrows`` -- read through the one ``narrows``
        # predicate, exactly as the four HTTP-family destinations do, so the token hop cannot drift
        # from them. Neither -> the shared opener, unmutated (ADR 0126), byte-identical.
        self._opener: urllib.request.OpenerDirector = (
            _no_redirect_opener(
                *(token_proxy.opener_handlers() if token_proxy is not None else ()),
                trust_anchor=trust_anchor,
            )
            if token_proxy is not None or trust_anchor.narrows
            else _NO_REDIRECT_OPENER
        )
        # #1498, #2112 (ADR 0173 §4.3): the revocation twin of the cleartext refusal, and the same
        # one-statement call its HTTP-family siblings make. The token hop VERIFIES the authorization
        # server's certificate but stdlib ssl performs no OCSP/CRL, so a revoked-but-unexpired
        # token-endpoint certificate WOULD be accepted on first deployment with no refusal, no warning
        # and no audit entry -- on the hop carrying the credential. Keyed on the https scheme, so the
        # cleartext refusal (which owns `http`) and this one decide disjoint hops and never
        # double-refuse one.
        #
        # PLACED BELOW `self._opener`, AND NOT BESIDE THE CLEARTEXT REFUSAL -- which is where it was
        # first written, and that was a false-refusal bug. `opener=` is what lets a CRL that really
        # reached THIS hop relax the gate, and the context does not exist until the opener does: a
        # `[tls].crl_file` resolved against the token host makes `trust_anchor.narrows` true, which
        # builds a per-provider opener carrying VERIFY_CRL_CHECK_LEAF. Guarding above that line refused
        # a hop that genuinely checks revocation while telling the operator to configure the CRL they
        # had already configured -- a refusal whose remedy cannot be performed, which is the SDS-3.7
        # defect.
        #
        # This file has no `ssl` usage, which is why ADR 0173 once withdrew the SMART row. That does
        # not reach the guard, which takes a scheme and a url for hops riding urllib's context
        # (ADR 0173 section 4.3, correction 1).
        #
        # The token host is frequently NOT the connection's data host (#1660 resolves this hop's anchor
        # against the token URL for that reason), so the sibling guard on the destination keys on a
        # different host and cannot answer for this one.
        #
        # InsecureHopRefused propagates rather than being re-wrapped as the provider's error: the
        # guard's own message names this hop and its ways across, which a re-wrap would discard, and
        # both are ValueError subclasses so the loader surfaces either identically.
        #
        # WITH AN ECH SIDECAR THE GUARD GETS NO OPENER (vault BACKLOG #2169). `_post_token`
        # re-addresses the POST to the loopback sidecar, and the sidecar makes its own TLS connection
        # to the token host. So this opener's context only ever meets the sidecar. A `[tls].crl_file`
        # covering the token host still lands on it, and reading it here lifted the refusal with no
        # check behind it. On an enforcing instance a non-loopback token host then crosses on the
        # per-connection attestation alone.
        refuse_unrevoked_verified_hop(
            scheme,
            token_url,
            connector=f"{self._LABEL} token endpoint",
            revocation_attested=revocation_attested,
            revocation_attested_reason=revocation_attested_reason,
            opener=None if ech_sidecar is not None else self._opener,
            ways_across=ECH_HOP_WAYS_ACROSS if ech_sidecar is not None else None,
            connection=revocation_connection,
        )
        self._proxy_auth: dict[str, str] = (
            token_proxy.auth_headers() if token_proxy is not None else {}
        )
        self._ech_sidecar = ech_sidecar
        self._lock = threading.Lock()
        self._cached_token: str | None = None
        self._cached_expiry_monotonic = 0.0

    def _post_token(self, data: bytes, headers: dict[str, str]) -> tuple[str, float]:
        """POST ``data`` to the token endpoint on this connection's egress route and return
        ``(access_token, ttl)``. With an ECH sidecar the request is re-addressed to it (#1176);
        without one it goes straight to the configured ``token_url``, byte-identical. The cleartext
        refusal keys on the DECLARED ``token_url`` scheme, which is what the sidecar re-originates --
        the engine->sidecar leg is same-host loopback (ADR 0092), as the delivery hop's is. A failure
        names only the redacted token host and a status, never the request or the reply body."""
        if self._ech_sidecar is not None:
            req = ech_readdressed_request(
                self._ech_sidecar, self.token_url, data=data, headers=headers, method="POST"
            )
        else:
            req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s)
                self.token_url, data=data, headers=headers, method="POST"
            )
        hop = f"{self._LABEL} token endpoint"
        return request_token(
            self._opener,
            req,
            timeout=self.timeout_seconds,
            endpoint=f"{hop} {_redact_url(self.token_url)}",
            connector=hop,
        )

    @abc.abstractmethod
    def _fetch_token(self) -> tuple[str, float]:
        """Build this provider's grant and return :meth:`_post_token`'s ``(access_token, ttl)``."""

    def access_token(self) -> str:
        """A valid bearer token — cached until it nears expiry, otherwise freshly acquired. Blocking
        (a token ``POST``); the connector calls it inside its off-loop ``send()`` worker. Raises
        :class:`~messagefoundry.transports.base.DeliveryError` (transient) if acquisition fails."""
        with self._lock:
            if self._cached_token is not None and time.monotonic() < self._cached_expiry_monotonic:
                return self._cached_token
            token, ttl = self._fetch_token()
            self._cached_expiry_monotonic = time.monotonic() + token_cache_seconds(
                ttl, self.expiry_skew_seconds
            )
            self._cached_token = token
            return token

    def invalidate(self) -> None:
        """Drop the cached token so the next :meth:`access_token` re-mints (called on a ``401``)."""
        with self._lock:
            self._cached_token = None
            self._cached_expiry_monotonic = 0.0


class SmartBackendTokenProvider(_TokenEndpointProvider):
    """Acquire + cache a SMART Backend Services bearer token for one outbound connection (ADR 0024).

    Built once at connector construction (the signing key + algorithm are validated here). At delivery
    time the connector calls :meth:`access_token` from its off-loop ``send()`` worker; the provider
    returns a cached token until it nears expiry, otherwise mints a fresh ``client_assertion`` and
    exchanges it at the token endpoint. :meth:`invalidate` drops the cache so the next call re-mints
    (the connector calls it on a ``401`` — a token that expired between mint and use)."""

    _LABEL = "SMART"
    _MISSING_URL = "SMART backend services requires a 'smart_token_url' setting"
    _URL_SETTING = "smart_token_url"
    _CREDENTIAL_SETTINGS = "smart_client_id/smart_private_key"
    _CREDENTIAL_NAME = "client_assertion"
    _ERROR = SmartAuthError

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
        attested: bool = False,
        # #1498 (ADR 0173 §4.3): the per-connection `tls_revocation_attested`, DISTINCT from `attested`
        # above (which attests a cleartext/verify-off hop is secure by other means, #200). Read from the
        # resolved settings by `token_provider_from_settings`, where the runner's `_dest_config` mirrors
        # the connection's top-level declaration and its mandatory reason (ADR 0173).
        revocation_attested: bool = False,
        revocation_attested_reason: str | None = None,
        cleartext_accepted: bool = False,
        cleartext_reason: str | None = None,
        connection: str | None = None,
        # ADR 0173: the connection named by the revocation guard's audit line and refusal. Today both
        # readers take it from the one `connection_name` mirror, so it equals `connection`; it stays a
        # separate parameter only because both bearer providers' constructors already take it.
        revocation_connection: str | None = None,
        proxy: ProxyConfig | None = None,
        # #1176 (ADR 0139): this connection's loopback ECH sidecar, when it has one. The token-endpoint
        # POST follows the connection's egress route exactly as ADR 0126 rules it must for a forward
        # proxy; for ECH that means the request is RE-ADDRESSED to the sidecar with the real
        # authorization-server host in ``Host``, so the AS hostname is never in a cleartext outer
        # ClientHello. Mutually exclusive with ``proxy`` (refused at connector construction). None
        # (default) -> byte-identical.
        ech_sidecar: str | None = None,
        # #1660 (#1180, ADR 0093): the client trust anchor for the TOKEN hop, already resolved against
        # the token host by :func:`token_provider_from_settings`. The data hop has carried one since
        # #1180 and this hop did not, so an internal-CA authorization server failed every mint with an
        # opaque URLError and a ``pinned`` policy was silently not honoured on the hop that carries the
        # credential. The default is the OS trust store -- the same value #1180's own default resolves
        # to, so a direct test construction and an unconfigured instance are byte-identical.
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
            raise SmartAuthError("SMART backend services requires a 'smart_client_id' setting")
        if not private_key:
            raise SmartAuthError(
                "SMART backend services requires a 'smart_private_key' setting (PEM via env())"
            )
        self.client_id = client_id
        self.scope = scope or None
        # SMART: aud = the token endpoint URL unless the server documents another audience.
        self.audience = audience or token_url
        # Loads + validates the key/curve for the algorithm — a bad key fails loud here, before the
        # token hop's revocation guard, as it always has.
        self._signer = CompactJwtSigner(
            private_key=private_key,
            algorithm=algorithm,
            private_key_password=private_key_password,
            key_id=key_id,
            setting="smart_private_key",
        )
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

    def _assertion_claims(self) -> dict[str, object]:
        """The five SMART-mandated client_assertion claims (iss=sub=client_id, aud, exp, jti)."""
        return client_assertion_claims(
            self.client_id, self.audience, ttl_seconds=_CLIENT_ASSERTION_TTL
        )

    def _fetch_token(self) -> tuple[str, float]:
        """Mint a client_assertion, POST it to the token endpoint, and return ``(access_token, ttl)``.

        PHI/secret-safe: a failure names only the redacted token host + HTTP status — never the
        request (the assertion) or the response body (which carries the bearer token)."""
        form = {
            "grant_type": "client_credentials",
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self._signer.sign(self._assertion_claims()),
        }
        if self.scope:
            form["scope"] = self.scope
        data = urllib.parse.urlencode(form).encode("ascii")
        # ASVS 4.2.5: the token URL is operator-supplied via env(), and the signed client assertion
        # rides the FORM body (not a header), so only the URL and the proxy credential are measurable
        # here -- both are config, so a blob-valued env() surfaces as a config error rather than an
        # opaque IdP failure on the first mint.
        enforce_outbound_length_limits(self.token_url, dict(self._proxy_auth))
        return self._post_token(
            data,
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                **self._proxy_auth,  # ADR 0126: pre-emptive Proxy-Authorization when behind an auth proxy
            },
        )


# One FHIR resource scope, SMART v2 (`system/Patient.cru`) or v1 (`system/Patient.read`), with the
# optional v2 search-parameter constraint (`?category=vital-signs`) tolerated and ignored. The context
# half is captured but unused: a Backend Services client is `system/`, and `patient/`/`user/` on a
# headless outbound is an operator's business, not this reader's.
_FHIR_SCOPE_RE = re.compile(
    r"^(?:patient|user|system)/(?:[A-Za-z*][A-Za-z0-9_*-]*)\.(?P<perms>[A-Za-z*]+)(?:\?.*)?$"
)
_V2_LETTERS = frozenset("cruds")  # create, read, update, delete, search
# SMART v1 permission words, expanded to the v2 letters they stand for, so a v1 scope string grades the
# same way a v2 one does. `*` here is the PERMISSION wildcard (`system/Patient.*`) and means every
# letter; the RESOURCE wildcard (`system/*.rs`) is a different position and is never a finding.
_V1_PERMS = {"read": frozenset("rs"), "write": frozenset("cud"), "*": _V2_LETTERS}


def smart_scope_letters(scope: str) -> frozenset[str] | None:
    """The union of SMART v2 permission letters a requested ``scope`` string asks for, or ``None`` when
    the string contains no parseable FHIR resource scope at all (#1159, ASVS 10.2.3).

    It lives beside :func:`token_provider_from_settings`, the code that puts ``scope`` on the wire, so
    this module does not transmit a grammar it has no knowledge of. Its reader is
    :func:`~messagefoundry.config.wiring.overbroad_smart_scopes`, which imports it lazily on the same
    precedent ``unverified_generic_db_hops`` states for ``generic_odbc_tls_unenforced``.

    A scope string is space-separated and may mix FHIR resource scopes with non-FHIR ones (``openid``,
    ``fhirUser``, ``offline_access``, ``launch/patient``). Only the resource scopes carry permission
    letters, so the rest are skipped rather than treated as an error — an unrecognised token is a scope
    this reader does not model, never evidence of over-breadth. So is an unmodelled permission word
    (``system/Patient.readwrite``, a vendor spelling).

    ``None`` means "this reader cannot grade the string", and the caller stays quiet on it: a vocabulary
    this function cannot read is exactly the case where computing a requirement would be guessing.

    The RESOURCE half is matched and discarded on purpose. It is not derivable at config time — the
    outbound reads the resourceType from the OUTGOING MESSAGE BODY at delivery — so ``system/*.rs``
    grades as ``{r, s}`` and the ``*`` is never itself a finding. A check that flagged that character
    instead would be pattern-matching a string rather than computing a requirement from the
    connection's declared shape.

    Pure — a string in, a letter set out. No graph, no I/O."""
    letters: set[str] = set()
    for token in scope.split():
        m = _FHIR_SCOPE_RE.match(token)
        if m is None:
            continue
        perms = m.group("perms").lower()
        found = _V1_PERMS.get(perms) or (frozenset(perms) if set(perms) <= _V2_LETTERS else None)
        if found:
            letters |= found
    return frozenset(letters) if letters else None


def revocation_attestation_from_settings(
    s: Mapping[str, Any],
) -> tuple[bool, str | None, str | None]:
    """``(attested, reason, connection)`` for a token hop's revocation guard (ADR 0173 section 4.3).

    The runner mirrors the connection's typed ``tls_revocation_attested`` declaration, its mandatory
    reason and the connection's name (:data:`MIRRORED_CONNECTION_SETTING`, written for every
    connection, so a REFUSAL names it too) into the resolved settings. This is the one reader of those
    keys for both bearer providers (BACKLOG #2112, #2115), as ``cleartext_acceptance_from_settings``
    is for the cleartext twin."""
    reason = s.get("tls_revocation_attested_reason")
    connection = s.get(MIRRORED_CONNECTION_SETTING)
    return (
        bool(s.get("tls_revocation_attested", False)),
        None if reason is None else str(reason),
        None if connection is None else str(connection),
    )


def smart_auth_configured(s: Mapping[str, Any]) -> bool:
    """Whether a settings mapping has SMART Backend Services auth turned ON.

    ON means ``smart_token_url`` is present and ``smart_enabled`` is not switched off, so any connection
    that never composed :func:`with_smart_backend` is byte-identical. The SINGLE definition, shared by
    :func:`token_provider_from_settings` (which builds the provider), by the mutual-exclusion screen in
    ``http_auth.bearer_provider_from_settings`` and by
    :func:`~messagefoundry.config.wiring.overbroad_smart_scopes` (which grades the requested scope).

    It exists because those three readers each carried their own spelling of the same test and the
    spellings had already drifted — one treated any falsy ``smart_enabled`` as off, another only a
    literal ``False``. They agreed only because ``with_smart_backend`` writes a real ``bool``, which is
    an agreement that decays silently the day anything else populates these settings. Off is the
    conservative reading, so a falsy value is off."""
    return bool(s.get("smart_token_url")) and bool(s.get("smart_enabled", True))


def token_provider_from_settings(
    s: Mapping[str, Any],
    *,
    proxy: ProxyConfig | None = None,
    ech_sidecar: str | None = None,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
) -> SmartBackendTokenProvider | None:
    """The :class:`SmartBackendTokenProvider` for an already-``env()``-resolved settings mapping, or
    ``None`` when SMART auth is off.

    SMART auth is OFF (``None``) unless ``smart_token_url`` is present (and ``smart_enabled`` is not
    ``False``), so any connection that didn't compose ``with_smart_backend`` is byte-identical. Shared by
    the FHIR/REST outbound (:func:`token_provider_from_destination`) and the ``FhirLookup`` read executor
    (ADR 0043) — both inject the minted bearer per request off-loop past the queue boundary. ``proxy``
    (ADR 0126) routes the token-endpoint POST through the connection's forward proxy; ``ech_sidecar``
    (#1176, ADR 0139) re-addresses it to the connection's loopback ECH sidecar instead. The two are
    mutually exclusive by construction.

    ``trust_anchor_policy`` (#1660) is the instance-wide ``[tls]`` policy the caller already holds --
    off its ``Destination`` for an outbound, threaded in explicitly for a ``FhirLookup``, which has
    none. ``None`` (a direct test construction) resolves to the OS trust store, byte-identical."""
    if not smart_auth_configured(s):
        return None
    # ADR 0153: the same per-connection declaration the delivery hop carries, mirrored into these
    # resolved settings by the runner's _dest_config (with the connection name, so the acceptance audit
    # record names the declaration). Read exactly as the OAuth2 sibling does.
    accepted = cleartext_acceptance_from_settings(s)
    revocation = revocation_attestation_from_settings(s)
    token_url = str(s.get("smart_token_url") or "")
    return SmartBackendTokenProvider(
        token_url=token_url,
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
        # #200: the per-connection insecure-hop attestation keys the posture-keyed cleartext refusal in
        # __init__ (read from settings exactly as _dest_config / the OAuth2 provider do).
        attested=bool(s.get("tls_hop_attested", False)),
        # #1498 (ADR 0173 §4.3): the revocation attestation `_dest_config` mirrors from the connection's
        # top-level declaration. A DIFFERENT claim from `attested` above, so it gets its own key.
        revocation_attested=revocation[0],
        revocation_attested_reason=revocation[1],
        cleartext_accepted=accepted[0],
        cleartext_reason=accepted[1],
        connection=accepted[2],
        revocation_connection=revocation[2],
        proxy=proxy,  # ADR 0126: forward-proxy the token-endpoint POST
        ech_sidecar=ech_sidecar,  # #1176: ...or re-address it to the ECH sidecar (ADR 0139)
        # #1660: resolved against the TOKEN url, not the connection's data url -- the authorization
        # server is frequently a different host from the FHIR/REST endpoint, and both the loopback
        # exemption and the internal-vs-public decision key on the host actually being dialled. The
        # connection's own ``tls_ca_file`` still wins verbatim, exactly as it does on the data hop.
        trust_anchor=http_family_trust_anchor(
            s, url=token_url, trust_anchor_policy=trust_anchor_policy, cell="smart_token_url"
        ),
    )


def token_provider_from_destination(
    config: Destination, *, proxy: ProxyConfig | None = None
) -> SmartBackendTokenProvider | None:
    """The :class:`SmartBackendTokenProvider` for an outbound, or ``None`` when SMART auth is off.

    SMART auth is OFF (``None``) unless ``smart_token_url`` is present (and ``smart_enabled`` is not
    ``False``), so every existing outbound is byte-identical. Settings arrive already ``env()``-resolved
    (the runner substitutes them before building the connector), exactly like the ``sign_*`` path.
    ``proxy`` (ADR 0126) routes the token-endpoint POST through the connection's forward proxy;
    #1660 threads the outbound's instance ``[tls]`` trust-anchor policy onto the token hop."""
    return token_provider_from_settings(
        config.settings, proxy=proxy, trust_anchor_policy=config.trust_anchor_policy
    )


def with_smart_backend(
    spec: ConnectionSpec | FhirLookupSpec,
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
) -> ConnectionSpec | FhirLookupSpec:
    """Enable SMART Backend Services client auth on a **REST/FHIR** outbound spec, or a **FhirLookup**
    read-side spec (ADR 0024/0043).

    Compose it over the ``Rest()`` / ``FHIR()`` factory — which supplies every transport default — so
    SMART auth is one code-first call and nothing else about the connector changes::

        from messagefoundry import FHIR, env, outbound
        from messagefoundry.transports.smart import with_smart_backend

        outbound("OB_EPIC_FHIR", with_smart_backend(
            FHIR(url=env("epic_fhir_base"), interaction="create"),
            token_url=env("epic_token_url"),      # the authorization server token endpoint
            client_id=env("epic_client_id"),
            scope="system/Patient.c",             # SMART v2, no human: ONLY what this feed writes
            private_key=env("epic_smart_key"),    # inline PEM via env(), or a PEM file path
            algorithm="RS384",                    # SMART SHALL: RS384 (default) | ES384
            key_id="epic-2026",                   # kid → the public key registered with the server
        ))

    **Request the least scope the connection can work with** (ASVS 10.2.3, #1159). The v2 permission
    letters are ``c``/``r``/``u``/``d``/``s`` (create/read/update/delete/search), so an
    ``interaction="create"`` outbound needs ``c`` and nothing else, and the resource half should name
    the type the feed actually writes rather than ``*``. ``messagefoundry check``'s advisory
    ``smart-scope`` line reports a request the connection's declared interaction cannot spend; it
    never blocks, because your authorization server registers the scopes it will grant and only it
    knows what your app is entitled to.

    ``token_url`` / ``client_id`` / ``private_key`` / ``audience`` / ``private_key_password`` may be
    :func:`~messagefoundry.config.wiring.env` references — keep every secret in ``env()``. The minted
    bearer **overrides** any static ``bearer_token`` on the spec. Mutates ``spec`` in place and returns
    it; SMART auth is OFF on any spec this was not called on. Accepts a ``FhirLookup`` read-side spec too
    (ADR 0043) — the read executor reuses the same provider for the GET's ``Authorization`` header."""
    # Lazy import avoids the transports -> config import cycle (config.wiring imports transports lazily).
    from messagefoundry.config.wiring import FhirLookupSpec

    if not isinstance(spec, FhirLookupSpec) and spec.type not in (
        ConnectorType.REST,
        ConnectorType.FHIR,
    ):
        raise SmartAuthError(
            f"SMART backend services auth applies to REST/FHIR outbound (or a FhirLookup) only, not "
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
