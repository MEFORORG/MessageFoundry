# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""REST transport: an HTTP destination that delivers each transformed payload to a URL.

The **destination** sends one payload (the request body, already produced by the Handler) to a
configured HTTP(S) endpoint and maps the outcome onto the engine's retry model:

- **2xx** → delivered.
- **5xx, 408, 429, connection/DNS/TLS/timeout** → :class:`DeliveryError` (transient — the pipeline
  retries with backoff).
- **other 4xx, or a refused 3xx redirect** → :class:`NegativeAckError` (``permanent=True``) so it
  **dead-letters immediately** instead of blocking the FIFO lane forever on a request the endpoint
  will never accept.

Standard library only (``urllib.request``) — no new dependency (ADR 0003). Redirects are **refused**
(a 3xx could divert PHI to an unintended host) and the scheme is constrained to http/https, mirroring
the alert-webhook hardening (ASVS 15.3.2 / 1.3.6); the `[egress].allowed_http` allowlist is the
fail-closed host gate (enforced by the runner at load/reload/start). Per-connection
``verify_tls=False`` is honored only when the dev escape ``MEFOR_ALLOW_INSECURE_TLS`` is set, exactly
like LDAPS / the SQL Server backend.

There is **no REST source yet** — a non-HL7 source needs the payload-agnostic ingress decided in
ADR 0003 (its own follow-up ADR). This is the first non-HL7 connector.

**Idempotency.** Delivery is at-least-once, so a retry re-sends the request; the receiving endpoint
**must be idempotent** (an idempotency key, or a natural upsert). See docs/CONNECTIONS.md.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import hop_insecure_escape_downgrades
from messagefoundry.config.tls_policy import (
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    RevocationHopGuard,
    current_hop_posture,
    enforce_insecure_hop,
    insecure_hop_disposition,
    is_loopback_hop_host,
    relax_verify_expiry,
)
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    NegativeAckError,
    register_destination,
)
from messagefoundry.transports.signing import MessageSigner, signer_from_destination

__all__ = [
    "DYNAMIC_HEADER_PREFIX",
    "InsecureHopGuard",
    "RestDestination",
    "capture_response_headers",
    "enforce_outbound_length_limits",
    "normalize_header_allowlist",
    "outbound_headers_from_metadata",
    "refuse_cleartext_credential_hop",
    "refuse_cleartext_credentials",
    "refuse_cleartext_egress",
    "refuse_unrevoked_verified_hop",
    "refuse_verify_off",
]

logger = logging.getLogger(__name__)

# --- per-message dynamic HTTP headers (BACKLOG #68) ------------------------------------------------
#
# A Handler computes a per-message request header (idempotency key, trace id, …) purely from the message
# and stamps it into the ADR 0081 user-metadata bag: ``SetMeta("http.header.X-Idempotency-Key", value)``.
# The bag rides the message as DATA (merged exactly-once inside the routed->outbound handoff), so the
# transform stays pure and a re-run re-derives the SAME headers. At delivery the REST/FHIR destinations
# project the ``http.header.*`` entries onto the outgoing request, MERGED OVER the construction-static
# headers (per-message value wins). No new store carry — it reuses the shipped metadata channel.

#: The reserved user-metadata key prefix whose entries become per-message HTTP request headers (#68). A
#: ``SetMeta("http.header.X-Trace-Id", v)`` write becomes the header ``X-Trace-Id: v``.
DYNAMIC_HEADER_PREFIX = "http.header."

# RFC 7230 header-name token: a message-derived name that isn't a valid token is DROPPED (never emitted),
# so a crafted metadata key can't smuggle a ':' / space / control char into the request as a header line.
_HEADER_NAME_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _strip_header_control_chars(value: str) -> str:
    """Neutralize a message-derived header VALUE (header-injection safety, #68): strip every C0 control
    (< 0x20 — incl. CR/LF) and DEL (0x7F) so the value can never split the request line or inject an
    extra header. Returns the value with those bytes removed (a single, safe header value)."""
    return "".join(ch for ch in value if not (ord(ch) < 0x20 or ord(ch) == 0x7F))


# --- captured HTTP response headers (BACKLOG #154, ADR 0013 amendment) -----------------------------
#
# A REST/SOAP/FHIR reply may carry a header the pipeline needs — a FHIR `create` returns the new
# resource's `Location`/`ETag`, a partner returns a correlation id. The delivery worker persists a
# capturing reply as a DeliveryResponse (ADR 0013); #154 folds a CONFIGURED ALLOW-LIST of response
# header names into that carriage so a re-ingressed answer's Handler reads them via
# `response_get(dest).headers`. Only the allow-listed names are ever captured — NEVER all headers:
# a partner reply header could carry sensitive data, so the allow-list is the PHI gate (the captured
# value is then encrypted at rest exactly like the reply body/detail).


def normalize_header_allowlist(setting: Any) -> frozenset[str]:
    """The per-connection ``capture_response_headers`` allow-list as a frozenset of **lowercased** header
    names (HTTP header names are case-insensitive, RFC 7230). Accepts a list/tuple/set of names or a
    single comma-separated string; anything else (incl. ``None``) → empty (capture nothing → the reply's
    ``DeliveryResponse.headers`` stays ``{}``, byte-identical). Blank entries are dropped."""
    if not setting:
        return frozenset()
    names: list[str]
    if isinstance(setting, str):
        names = setting.split(",")
    elif isinstance(setting, (list, tuple, set, frozenset)):
        names = [str(x) for x in setting]
    else:
        return frozenset()
    return frozenset(n.strip().lower() for n in names if n and str(n).strip())


def capture_response_headers(resp_headers: Any, allowlist: frozenset[str]) -> dict[str, str]:
    """The allow-listed subset of a reply's HTTP response headers as ``{name: value}`` (#154).

    ``resp_headers`` is a urllib/``http.client`` response header object (an ``email.message.Message``
    exposing ``.items()``). Only names whose lowercase form is in ``allowlist`` are kept (case-
    insensitive match); the header's own casing is preserved as the key. An empty ``allowlist`` → ``{}``
    (byte-identical — no capture). On a repeated header the LAST value wins (deterministic per reply, so
    re-ingress stays re-run-stable). Defensive: a header object without ``.items()`` → ``{}``."""
    if not allowlist:
        return {}
    items = getattr(resp_headers, "items", None)
    if items is None:
        return {}
    out: dict[str, str] = {}
    for name, value in items():
        if isinstance(name, str) and name.lower() in allowlist:
            out[name] = str(value)
    return out


def outbound_headers_from_metadata(metadata: Mapping[str, str] | None) -> dict[str, str]:
    """Project a message's user-metadata bag onto per-message HTTP request headers (#68).

    Only entries whose key starts with :data:`DYNAMIC_HEADER_PREFIX` become headers; the remainder of the
    key is the header name. **Header-injection-safe:** a name that is not a valid RFC 7230 token is
    dropped (it can never be emitted), and CR/LF/NUL/other control chars are stripped from the value via
    :func:`_strip_header_control_chars`, so a message-derived value cannot split the request or inject an
    extra header. **``Authorization`` is never settable per-message** — auth is connection config only, so
    a message-derived value can neither weaken nor replace the connection's credential. **Pure:** the
    result is a deterministic function of ``metadata`` (itself pure from the transform), so an
    at-least-once re-run yields byte-identical headers. ``None``/empty → ``{}`` (the default,
    byte-identical) — no per-message headers."""
    if not metadata:
        return {}
    out: dict[str, str] = {}
    for key, value in metadata.items():
        if not key.startswith(DYNAMIC_HEADER_PREFIX):
            continue
        name = key[len(DYNAMIC_HEADER_PREFIX) :]
        if not name or not _HEADER_NAME_TOKEN.match(name):
            continue  # not a valid header-name token — never emit it (can't inject a header line)
        if name.lower() == "authorization":
            continue  # auth is connection-configured only — a message never sets/overrides it
        if not isinstance(value, str):
            continue  # SetMeta enforces str, but stay defensive against a hand-built bag
        out[name] = _strip_header_control_chars(value)
    return out


# WP-L3-09 (ASVS 4.2.5): bound the resolved outbound URL and each built header value at connector
# construction. Every value is operator-supplied today (config + env()), so this is defense-in-depth
# that also surfaces a misconfiguration early — e.g. an env() secret that resolved to an unexpected
# blob, or a runaway concatenated header — as a clear config error instead of a wire-level surprise on
# the first delivery. 8 KiB comfortably exceeds any legitimate endpoint URL or Basic/Bearer credential.
MAX_OUTBOUND_URL_LEN = 8192
MAX_OUTBOUND_HEADER_VALUE_LEN = 8192

# 4xx statuses worth retrying anyway: the server is up but momentarily unwilling, not a hard reject.
_RETRYABLE_4XX = frozenset({408, 429})


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse to follow HTTP redirects (ASVS 15.3.2): a 3xx could divert a PHI-bearing POST to an
    unintended host. Returning ``None`` makes urllib raise the 3xx as an ``HTTPError`` instead of
    following it, so the delivery is classified (permanent) rather than silently redirected."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


# Shared opener that verifies TLS (urllib's default context) and never follows redirects.
_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)


def _insecure_opener() -> urllib.request.OpenerDirector:
    """A no-redirect opener that does **not** verify TLS — built only when the dev escape is set."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(_NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx))


def _expiry_relaxed_opener(host: str) -> urllib.request.OpenerDirector:
    """A no-redirect opener that verifies chain + hostname but tolerates an EXPIRED server cert (#129,
    ADR 0094). Built per connection (not the shared module-level verifying opener) only when
    ``tls_allow_expired=true``: it starts from the same verifying default context (OS trust store,
    ``check_hostname=True``) and relaxes ONLY the validity-period check via
    :func:`~messagefoundry.config.tls_policy.relax_verify_expiry`. Verification stays ON, so this is the
    granular alternative to ``verify_tls=false`` — a MITM-able peer (wrong host / untrusted chain) is
    still rejected. Shared verbatim by the SOAP destination."""
    ctx = ssl.create_default_context()
    relax_verify_expiry(ctx, host=host)  # chain + hostname stay enforced; only expiry is relaxed
    return urllib.request.build_opener(_NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx))


def _redact_url(url: str) -> str:
    """``scheme://host[:port]/path`` only — drops query/userinfo so a token or PHI in the query
    string never reaches a log line."""
    p = urllib.parse.urlsplit(url)
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname or ''}{port}{p.path}"


# --- posture-keyed insecure-hop enforcement (#200, ADR 0092) -----------------------------------
#
# The HTTP-family cells (REST/SOAP/FHIR/DICOMweb + the FhirLookup read path) shipped three escape-only,
# construction-only refusals — cleartext-credentials, cleartext body-egress, and verify_tls=false. #200
# re-keys them onto the ONE authority (``tls_policy.insecure_hop_disposition``) so they decide on the
# instance POSTURE (PHI? production?) instead of the blunt global escape, and adds a zero-I/O SEND-TIME
# re-assertion at the byte-crossing (defense-in-depth). Decision 5 (no-loosen): these cells refused BOTH
# staging and production PHI today, so :func:`_shipped_strict_disposition` FLOORS a non-prod PHI hop that
# would otherwise warn-and-cross back to REFUSE — only the (clamped, non-prod) escape, a per-hop
# attestation, on-box loopback, or a synthetic (non-PHI) instance relaxes it.


def _current_hop_posture_fail_closed() -> HopPosture:
    """The active hop posture, or the fail-closed ``(prod, PHI)`` default when unstamped (#200).

    A connector built inside the construction gate (``build_check_registry``'s ``active_hop_posture``
    scope) reads the LOADED config's derived posture; one built OUTSIDE it (an embedding/test, or the
    send-time recompute which runs past that scope) sees ``None`` and fails closed — treats the hop as
    production PHI so an unproven posture never *relaxes* a refusal (ADR 0092 decision 7)."""
    posture = current_hop_posture()
    return HopPosture(is_phi=True, production=True) if posture is None else posture


def _shipped_strict_disposition(
    posture: HopPosture, *, host: str, attested: bool
) -> HopDisposition:
    """The floored posture-keyed disposition for an ALREADY-SHIPPED insecure-egress cell (#200).

    Runs the instance ``posture`` through the ONE authority (:func:`insecure_hop_disposition`) with the
    global escape CLAMPED to non-production (:func:`hop_insecure_escape_downgrades`), then applies
    decision 5's no-loosen floor: a cell that refused BOTH staging and production PHI today must keep
    REFUSE for a non-prod PHI hop that reaches the gradient's WARN *without* the escape (arm 6). Only the
    non-prod escape (arm 4 → WARN), a per-hop attestation, on-box loopback, or a synthetic instance
    (all → ALLOW) relaxes it. Pure — no I/O — so the send-time guard can reuse it verbatim."""
    audited_opt_out = hop_insecure_escape_downgrades(production=posture.production)
    disposition = insecure_hop_disposition(
        is_phi=posture.is_phi,
        production=posture.production,
        is_loopback_hop=is_loopback_hop_host(host),
        hop_attested=attested,
        audited_opt_out=audited_opt_out,
    )
    if disposition is HopDisposition.WARN and not audited_opt_out:
        # arm-6 WARN (non-prod PHI, no escape) — this shipped cell REFUSED it; keep it strict.
        return HopDisposition.REFUSE
    return disposition


@dataclass(frozen=True, slots=True)
class InsecureHopGuard:
    """Captured posture for the zero-I/O SEND-TIME re-assertion of a permitted insecure hop (#200).

    An already-shipped cell decides its posture-keyed refusal at CONSTRUCTION (the enforced gate). When
    it PERMITS an insecure hop (a warned cleartext/verify-off egress, or an attested one) it captures the
    LOADED posture here so :meth:`assert_send` can re-assert the SAME decision at the byte-crossing —
    defense-in-depth against a reload / per-message target routing a PHI hop past a construction-only
    check (ADR 0092 decision 4). Recompute-only: it touches no wire and, unlike construction, does not
    re-log the WARN (that fired once at build); it raises :class:`InsecureHopRefused` only if the hop is
    now REFUSE."""

    posture: HopPosture
    attested: bool
    cell: str

    def assert_send(self, host: str, redacted_url: str) -> None:
        """Re-assert (zero I/O) that ``host`` is still a permitted hop under the captured posture."""
        if (
            _shipped_strict_disposition(self.posture, host=host, attested=self.attested)
            is HopDisposition.REFUSE
        ):
            raise InsecureHopRefused(
                f"{self.cell}: send-time refusal — insecure hop to {host!r} ({redacted_url}) is not "
                "permitted under the instance posture"
            )


def _enforce_shipped_hop(
    host: str, *, cell: str, message: str, attested: bool
) -> tuple[HopDisposition, HopPosture]:
    """Decide + enforce an already-shipped insecure hop at CONSTRUCTION, returning (disposition, posture).

    Keys on the active (fail-closed) posture, applies the decision-5 floor, then acts via
    :func:`enforce_insecure_hop` (raise on REFUSE, loud-log on WARN, no-op on ALLOW). When a per-hop
    attestation SUPPRESSES a would-be production-PHI refusal it is recorded loudly — the audited opt-in
    that replaces the blunt global escape for the production case (decision 3)."""
    posture = _current_hop_posture_fail_closed()
    disposition = _shipped_strict_disposition(posture, host=host, attested=attested)
    if (
        disposition is HopDisposition.ALLOW
        and attested
        and posture.is_phi
        and posture.production
        and not is_loopback_hop_host(host)
    ):
        logger.warning(
            "insecure transport hop ATTESTED secure (suppresses a production-PHI refusal) — %s: %s",
            cell,
            message,
        )
    enforce_insecure_hop(disposition, message=message, cell=cell)
    return disposition, posture


def refuse_cleartext_credential_hop(
    scheme: str, url: str, *, credential: str, attested: bool = False
) -> None:
    """Refuse a named ``credential`` riding a cleartext (``http``) hop (posture-keyed, #200).

    The header-agnostic core of :func:`refuse_cleartext_credentials`, reused for a credential that does
    NOT ride the ``Authorization`` header (a SOAP WS-Security UsernameToken in the body). Re-keyed onto
    the ONE authority: a production-PHI hop is REFUSED (the clamped global escape can no longer silence
    it — decision 2), a non-prod PHI hop is refused unless the escape downgrades it to a loud WARN, and an
    on-box loopback / per-hop-attested / synthetic hop is allowed."""
    if scheme != "http":
        return
    host = urllib.parse.urlsplit(url).hostname or ""
    _enforce_shipped_hop(
        host,
        cell="HTTP cleartext credentials",
        message=f"sends a {credential} over cleartext http to {host!r}",
        attested=attested,
    )


def refuse_cleartext_credentials(
    scheme: str, headers: dict[str, str], url: str, *, attested: bool = False
) -> None:
    """Refuse to send credentials over a cleartext (``http``) channel (posture-keyed, #200).

    Basic/bearer auth in an ``Authorization`` header over plain ``http`` puts the credential on the wire
    (and the body is PHI). Delegates to :func:`refuse_cleartext_credential_hop`. Shared by the
    REST/SOAP/FHIR/DICOMweb HTTP cells and the FhirLookup read path."""
    if "Authorization" not in headers:
        return
    refuse_cleartext_credential_hop(
        scheme, url, credential="credential (Authorization header)", attested=attested
    )


def refuse_cleartext_egress(
    scheme: str, url: str, *, attested: bool = False
) -> InsecureHopGuard | None:
    """Refuse a cleartext (``http``) outbound to a **non-loopback** host (ASVS 12.2.1, posture-keyed #200).

    A plaintext ``http://`` destination puts the PHI-bearing request body on the wire even with no
    ``Authorization`` header, so an off-box http egress is decided by the instance posture: a
    production-PHI hop REFUSES (escape inert — decision 2), a non-prod PHI hop refuses unless the clamped
    escape downgrades it to a loud WARN (decision 5 floor keeps it strict otherwise), and an on-box
    loopback / per-hop-attested / synthetic hop is allowed — so the default ``127.0.0.1`` posture stays
    byte-identical. Complements :func:`refuse_cleartext_credentials`, which fires first (more specific)
    when the connection also carries credentials.

    Returns an :class:`InsecureHopGuard` when the cleartext hop was PERMITTED (a warned / attested off-box
    egress) so the caller re-asserts it at send; ``None`` for a secure or loopback hop (no send guard
    needed — the send stays byte-identical)."""
    if scheme != "http":
        return None
    host = urllib.parse.urlsplit(url).hostname or ""
    _, posture = _enforce_shipped_hop(
        host,
        cell="HTTP cleartext egress",
        message=(f"delivers its payload over cleartext http to a non-loopback host ({host!r})"),
        attested=attested,
    )
    if is_loopback_hop_host(host):
        return None  # on-box loopback — not a network exposure, so no send-time guard
    return InsecureHopGuard(posture=posture, attested=attested, cell="HTTP cleartext egress")


def refuse_verify_off(
    scheme: str, url: str, *, connector: str, attested: bool = False
) -> InsecureHopGuard | None:
    """Refuse a ``verify_tls=false`` (unverified-TLS) hop to a non-loopback host (posture-keyed, #200).

    Disabling certificate verification makes the ``https`` hop MITM-able, so it is an insecure hop and is
    decided exactly like cleartext egress: production-PHI REFUSES (escape inert), a non-prod PHI hop
    refuses unless the clamped escape downgrades it to a loud WARN, an on-box loopback / attested /
    synthetic hop is allowed. Only meaningful for ``https`` (an ``http`` url has no TLS to verify and is
    handled by :func:`refuse_cleartext_egress`); returns ``None`` for a non-https scheme. Returns an
    :class:`InsecureHopGuard` when the hop was permitted (a warned / attested off-box hop)."""
    if scheme != "https":
        return None
    host = urllib.parse.urlsplit(url).hostname or ""
    cell = f"{connector} verify_tls=false"
    _, posture = _enforce_shipped_hop(
        host,
        cell=cell,
        message=f"disables TLS certificate verification for non-loopback host {host!r}",
        attested=attested,
    )
    if is_loopback_hop_host(host):
        return None
    return InsecureHopGuard(posture=posture, attested=attested, cell=cell)


def refuse_unrevoked_verified_hop(
    scheme: str, url: str, *, connector: str, revocation_attested: bool = False
) -> None:
    """Refuse a VERIFYING ``https`` hop that does no certificate revocation checking (#201, ADR 0078 amend).

    The revocation twin of :func:`refuse_verify_off`, for the *verify-ON* https path the HTTP-family cells
    (REST/SOAP/FHIR) take when ``verify_tls`` is true: urllib rides stdlib ssl, which validates the chain
    (+ strict RFC 5280) but performs NO OCSP/CRL, so a revoked-but-unexpired server cert is still accepted.
    A production-PHI verified hop to a non-loopback host is REFUSED at construction unless revocation is
    attested (per-connection ``tls_revocation_attested`` or the blanket ``MEFOR_TLS_REVOCATION_ATTESTED``
    env, folded in by :meth:`RevocationHopGuard.capture`); a non-prod PHI hop WARNs; loopback / synthetic /
    attested hops are byte-identical. Only meaningful for ``https`` — an ``http`` url has no TLS (its
    cleartext body is refused by :func:`refuse_cleartext_egress`) and ``verify_tls=false`` is not a
    verifying hop (refused by :func:`refuse_verify_off`), so the revocation gate and the #200 cleartext /
    verify-off gates key on disjoint conditions and never double-refuse one hop."""
    if scheme != "https":
        return
    host = urllib.parse.urlsplit(url).hostname or ""
    RevocationHopGuard.capture(
        host=host,
        cell=f"{connector} (verified TLS, no revocation check)",
        description="delivers over verified https but performs no certificate revocation checking",
        attested=revocation_attested,
    ).enforce_construction()


def enforce_outbound_length_limits(url: str, headers: dict[str, str]) -> None:
    """Reject an over-length outbound URL or request-header value at connector construction (ASVS
    4.2.5). Shared by the REST and SOAP destinations (SOAP reuses REST's HTTP plumbing). Raises
    :class:`ValueError` with a PHI-free message naming only the limit and the offending header name —
    never the value (a header may carry a credential)."""
    if len(url) > MAX_OUTBOUND_URL_LEN:
        raise ValueError(
            f"outbound URL is {len(url)} chars, over the {MAX_OUTBOUND_URL_LEN}-char limit; "
            "check the configured 'url' / its env() value"
        )
    for name, value in headers.items():
        if len(value) > MAX_OUTBOUND_HEADER_VALUE_LEN:
            raise ValueError(
                f"outbound header {name!r} is {len(value)} chars, over the "
                f"{MAX_OUTBOUND_HEADER_VALUE_LEN}-char limit; check the configured header / "
                "credential value"
            )


class RestDestination(DestinationConnector):
    """Deliver each transformed payload to an HTTP(S) endpoint (outbound only today)."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        url = s.get("url")
        if not isinstance(url, str) or not url:
            raise ValueError("REST destination requires a 'url' setting")
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"REST destination 'url' must be http or https, got scheme {scheme!r}")
        self.url = url
        self.method: str = str(s.get("method", "POST")).upper()
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.encoding: str = s.get("encoding", "utf-8")
        # ADR 0013: capture the HTTP response body. Default False → returns None, byte-identical. A 2xx
        # with a body → outcome='accepted'; a 2xx with an empty body → outcome='no_reply' (a successful
        # round-trip, not an error). Non-2xx keeps today's DeliveryError/NegativeAckError classification.
        self.capture_response: bool = bool(s.get("capture_response", False))
        # #154: the allow-list of HTTP response header names to capture into the DeliveryResponse. Empty
        # (the default) → no headers captured, byte-identical. Only meaningful when the reply is captured.
        self.capture_response_headers = normalize_header_allowlist(
            s.get("capture_response_headers")
        )
        # #68: opt in to per-message HTTP headers stamped by a Handler into the ADR 0081 metadata bag
        # (http.header.* entries). Default False → the delivery worker skips the metadata read and send
        # is byte-identical. When True, consumes_metadata tells the worker to pass this message's bag.
        self.consumes_metadata: bool = bool(s.get("dynamic_headers", False))
        # #200 (ADR 0092): the per-connection insecure-hop attestation, keying the posture-keyed refusal.
        attested = config.tls_hop_attested
        # Captured at construction; re-asserted (zero I/O) at the byte-crossing in _post (decision 4).
        self._hop_guard: InsecureHopGuard | None = None
        self._headers = self._build_headers(s)
        enforce_outbound_length_limits(self.url, self._headers)
        refuse_cleartext_credentials(scheme, self._headers, self.url, attested=attested)
        # ASVS 12.2.1: even without an Authorization header the request body is PHI, so a cleartext
        # http egress to a non-loopback host is refused (loopback stays byte-identical). See rest.py.
        self._hop_guard = refuse_cleartext_egress(scheme, self.url, attested=attested)
        # ASVS 4.1.5 (ADR 0018): opt-in detached-JWS signing of the outbound body. None = off (byte-
        # identical). Built here so a bad key/algorithm fails loud at connector construction (check/
        # dry-run/start), like a bad TLS cert; the per-request signature is minted in _post (off-loop).
        self._signer: MessageSigner | None = signer_from_destination(config)
        # ADR 0024 + #65: opt-in bearer-token auth — SMART Backend Services (asymmetric JWT) OR OAuth2
        # client-credentials (symmetric secret), unified behind the one bearer seam. None = off (byte-
        # identical). Lazy import breaks the rest <-> http_auth/smart cycle (they reuse rest's opener);
        # built here so a bad key/secret/token_url fails loud. The minted bearer is injected per-request
        # in _post; the two modes are mutually exclusive (a loud HttpAuthError otherwise).
        from messagefoundry.transports.http_auth import bearer_provider_from_settings

        self._token_provider = bearer_provider_from_settings(s)
        if self._token_provider is not None:
            # The SMART bearer is injected per-request in _post, so the static-header cleartext check
            # above can't see it. Re-run the check treating the connection as credential-bearing, so a
            # SMART access token never ships over cleartext http (the detached-JWS signature, by
            # contrast, is public-verifiable and needs no such guard).
            refuse_cleartext_credentials(
                scheme, {**self._headers, "Authorization": "Bearer"}, self.url, attested=attested
            )
        if bool(s.get("verify_tls", True)):
            # #201 (ADR 0078 amendment): the verify-ON https hop validates the peer cert but does no
            # OCSP/CRL revocation (stdlib ssl has none) — refuse an off-loopback production-PHI verified
            # hop unless revocation is attested (loopback / synthetic / non-prod / attested byte-identical).
            # Composes with #200: it keys on the verify-ON https path, disjoint from the cleartext /
            # verify-off gates above, so no hop is ever double-refused.
            refuse_unrevoked_verified_hop(
                scheme,
                self.url,
                connector="REST destination",
                revocation_attested=config.tls_revocation_attested,
            )
            # #129 (ADR 0094): granular expiry-only relaxation — verify chain + hostname but tolerate an
            # expired server cert (opt-in; default off = the shared verifying opener, byte-identical). It
            # keeps verification ON, so it is NOT an insecure hop in the #200 sense (no refusal keys on it).
            if bool(s.get("tls_allow_expired", False)):
                self._opener = _expiry_relaxed_opener(
                    urllib.parse.urlsplit(self.url).hostname or ""
                )
            else:
                self._opener = _NO_REDIRECT_OPENER
        else:
            # verify_tls=false makes the https hop MITM-able — an insecure hop decided by the instance
            # posture (#200): production-PHI REFUSES (escape inert), a non-prod PHI hop refuses unless the
            # clamped escape / a per-hop attestation permits it. Loopback stays byte-identical.
            guard = refuse_verify_off(
                scheme, self.url, connector="REST destination", attested=attested
            )
            if guard is not None:
                self._hop_guard = guard
            logger.warning(
                "REST destination %s has TLS verification DISABLED (verify_tls=false)",
                _redact_url(self.url),
            )
            self._opener = _insecure_opener()
        # #65: HTTP Digest (RFC 7616) — fold the challenge-answering handler into a PER-CONNECTION opener
        # (never mutate the shared _NO_REDIRECT_OPENER). urllib answers the 401 + retries within
        # opener.open(). None (default) → byte-identical. Mutually exclusive with a bearer provider.
        from messagefoundry.transports.http_auth import HttpAuthError, digest_handler_from_settings

        digest = digest_handler_from_settings(s, url=self.url)
        if digest is not None:
            if self._token_provider is not None:
                raise HttpAuthError(
                    "a connection cannot use BOTH a bearer-token provider and HTTP Digest auth "
                    "(mutually exclusive — configure exactly one)"
                )
            if self._opener is _NO_REDIRECT_OPENER:
                # Rebuild a per-connection verifying opener so add_handler never touches the shared one.
                self._opener = urllib.request.build_opener(_NoRedirectHandler)
            self._opener.add_handler(digest)

    @staticmethod
    def _build_headers(s: dict[str, Any]) -> dict[str, str]:
        """Content-Type + any static ``headers`` + optional bearer/basic auth. Secrets (token,
        password) come in as resolved top-level settings (``env()``-friendly); static ``headers`` are
        literal and must not carry secrets (they aren't ``env()``-resolved)."""
        headers: dict[str, str] = {"Content-Type": str(s.get("content_type", "application/json"))}
        extra = s.get("headers") or {}
        if isinstance(extra, dict):
            headers.update({str(k): str(v) for k, v in extra.items()})
        token = s.get("bearer_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        user, password = s.get("basic_user"), s.get("basic_password")
        if user and password:
            raw = f"{user}:{password}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        return headers

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:
        # #68: build this message's dynamic headers from its user-metadata bag (pure; None → {} → byte-
        # identical). urllib is blocking — keep it off the event loop (the delivery worker awaits this).
        dynamic_headers = outbound_headers_from_metadata(metadata)
        body, status, headers = await asyncio.to_thread(self._post, payload, dynamic_headers)
        if not self.capture_response:
            return None
        if body == "":
            # A successful round-trip with no payload — captured as a deliberate empty reply, NOT an
            # error (the request succeeded). Distinct from a read failure, which raised above.
            return DeliveryResponse(
                body="", outcome="no_reply", detail=f"HTTP {status}", headers=headers
            )
        return DeliveryResponse(
            body=body, outcome="accepted", detail=f"HTTP {status}", headers=headers
        )

    async def test_connection(self) -> None:
        await asyncio.to_thread(self._probe)

    def _probe(self) -> None:
        # Reachability only: a HEAD reaches the endpoint without POSTing a body. An HTTP response means
        # the host answered, so a 405 (HEAD not allowed on a POST endpoint) is still a pass — but a 401/
        # 403 means the configured credentials would be rejected, which a real delivery dead-letters, so
        # surface it as a failure. Connection/DNS/TLS/timeout is always a fail.
        headers = self._headers
        if self._token_provider is not None:
            # Acquire a real SMART token so reachability reflects the actual credentials (a token-
            # endpoint failure raises DeliveryError, surfaced as unreachable).
            headers = {
                **self._headers,
                "Authorization": f"Bearer {self._token_provider.access_token()}",
            }
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.url, headers=headers, method="HEAD"
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise DeliveryError(
                    f"REST {_redact_url(self.url)} returned HTTP {exc.code} (check credentials)"
                ) from exc
            return  # any other status (the host answered) → reachable
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise DeliveryError(f"REST {_redact_url(self.url)} unreachable: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"REST {_redact_url(self.url)} failed: {exc}") from exc

    def _post(
        self, payload: str, dynamic_headers: dict[str, str] | None = None
    ) -> tuple[str, int, dict[str, str]]:
        # #200 (ADR 0092 decision 4): zero-I/O send-time re-assertion of a permitted insecure hop, before
        # a single byte crosses — defense against a reload / per-message target sneaking PHI past the
        # construction-only gate. A None guard (secure/loopback hop) is byte-identical.
        if self._hop_guard is not None:
            self._hop_guard.assert_send(
                urllib.parse.urlsplit(self.url).hostname or "", _redact_url(self.url)
            )
        data = payload.encode(self.encoding)
        headers = self._headers
        if dynamic_headers or self._token_provider is not None or self._signer is not None:
            headers = dict(self._headers)
            if dynamic_headers:
                # #68: per-message headers MERGE OVER the construction-static ones (per-message wins).
                # Applied BEFORE the SMART bearer / JWS signature below so a message-derived value can
                # never clobber the security-critical Authorization / signature headers.
                headers.update(dynamic_headers)
            if self._token_provider is not None:
                # ADR 0024: a fresh SMART bearer per request, acquired off-loop past the queue boundary
                # (a retry re-mints — re-run purity holds). Overrides any static bearer_token.
                headers["Authorization"] = f"Bearer {self._token_provider.access_token()}"
            if self._signer is not None:
                # ASVS 4.1.5 (ADR 0018): mint a detached JWS over the exact body bytes and carry it in a
                # per-request header. Minted here in send()'s off-loop worker, past the queue boundary, so
                # a retry re-mints it (re-run purity holds, like the WS-Security nonce — ADR 0015).
                headers.update(self._signer.signature_headers(data))
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.url,
            data=data,
            headers=headers,
            method=self.method,
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                # Read the body (drains the connection for clean close; returned for capture). 2xx ⇒
                # delivered. Decoding a drained body is cheap, so this stays byte-identical when capture
                # is off (the worker just ignores the return).
                body = resp.read().decode(self.encoding, errors="replace")
                status = int(getattr(resp, "status", 200))
                # #154: capture only the allow-listed response headers (empty allow-list → {}).
                headers = capture_response_headers(
                    getattr(resp, "headers", None), self.capture_response_headers
                )
                return body, status, headers
        except urllib.error.HTTPError as exc:
            status = exc.code
            if self._token_provider is not None and status == 401:
                # ADR 0024: the SMART token may have expired between mint and use — drop it and retry
                # with a fresh one (transient). A 403 is left permanent (an authz/scope denial a re-mint
                # won't fix). PHI/secret-safe: no body, redacted URL only.
                self._token_provider.invalidate()
                raise DeliveryError(
                    f"REST {_redact_url(self.url)} returned HTTP 401; refreshing SMART token"
                ) from exc
            if status in _RETRYABLE_4XX or 500 <= status < 600:
                raise DeliveryError(f"REST {_redact_url(self.url)} returned HTTP {status}") from exc
            # Other 4xx (and a refused 3xx) — the endpoint won't accept this request as-is; fail fast
            # to the dead-letter queue rather than retry a permanent rejection forever.
            raise NegativeAckError(
                f"REST {_redact_url(self.url)} rejected with HTTP {status}",
                code=str(status),
                permanent=True,
            ) from exc
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise DeliveryError(f"REST {_redact_url(self.url)} unreachable: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"REST {_redact_url(self.url)} failed: {exc}") from exc


register_destination(ConnectorType.REST, RestDestination)
