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
from messagefoundry.config.tls_policy import (
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    RevocationHopGuard,
    cleartext_acceptance_audit_sink,
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
    encode_wire_body,
    register_destination,
)
from messagefoundry.transports.signing import MessageSigner, signer_from_destination

__all__ = [
    "DYNAMIC_HEADER_PREFIX",
    "InsecureHopGuard",
    "ProxyConfig",
    "RestDestination",
    "capture_response_headers",
    "ech_sidecar_url_from_settings",
    "egress_route_from_settings",
    "proxy_auth_handler_from_settings",
    "proxy_config_from_settings",
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


def _no_redirect_opener(
    *extra_handlers: urllib.request.BaseHandler,
) -> urllib.request.OpenerDirector:
    """A PER-CONNECTION verifying, no-redirect opener carrying ``extra_handlers`` (a forward-proxy
    ``ProxyHandler``, a reactive ``ProxyDigestAuthHandler``, …) — used in place of the shared
    :data:`_NO_REDIRECT_OPENER` whenever a connection needs a handler the shared one lacks, so the shared
    opener is **never** mutated (ADR 0126). Passing a ``ProxyHandler`` here also suppresses urllib's
    default env-reading ProxyHandler (``build_opener`` skips a default whose class a supplied handler
    already covers), so there is never a competing double-proxy."""
    return urllib.request.build_opener(_NoRedirectHandler, *extra_handlers)


def _insecure_opener(
    *extra_handlers: urllib.request.BaseHandler,
) -> urllib.request.OpenerDirector:
    """A no-redirect opener that does **not** verify TLS — built only when the dev escape is set. Threads
    any ``extra_handlers`` (e.g. a forward-proxy handler, ADR 0126) into the same per-connection opener."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        _NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx), *extra_handlers
    )


def _expiry_relaxed_opener(
    host: str, *extra_handlers: urllib.request.BaseHandler
) -> urllib.request.OpenerDirector:
    """A no-redirect opener that verifies chain + hostname but tolerates an EXPIRED server cert (#129,
    ADR 0094). Built per connection (not the shared module-level verifying opener) only when
    ``tls_allow_expired=true``: it starts from the same verifying default context (OS trust store,
    ``check_hostname=True``) and relaxes ONLY the validity-period check via
    :func:`~messagefoundry.config.tls_policy.relax_verify_expiry`. Verification stays ON, so this is the
    granular alternative to ``verify_tls=false`` — a MITM-able peer (wrong host / untrusted chain) is
    still rejected. Shared verbatim by the SOAP destination."""
    ctx = ssl.create_default_context()
    relax_verify_expiry(ctx, host=host)  # chain + hostname stay enforced; only expiry is relaxed
    return urllib.request.build_opener(
        _NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx), *extra_handlers
    )


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
    return HopPosture(is_phi=True, enforcing=True) if posture is None else posture


def _shipped_strict_disposition(
    posture: HopPosture,
    *,
    host: str,
    attested: bool,
    cleartext_accepted: bool = False,
) -> HopDisposition:
    """The floored disposition for an ALREADY-SHIPPED insecure-egress cell (#200, amended by ADR 0153).

    Runs the instance ``posture`` through the ONE authority (:func:`insecure_hop_disposition`), then
    applies ADR 0092 decision 5's no-loosen floor: a cell that refused BOTH staging and production PHI
    today must keep REFUSE for a hop that only reaches the gradient's WARN because the instance is not
    enforcing. Pure — no I/O — so the send-time guard can reuse it verbatim.

    **The floor is now keyed on ``cleartext_accepted``, not on the global escape.** Before ADR 0153 it
    read ``not audited_opt_out``, which is how ``MEFOR_ALLOW_INSECURE_TLS`` relaxed an HTTP-family
    cleartext hop. 0153 decision 5 says the variable "can no longer influence a cleartext-hop decision",
    and these cells — REST/SOAP/FHIR/DICOMweb bodies, HTTP credentials, ``verify_tls=false`` — *are*
    cleartext-hop decisions: the ADR's out-of-scope note about this function means its **floor** is not
    being reworked, not that the HTTP family keeps a data-label carve-out. Re-keying it (a) keeps 0092
    §5 exactly (a non-enforcing hop that reaches WARN with no declaration is still floored to REFUSE, as
    today), and (b) makes decision 2's escape effective on the largest cleartext-egress family in the
    product — the only one where it is a genuine escape, since Tcp()/X12() never reach this cell.

    Side effect, stated plainly: an instance that set ``MEFOR_ALLOW_INSECURE_TLS`` to cross a
    non-enforcing HTTP cleartext hop no longer can. That is a TIGHTENING, and it is intended — it is
    also what makes the raw-transport guards and this one agree again, rather than leaving the blunt env
    var alive on HTTP and dead on raw TCP."""
    disposition = insecure_hop_disposition(
        enforcing=posture.enforcing,
        is_loopback_hop=is_loopback_hop_host(host),
        hop_attested=attested,
        cleartext_accepted=cleartext_accepted,
    )
    if disposition is HopDisposition.WARN and not cleartext_accepted:
        # A WARN reached via the non-enforcing dial alone — this shipped cell REFUSED it; keep it strict.
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
    # ADR 0153 decision 2 — captured with the posture so the send-time re-assertion sees exactly the
    # declaration the construction gate decided on.
    cleartext_accepted: bool = False

    def assert_send(self, host: str, redacted_url: str) -> None:
        """Re-assert (zero I/O) that ``host`` is still a permitted hop under the captured posture."""
        if (
            _shipped_strict_disposition(
                self.posture,
                host=host,
                attested=self.attested,
                cleartext_accepted=self.cleartext_accepted,
            )
            is HopDisposition.REFUSE
        ):
            raise InsecureHopRefused(
                f"{self.cell}: send-time refusal — insecure hop to {host!r} ({redacted_url}) is not "
                "permitted under the instance posture"
            )


def _enforce_shipped_hop(
    host: str,
    *,
    cell: str,
    message: str,
    attested: bool,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
) -> tuple[HopDisposition, HopPosture]:
    """Decide + enforce an already-shipped insecure hop at CONSTRUCTION, returning (disposition, posture).

    Keys on the active (fail-closed) posture, applies the decision-5 floor, then acts via
    :func:`enforce_insecure_hop` (raise on REFUSE, loud-log on WARN, no-op on ALLOW). When a per-hop
    attestation SUPPRESSES a would-be refusal it is recorded loudly — the audited opt-in that replaced
    the blunt global escape (ADR 0092 decision 3). When an ADR 0153 ``cleartext_accepted`` declaration is
    what produced the WARN, that is recorded too, at every construction."""
    posture = _current_hop_posture_fail_closed()
    disposition = _shipped_strict_disposition(
        posture, host=host, attested=attested, cleartext_accepted=cleartext_accepted
    )
    # The `posture.is_phi` conjunct this branch used to carry went with ADR 0153: the authority no longer
    # reads the label, so gating the audit on it would silence the record for exactly the hops that
    # newly depend on the attestation to cross.
    if (
        disposition is HopDisposition.ALLOW
        and attested
        and posture.enforcing
        and not is_loopback_hop_host(host)
    ):
        logger.warning(
            "insecure transport hop ATTESTED secure (suppresses an enforcing refusal) — %s: %s",
            cell,
            message,
        )
    enforce_insecure_hop(
        disposition,
        message=message,
        cell=cell,
        audit_sink=(
            cleartext_acceptance_audit_sink(cleartext_reason)
            if disposition is HopDisposition.WARN and cleartext_accepted
            else None
        ),
    )
    return disposition, posture


def cleartext_acceptance_from_settings(s: Mapping[str, Any]) -> tuple[bool, str | None]:
    """``(cleartext_accepted, cleartext_reason)`` read off an ``env()``-resolved settings mapping.

    ADR 0153's pair is a **top-level outbound key**, but the deep settings-driven seams — the forward-proxy
    credential chain, the HTTP Digest / OAuth2 token-endpoint providers, and the ``FhirLookup`` read
    executor — receive only a settings mapping, exactly as they already do for ``tls_hop_attested``. The
    runner's ``_dest_config`` mirrors the declaration into those resolved settings (and only when it is
    set, so an outbound that declared nothing is byte-identical), and this is the single reader, so the
    mirror is never re-parsed by hand at four call sites. A ``FhirLookup`` connection, which has no
    ``Destination``, carries the pair as a spec setting directly — the same surface its
    ``tls_hop_attested`` already uses."""
    reason = s.get("cleartext_reason")
    return bool(s.get("cleartext_accepted", False)), None if reason is None else str(reason)


def refuse_cleartext_credential_hop(
    scheme: str,
    url: str,
    *,
    credential: str,
    attested: bool = False,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
) -> None:
    """Refuse a named ``credential`` riding a cleartext (``http``) hop (#200, amended by ADR 0153).

    The header-agnostic core of :func:`refuse_cleartext_credentials`, reused for a credential that does
    NOT ride the ``Authorization`` header (a SOAP WS-Security UsernameToken in the body). Keyed on the
    ONE authority: an enforcing hop is REFUSED, an on-box loopback / per-hop-attested hop is allowed, and
    an ADR 0153 ``cleartext_accepted`` declaration crosses it with a loud, audited WARN.

    **``cleartext_accepted`` deliberately reaches the credential hops too**, even though putting a
    password on the wire is a worse claim than putting a body on it. ADR 0153 is silent here, and the
    alternative — leaving credentials with no expressible declaration — would push an operator whose
    legacy peer needs Basic auth over a cleartext segment into writing a FALSE ``tls_hop_attested``,
    which is precisely the defect 0153 exists to remove. The declaration stays per-connection, WARNs at
    every construction, is audited, and is reported as a loosening, so it is strictly more visible than
    the blanket escape that used to permit exactly this. (SMTP AUTH over cleartext remains refused
    OUTRIGHT in ``transports.email`` — that is a hard refusal, not a posture decision, and is
    untouched.)"""
    if scheme != "http":
        return
    host = urllib.parse.urlsplit(url).hostname or ""
    _enforce_shipped_hop(
        host,
        cell="HTTP cleartext credentials",
        message=f"sends a {credential} over cleartext http to {host!r}",
        attested=attested,
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
    )


def refuse_cleartext_credentials(
    scheme: str,
    headers: dict[str, str],
    url: str,
    *,
    attested: bool = False,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
) -> None:
    """Refuse to send credentials over a cleartext (``http``) channel (posture-keyed, #200).

    Basic/bearer auth in an ``Authorization`` header over plain ``http`` puts the credential on the wire
    (and the body is PHI). Delegates to :func:`refuse_cleartext_credential_hop`. Shared by the
    REST/SOAP/FHIR/DICOMweb HTTP cells and the FhirLookup read path."""
    if "Authorization" not in headers:
        return
    refuse_cleartext_credential_hop(
        scheme,
        url,
        credential="credential (Authorization header)",
        attested=attested,
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
    )


def refuse_cleartext_egress(
    scheme: str,
    url: str,
    *,
    attested: bool = False,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
) -> InsecureHopGuard | None:
    """Refuse a cleartext (``http``) outbound to a **non-loopback** host (ASVS 12.2.1, #200 / ADR 0153).

    A plaintext ``http://`` destination puts the PHI-bearing request body on the wire even with no
    ``Authorization`` header, so an off-box http egress is decided by the ONE authority: an enforcing hop
    REFUSES, an on-box loopback / per-hop-attested hop is allowed — so the default ``127.0.0.1`` posture
    stays byte-identical — and an ADR 0153 ``cleartext_accepted`` declaration crosses it with a loud,
    audited WARN. Complements :func:`refuse_cleartext_credentials`, which fires first (more specific)
    when the connection also carries credentials.

    Returns an :class:`InsecureHopGuard` when the cleartext hop was PERMITTED (a warned / attested /
    accepted off-box egress) so the caller re-asserts it at send; ``None`` for a secure or loopback hop
    (no send guard needed — the send stays byte-identical)."""
    if scheme != "http":
        return None
    host = urllib.parse.urlsplit(url).hostname or ""
    _, posture = _enforce_shipped_hop(
        host,
        cell="HTTP cleartext egress",
        message=(f"delivers its payload over cleartext http to a non-loopback host ({host!r})"),
        attested=attested,
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
    )
    if is_loopback_hop_host(host):
        return None  # on-box loopback — not a network exposure, so no send-time guard
    return InsecureHopGuard(
        posture=posture,
        attested=attested,
        cell="HTTP cleartext egress",
        cleartext_accepted=cleartext_accepted,
    )


def refuse_verify_off(
    scheme: str,
    url: str,
    *,
    connector: str,
    attested: bool = False,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
) -> InsecureHopGuard | None:
    """Refuse a ``verify_tls=false`` (unverified-TLS) hop to a non-loopback host (#200 / ADR 0153).

    Disabling certificate verification makes the ``https`` hop MITM-able, so it is an insecure hop and is
    decided exactly like cleartext egress: an enforcing hop REFUSES, an on-box loopback / attested hop is
    allowed, and a ``cleartext_accepted`` declaration crosses it with a loud, audited WARN. Only
    meaningful for ``https`` (an ``http`` url has no TLS to verify and is handled by
    :func:`refuse_cleartext_egress`); returns ``None`` for a non-https scheme. Returns an
    :class:`InsecureHopGuard` when the hop was permitted (a warned / attested / accepted off-box hop)."""
    if scheme != "https":
        return None
    host = urllib.parse.urlsplit(url).hostname or ""
    cell = f"{connector} verify_tls=false"
    _, posture = _enforce_shipped_hop(
        host,
        cell=cell,
        message=f"disables TLS certificate verification for non-loopback host {host!r}",
        attested=attested,
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
    )
    if is_loopback_hop_host(host):
        return None
    return InsecureHopGuard(
        posture=posture, attested=attested, cell=cell, cleartext_accepted=cleartext_accepted
    )


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


# --- forward/egress web proxy (BACKLOG #112/#127/#128, ADR 0126) -----------------------------------
#
# A per-connection forward proxy for the whole stdlib HTTP family (REST/SOAP/FHIR/fhir_lookup/DICOMweb +
# the OAuth2/SMART token endpoints). Built into a per-connection ``ProxyHandler`` threaded through EVERY
# opener path (the shared _NO_REDIRECT_OPENER is NEVER mutated), plus the pre-emptive tunnel-header Basic
# credential the reactive stdlib handlers cannot supply for an https destination. Off by default →
# byte-identical.

#: Sentinel ``proxy_url`` value meaning "Use the OS/environment default web proxy" (getproxies()), #112.
_PROXY_DEFAULT = "default"


def _normalize_no_proxy(value: Any) -> tuple[str, ...]:
    """The per-connection proxy-bypass list as a tuple of lowercased host patterns (#128). Accepts a
    list/tuple of names or a single comma-separated string; anything else (incl. ``None``) → empty."""
    if not value:
        return ()
    items: list[str]
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = [str(x) for x in value]
    else:
        return ()
    return tuple(p.strip().lower() for p in items if p and str(p).strip())


def _strip_proxy_host_port(host: str) -> str:
    """A bypass-comparable host: strip an optional ``[…]`` bracket and a trailing ``:port`` — but NEVER
    port-split an IPv6 literal. The callers pass ``urlsplit(url).hostname``, which is already UNBRACKETED
    and PORT-LESS (``https://[::1]:8443/`` → ``"::1"``), so an IPv6 host (>= 2 colons) must be left intact:
    ``"::1".split(":")`` would truncate it to ``""``. A bypass-LIST entry may be authored ``[::1]`` or
    ``::1``; both normalize to ``::1`` here. A non-IPv6 ``name:port`` / IPv4:port still strips its port."""
    bare = host.strip().strip("[]")
    return bare if bare.count(":") >= 2 else bare.split(":", 1)[0]


def _proxy_bypasses(host: str, bypass: tuple[str, ...]) -> bool:
    """NO_PROXY-style match of ``host`` against a per-connection bypass list (#128): exact host, a
    ``.suffix`` / ``*.suffix`` domain match, or ``*`` (bypass all). Optional port + trailing dot are
    stripped; an IPv6 literal (``::1``, ``2001:db8::1``) is matched intact (never port-truncated)."""
    if not host or not bypass:
        return False
    h = _strip_proxy_host_port(host).lower().rstrip(".")
    for raw in bypass:
        pat = _strip_proxy_host_port(raw).lower().rstrip(".")
        if not pat:
            continue
        if pat == "*":
            return True
        suffix = pat.lstrip("*").strip(".")
        if not suffix:
            continue
        if h == suffix or h.endswith("." + suffix):
            return True
    return False


@dataclass(frozen=True, slots=True)
class _ProxyDigestRecipe:
    """Inputs for a fresh reactive ``ProxyDigestAuthHandler`` (#127, http-destination only). Rebuilt per
    opener (a urllib handler binds to its opener, so it is never shared across openers)."""

    proxy_url: str
    user: str
    password: str

    def build(self) -> urllib.request.ProxyDigestAuthHandler:
        pwmgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        pwmgr.add_password(None, self.proxy_url, self.user, self.password)
        return urllib.request.ProxyDigestAuthHandler(pwmgr)


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    """A resolved per-connection forward proxy (ADR 0126). Carries the proxy address (or the "use default
    web proxy" flag), the NO_PROXY bypass list, the pre-emptive Basic ``Proxy-Authorization`` header (or
    none), and the reactive Digest recipe (or none). :meth:`for_host` resolves it against a specific
    target host (a destination / a token endpoint), returning ``None`` when that host is bypassed (#128)."""

    proxies: tuple[tuple[str, str], ...]  # (("http", url), ("https", url)); () when use_default
    use_default: bool  # True → ProxyHandler() reading getproxies() ("Use Default Web Proxy", #112)
    bypass: tuple[str, ...]
    auth_header: tuple[tuple[str, str], ...]  # (("Proxy-Authorization", "Basic .."),) or ()
    digest: _ProxyDigestRecipe | None
    redacted: str  # a PHI/secret-safe rendering of the proxy for logs (never the raw URL/creds)

    def _build_proxy_handler(self) -> urllib.request.ProxyHandler:
        if self.use_default:
            return urllib.request.ProxyHandler()  # reads getproxies() (+ system no_proxy) fresh
        return urllib.request.ProxyHandler(dict(self.proxies))

    def for_host(self, host: str) -> _HostProxy | None:
        """The proxy resolved for ``host``, or ``None`` if the host is bypassed (#128) — a bypassed host
        gets NO proxy handler and NO proxy credential (byte-identical to no proxy)."""
        if _proxy_bypasses(host, self.bypass):
            return None
        return _HostProxy(self)


@dataclass(frozen=True, slots=True)
class _HostProxy:
    """A :class:`ProxyConfig` resolved for one (non-bypassed) target host."""

    config: ProxyConfig

    def opener_handlers(self) -> tuple[urllib.request.BaseHandler, ...]:
        """Fresh handlers to thread into THIS host's opener (a ProxyHandler, + a reactive Digest handler
        when configured). Fresh each call — a urllib handler binds to its opener, so it is never shared."""
        handlers: list[urllib.request.BaseHandler] = [self.config._build_proxy_handler()]
        if self.config.digest is not None:
            handlers.append(self.config.digest.build())
        return tuple(handlers)

    def auth_headers(self) -> dict[str, str]:
        """The pre-emptive proxy-auth header(s) to add to each request (Basic; empty for Digest/none)."""
        return dict(self.config.auth_header)


def proxy_auth_handler_from_settings(
    s: Mapping[str, Any],
    *,
    proxy_url: str,
    proxy_scheme: str,
    dest_scheme: str,
    attested: bool,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
) -> tuple[tuple[tuple[str, str], ...], _ProxyDigestRecipe | None]:
    """The #127 proxy-credential-type dispatch: returns ``(pre-emptive auth header, reactive digest
    recipe)`` for an already-``env()``-resolved settings mapping ``s``. (Named per the phase doc; lives
    here beside the opener plumbing so ``smart.py``'s token opener can reuse it without a
    ``smart → http_auth`` import cycle; ``http_auth.py`` re-exports the name.)

    Basic (the default when a credential is set) → a pre-emptive ``Proxy-Authorization: Basic`` header,
    which works for BOTH http and https destinations (urllib moves it into the CONNECT tunnel for https).
    Digest → the reactive stdlib handler, **refused for an https destination** (the 407 is inside the
    CONNECT tunnel; digest-over-CONNECT is unsupported). NTLM/Windows → **refused** (deferred, ADR 0126).
    A cleartext ``http`` proxy hop carrying the credential is refused REGARDLESS of destination scheme via
    the ONE posture-keyed authority (:func:`refuse_cleartext_credential_hop`)."""
    user = s.get("proxy_user")
    password = s.get("proxy_password")
    auth_type = s.get("proxy_auth_type")
    if not user and not password:
        if auth_type:
            raise ValueError(
                "proxy_auth_type is set without proxy_user/proxy_password — configure the proxy "
                "credentials (via env()) or drop proxy_auth_type (ADR 0126)"
            )
        return (), None
    if not user or not password:
        raise ValueError(
            "a proxy credential needs BOTH proxy_user and proxy_password (put the password in env()) "
            "(ADR 0126)"
        )
    # A proxy credential over a cleartext http proxy hop crosses in the clear on the CONNECT/request —
    # refuse it REGARDLESS of destination scheme, posture-keyed (ADR 0092). Names only the proxy host.
    # ADR 0153: the proxy hop is a distinct crossing from the destination hop, but it belongs to the
    # SAME connection, so it is governed by that connection's one declaration. Threaded explicitly (like
    # `attested` beside it) rather than read off the settings mapping — one declaration, one source.
    refuse_cleartext_credential_hop(
        proxy_scheme,
        proxy_url,
        credential="web-proxy credential",
        attested=attested,
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
    )
    kind = str(auth_type or "basic").strip().lower()
    if kind == "basic":
        raw = f"{user}:{password}".encode()
        header = ("Proxy-Authorization", "Basic " + base64.b64encode(raw).decode("ascii"))
        return (header,), None
    if kind == "digest":
        if dest_scheme == "https":
            raise ValueError(
                "proxy_auth_type='digest' is not supported for an https destination — the proxy's 407 "
                "challenge arrives inside the CONNECT tunnel (digest-over-CONNECT is unsupported); use "
                "proxy_auth_type='basic' (pre-emptive) or a local authenticating proxy (ADR 0126)"
            )
        return (), _ProxyDigestRecipe(proxy_url, str(user), str(password))
    if kind in ("ntlm", "windows"):
        raise ValueError(
            f"proxy_auth_type={kind!r} is deferred (NTLM/Negotiate is connection-bound; urllib opens a "
            "new connection per request) — use 'basic'/'digest' or a local authenticating proxy such as "
            "cntlm (ADR 0126)"
        )
    raise ValueError(
        f"proxy_auth_type must be one of basic/digest/ntlm/windows, got {kind!r} (ADR 0126)"
    )


def proxy_config_from_settings(
    s: Mapping[str, Any],
    *,
    dest_scheme: str,
    attested: bool = False,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
) -> ProxyConfig | None:
    """Build the per-connection :class:`ProxyConfig` from an already-``env()``-resolved settings mapping,
    or ``None`` when no proxy is configured (byte-identical). Reads ``proxy_url`` (#112), ``proxy_no_proxy``
    (#128), and ``proxy_user``/``proxy_password``/``proxy_auth_type`` (#127). ``dest_scheme`` is the
    target's scheme (for the digest-over-https refusal); ``attested`` keys the cleartext-proxy-hop guard.

    ``proxy_url``: absent/empty → ``None``; ``"default"`` → the OS/environment default web proxy
    (``getproxies()``); an ``http(s)://`` URL → an explicit forward proxy used for both schemes."""
    raw = s.get("proxy_url")
    if not raw:
        return None
    bypass = _normalize_no_proxy(s.get("proxy_no_proxy"))
    proxy_url = str(raw).strip()
    if proxy_url.lower() == _PROXY_DEFAULT:
        # "Use Default Web Proxy" — explicit creds are meaningless here (the system proxy carries its own),
        # so reject the ambiguous combo rather than silently drop a configured credential.
        if s.get("proxy_user") or s.get("proxy_password") or s.get("proxy_auth_type"):
            raise ValueError(
                "proxy_url='default' (use the system default web proxy) cannot be combined with "
                "explicit proxy credentials — set an explicit proxy_url to authenticate (ADR 0126)"
            )
        return ProxyConfig(
            proxies=(),
            use_default=True,
            bypass=bypass,
            auth_header=(),
            digest=None,
            redacted="default web proxy",
        )
    proxy_scheme = urllib.parse.urlsplit(proxy_url).scheme.lower()
    if proxy_scheme not in ("http", "https"):
        raise ValueError(
            f"proxy_url must be 'default' or an http(s):// address, got scheme {proxy_scheme!r} "
            "(ADR 0126)"
        )
    auth_header, digest = proxy_auth_handler_from_settings(
        s,
        proxy_url=proxy_url,
        proxy_scheme=proxy_scheme,
        dest_scheme=dest_scheme,
        attested=attested,
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
    )
    return ProxyConfig(
        proxies=(("http", proxy_url), ("https", proxy_url)),
        use_default=False,
        bypass=bypass,
        auth_header=auth_header,
        digest=digest,
        redacted=_redact_url(proxy_url),
    )


# --- ECH egress route (ADR 0139, ASVS 12.1.5) ---------------------------------------------------------

_ECH_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _is_loopback_host(host: str) -> bool:
    h = host.strip().lower().strip("[]")
    return h in _ECH_LOOPBACK_HOSTS or h.startswith("127.")


def ech_sidecar_url_from_settings(s: Mapping[str, Any]) -> str | None:
    """The loopback ECH-sidecar base URL for this connection (ADR 0139), or ``None`` when ``ech_egress``
    is unset (byte-identical).

    ECH hides the outbound SNI, but stdlib ``ssl`` (OpenSSL 3.5.x) has no ECH — it is an OpenSSL 4.0
    feature (a local ``ctypes`` probe found zero ECH symbols in the bundled ``libssl``). So an
    ``ech_egress`` connection routes through a **loopback ECH sidecar** — the TLS-**terminating**
    re-originator at ``tools/ech-sidecar/`` (proven to hide the SNI against a real ECH endpoint). It is
    NOT a forward proxy: a proxy would tunnel ``https`` via CONNECT and the engine's own non-ECH
    ClientHello would still leak the SNI. Instead the REST destination sends its request to the sidecar
    over **cleartext loopback** with the real destination in the ``Host`` header (see
    :meth:`RestDestination._ech_request`), and the sidecar re-originates the ``https`` + ECH connection —
    verifying the upstream cert. So **destination TLS (verification + ECH) is delegated to the sidecar**;
    the engine→sidecar hop is same-host cleartext (ADR 0092 loopback posture).

    Config fails closed: ``ech_egress`` set with no ``ech_sidecar`` raises, and a **non-loopback** sidecar
    is refused (a remote "sidecar" would leak the SNI on the hop to it, defeating the purpose).

    Inert until a destination actually publishes an ECHConfig (as of 2026-07 a DoH probe found no EHR
    endpoint does — demand-gated, ADR 0139)."""
    if not s.get("ech_egress"):
        return None
    raw = s.get("ech_sidecar")
    sidecar = str(raw).strip() if raw else ""
    if not sidecar:
        raise ValueError(
            "ech_egress is set but ech_sidecar is empty — supply the loopback ECH sidecar URL, "
            "e.g. http://127.0.0.1:8123 (ADR 0139)"
        )
    parsed = urllib.parse.urlsplit(sidecar)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            f"ech_sidecar must be an http(s):// loopback URL, got {sidecar!r} (ADR 0139)"
        )
    if not _is_loopback_host(parsed.hostname):
        raise ValueError(
            "ech_sidecar must be a loopback address (the ECH sidecar runs beside the engine; a remote "
            "sidecar would leak the SNI on the hop to it, defeating the purpose) (ADR 0139)"
        )
    return sidecar.rstrip("/")


def egress_route_from_settings(
    s: Mapping[str, Any],
    *,
    dest_scheme: str,
    attested: bool = False,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
) -> ProxyConfig | None:
    """Resolve the per-connection forward/egress **proxy** (ADR 0126) from ``proxy_url``, or ``None``
    (byte-identical). **Fails closed on ``ech_egress``:** the ECH SNI-hiding send-path (ADR 0139) is
    implemented only on the REST destination in this build, so any *other* connector that reaches here
    with ``ech_egress`` set would silently NOT hide the SNI — refuse loudly rather than leak it. (The
    REST destination resolves ECH itself via :func:`ech_sidecar_url_from_settings` and never calls this
    for the ECH case.)"""
    if s.get("ech_egress"):
        raise ValueError(
            "ech_egress (ASVS 12.1.5 SNI hiding) is supported only on the REST destination in this "
            "build; on this connector it would NOT hide the SNI, so it is refused rather than silently "
            "leaking it (ADR 0139)"
        )
    return proxy_config_from_settings(
        s,
        dest_scheme=dest_scheme,
        attested=attested,
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
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
        # ADR 0153 decision 2: the OPPOSITE per-connection declaration — this hop is cleartext, is not
        # secure, and that is accepted (WARN + audit, never a silent ALLOW).
        accepted, accept_reason = config.cleartext_accepted, config.cleartext_reason
        # Captured at construction; re-asserted (zero I/O) at the byte-crossing in _post (decision 4).
        self._hop_guard: InsecureHopGuard | None = None
        # ADR 0139 (ASVS 12.1.5): opt-in ECH SNI-hiding. When set, this connection re-addresses each
        # request to a loopback terminating sidecar at send time (see _ech_request); destination TLS +
        # ECH are the sidecar's, so no forward proxy is used. Off (default) → None → byte-identical.
        self._ech_sidecar: str | None = ech_sidecar_url_from_settings(s)
        if self._ech_sidecar is not None and s.get("proxy_url"):
            raise ValueError(
                "ech_egress and proxy_url are mutually exclusive — the ECH sidecar IS this connection's "
                "egress path (ADR 0139)"
            )
        # BACKLOG #112/#127/#128 (ADR 0126): per-connection forward/egress proxy. None (default, or when
        # ECH is active) → no ProxyHandler and no Proxy-Authorization threaded below → byte-identical.
        self._proxy: ProxyConfig | None = (
            None
            if self._ech_sidecar is not None
            else egress_route_from_settings(
                s,
                dest_scheme=scheme,
                attested=attested,
                cleartext_accepted=accepted,
                cleartext_reason=accept_reason,
            )
        )
        dest_host = urllib.parse.urlsplit(self.url).hostname or ""
        proxy_dest = self._proxy.for_host(dest_host) if self._proxy is not None else None
        proxy_handlers = proxy_dest.opener_handlers() if proxy_dest is not None else ()
        self._headers = self._build_headers(s)
        if proxy_dest is not None:
            # Pre-emptive Proxy-Authorization (Basic; empty for Digest/none). urllib moves it into the
            # CONNECT tunnel for an https destination, sends it to the proxy for an http one (ADR 0126).
            self._headers.update(proxy_dest.auth_headers())
        enforce_outbound_length_limits(self.url, self._headers)
        refuse_cleartext_credentials(
            scheme,
            self._headers,
            self.url,
            attested=attested,
            cleartext_accepted=accepted,
            cleartext_reason=accept_reason,
        )
        # ASVS 12.2.1: even without an Authorization header the request body is PHI, so a cleartext
        # http egress to a non-loopback host is refused (loopback stays byte-identical). See rest.py.
        self._hop_guard = refuse_cleartext_egress(
            scheme,
            self.url,
            attested=attested,
            cleartext_accepted=accepted,
            cleartext_reason=accept_reason,
        )
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

        # ADR 0126: the token-endpoint call must ALSO traverse the proxy — thread the same ProxyConfig in.
        self._token_provider = bearer_provider_from_settings(s, proxy=self._proxy)
        if self._token_provider is not None:
            # The SMART bearer is injected per-request in _post, so the static-header cleartext check
            # above can't see it. Re-run the check treating the connection as credential-bearing, so a
            # SMART access token never ships over cleartext http (the detached-JWS signature, by
            # contrast, is public-verifiable and needs no such guard).
            refuse_cleartext_credentials(
                scheme,
                {**self._headers, "Authorization": "Bearer"},
                self.url,
                attested=attested,
                cleartext_accepted=accepted,
                cleartext_reason=accept_reason,
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
                    urllib.parse.urlsplit(self.url).hostname or "", *proxy_handlers
                )
            elif proxy_handlers:
                # A forward proxy is configured → a PER-CONNECTION verifying opener carrying it (never the
                # shared one; ADR 0126). No proxy → the shared opener stays (byte-identical).
                self._opener = _no_redirect_opener(*proxy_handlers)
            else:
                self._opener = _NO_REDIRECT_OPENER
        else:
            # verify_tls=false makes the https hop MITM-able — an insecure hop decided by the instance
            # posture (#200): production-PHI REFUSES (escape inert), a non-prod PHI hop refuses unless the
            # clamped escape / a per-hop attestation permits it. Loopback stays byte-identical.
            guard = refuse_verify_off(
                scheme,
                self.url,
                connector="REST destination",
                attested=attested,
                cleartext_accepted=accepted,
                cleartext_reason=accept_reason,
            )
            if guard is not None:
                self._hop_guard = guard
            logger.warning(
                "REST destination %s has TLS verification DISABLED (verify_tls=false)",
                _redact_url(self.url),
            )
            self._opener = _insecure_opener(*proxy_handlers)
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
        if self._ech_sidecar is not None:
            # ECH mode (ADR 0139): the engine->sidecar hop is cleartext http over loopback (the sidecar
            # owns destination TLS + ECH + cert verification), so a plain no-redirect opener carries it —
            # never the verify/proxy/insecure opener built above for a direct destination hop.
            self._opener = _no_redirect_opener()

    def _ech_request(
        self, data: bytes | None, headers: dict[str, str], method: str
    ) -> urllib.request.Request:
        """Re-address the request to the loopback ECH sidecar (ADR 0139): the request goes to the sidecar
        over cleartext http with the real destination in the ``Host`` header; the sidecar re-originates
        the ``https`` + ECH connection to that host (verifying its cert), so the SNI never leaves this
        host in cleartext. Destination TLS is delegated to the sidecar; the engine->sidecar hop is
        same-host loopback (ADR 0092 posture)."""
        assert self._ech_sidecar is not None  # only called on the ECH path (guarded by the caller)
        parsed = urllib.parse.urlsplit(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        h = dict(headers)
        h["Host"] = parsed.netloc  # tell the sidecar the real upstream (host[:port])
        return urllib.request.Request(  # noqa: S310  # nosec B310 — http to a validated loopback sidecar
            self._ech_sidecar + path, data=data, headers=h, method=method
        )

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
        req = (
            self._ech_request(None, dict(headers), "HEAD")
            if self._ech_sidecar is not None
            else urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s)
                self.url, headers=headers, method="HEAD"
            )
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
        data = encode_wire_body(payload, self.encoding, transport="REST")
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
        req = (
            self._ech_request(data, headers, self.method)
            if self._ech_sidecar is not None
            else urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s)
                self.url, data=data, headers=headers, method=self.method
            )
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
