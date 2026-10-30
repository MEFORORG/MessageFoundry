# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Engine-brokered AI-assistance HTTP client (ADR 0135, BACKLOG #95).

The broker POSTs a **code_only** assist prompt to a CUSTOMER-MANAGED / self-hosted LLM endpoint and
returns the reply text. It is the transport half of the engine-brokered AI path: the API route
(``POST /ai/chat`` in :mod:`messagefoundry.api.app`) is the SOLE policy-enforcement point — it re-resolves
the effective policy server-side, gates on ``AI_ASSIST``, and audits every use; this module only performs
the vetted network call.

**Security posture (this is the crown-jewel AI-egress surface):**

* **SSRF fail-closed.** ``[egress].allowed_http`` is opt-in *permissive-when-empty*, so the broker CANNOT
  rely on it. Instead the configured ``endpoint`` is validated at construction against the dedicated
  ``[ai].allowed_endpoints`` list — an un-listed host (**or an EMPTY list**) is REFUSED. Combined with
  rest.py's hardened **no-redirect** opener, a crafted or redirected endpoint cannot exfiltrate the prompt
  to an unintended host.
* **No new dependency.** The POST reuses rest.py's TLS-verifying, no-redirect ``_NO_REDIRECT_OPENER`` +
  ``_redact_url`` (stdlib :mod:`urllib`) — exactly as smart.py does. A vendor SDK would be a separate
  DEP-1 vet, so it is intentionally avoided.
* **Off the event loop.** :meth:`AiBroker.chat` blocks (a provider POST); the API route awaits
  :meth:`AiBroker.chat_async`, which runs it via :func:`asyncio.to_thread`, so the engine loop never
  blocks.
* **Revocation (BACKLOG #2193 slice (e)).** The endpoint's certificate is verified, but stdlib ssl
  checks no CRL and no OCSP, and the shared opener carries no CRL. So an off-box endpoint is refused
  under an enforcing or unknown posture unless ``[ai].endpoint_revocation_attested`` is set with its
  reason: :func:`_refuse_an_unrevoked_ai_hop`.
* **Secrets / PHI.** The prompt, the reply, and the provider ``api_key`` are NEVER logged. A failure names
  only the redacted endpoint host + HTTP status — never the request or response body (either may echo
  content or the key).
* **One-way deps.** This module MUST NOT import ``api/`` (CLAUDE.md §4): the API depends on the engine,
  not the reverse.

MVP is code_only + non-streaming (ADR 0135). The Anthropic Messages wire shape is built
UNCONDITIONALLY -- nothing here dispatches on ``provider``, which is carried for addressing and for the
per-use audit only. ``claude`` is therefore the sole serviceable value, and ``[ai].provider`` is
validated at config load to refuse anything else (BACKLOG #95) rather than let it fail at request
time. The customer-managed endpoint is expected to speak that shape (a real Claude subscription, an
Azure/Bedrock-style gateway, or a self-hosted Anthropic-compatible server). If a second wire shape is
ever added here, widen ``_SERVICEABLE_AI_PROVIDERS`` in ``config/settings.py`` with it -- and only
then.
"""

from __future__ import annotations

import http.client
import json
import logging
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING

from messagefoundry.config.tls_policy import (
    HopDisposition,
    HopPosture,
    RevocationHopGuard,
    hop_url_host,
    is_loopback_hop_host,
    log_attested_crossing,
)
from messagefoundry.redaction import json_loads_or_refusal
from messagefoundry.transports.bounded_read import EgressReplyError, read_bounded_text

# Reuse rest.py's hardened, TLS-verifying, no-redirect opener + URL redaction (no new HTTP plumbing) —
# exactly as smart.py / fhir.py / soap.py do. No import cycle: rest.py never imports this module.
from messagefoundry.transports.rest import (
    _NO_REDIRECT_OPENER,
    _redact_url,
    find_outbound_length_violation,
    opener_tls_context,
    refuse_url_credentials,
    url_host_label,
    url_scheme,
)

if TYPE_CHECKING:  # only for the from-settings factory annotation
    from messagefoundry.config.settings import AiSettings

__all__ = [
    "AiBroker",
    "AiBrokerError",
    "ai_broker_from_settings",
    "endpoint_host_allowed",
]

logger = logging.getLogger(__name__)

# Anthropic Messages API wire constants (the MVP provider shape). The customer-managed endpoint speaks
# this; the version header is the stable public value.
_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MAX_OUTPUT_TOKENS = 4096
_DEFAULT_TIMEOUT = 60.0


#: The cell the AI hop's revocation refusal and its log lines name. PHI-free and fixed.
_AI_HOP_CELL = "[ai] engine AI broker (verified TLS, no revocation check)"

#: The one way across that refusal under an enforcing posture, besides an endpoint on this machine.
#: No CRL lever is built for this hop (owner ruling 2026-10-27, on the ADR 0173 section 12
#: pattern), so the text offers neither ``[tls].crl_file`` nor a connection's attestation: neither
#: reaches it, and naming either would be a remedy the operator cannot perform.
_AI_REVOCATION_LEVER = (
    "No CRL can reach this hop. Set [ai].endpoint_revocation_attested = true with an "
    "[ai].endpoint_revocation_attested_reason that says what covers revocation of the AI "
    "endpoint's certificate, or use an endpoint on this machine."
)

#: Each crossing line already logged, keyed by its kind and the endpoint host, so each is written
#: once per process for each hop, as the Vault hop's are. The broker is built for every request, so
#: without this an attested or warned hop would log a WARNING on every assist call.
_LOGGED_CROSSINGS: set[tuple[str, str]] = set()
_LOGGED_CROSSINGS_LOCK = threading.Lock()


def _first_crossing(kind: str, host: str) -> bool:
    """``True`` the first time ``(kind, host)`` is seen in this process, and ``False`` after."""
    with _LOGGED_CROSSINGS_LOCK:
        if (kind, host) in _LOGGED_CROSSINGS:
            return False
        _LOGGED_CROSSINGS.add((kind, host))
        return True


class AiBrokerError(ValueError):
    """The engine broker is mis-configured (at least: missing endpoint/key, an endpoint outside the SSRF
    allowlist, a cleartext-http endpoint, which always carries the key, or an off-box endpoint the
    revocation guard refuses) or the provider call failed. Raised with a PHI-/secret-safe
    message (redacted host + status only) so it can surface as a clean API error without leaking the
    prompt, the response, or the key."""


def endpoint_host_allowed(url: str, allowed: list[str]) -> bool:
    """True if ``url``'s host (and port, when an allow entry pins one) is on ``allowed`` — the same
    ``host`` / ``host:port`` matching the egress gate uses, but applied FAIL-CLOSED by the caller (an
    empty ``allowed`` matches nothing). Kept local so ``transports/`` never imports ``pipeline/``."""
    if not allowed:
        return False
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        return False
    for entry in allowed:
        allow_host, _, allow_port = entry.partition(":")
        if allow_host.strip().lower() == host and (
            not allow_port or str(parts.port) == allow_port.strip()
        ):
            return True
    return False


def _refuse_an_unrevoked_ai_hop(
    endpoint: str,
    *,
    opener: urllib.request.OpenerDirector,
    posture: HopPosture | None,
    revocation_attested: bool,
    revocation_reason: str | None,
) -> None:
    """Refuse a verifying AI endpoint hop that checks no revocation and carries no attestation
    (BACKLOG #2193 slice (e), owner ruling 2026-10-27, on the ADR 0173 section 12 pattern).

    Every call sends ``[ai].api_key`` and the code sent for assistance over https that verifies
    the endpoint's certificate. Stdlib ssl checks no CRL and no OCSP, so a revoked but unexpired
    certificate would be accepted with no refusal and no record.

    The decision is ``tls_policy.revocation_hop_disposition``, the authority every revocation
    guard uses, asked through ``RevocationHopGuard.capture(...).disposition()``, with these inputs:

    * **On the box** is :func:`~messagefoundry.config.tls_policy.is_loopback_hop_host` on the
      endpoint's host. Every opener dials a loopback host direct, whatever proxy it has (vault
      BACKLOG #2579), so a proxy does not move a loopback endpoint off the box.
    * ``revocation_attested`` goes in the per-hop ``attested`` slot. It is
      ``[ai].endpoint_revocation_attested``, which load refuses without a reason. Only the value
      ``True`` counts, so a truthy string cannot cross.
    * ``tls_revocation_attested()``, the process-wide variable, goes in ``blanket_attested``
      only. The authority ranks it below the enforcing refusal (BACKLOG #299), so it does not
      cross this hop under an enforcing or unknown posture.
    * ``crl_checked`` is read off ``opener``'s https context, the opener the broker will dial
      through, never off a setting. Today that is rest.py's shared import-time opener, which
      loads no CRL, so it is ``False``, and no CRL lever is built for this hop.
    * An attestation with no reason, or a blank one, is refused here as at settings load, so a
      broker built directly cannot cross with no recorded reason.
    * ``posture`` is the instance posture the caller holds, or ``None``. **An unknown posture
      counts as enforcing**, as on the Vault hops: the broker is built per request, outside the
      construction gate, so there is no ambient posture to read.

    **The three answers.** REFUSE raises :class:`AiBrokerError`, which the route answers 503.
    WARN crosses and logs a WARNING that names the pair; that is an off-box, unattested hop on an
    instance whose ``[security].enforcement`` is ``warn``. ALLOW crosses; a hop that crossed an
    enforcing or unknown posture on its attestation logs a WARNING through
    ``tls_policy.log_attested_crossing``, with the reason. A hop on the box logs nothing, and
    neither does a hop the process-wide variable crossed on a warn instance. Each line is written
    once per process for each host. Any other answer refuses, so a new one fails closed.

    It acts on the answer itself rather than through ``RevocationHopGuard.enforce_construction``,
    for three reasons: that method's attested-crossing line names a connection's
    ``tls_revocation_attested`` as the declaration, where this hop's lever is the ``[ai]`` pair; it
    logs on every build, and the broker is built per request; and it raises
    ``InsecureHopRefused``, which the route does not map, so a refusal would surface as an
    unhandled 500. :class:`AiBrokerError` is answered 503."""
    try:
        host = hop_url_host(endpoint, cell="[ai].endpoint")
    except ValueError as exc:
        # hop_url_host's text names no part of the URL; this module's single error type carries it.
        raise AiBrokerError(str(exc)) from None
    attested = revocation_attested is True
    if attested and not (revocation_reason and revocation_reason.strip()):
        raise AiBrokerError(
            "[ai].endpoint_revocation_attested=true requires an "
            "[ai].endpoint_revocation_attested_reason that says what covers revocation of the AI "
            "endpoint's certificate"
        )
    held = HopPosture.fail_closed(enforcing=None) if posture is None else posture
    on_box = is_loopback_hop_host(host)
    # capture() reads the process-wide variable into its own field and the CRL flag off the
    # context; disposition() asks revocation_hop_disposition, logging and raising nothing. It is
    # never None here, since a posture is held. The texts below are this hop's own.
    disposition = RevocationHopGuard.capture(
        host=host,
        cell=_AI_HOP_CELL,
        description="sends [ai].api_key over verified https",
        attested=attested,
        context=opener_tls_context(opener, connector="AI endpoint"),
        posture=held,
        connection=None,  # the [ai] endpoint, not a connection
    ).disposition()
    enforcing = held.enforcing
    detail = (
        f"the AI endpoint {host!r} is sent [ai].api_key over https that verifies its "
        "certificate, but NO certificate revocation checking (OCSP/CRL) is performed"
    )
    if disposition is HopDisposition.ALLOW:
        if attested and enforcing and not on_box and _first_crossing("attested", host):
            log_attested_crossing(
                logger,
                crossing="verified TLS hop crossed without certificate revocation checking",
                connection=None,
                detail=f"{_AI_HOP_CELL}: {detail}",
                reason=revocation_reason,
                declaration="[ai].endpoint_revocation_attested",
            )
        return
    if disposition is HopDisposition.WARN:
        if _first_crossing("warn", host):
            logger.warning(
                "insecure transport hop permitted -- %s: %s; under [security].enforcement = "
                "enforce this hop is refused unless [ai].endpoint_revocation_attested is true "
                "with its reason",
                _AI_HOP_CELL,
                detail,
            )
        return
    raise AiBrokerError(f"{_AI_HOP_CELL}: {detail}. {_AI_REVOCATION_LEVER}")


class AiBroker:
    """Broker one code_only assist prompt to a customer-managed / self-hosted LLM (ADR 0135).

    Built from the loaded ``[ai]`` settings (:func:`ai_broker_from_settings`), once for each
    ``POST /ai/chat`` request. Construction validates at least the endpoint scheme, the
    credential, that the endpoint host is on ``allowed_endpoints`` (the SSRF gate, fail-closed),
    and, last, the revocation guard (:func:`_refuse_an_unrevoked_ai_hop`). :meth:`chat` performs
    the blocking POST; the API route awaits :meth:`chat_async`."""

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        allowed_endpoints: list[str],
        provider: str = "claude",
        model: str = "claude-opus-4-8",
        max_output_tokens: int = _DEFAULT_MAX_OUTPUT_TOKENS,
        timeout_seconds: float = _DEFAULT_TIMEOUT,
        posture: HopPosture | None = None,
        revocation_attested: bool = False,
        revocation_attested_reason: str | None = None,
    ) -> None:
        if not endpoint:
            raise AiBrokerError(
                "engine-brokered AI requires an '[ai].endpoint' (the customer-managed LLM's URL)"
            )
        # Read through url_scheme, never a bare urlsplit: a URL it cannot parse raises urlsplit's own
        # ValueError, which quotes the netloc. The full credential screen stays after the http
        # refusal below, so that order is unchanged (BACKLOG #2686).
        scheme = url_scheme(endpoint, "[ai].endpoint", use="[ai].api_key", error=AiBrokerError)
        # The api_key is a credential, and every call sends it (an empty key is refused below), so a
        # cleartext http endpoint is refused with no escape and in every posture: vault BACKLOG #3533
        # item 5, which applies docs/SECURITY-LOOSENING.md, *No escape sends a credential to an
        # unverified peer*. The insecure-TLS escape released it at warn until then. Refused first,
        # so an http endpoint is never sent to fix an allowlist entry it cannot use.
        if scheme == "http":
            raise AiBrokerError(
                "[ai].endpoint over cleartext http would send the api_key in clear; refused, with "
                "no escape. Use an https endpoint."
            )
        if scheme != "https":
            raise AiBrokerError(f"[ai].endpoint must be https, got scheme {scheme!r}")
        refuse_url_credentials(endpoint, "[ai].endpoint", use="[ai].api_key", error=AiBrokerError)
        if not api_key:
            raise AiBrokerError(
                "engine-brokered AI requires an '[ai].api_key' (the LLM credential, via MEFOR_AI_API_KEY)"
            )
        # SSRF fail-closed (ADR 0135): the endpoint host MUST be explicitly allow-listed. This is stricter
        # than — and independent of — the permissive-when-empty [egress].allowed_http, so the engine can
        # never be pointed at an un-allowlisted LLM host. An EMPTY allowlist permits NOTHING.
        if not endpoint_host_allowed(endpoint, allowed_endpoints):
            host = url_host_label(endpoint)
            raise AiBrokerError(
                f"[ai].endpoint host {host!r} is not in the [ai].allowed_endpoints allowlist; "
                "list it explicitly to permit engine-brokered AI egress (SSRF fail-closed)"
            )
        # ASVS 4.2.5. Both values are operator-supplied via env() and both ship on every provider call
        # -- the endpoint as the request line, the key as the ``x-api-key`` header. Bounded here rather
        # than per call because neither varies per prompt. Raised as AiBrokerError (a ValueError
        # subclass) so the API surface keeps its single error type, and the key is NEVER echoed.
        violation = find_outbound_length_violation(endpoint, {"x-api-key": api_key})
        if violation is not None:
            raise AiBrokerError(
                f"[ai] {violation.kind} is {violation.length} chars, over the "
                f"{violation.limit}-char limit; check [ai].endpoint / the api_key env() value"
            )
        # The opener is chosen before the guard and handed to it, so the guard judges the context
        # this broker really dials with, whichever opener that later becomes.
        opener: urllib.request.OpenerDirector = _NO_REDIRECT_OPENER
        # Last, so an endpoint refused for any reason above never logs a revocation crossing, and
        # the operator is never sent to attest a hop that is refused anyway (BACKLOG #2193 (e)).
        _refuse_an_unrevoked_ai_hop(
            endpoint,
            opener=opener,
            posture=posture,
            revocation_attested=revocation_attested,
            revocation_reason=revocation_attested_reason,
        )
        self.endpoint = endpoint
        self.api_key = api_key
        self.provider = provider or "claude"
        self.model = model or "claude-opus-4-8"
        self.max_output_tokens = max(1, int(max_output_tokens))
        self.timeout_seconds = timeout_seconds
        self._opener: urllib.request.OpenerDirector = opener

    @property
    def endpoint_host(self) -> str:
        """The endpoint host (no scheme/path/query) — PHI-safe metadata for the audit ``detail``."""
        return urllib.parse.urlsplit(self.endpoint).hostname or ""

    def chat(self, prompt: str) -> str:
        """POST the code_only ``prompt`` to the endpoint and return the reply text. BLOCKING (a provider
        POST over urllib); the API route calls :meth:`chat_async`. Raises :class:`AiBrokerError` (PHI-/
        secret-safe: redacted host + status only) on any failure."""
        data = json.dumps(
            {
                "model": self.model,
                "max_tokens": self.max_output_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
        ).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to https in __init__
            self.endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": _ANTHROPIC_VERSION,
            },
            method="POST",
        )
        try:
            with self._opener.open(req, timeout=self.timeout_seconds) as resp:
                # ASVS 15.2.2: bounded on the socket read. The AI endpoint is operator-configured but
                # off-premises, so its reply is the least-trusted body the engine buffers on egress.
                body = read_bounded_text(
                    resp,
                    connector="AI endpoint",
                    encoding="utf-8",
                )
        except EgressReplyError as exc:
            # Mapped onto this module's single error type: the API route handles AiBrokerError, and a
            # DeliveryError escaping here would be unmapped. The message already names only the
            # fixed label "AI endpoint" and the refusal, never the URL (BACKLOG #2060).
            #
            # Caught as the FAMILY, not as ResponseTooLargeError: a refusal added beside it later
            # shares this reason exactly, and catching the member is how #1575's first cut let
            # TruncatedResponseError escape this arm as an unhandled 500.
            raise AiBrokerError(str(exc)) from exc
        except urllib.error.HTTPError as exc:
            # Never echo exc.read() — the error body may carry provider detail; redacted host + status only.
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} returned HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} unreachable: {exc.reason}"
            ) from exc
        except (ValueError, http.client.InvalidURL) as exc:
            # BACKLOG #2113, closing the arm #1793 left open here: urllib refused a request value. Its
            # text can quote that value, and the x-api-key header is one, so it is never echoed.
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} rejected an invalid request value"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise AiBrokerError(f"AI endpoint {_redact_url(self.endpoint)} failed: {exc}") from exc
        except http.client.HTTPException as exc:
            # BACKLOG #2113: a malformed status or header line (BadStatusLine, LineTooLong) is
            # neither an OSError nor a URLError, so it escaped the route's AiBrokerError mapping as
            # an unhandled 500. Named by class only: its text can echo the provider's bytes. Last,
            # so InvalidURL and RemoteDisconnected keep the arms above.
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} sent a malformed HTTP reply "
                f"({type(exc).__name__})"
            ) from exc
        return self._extract_text(body)

    async def chat_async(self, prompt: str) -> str:
        """Awaitable wrapper: run the blocking :meth:`chat` OFF the event loop (CLAUDE.md §6) so the
        engine's asyncio loop never blocks on the provider round-trip."""
        import asyncio

        return await asyncio.to_thread(self.chat, prompt)

    def _extract_text(self, body: str) -> str:
        """Pull the reply text from an Anthropic Messages response. Defensive: a refusal or an
        unparseable/empty body raises :class:`AiBrokerError` (never echoing ``body`` — it may carry
        content). Concatenates every ``text`` content block."""
        # Raised with no chain, so the decode error holding the whole reply stays off it (#2085).
        payload, refused = json_loads_or_refusal(body)
        if refused is not None:
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} returned an unparseable response"
            )
        if isinstance(payload, dict) and payload.get("stop_reason") == "refusal":
            raise AiBrokerError("the AI provider declined the request (refusal)")
        blocks = payload.get("content") if isinstance(payload, dict) else None
        if not isinstance(blocks, list):
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} returned an unexpected response shape"
            )
        text = "".join(
            str(b.get("text", ""))
            for b in blocks
            if isinstance(b, dict) and b.get("type") == "text"
        )
        if not text:
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} returned an empty completion"
            )
        return text


def ai_broker_from_settings(ai: AiSettings, *, posture: HopPosture | None = None) -> AiBroker:
    """Build the :class:`AiBroker` from the loaded ``[ai]`` settings, or raise :class:`AiBrokerError`
    when the engine broker is not fully configured. Settings arrive already ``env()``-resolved (the API
    lifespan stashes the resolved :class:`AiSettings` on ``app.state.ai``).

    ``posture`` keys the revocation refusal (BACKLOG #2193 slice (e)), and ``None`` counts as
    enforcing there: :func:`_refuse_an_unrevoked_ai_hop` says why. It no longer reaches the
    cleartext-http refusal, which takes no escape in any posture since vault BACKLOG #3533 item 5."""
    return AiBroker(
        endpoint=ai.endpoint or "",
        api_key=ai.api_key or "",
        allowed_endpoints=list(ai.allowed_endpoints),
        provider=ai.provider,
        model=ai.model,
        posture=posture,
        revocation_attested=ai.endpoint_revocation_attested,
        revocation_attested_reason=ai.endpoint_revocation_attested_reason,
    )
