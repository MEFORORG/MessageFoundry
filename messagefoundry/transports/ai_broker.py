# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING

from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, weakened_tls_escape_permitted
from messagefoundry.config.tls_policy import HopPosture

# Reuse rest.py's hardened, TLS-verifying, no-redirect opener + URL redaction (no new HTTP plumbing) —
# exactly as smart.py / fhir.py / soap.py do. No import cycle: rest.py never imports this module.
from messagefoundry.transports.rest import (
    _NO_REDIRECT_OPENER,
    _redact_url,
    find_outbound_length_violation,
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


class AiBrokerError(ValueError):
    """The engine broker is mis-configured (missing endpoint/key, an endpoint outside the SSRF allowlist,
    a cleartext-http endpoint carrying the key) or the provider call failed. Raised with a PHI-/secret-safe
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


class AiBroker:
    """Broker one code_only assist prompt to a customer-managed / self-hosted LLM (ADR 0135).

    Built once from the loaded ``[ai]`` settings (:func:`ai_broker_from_settings`). Construction validates
    the endpoint scheme, the credential, and — the SSRF gate — that the endpoint host is on
    ``allowed_endpoints`` (fail-closed). :meth:`chat` performs the blocking POST; the API route awaits
    :meth:`chat_async`."""

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
    ) -> None:
        if not endpoint:
            raise AiBrokerError(
                "engine-brokered AI requires an '[ai].endpoint' (the customer-managed LLM URL)"
            )
        scheme = urllib.parse.urlsplit(endpoint).scheme.lower()
        if scheme not in ("http", "https"):
            raise AiBrokerError(f"[ai].endpoint must be http or https, got scheme {scheme!r}")
        if not api_key:
            raise AiBrokerError(
                "engine-brokered AI requires an '[ai].api_key' (the LLM credential, via MEFOR_AI_API_KEY)"
            )
        # SSRF fail-closed (ADR 0135): the endpoint host MUST be explicitly allow-listed. This is stricter
        # than — and independent of — the permissive-when-empty [egress].allowed_http, so the engine can
        # never be pointed at an un-allowlisted LLM host. An EMPTY allowlist permits NOTHING.
        if not endpoint_host_allowed(endpoint, allowed_endpoints):
            host = urllib.parse.urlsplit(endpoint).hostname or ""
            raise AiBrokerError(
                f"[ai].endpoint host {host!r} is not in the [ai].allowed_endpoints allowlist; "
                "list it explicitly to permit engine-brokered AI egress (SSRF fail-closed)"
            )
        # The api_key is a credential — refuse to send it over cleartext http (mirrors smart.py's token
        # endpoint), unless the dev escape is set for a trusted-network dev/test box. #329: read the
        # escape through the ADR-0092 clamp (weakened_tls_escape_permitted) so on an enforcing-PHI
        # instance the blunt env var can never re-permit the key on the wire. The broker is built out of
        # the connector-construction gate (the create_app ai_chat route), so the posture is threaded
        # explicitly; None (a direct/test construction) falls back to the unclamped escape — byte-
        # identical to the pre-#329 bare read.
        if scheme == "http" and not weakened_tls_escape_permitted(posture):
            raise AiBrokerError(
                "[ai].endpoint over cleartext http would expose the api_key; refused unless "
                f"{INSECURE_TLS_ESCAPE_ENV} is set (dev/trusted-network only) — use https"
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
        self.endpoint = endpoint
        self.api_key = api_key
        self.provider = provider or "claude"
        self.model = model or "claude-opus-4-8"
        self.max_output_tokens = max(1, int(max_output_tokens))
        self.timeout_seconds = timeout_seconds
        self._opener: urllib.request.OpenerDirector = _NO_REDIRECT_OPENER

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
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
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
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            # Never echo exc.read() — the error body may carry provider detail; redacted host + status only.
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} returned HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} unreachable: {exc.reason}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise AiBrokerError(f"AI endpoint {_redact_url(self.endpoint)} failed: {exc}") from exc
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
        try:
            payload = json.loads(body)
        except (ValueError, TypeError) as exc:
            raise AiBrokerError(
                f"AI endpoint {_redact_url(self.endpoint)} returned an unparseable response"
            ) from exc
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

    ``posture`` (#329) is the derived instance hop posture, threaded from the create_app ai_chat route so
    the broker's cleartext-http credential refusal is clamped on an enforcing-PHI instance (the escape
    can no longer put the ``api_key`` on the wire there). ``None`` = the unclamped escape, byte-identical
    to before."""
    return AiBroker(
        endpoint=ai.endpoint or "",
        api_key=ai.api_key or "",
        allowed_endpoints=list(ai.allowed_endpoints),
        provider=ai.provider,
        model=ai.model,
        posture=posture,
    )
