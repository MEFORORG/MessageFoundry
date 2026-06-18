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
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    NegativeAckError,
    register_destination,
)

__all__ = [
    "RestDestination",
    "enforce_outbound_length_limits",
    "refuse_cleartext_credentials",
]

logger = logging.getLogger(__name__)

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


def _redact_url(url: str) -> str:
    """``scheme://host[:port]/path`` only — drops query/userinfo so a token or PHI in the query
    string never reaches a log line."""
    p = urllib.parse.urlsplit(url)
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname or ''}{port}{p.path}"


def refuse_cleartext_credentials(scheme: str, headers: dict[str, str], url: str) -> None:
    """Refuse to send credentials over a cleartext (``http``) channel.

    Basic/bearer auth in an ``Authorization`` header over plain ``http`` puts the credential on the
    wire (and the body is PHI). Mirrors the ``verify_tls=false`` posture: refused unless the explicit
    dev/trusted-network escape ``MEFOR_ALLOW_INSECURE_TLS`` is set, and logged loudly when allowed.
    Shared by the REST and SOAP destinations (SOAP reuses REST's HTTP plumbing)."""
    if scheme != "http" or "Authorization" not in headers:
        return
    if not insecure_tls_allowed():
        raise ValueError(
            "destination sends credentials (Authorization header) over cleartext http; refused "
            f"unless {INSECURE_TLS_ESCAPE_ENV} is set — use https"
        )
    logger.warning(
        "destination %s sends credentials over CLEARTEXT http (no TLS)", _redact_url(url)
    )


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
        self._headers = self._build_headers(s)
        enforce_outbound_length_limits(self.url, self._headers)
        refuse_cleartext_credentials(scheme, self._headers, self.url)
        if bool(s.get("verify_tls", True)):
            self._opener = _NO_REDIRECT_OPENER
        else:
            # Mirror the LDAPS / SQL Server posture: disabling verification is refused unless the
            # operator set the explicit dev escape, and is logged loudly when used.
            if scheme == "https" and not insecure_tls_allowed():
                raise ValueError(
                    "REST destination verify_tls=false disables TLS certificate verification; "
                    f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set (dev/trusted-network only)"
                )
            logger.warning(
                "REST destination %s has TLS verification DISABLED (verify_tls=false)",
                _redact_url(self.url),
            )
            self._opener = _insecure_opener()

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

    async def send(self, payload: str) -> DeliveryResponse | None:
        # urllib is blocking — keep it off the event loop (the delivery worker awaits this).
        body, status = await asyncio.to_thread(self._post, payload)
        if not self.capture_response:
            return None
        if body == "":
            # A successful round-trip with no payload — captured as a deliberate empty reply, NOT an
            # error (the request succeeded). Distinct from a read failure, which raised above.
            return DeliveryResponse(body="", outcome="no_reply", detail=f"HTTP {status}")
        return DeliveryResponse(body=body, outcome="accepted", detail=f"HTTP {status}")

    async def test_connection(self) -> None:
        await asyncio.to_thread(self._probe)

    def _probe(self) -> None:
        # Reachability only: a HEAD reaches the endpoint without POSTing a body. An HTTP response means
        # the host answered, so a 405 (HEAD not allowed on a POST endpoint) is still a pass — but a 401/
        # 403 means the configured credentials would be rejected, which a real delivery dead-letters, so
        # surface it as a failure. Connection/DNS/TLS/timeout is always a fail.
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.url, headers=self._headers, method="HEAD"
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

    def _post(self, payload: str) -> tuple[str, int]:
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.url,
            data=payload.encode(self.encoding),
            headers=self._headers,
            method=self.method,
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                # Read the body (drains the connection for clean close; returned for capture). 2xx ⇒
                # delivered. Decoding a drained body is cheap, so this stays byte-identical when capture
                # is off (the worker just ignores the return).
                body = resp.read().decode(self.encoding, errors="replace")
                status = int(getattr(resp, "status", 200))
                return body, status
        except urllib.error.HTTPError as exc:
            status = exc.code
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
