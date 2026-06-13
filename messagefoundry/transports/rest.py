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
    DestinationConnector,
    NegativeAckError,
    register_destination,
)

__all__ = ["RestDestination", "refuse_cleartext_credentials"]

logger = logging.getLogger(__name__)

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
        self._headers = self._build_headers(s)
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

    async def send(self, payload: str) -> None:
        # urllib is blocking — keep it off the event loop (the delivery worker awaits this).
        await asyncio.to_thread(self._post, payload)

    def _post(self, payload: str) -> None:
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.url,
            data=payload.encode(self.encoding),
            headers=self._headers,
            method=self.method,
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                resp.read()  # drain the body so the connection closes cleanly; 2xx ⇒ delivered
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
