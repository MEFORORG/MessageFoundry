"""SOAP transport: a destination that POSTs a SOAP envelope to a web service.

The **destination** is a thin SOAP layer over the same stdlib HTTP client the REST connector uses
(ADR 0003) — it reuses REST's no-redirect, http(s)-only opener (so a 3xx can't divert a PHI-bearing
request; ASVS 15.3.2) and the fail-closed ``[egress].allowed_http`` host gate. The Handler produces the
**full SOAP envelope** (XML); this adds the SOAP ``Content-Type`` + action and POSTs it.

**SOAP version.** ``1.1`` → ``Content-Type: text/xml; charset=utf-8`` + a ``SOAPAction`` header;
``1.2`` → ``Content-Type: application/soap+xml; charset=utf-8; action="…"`` (no ``SOAPAction`` header).

**Fault mapping.** A response is inspected for a SOAP ``Fault`` (faults can arrive as HTTP 500 *or* an
HTTP 200 body). A **Sender/Client** fault → :class:`NegativeAckError` (``permanent=True``) → dead-letter
(the request is rejected; a retry won't help). A **Receiver/Server** fault → :class:`DeliveryError`
(retry). An unrecognized fault is treated as permanent (so a rejected request can't loop the lane).
With no fault, the HTTP status decides: 2xx delivered, 5xx retry, other 4xx / refused 3xx dead-letter;
a connection/timeout error retries. Fault bodies are **not** echoed into errors/logs (they may carry
PHI) — only the SOAP fault role + HTTP status are.

**Idempotency.** Delivery is at-least-once, so a retry **re-sends**. The service operation **must be
idempotent**. See docs/CONNECTIONS.md.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
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

# Reuse REST's hardened HTTP plumbing — same transports/ package, same no-redirect + TLS posture.
from messagefoundry.transports.rest import (
    _NO_REDIRECT_OPENER,
    _insecure_opener,
    _redact_url,
    refuse_cleartext_credentials,
)

__all__ = ["SoapDestination"]

logger = logging.getLogger(__name__)

_FAULT_RE = re.compile(r"<(?:\w+:)?Fault[\s>]", re.IGNORECASE)
_SENDER_RE = re.compile(r"client|sender", re.IGNORECASE)
_RECEIVER_RE = re.compile(r"server|receiver", re.IGNORECASE)
# SOAP 1.1 <faultcode>…</faultcode>; SOAP 1.2 <Code><Value>…</Value></Code>.
_FAULTCODE_RE = re.compile(r"<(?:\w+:)?faultcode\b[^>]*>(.*?)</", re.IGNORECASE | re.DOTALL)
_CODEVALUE_RE = re.compile(r"<(?:\w+:)?Value\b[^>]*>(.*?)</", re.IGNORECASE | re.DOTALL)


def _fault_code(body: str) -> str:
    """The fault code text (e.g. ``soap:Client`` / ``soap:Receiver``), SOAP 1.1 or 1.2, or ``""``."""
    m = _FAULTCODE_RE.search(body) or _CODEVALUE_RE.search(body)
    return m.group(1) if m else ""


def _classify_soap(status: int, body: str) -> DeliveryError | None:
    """``None`` if delivered, else the classified failure. A SOAP fault is classified by its code
    (Sender/Client → permanent; Receiver/Server → transient; unrecognized → permanent so a rejected
    request can't loop the lane); a fault-less response falls back to the HTTP status."""
    if _FAULT_RE.search(body):
        code = _fault_code(body)
        if _SENDER_RE.search(code):
            return NegativeAckError(
                f"SOAP Sender fault (HTTP {status})", code="soap-sender", permanent=True
            )
        if _RECEIVER_RE.search(code):
            return DeliveryError(f"SOAP Receiver fault (HTTP {status})")
        return NegativeAckError(f"SOAP fault (HTTP {status})", code="soap-fault", permanent=True)
    if 200 <= status < 300:
        return None
    if 500 <= status < 600:
        return DeliveryError(f"SOAP endpoint returned HTTP {status}")
    return NegativeAckError(
        f"SOAP endpoint rejected with HTTP {status}", code=str(status), permanent=True
    )


class SoapDestination(DestinationConnector):
    """POST each SOAP envelope (the Handler's body) to a web-service endpoint."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        url = s.get("url")
        if not isinstance(url, str) or not url:
            raise ValueError("SOAP destination requires a 'url' setting")
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"SOAP destination 'url' must be http or https, got scheme {scheme!r}")
        self.url = url
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.encoding: str = s.get("encoding", "utf-8")
        self.version: str = str(s.get("soap_version", "1.1"))
        if self.version not in ("1.1", "1.2"):
            raise ValueError(
                f"SOAP destination soap_version must be 1.1 or 1.2, got {self.version!r}"
            )
        self._headers = self._build_headers(s)
        refuse_cleartext_credentials(scheme, self._headers, self.url)
        if bool(s.get("verify_tls", True)):
            self._opener = _NO_REDIRECT_OPENER
        else:
            if scheme == "https" and not insecure_tls_allowed():
                raise ValueError(
                    "SOAP destination verify_tls=false disables TLS certificate verification; "
                    f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set (dev/trusted-network only)"
                )
            logger.warning(
                "SOAP destination %s has TLS verification DISABLED (verify_tls=false)",
                _redact_url(self.url),
            )
            self._opener = _insecure_opener()

    def _build_headers(self, s: dict[str, Any]) -> dict[str, str]:
        """SOAP Content-Type (+ SOAPAction for 1.1) + static ``headers`` + optional bearer/basic auth."""
        action = str(s.get("soap_action") or "")
        headers: dict[str, str] = {}
        if self.version == "1.2":
            ctype = "application/soap+xml; charset=utf-8"
            if action:
                ctype += f'; action="{action}"'
            headers["Content-Type"] = ctype
        else:
            headers["Content-Type"] = "text/xml; charset=utf-8"
            headers["SOAPAction"] = f'"{action}"'  # quoted; an empty "" is the no-action convention
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
        await asyncio.to_thread(self._post, payload)

    def _post(self, payload: str) -> None:
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.url,
            data=payload.encode(self.encoding),
            headers=self._headers,
            method="POST",
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode(self.encoding, errors="replace")
                status = int(getattr(resp, "status", 200))
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode(self.encoding, errors="replace")
            except Exception:  # noqa: BLE001 - a body we can't read just becomes status-only
                body = ""
            # A non-2xx status: _classify_soap always returns a failure here (it returns None only on 2xx).
            raise (
                _classify_soap(exc.code, body) or DeliveryError(f"SOAP HTTP {exc.code}")
            ) from exc
        except urllib.error.URLError as exc:
            raise DeliveryError(f"SOAP {_redact_url(self.url)} unreachable: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"SOAP {_redact_url(self.url)} failed: {exc}") from exc
        # 2xx — but a fault can still arrive in a 200 body, so classify before declaring success.
        failure = _classify_soap(status, body)
        if failure is not None:
            raise failure


register_destination(ConnectorType.SOAP, SoapDestination)
