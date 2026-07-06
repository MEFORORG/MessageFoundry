# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
r"""SOAP transport: a destination that POSTs a SOAP envelope to a web service.

The **destination** is a thin SOAP layer over the same stdlib HTTP client the REST connector uses
(ADR 0003) — it reuses REST's no-redirect, http(s)-only opener (so a 3xx can't divert a PHI-bearing
request; ASVS 15.3.2) and the fail-closed ``[egress].allowed_http`` host gate.

**Two modes (ADR 0015).**
- *Plain* (the default): the Handler produces the **full SOAP envelope** (XML); this adds the SOAP
  ``Content-Type`` + action and POSTs it — byte-identical to the original connector.
- *WS-\** (opt-in, `ws_addressing`/`ws_security`): the Handler produces only the operation **`<Body>`
  fragment**; the **transport** wraps it in the envelope and **stamps the non-deterministic
  WS-Addressing / WS-Security headers** (``<wsa:MessageID>``, ``<wsu:Timestamp>``, optional
  ``<wsse:UsernameToken>`` Nonce/Created) **in `send()`** — after the queue boundary, so a pure
  transform never produces a per-call nonce/timestamp and re-run purity holds (ADR 0015 §1). Envelope
  assembly is **stdlib string templating** (no XML parser); the attacker-influenceable ``<Body>``
  fragment is checked once with a hardened, non-resolving, no-DTD well-formedness gate (XXE-negative).
  WS-\* requires SOAP 1.2.

**Mutual TLS (ADR 0015).** ``client_cert_file``/``client_key_file`` present a client certificate via a
per-connection opener (server verification stays on); incompatible with ``verify_tls=False``.

**SOAP version.** ``1.1`` → ``Content-Type: text/xml; charset=utf-8`` + a ``SOAPAction`` header;
``1.2`` → ``Content-Type: application/soap+xml; charset=utf-8; action="…"`` (no ``SOAPAction`` header).

**Fault mapping.** A response is inspected for a SOAP ``Fault`` (faults can arrive as HTTP 500 *or* an
HTTP 200 body). A WS-Security fault (FailedAuthentication / InvalidSecurityToken / MessageExpired) →
:class:`NegativeAckError` (``permanent=True``) → dead-letter (a credential/expiry reject won't fix on a
retry). A **Sender/Client** fault → permanent dead-letter; a **Receiver/Server** fault →
:class:`DeliveryError` (retry). An unrecognized fault is treated as permanent. With no fault, the HTTP
status decides: 2xx delivered, 5xx retry, other 4xx / refused 3xx dead-letter; a connection/timeout
error retries. Fault bodies are **not** echoed into errors/logs (they may carry PHI) — only the SOAP
fault role + HTTP status are.

**Idempotency.** Delivery is at-least-once, so a retry **re-sends** (minting a fresh ``<wsa:MessageID>``
in WS-\* mode — correct WS-\* retry semantics). The service operation **must be idempotent** and its
dedup must treat a re-send as a retry, not a duplicate. See docs/CONNECTIONS.md.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import logging
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.sax  # nosec B406 — hardened, non-resolving, no-DTD well-formedness gate only (ADR 0015 §2a)
from collections.abc import Callable
from typing import Any
from xml.sax.handler import (  # nosec B406 — see _assert_well_formed_fragment (external entities OFF)
    ContentHandler,
    feature_external_ges,
    feature_external_pes,
)
from xml.sax.saxutils import escape as _xml_escape  # nosec B406 — pure string escaper, not a parser
from xml.sax.xmlreader import InputSource  # nosec B406 — fed only the hardened, no-DTD parser

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    NegativeAckError,
    register_destination,
)

# Reuse REST's hardened HTTP plumbing — same transports/ package, same no-redirect + TLS posture.
from messagefoundry.transports.rest import (
    _NO_REDIRECT_OPENER,
    _NoRedirectHandler,
    _insecure_opener,
    _redact_url,
    enforce_outbound_length_limits,
    refuse_cleartext_credentials,
)
from messagefoundry.transports.signing import MessageSigner, signer_from_destination

__all__ = ["SoapDestination"]

logger = logging.getLogger(__name__)

_FAULT_RE = re.compile(r"<(?:\w+:)?Fault[\s>]", re.IGNORECASE)
_SENDER_RE = re.compile(r"client|sender", re.IGNORECASE)
_RECEIVER_RE = re.compile(r"server|receiver", re.IGNORECASE)
# WS-Security fault codes that are PERMANENT (a retry won't fix a rejected/expired credential).
_WSSE_FAULT_RE = re.compile(
    r"FailedAuthentication|InvalidSecurityToken|MessageExpired", re.IGNORECASE
)
# SOAP 1.1 <faultcode>…</faultcode>; SOAP 1.2 <Code><Value>…</Value></Code>.
_FAULTCODE_RE = re.compile(r"<(?:\w+:)?faultcode\b[^>]*>(.*?)</", re.IGNORECASE | re.DOTALL)
_CODEVALUE_RE = re.compile(r"<(?:\w+:)?Value\b[^>]*>(.*?)</", re.IGNORECASE | re.DOTALL)
# A <…:Header> element (any/no namespace prefix) smuggled into a <Body> fragment (purity-leak lint).
_HEADER_EL_RE = re.compile(r"<\s*(?:[\w.\-]+:)?Header[\s/>]", re.IGNORECASE)

# Namespace URIs (fixed; the transport's header is namespace-controlled, ADR 0015 §2a).
_NS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
_NS_WSA = "http://www.w3.org/2005/08/addressing"
_NS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
_NS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
_PW_TEXT = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-username-token-profile-1.0#PasswordText"
)
_PW_DIGEST = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
)
_NONCE_ENC = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)

# The envelope skeleton (SOAP 1.2 only; WS-* requires 1.2). Built by string concatenation, NOT
# str.format — an HL7-derived <Body> fragment may contain literal { } that would break .format.
_ENV_OPEN = (
    '<?xml version="1.0" encoding="utf-8"?>'
    f'<soap:Envelope xmlns:soap="{_NS_SOAP12}" xmlns:wsa="{_NS_WSA}" '
    f'xmlns:wsse="{_NS_WSSE}" xmlns:wsu="{_NS_WSU}">'
)


def _fault_code(body: str) -> str:
    """The fault code text (e.g. ``soap:Client`` / ``soap:Receiver``), SOAP 1.1 or 1.2, or ``""``."""
    m = _FAULTCODE_RE.search(body) or _CODEVALUE_RE.search(body)
    return m.group(1) if m else ""


def _classify_soap(status: int, body: str) -> DeliveryError | None:
    """``None`` if delivered, else the classified failure. A WS-Security fault (auth/expiry) →
    permanent; a SOAP fault is classified by its code (Sender/Client → permanent; Receiver/Server →
    transient; unrecognized → permanent so a rejected request can't loop the lane); a fault-less
    response falls back to the HTTP status."""
    if _FAULT_RE.search(body):
        code = _fault_code(body)
        if _WSSE_FAULT_RE.search(code) or _WSSE_FAULT_RE.search(body):
            return NegativeAckError(
                f"WS-Security fault (HTTP {status})", code="wssecurity", permanent=True
            )
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


def _client_cert_opener(
    certfile: str, keyfile: str, password: str | None
) -> urllib.request.OpenerDirector:
    """A no-redirect opener that presents a **client certificate** for mutual TLS (ADR 0015 §3).

    Server verification stays on (``create_default_context`` verifies the peer + hostname); a client
    cert against an unverified peer is incoherent and rejected at construction, so this never combines
    with ``verify_tls=False``. TLS 1.2+ floor (ADR 0002), as in ``mllp.py``/``api/tls.py``. Per
    connection — REST's shared module-level openers are left untouched."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile, password)
    return urllib.request.build_opener(_NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx))


def _assert_well_formed_fragment(fragment: str) -> None:
    """Reject a ``<Body>`` fragment that is not well-formed XML, **before** it reaches the wire
    (ADR 0015 §2a). Uses a single hardened, **non-resolving, no-DTD** ``xml.sax`` parse of the fragment
    *in isolation* (wrapped in a throwaway shell we discard) — external entity resolution is OFF, so it
    is **not** an XXE vector; a DOCTYPE is rejected outright (no internal entity expansion). This is a
    balanced-tags / no-smuggled-close gate on attacker-influenceable HL7-derived content, not a schema
    check; no parsed tree is kept or trusted."""
    if "<!doctype" in fragment.lower():
        raise ValueError("SOAP <Body> fragment must not contain a DOCTYPE (ADR 0015)")
    parser = xml.sax.make_parser()  # noqa: S317  # nosec B317 — hardened below: external entities OFF
    parser.setFeature(feature_external_ges, False)
    parser.setFeature(feature_external_pes, False)
    parser.setContentHandler(ContentHandler())
    source = InputSource()
    source.setByteStream(io.BytesIO(f"<_mf_frag>{fragment}</_mf_frag>".encode()))
    try:
        parser.parse(source)
    except xml.sax.SAXException as exc:
        raise ValueError(f"SOAP <Body> fragment is not well-formed XML: {exc}") from exc


def _reject_ws_leak(fragment: str) -> None:
    """Best-effort lint (ADR 0015 §2b, NOT a structural guarantee): reject a ``<Body>`` fragment that
    already carries a ``<Header>`` or a WS-\\* element **by namespace URI** — i.e. an author trying to
    hand-build the non-deterministic header inside the (pure) transform. The real purity guarantee is
    §1's value-placement; this only catches an accidental mistake early. Matches on URI (prefixes are
    author-chosen) so it can be evaded (a URI in a comment/CDATA) and is intentionally conservative."""
    if any(ns in fragment for ns in (_NS_WSA, _NS_WSSE, _NS_WSU)):
        raise ValueError(
            "SOAP <Body> fragment declares a WS-* namespace (wsa/wsse/wsu); the transport stamps those "
            "headers in send() to preserve re-run purity — the Handler must return only the <Body> "
            "operation fragment (ADR 0015)"
        )
    if _HEADER_EL_RE.search(fragment):
        raise ValueError(
            "SOAP <Body> fragment contains a <Header> element; in WS-* mode the Handler returns only "
            "the operation <Body> fragment and the transport builds the <Header> (ADR 0015)"
        )


def _iso(t: float) -> str:
    """An XSD ``dateTime`` in UTC, e.g. ``2026-06-15T05:30:00Z`` (WS-Security Created/Expires)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _default_message_id() -> str:
    """A fresh WS-Addressing MessageID (a per-call URN); overridable for deterministic tests."""
    return f"urn:uuid:{uuid.uuid4()}"


def _default_nonce() -> bytes:
    """A fresh WS-Security nonce; overridable for deterministic tests."""
    return os.urandom(16)


class SoapDestination(DestinationConnector):
    """POST each SOAP envelope to a web-service endpoint (plain or WS-* mode; ADR 0003 + 0015)."""

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
        # The action is the single source of truth: the 1.2 Content-Type action param AND wsa:Action.
        self.soap_action: str = str(s.get("soap_action") or "")
        # ADR 0013: capture the SOAP response envelope. Default False → returns None, byte-identical.
        self.capture_response: bool = bool(s.get("capture_response", False))

        # --- ADR 0015: WS-* + mutual-TLS settings -----------------------------------------------
        self.client_cert_file: str | None = s.get("client_cert_file") or None
        self.client_key_file: str | None = s.get("client_key_file") or None
        self.client_key_password: str | None = s.get("client_key_password") or None
        self.ws_addressing: bool = bool(s.get("ws_addressing", False))
        self.ws_security: bool = bool(s.get("ws_security", False))
        self.ws_username: str | None = s.get("ws_username") or s.get("basic_user") or None
        self.ws_password: str | None = s.get("ws_password") or s.get("basic_password") or None
        self.ws_password_type: str = str(s.get("ws_password_type", "text"))
        self.ws_timestamp_ttl_seconds: int = int(s.get("ws_timestamp_ttl_seconds", 300))
        self._ws_mode: bool = self.ws_addressing or self.ws_security

        # Non-deterministic generators — instance attributes so tests can inject a fixed clock / UUID /
        # nonce and assert the values are minted in send() (ADR 0015 testing strategy).
        self._now_fn: Callable[[], float] = time.time
        self._uuid_fn: Callable[[], str] = _default_message_id
        self._nonce_fn: Callable[[], bytes] = _default_nonce

        self._validate_ws(scheme, s)

        self._headers = self._build_headers(s)
        enforce_outbound_length_limits(self.url, self._headers)
        refuse_cleartext_credentials(scheme, self._headers, self.url)
        # ASVS 4.1.5 (ADR 0018): opt-in detached-JWS signing of the outbound envelope. None = off
        # (byte-identical). Built here so a bad key/algorithm fails loud at connector construction; the
        # signature is minted in _post over the FINAL wire bytes (the WS-* wrapped envelope, ADR 0015).
        self._signer: MessageSigner | None = signer_from_destination(config)

        if self.client_cert_file and self.client_key_file:  # NEW — mutual TLS, takes precedence
            self._opener: urllib.request.OpenerDirector = _client_cert_opener(
                self.client_cert_file, self.client_key_file, self.client_key_password
            )
        elif bool(s.get("verify_tls", True)):
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

    def _validate_ws(self, scheme: str, s: dict[str, Any]) -> None:
        """Runtime validation of the WS-* / mTLS settings (also enforced at wiring time by
        ``build_outbound_connection`` so ``check``/dry-run catches it without a store; the url-scheme
        checks need the resolved url and live here). ADR 0015 §6."""
        if self.client_cert_file and not self.client_key_file:
            raise ValueError("SOAP client_cert_file requires client_key_file (ADR 0015)")
        if self.client_key_file and not self.client_cert_file:
            raise ValueError("SOAP client_key_file requires client_cert_file (ADR 0015)")
        if self.client_cert_file:
            if scheme != "https":
                raise ValueError("SOAP client certificate requires an https url (ADR 0015)")
            if not bool(s.get("verify_tls", True)):
                raise ValueError(
                    "SOAP client cert is incompatible with verify_tls=false — the peer must be "
                    "verified (ADR 0015)"
                )
        if self.ws_password_type not in ("text", "digest"):
            raise ValueError("SOAP ws_password_type must be 'text' or 'digest' (ADR 0015)")
        if self._ws_mode and self.version != "1.2":
            raise ValueError("SOAP ws_addressing/ws_security require soap_version='1.2' (ADR 0015)")
        # A UsernameToken password over cleartext http is a credential on the wire — refuse like the
        # Authorization-header path (ADR 0015 §6), unless the dev escape is set.
        if self.ws_username and scheme == "http" and not insecure_tls_allowed():
            raise ValueError(
                "SOAP ws_username sends a UsernameToken credential over cleartext http; refused "
                f"unless {INSECURE_TLS_ESCAPE_ENV} is set — use https (ADR 0015)"
            )

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

    # --- WS-* envelope assembly (all non-deterministic values minted here, in send()) -------------

    def _build_wsa_header(self) -> str:
        # wsa:Action is sourced from soap_action — the single source of truth, never a divergent second
        # value (ADR 0015 §6). wsa:To is the static endpoint url; wsa:MessageID is per-call.
        action = _xml_escape(self.soap_action)
        to = _xml_escape(self.url)
        message_id = _xml_escape(self._uuid_fn())
        return (
            f"<wsa:Action>{action}</wsa:Action>"
            f"<wsa:To>{to}</wsa:To>"
            f"<wsa:MessageID>{message_id}</wsa:MessageID>"
        )

    def _build_wsse_header(self, now: float) -> str:
        created = _iso(now)
        expires = _iso(now + self.ws_timestamp_ttl_seconds)
        timestamp = (
            '<wsu:Timestamp wsu:Id="TS-1">'
            f"<wsu:Created>{created}</wsu:Created><wsu:Expires>{expires}</wsu:Expires>"
            "</wsu:Timestamp>"
        )
        token = self._build_username_token(created) if self.ws_username else ""
        return f'<wsse:Security soap:mustUnderstand="true">{timestamp}{token}</wsse:Security>'

    def _build_username_token(self, created: str) -> str:
        username = _xml_escape(self.ws_username or "")
        if self.ws_password_type == "digest":  # nosec B105 — a WS-Security password *type*, not a secret
            nonce = self._nonce_fn()
            # Legacy WS-Security UsernameToken digest = Base64(SHA1(Nonce + Created + Password)). This
            # is the spec's token construction, NOT a message-integrity signature (SHA1 here is the
            # profile's defined hash; XML-DSig is deferred — ADR 0015 §4a).
            digest = base64.b64encode(
                hashlib.sha1(  # noqa: S324  # nosec B324 — WS-Security UsernameToken profile, not integrity
                    nonce + created.encode() + (self.ws_password or "").encode()
                ).digest()
            ).decode("ascii")
            nonce_b64 = base64.b64encode(nonce).decode("ascii")
            return (
                f"<wsse:UsernameToken><wsse:Username>{username}</wsse:Username>"
                f'<wsse:Password Type="{_PW_DIGEST}">{_xml_escape(digest)}</wsse:Password>'
                f'<wsse:Nonce EncodingType="{_NONCE_ENC}">{nonce_b64}</wsse:Nonce>'
                f"<wsu:Created>{created}</wsu:Created></wsse:UsernameToken>"
            )
        password = _xml_escape(self.ws_password or "")
        return (
            f"<wsse:UsernameToken><wsse:Username>{username}</wsse:Username>"
            f'<wsse:Password Type="{_PW_TEXT}">{password}</wsse:Password></wsse:UsernameToken>'
        )

    def _wrap_envelope(self, body_fragment: str) -> str:
        """Wrap the Handler's operation ``<Body>`` fragment in a transport-built envelope + stamped
        ``<Header>`` (ADR 0015 §2). The fragment is well-formedness-checked and lint-screened first."""
        _assert_well_formed_fragment(body_fragment)
        _reject_ws_leak(body_fragment)
        now = self._now_fn()
        header = ""
        if self.ws_addressing:
            header += self._build_wsa_header()
        if self.ws_security:
            header += self._build_wsse_header(now)
        return (
            _ENV_OPEN
            + f"<soap:Header>{header}</soap:Header>"
            + f"<soap:Body>{body_fragment}</soap:Body>"
            + "</soap:Envelope>"
        )

    async def send(self, payload: str) -> DeliveryResponse | None:
        # WS-* mode: the Handler returned only the <Body> fragment; wrap + stamp here (post-queue
        # boundary), so the per-call MessageID/Timestamp/Nonce never live in a pure transform.
        if self._ws_mode:
            payload = self._wrap_envelope(payload)
        body, status = await asyncio.to_thread(self._post, payload)
        # A fault can arrive inside a 2xx body, so classify it. Transport-level faults (non-2xx,
        # URL/timeout) already raised inside _post, for both modes.
        failure = _classify_soap(status, body)
        if not self.capture_response:
            if failure is not None:
                raise failure  # byte-identical: a 2xx <Fault> still dead-letters/retries
            return None
        if failure is not None:
            # Capturing: record the application <Fault> as a rejected reply rather than raising, so the
            # row is delivered-with-a-rejection (operators reconcile from the captured response).
            return DeliveryResponse(
                body=body, outcome="rejected", detail=f"SOAP fault (HTTP {status})"
            )
        if not body:
            return DeliveryResponse(body="", outcome="no_reply", detail=f"HTTP {status}")
        return DeliveryResponse(body=body, outcome="accepted", detail=f"HTTP {status}")

    async def test_connection(self) -> None:
        await asyncio.to_thread(self._probe)

    def _probe(self) -> None:
        # Reachability only: a HEAD reaches the endpoint without POSTing an envelope. An HTTP response
        # means the host answered (a 405 is still a pass), but a 401/403 means the configured
        # credentials would be rejected — surface that as a failure. Connection/DNS/TLS/timeout fails.
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.url, headers=self._headers, method="HEAD"
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise DeliveryError(
                    f"SOAP {_redact_url(self.url)} returned HTTP {exc.code} (check credentials)"
                ) from exc
            return  # any other status (the host answered) → reachable
        except urllib.error.URLError as exc:
            raise DeliveryError(f"SOAP {_redact_url(self.url)} unreachable: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"SOAP {_redact_url(self.url)} failed: {exc}") from exc

    def _post(self, payload: str) -> tuple[str, int]:
        # payload is the FINAL wire body (in WS-* mode send() already wrapped + stamped the envelope),
        # so signing over these bytes covers exactly what the partner receives.
        data = payload.encode(self.encoding)
        headers = self._headers
        if self._signer is not None:
            # ASVS 4.1.5 (ADR 0018): detached JWS over the envelope, minted off-loop past the queue
            # boundary so a retry re-mints it (re-run purity holds, like the WS-Security nonce).
            headers = {**self._headers, **self._signer.signature_headers(data)}
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.url,
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode(self.encoding, errors="replace")
                status = int(getattr(resp, "status", 200))
                return body, status
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode(self.encoding, errors="replace")
            except Exception:  # noqa: BLE001 - a body we can't read just becomes status-only
                body = ""
            # A non-2xx status: _classify_soap always returns a failure here (it returns None only on
            # 2xx). This is a transport-level fault — raised for BOTH capturing and non-capturing.
            raise (
                _classify_soap(exc.code, body) or DeliveryError(f"SOAP HTTP {exc.code}")
            ) from exc
        except urllib.error.URLError as exc:
            raise DeliveryError(f"SOAP {_redact_url(self.url)} unreachable: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"SOAP {_redact_url(self.url)} failed: {exc}") from exc


register_destination(ConnectorType.SOAP, SoapDestination)
