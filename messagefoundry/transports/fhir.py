# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""FHIR REST transport: a destination that delivers a FHIR resource to a FHIR server (ADR 0022 §2).

``FhirDestination`` is a sibling :class:`~messagefoundry.transports.base.DestinationConnector` that
**reuses** the hardened HTTP plumbing in :mod:`messagefoundry.transports.rest` — exactly as
:mod:`messagefoundry.transports.soap` does — rather than wrapping ``RestDestination``: the no-redirect,
http(s)-only, TLS-verifying opener (a 3xx can't divert a PHI-bearing request; ASVS 15.3.2), the
cleartext-credential refusal, the outbound length limits, and the optional detached-JWS signer. The
fail-closed ``[egress].allowed_http`` host gate is enforced by the runner (it folds FHIR into the
REST/SOAP arm — see wiring_runner ``_allowlist_for``/``check_egress_allowed``).

**FHIR-specific layer (on top of REST):**
- Media type ``application/fhir+json`` on both ``Content-Type`` and ``Accept`` (JSON-only MVP; FHIR-XML
  is deferred — ADR 0022 Options #5).
- Interaction → method + path off the FHIR service **base** ``url`` (e.g. ``https://host/fhir``): a
  ``create`` is ``POST {base}/{ResourceType}``, an ``update`` is ``PUT {base}/{ResourceType}/{id}``, and
  a ``transaction``/``batch`` is ``POST {base}`` with a ``Bundle`` body (the server applies it). The
  ResourceType/id are read from the outgoing body with the cheap :class:`FhirPeek` (no typed parse).
- The three opt-in conditional knobs (idempotency/concurrency levers, off by default): ``if-none-exist``
  (conditional create — ``If-None-Exist`` header), ``conditional-update`` (search-based ``PUT
  {base}/{ResourceType}?<query>``), and ``if-match`` (version-aware ``PUT`` with an ``If-Match`` ETag
  derived from the resource's ``meta.versionId``).
- ``OperationOutcome`` classification refines the HTTP-status retry model: 2xx → delivered (a returned
  OperationOutcome is captured, never an error); 5xx → transient retry; a 4xx whose OperationOutcome
  carries a FHIR *transient* IssueType code (lock-error/throttled/timeout/incomplete) → transient retry;
  any other 4xx / refused 3xx → permanent dead-letter. **The HTTP status wins when in doubt; a 5xx
  stays transient.**

**PHI:** an ``OperationOutcome``/error body may carry PHI, so it is **never** echoed into a log/error —
only the HTTP status and a redacted URL are. **Idempotency:** delivery is at-least-once, so a retry
re-sends; the FHIR server operation must be idempotent (the conditional knobs are the native lever).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.parsing.fhir import FhirPeek, FhirPeekError
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    NegativeAckError,
    register_destination,
)

# Reuse REST's hardened HTTP plumbing — same transports/ package, same no-redirect + TLS posture
# (NOT a wrapper around RestDestination; ADR 0022 §2, exactly as soap.py does).
from messagefoundry.transports.rest import (
    _NO_REDIRECT_OPENER,
    _RETRYABLE_4XX,
    _insecure_opener,
    _redact_url,
    enforce_outbound_length_limits,
    refuse_cleartext_credentials,
)
from messagefoundry.transports.signing import MessageSigner, signer_from_destination

__all__ = ["FhirDestination", "FhirLookupExecutor"]

logger = logging.getLogger(__name__)

_INTERACTIONS = ("create", "update", "transaction", "batch")
_CONDITIONALS = ("if-none-exist", "conditional-update", "if-match")
# FHIR transient IssueType group (children of `transient`): a retry may succeed.
# https://www.hl7.org/fhir/valueset-issue-type.html
_TRANSIENT_ISSUE_CODES = frozenset(
    {"transient", "lock-error", "throttled", "timeout", "incomplete"}
)

# FHIR path-segment grammars (https://hl7.org/fhir/datatypes.html#id). A resourceType is a token of
# ASCII letters; an id is 1-64 of [A-Za-z0-9.-] (note: '_' is NOT in the FHIR id grammar). These gate
# the message-derived path segments so a crafted resource can't smuggle '/', '..', '?', '#', or '@'
# into the request path and redirect a PHI-bearing write to a different resource/operation on the same
# allow-listed host (the [egress].allowed_http gate pins the host, not the path).
_FHIR_TYPE_RE = re.compile(r"^[A-Za-z]+$")
_FHIR_ID_RE = re.compile(r"^[A-Za-z0-9.\-]{1,64}$")


def _operation_outcome(body: str) -> dict[str, Any] | None:
    """Parse ``body`` as a FHIR ``OperationOutcome`` JSON resource, or None if it is not one."""
    try:
        obj = json.loads(body)
    except ValueError:
        return None
    if isinstance(obj, dict) and obj.get("resourceType") == "OperationOutcome":
        return obj
    return None


def _issue_field(outcome: dict[str, Any], field: str) -> list[str]:
    """The ``issue[].<field>`` string values of an OperationOutcome (severity/code), tolerant of shape."""
    issues = outcome.get("issue")
    if not isinstance(issues, list):
        return []
    return [
        issue[field]
        for issue in issues
        if isinstance(issue, dict) and isinstance(issue.get(field), str)
    ]


def _classify_fhir(status: int, body: str) -> DeliveryError | None:
    """``None`` if delivered (2xx), else the classified failure. Refines the HTTP-status base with the
    ``OperationOutcome`` issue codes, but the HTTP status wins when in doubt (a 5xx stays transient).
    PHI-safe: only the status is named, never the OperationOutcome body."""
    if 200 <= status < 300:
        return None
    if 500 <= status < 600:
        return DeliveryError(f"FHIR server returned HTTP {status}")  # 5xx always transient
    outcome = _operation_outcome(body)
    transient_issue = outcome is not None and any(
        code in _TRANSIENT_ISSUE_CODES for code in _issue_field(outcome, "code")
    )
    if status in _RETRYABLE_4XX or transient_issue:
        return DeliveryError(f"FHIR server returned HTTP {status} (transient)")
    return NegativeAckError(
        f"FHIR server rejected with HTTP {status}", code=str(status), permanent=True
    )


def _capture_outcome(body: str) -> str:
    """Classify a 2xx reply body into the RESPONSE_OUTCOMES vocabulary (ADR 0022 §2.4): an error
    ``OperationOutcome`` → ``rejected``; any other parseable FHIR resource (assigned resource / success
    OperationOutcome) → ``accepted``; a received-but-unparseable body → ``unparseable``."""
    try:
        obj = json.loads(body)
    except ValueError:
        return "unparseable"
    if not isinstance(obj, dict) or not isinstance(obj.get("resourceType"), str):
        return "unparseable"
    if obj["resourceType"] == "OperationOutcome":
        severities = _issue_field(obj, "severity")
        return "rejected" if any(s in ("fatal", "error") for s in severities) else "accepted"
    return "accepted"


def _reject_control_chars(value: str, field: str) -> str:
    """Reject a value (read from the outgoing body) that carries a C0/DEL control char before it flows
    into a URL path or HTTP header. A CR/LF/NUL in a crafted resource id / meta.versionId would let a
    malicious resource split the request line or inject a header — urllib rejects it with a bare
    ``ValueError`` that would otherwise escape ``send()`` as an 'internal error'. Surface it as a
    permanent ``NegativeAckError`` (a retry re-sends the same body) with a PHI-safe message (the field
    name only, never the value)."""
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise NegativeAckError(
            f"FHIR {field} contains an illegal control character",
            code="bad-request-value",
            permanent=True,
        )
    return value


def _validate_path_token(value: str, pattern: re.Pattern[str], field: str) -> str:
    """Reject a message-derived path segment that doesn't match its FHIR grammar before it flows into
    the request URL. ``_reject_control_chars`` blocks CRLF/NUL but NOT path metacharacters ('/', '..',
    '?', '#', '@'); a crafted resource id/resourceType could otherwise redirect a PHI-bearing PUT/POST
    to a different resource or ``$operation`` on the same allow-listed host (CWE-918). Surfaced as a
    permanent ``NegativeAckError`` (a retry re-sends the same body) with a PHI-safe message naming only
    the field, mirroring ``_reject_control_chars``."""
    if not pattern.match(value):
        raise NegativeAckError(
            f"FHIR {field} is not a valid FHIR token/id",
            code="bad-request-value",
            permanent=True,
        )
    return value


class FhirDestination(DestinationConnector):
    """Deliver a FHIR resource to a FHIR server over REST (create/update/transaction; ADR 0022)."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        url = s.get("url")
        if not isinstance(url, str) or not url:
            raise ValueError(
                "FHIR destination requires a 'url' setting (the FHIR service base URL)"
            )
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"FHIR destination 'url' must be http or https, got scheme {scheme!r}")
        self.base_url = url
        self.fhir_version: str = str(s.get("fhir_version", "R4B"))
        self.format: str = str(s.get("format", "json"))
        if self.format != "json":
            # JSON-only MVP; FHIR-XML is deferred to a hardened-lxml path (ADR 0022 Options #5).
            raise ValueError(
                f"FHIR destination format={self.format!r} is not supported (JSON only; ADR 0022)"
            )
        self.interaction: str = str(s.get("interaction", "create"))
        if self.interaction not in _INTERACTIONS:
            raise ValueError(
                f"FHIR destination interaction must be one of {_INTERACTIONS}, got {self.interaction!r}"
            )
        conditional = s.get("conditional")
        self.conditional: str | None = str(conditional) if conditional else None
        if self.conditional is not None and self.conditional not in _CONDITIONALS:
            raise ValueError(
                f"FHIR destination conditional must be one of {_CONDITIONALS} or unset, "
                f"got {self.conditional!r}"
            )
        self.conditional_query: str | None = s.get("conditional_query") or None
        if (
            self.conditional in ("if-none-exist", "conditional-update")
            and not self.conditional_query
        ):
            raise ValueError(
                f"FHIR destination conditional={self.conditional!r} requires a 'conditional_query' "
                "setting (the search parameters)"
            )
        if self.conditional is not None and self.interaction in ("transaction", "batch"):
            # A connection-level conditional applies to a single create/update, not a Bundle — it would
            # be silently ignored for transaction/batch (per-entry conditionals go in Bundle.entry.request
            # in the Handler). Refuse the incoherent combo at wiring time rather than no-op it.
            raise ValueError(
                f"FHIR destination conditional={self.conditional!r} is incompatible with "
                f"interaction={self.interaction!r}; set per-entry Bundle.entry.request fields instead"
            )
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.encoding: str = s.get("encoding", "utf-8")
        # ADR 0013: capture the FHIR server reply (assigned resource / ETag / OperationOutcome). Default
        # False → returns None, byte-identical.
        self.capture_response: bool = bool(s.get("capture_response", False))

        self._headers = self._build_headers(s)
        enforce_outbound_length_limits(self.base_url, self._headers)
        refuse_cleartext_credentials(scheme, self._headers, self.base_url)
        # ASVS 4.1.5 (ADR 0018): opt-in detached-JWS signing; None = off (byte-identical). Built here so
        # a bad key fails loud at construction; the signature is minted in _post over the body bytes.
        self._signer: MessageSigner | None = signer_from_destination(config)
        # ADR 0024: opt-in SMART Backend Services token provider. None = off (byte-identical). Lazy
        # import breaks the rest <-> smart cycle (smart reuses rest's opener); built here so a bad
        # key/curve/token_url fails loud. The minted bearer is injected per-request in _post.
        from messagefoundry.transports.smart import token_provider_from_destination

        self._token_provider = token_provider_from_destination(config)
        if self._token_provider is not None:
            # The SMART bearer is injected per-request in _post, so the static-header cleartext check
            # above can't see it. Re-run the check treating the connection as credential-bearing, so a
            # SMART access token never ships over cleartext http.
            refuse_cleartext_credentials(
                scheme, {**self._headers, "Authorization": "Bearer"}, self.base_url
            )

        if bool(s.get("verify_tls", True)):
            self._opener: urllib.request.OpenerDirector = _NO_REDIRECT_OPENER
        else:
            if scheme == "https" and not insecure_tls_allowed():
                raise ValueError(
                    "FHIR destination verify_tls=false disables TLS certificate verification; "
                    f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set (dev/trusted-network only)"
                )
            logger.warning(
                "FHIR destination %s has TLS verification DISABLED (verify_tls=false)",
                _redact_url(self.base_url),
            )
            self._opener = _insecure_opener()

    def _build_headers(self, s: dict[str, Any]) -> dict[str, str]:
        """FHIR media type on Content-Type + Accept + static ``headers`` + optional bearer/basic auth."""
        media = "application/fhir+json"  # format is constrained to json in __init__ (XML deferred)
        headers: dict[str, str] = {"Content-Type": media, "Accept": media}
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

    def _peek(self, payload: str) -> FhirPeek:
        """Cheap routing peek of the outgoing body. A non-FHIR body is a Handler bug → permanent
        dead-letter (a retry re-sends the same bad body)."""
        try:
            return FhirPeek.parse(payload)
        except FhirPeekError as exc:
            raise NegativeAckError(
                "outgoing FHIR body is not parseable JSON", code="bad-body", permanent=True
            ) from exc

    def _resolve_request(self, payload: str) -> tuple[str, str, dict[str, str]]:
        """Derive (method, url, extra per-request headers) from the interaction/conditional + the body.

        ResourceType/id/versionId are read from the outgoing body via FhirPeek. A missing required field
        is a permanent failure (retrying re-sends the same body). PHI-safe: errors name only the missing
        field, never the body."""
        base = self.base_url.rstrip("/")
        if self.interaction in ("transaction", "batch"):
            return "POST", base, {}  # the body is itself a Bundle; the server applies it

        peek = self._peek(payload)
        resource_type = peek.resource_type
        if not resource_type:
            raise NegativeAckError(
                "outgoing FHIR body has no resourceType", code="no-resource-type", permanent=True
            )
        _reject_control_chars(resource_type, "resourceType")  # it flows into the URL path
        # Grammar-gate the message-derived type so a crafted resource can't smuggle path metacharacters
        # ('/', '..', '?', '#') into the path and redirect the write to another resource/operation.
        _validate_path_token(resource_type, _FHIR_TYPE_RE, "resourceType")
        type_seg = urllib.parse.quote(resource_type, safe="")  # defense-in-depth percent-encode

        if self.conditional == "conditional-update":
            return "PUT", f"{base}/{type_seg}?{self.conditional_query}", {}
        if self.conditional == "if-none-exist":
            return (
                "POST",
                f"{base}/{type_seg}",
                {"If-None-Exist": self.conditional_query or ""},
            )
        if self.conditional == "if-match":
            version_id = self._version_id(peek)
            if not version_id:
                raise NegativeAckError(
                    "FHIR if-match requires the resource's meta.versionId",
                    code="no-version-id",
                    permanent=True,
                )
            _reject_control_chars(version_id, "meta.versionId")  # it flows into the If-Match header
            # versionId is an id-typed FHIR value: gate it to the id grammar so it can't break out of
            # the W/"..." ETag (quoting is wrong for a header value, so reject rather than encode).
            _validate_path_token(version_id, _FHIR_ID_RE, "meta.versionId")
            id_seg = urllib.parse.quote(self._require_id(peek), safe="")
            return "PUT", f"{base}/{type_seg}/{id_seg}", {"If-Match": f'W/"{version_id}"'}

        if self.interaction == "update":
            id_seg = urllib.parse.quote(self._require_id(peek), safe="")
            return "PUT", f"{base}/{type_seg}/{id_seg}", {}
        return "POST", f"{base}/{type_seg}", {}  # create (default)

    @staticmethod
    def _require_id(peek: FhirPeek) -> str:
        if not peek.id:
            raise NegativeAckError(
                "FHIR update requires the resource id", code="no-id", permanent=True
            )
        _reject_control_chars(peek.id, "resource id")  # it flows into the URL path
        # Grammar-gate the message-derived id so '../$reindex'-style traversal can't redirect the write.
        return _validate_path_token(peek.id, _FHIR_ID_RE, "resource id")

    @staticmethod
    def _version_id(peek: FhirPeek) -> str | None:
        meta = peek.obj.get("meta")
        if isinstance(meta, dict):
            version_id = meta.get("versionId")
            if isinstance(version_id, str) and version_id:
                return version_id
        return None

    async def send(self, payload: str) -> DeliveryResponse | None:
        method, url, extra_headers = self._resolve_request(payload)
        # urllib is blocking — keep it off the event loop (the delivery worker awaits this).
        body, status = await asyncio.to_thread(self._post, payload, method, url, extra_headers)
        # A non-2xx already raised inside _post (transient retry / permanent dead-letter). Here status is
        # 2xx: FHIR treats a 2xx as delivered (a returned OperationOutcome is captured, not an error).
        if not self.capture_response:
            return None
        if not body:
            return DeliveryResponse(body="", outcome="no_reply", detail=f"HTTP {status}")
        return DeliveryResponse(body=body, outcome=_capture_outcome(body), detail=f"HTTP {status}")

    async def test_connection(self) -> None:
        await asyncio.to_thread(self._probe)

    def _probe(self) -> None:
        # Reachability only: a GET of the FHIR base metadata (CapabilityStatement) reaches the server
        # without POSTing a resource. Any HTTP response means the host answered; 401/403 means the
        # configured credentials would be rejected. Connection/DNS/TLS/timeout always fails.
        url = f"{self.base_url.rstrip('/')}/metadata"
        headers = self._headers
        if self._token_provider is not None:
            # Acquire a real SMART token so reachability reflects the actual credentials.
            headers = {
                **self._headers,
                "Authorization": f"Bearer {self._token_provider.access_token()}",
            }
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            url, headers=headers, method="GET"
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise DeliveryError(
                    f"FHIR {_redact_url(self.base_url)} returned HTTP {exc.code} (check credentials)"
                ) from exc
            return  # any other status (the host answered) → reachable
        except urllib.error.URLError as exc:
            raise DeliveryError(
                f"FHIR {_redact_url(self.base_url)} unreachable: {exc.reason}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"FHIR {_redact_url(self.base_url)} failed: {exc}") from exc

    def _post(
        self, payload: str, method: str, url: str, extra_headers: dict[str, str]
    ) -> tuple[str, int]:
        data = payload.encode(self.encoding)
        headers = {**self._headers, **extra_headers}
        if self._token_provider is not None:
            # ADR 0024: a fresh SMART bearer per request, acquired off-loop past the queue boundary (a
            # retry re-mints — re-run purity holds). Overrides any static bearer_token.
            headers["Authorization"] = f"Bearer {self._token_provider.access_token()}"
        if self._signer is not None:
            # ASVS 4.1.5 (ADR 0018): detached JWS over the body bytes, minted off-loop past the queue
            # boundary so a retry re-mints it (re-run purity holds).
            headers = {**headers, **self._signer.signature_headers(data)}
        try:
            req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
                url,
                data=data,
                headers=headers,
                method=method,
            )
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode(self.encoding, errors="replace")
                status = int(getattr(resp, "status", 200))
                return body, status
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode(self.encoding, errors="replace")
            except Exception:  # noqa: BLE001 - a body we can't read just becomes status-only
                body = ""
            if self._token_provider is not None and exc.code == 401:
                # ADR 0024: the SMART token may have expired between mint and use — drop it and retry
                # with a fresh one (transient). A 403 stays permanent (an authz/scope denial a re-mint
                # won't fix; classified below). PHI/secret-safe: redacted url only, never the body.
                self._token_provider.invalidate()
                raise DeliveryError(
                    f"FHIR {_redact_url(self.base_url)} returned HTTP 401; refreshing SMART token"
                ) from exc
            # Non-2xx: _classify_fhir always returns a failure here (None only on 2xx). Raised for BOTH
            # capturing and non-capturing — a non-2xx is a transport/server failure, not a captured reply.
            raise (
                _classify_fhir(exc.code, body) or DeliveryError(f"FHIR HTTP {exc.code}")
            ) from exc
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise DeliveryError(
                f"FHIR {_redact_url(self.base_url)} unreachable: {exc.reason}"
            ) from exc
        except ValueError as exc:
            # Backstop for an illegal request value urllib rejects (a CRLF in a header/URL that slipped
            # past the control-char guard, or a bad conditional_query) — a permanent failure (a retry
            # re-sends the same body), never an escaping internal error. PHI-safe: redacted url only.
            raise NegativeAckError(
                f"FHIR {_redact_url(self.base_url)} rejected an invalid request value",
                code="bad-request-value",
                permanent=True,
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"FHIR {_redact_url(self.base_url)} failed: {exc}") from exc


register_destination(ConnectorType.FHIR, FhirDestination)


# --- handler-callable live FHIR read (fhir_lookup, ADR 0043) ------------------
# The read-side mirror of DatabaseLookupExecutor: a GET-only executor reused by the RegistryRunner from
# the graph's FhirLookup specs. It reuses rest.py's hardened opener (TLS-verifying, no-redirect — a 3xx
# can't divert a PHI-bearing read to another host; ASVS 15.3.2), the SMART bearer (ADR 0024), and the
# pure parsing/fhir/ codec to parse the reply. Read-only is STRUCTURAL: it builds only a GET (no verb, no
# body), so a Handler cannot mutate the FHIR server through it (FHIR writes stay on FhirDestination).


def _resolve_read_url(base: str, query: str) -> str:
    """Build a read-only ``GET`` URL from a ``FhirLookup`` ``query``: a read-by-id (``"Patient/123"``) or a
    search (``"Patient?identifier=MRN|123"``).

    Grammar-gates the resource-type and id **path segments** to the FHIR token/id grammars (the same gate
    ``FhirDestination`` applies to a write path, CWE-918): a crafted query can't smuggle ``/``, ``..``,
    ``#``, ``@`` (or a leading ``/`` / absolute URL) into the path and redirect the read to another
    resource/operation — or off the allow-listed host. The optional search string (after ``?``) rides the
    URL query verbatim after a control-char check (it never adds a path segment). Raises a PHI-safe
    ``ValueError`` (it names only the offending shape/segment, never the query's parameter values)."""
    raw = query.strip()
    if not raw:
        raise ValueError("FHIR read query is empty")
    path_part, sep, search_part = raw.partition("?")
    segments = path_part.split("/")
    if not (1 <= len(segments) <= 2):
        # Only {ResourceType} or {ResourceType}/{id} — never a nested/operation path.
        raise ValueError("FHIR read path must be 'ResourceType' or 'ResourceType/id'")
    resource_type = segments[0]
    if not _FHIR_TYPE_RE.match(resource_type):
        raise ValueError("FHIR read resourceType is not a valid FHIR token")
    type_seg = urllib.parse.quote(resource_type, safe="")
    path = type_seg
    if len(segments) == 2:
        resource_id = segments[1]
        if not _FHIR_ID_RE.match(resource_id):
            raise ValueError("FHIR read id is not a valid FHIR id")
        path = f"{type_seg}/{urllib.parse.quote(resource_id, safe='')}"
    url = f"{base.rstrip('/')}/{path}"
    if sep:  # a search query string — control-char gate (it never adds a path segment)
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in search_part):
            raise ValueError("FHIR read search query contains an illegal control character")
        url = f"{url}?{search_part}"
    return url


class FhirLookupExecutor:
    """GET-only executor for handler-callable **live** FHIR reads (``fhir_lookup``, ADR 0043).

    Built by the :class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner` from the graph's
    ``FhirLookup`` specs (``env()``-resolved + ``[egress].allowed_http``-checked by the runner). For each
    named connection it builds the hardened opener (TLS-verifying, no-redirect), the request headers, and
    an optional SMART Backend Services token provider (the same provider/cache/401-invalidate the FHIR
    outbound uses). :meth:`read` issues a read-by-id / search ``GET`` **off the event loop** and returns
    the parsed result as a plain dict (a resource, or a searchset ``Bundle``); the Handler reads it via the
    pure ``parsing/fhir/`` codec.

    **PHI/secret-safe:** an error names only routing-safe identifiers (connection, HTTP status, an
    ``OperationOutcome`` issue code, a redacted host) — never the returned body, the query's parameter
    values, or the SMART token."""

    def __init__(self, connections: Mapping[str, Mapping[str, Any]]) -> None:
        # connections: name -> already-env-resolved settings (the runner substitutes env() first).
        from messagefoundry.transports.smart import token_provider_from_settings

        self._base: dict[str, str] = {}
        self._headers: dict[str, dict[str, str]] = {}
        self._timeout: dict[str, float] = {}
        self._encoding: dict[str, str] = {}
        self._opener: dict[str, urllib.request.OpenerDirector] = {}
        self._token: dict[str, Any] = {}  # name -> SmartBackendTokenProvider | None
        for cname, raw in connections.items():
            s = dict(raw)
            url = s.get("url")
            if not isinstance(url, str) or not url:
                raise ValueError(
                    f"FhirLookup {cname!r} requires a 'url' setting (the FHIR base URL)"
                )
            scheme = urllib.parse.urlsplit(url).scheme.lower()
            if scheme not in ("http", "https"):
                raise ValueError(
                    f"FhirLookup {cname!r} 'url' must be http or https, got scheme {scheme!r}"
                )
            self._base[cname] = url
            self._timeout[cname] = float(s.get("timeout_seconds", 30.0))
            self._encoding[cname] = str(s.get("encoding", "utf-8"))
            headers = self._build_headers(s)
            # The read sends Authorization (static or SMART) — refuse it over cleartext http.
            token = token_provider_from_settings(s)
            check_headers = {**headers, "Authorization": "Bearer"} if token is not None else headers
            refuse_cleartext_credentials(scheme, check_headers, url)
            self._headers[cname] = headers
            self._token[cname] = token
            if bool(s.get("verify_tls", True)):
                self._opener[cname] = _NO_REDIRECT_OPENER
            else:
                if scheme == "https" and not insecure_tls_allowed():
                    raise ValueError(
                        f"FhirLookup {cname!r} verify_tls=false disables TLS certificate verification; "
                        f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set (dev/trusted-network only)"
                    )
                logger.warning(
                    "FhirLookup %s has TLS verification DISABLED (verify_tls=false)",
                    _redact_url(url),
                )
                self._opener[cname] = _insecure_opener()

    @staticmethod
    def _build_headers(s: Mapping[str, Any]) -> dict[str, str]:
        """``Accept: application/fhir+json`` + static ``headers`` + optional static bearer/basic auth (a
        SMART bearer, when composed, is injected per-request in :meth:`_get`, overriding any static one)."""
        media = "application/fhir+json"
        headers: dict[str, str] = {"Accept": media}
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

    @property
    def connections(self) -> frozenset[str]:
        """The declared lookup connection names."""
        return frozenset(self._base)

    async def read(self, connection: str, query: str) -> dict[str, Any]:
        """Issue a read-only ``GET`` for ``query`` against ``connection`` and return the parsed result.

        Runs the blocking GET **off the event loop** (the engine loop awaits this; ``fhir_lookup`` bridges
        in from the handler's worker thread via ``run_coroutine_threadsafe``). Raises
        :class:`~messagefoundry.config.fhir_lookup.FhirLookupError` (PHI/secret-safe) on an unknown
        connection, an invalid query path, a non-2xx, an unparseable body, or a network/timeout error."""
        # Lazy import keeps transports/ from importing config at module load (config imports transports).
        from messagefoundry.config.fhir_lookup import FhirLookupError

        if connection not in self._base:
            known = ", ".join(sorted(self._base)) or "(none declared)"
            raise FhirLookupError(
                f"fhir_lookup: no FhirLookup connection named {connection!r} (declared: {known})"
            )
        try:
            url = _resolve_read_url(self._base[connection], query)
        except ValueError as exc:
            # PHI-safe: _resolve_read_url names only the offending shape/segment, never the query values.
            raise FhirLookupError(f"fhir_lookup on {connection!r}: {exc}") from exc
        body, status = await asyncio.to_thread(self._get, connection, url)
        return self._parse(connection, body, status)

    def _get(self, connection: str, url: str) -> tuple[str, int]:
        """The blocking GET (off-loop). Injects a fresh SMART bearer when composed; on a 401 invalidates
        the cached token so the next read re-mints. PHI/secret-safe: errors name only the redacted host +
        HTTP status, never the body or token."""
        from messagefoundry.config.fhir_lookup import FhirLookupError

        base = self._base[connection]
        encoding = self._encoding[connection]
        headers = dict(self._headers[connection])
        token = self._token[connection]
        if token is not None:
            headers["Authorization"] = f"Bearer {token.access_token()}"
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            url, headers=headers, method="GET"
        )
        try:
            with self._opener[connection].open(req, timeout=self._timeout[connection]) as resp:
                read_body = resp.read().decode(encoding, errors="replace")
                status = int(getattr(resp, "status", 200))
                return read_body, status
        except urllib.error.HTTPError as exc:
            if token is not None and exc.code == 401:
                token.invalidate()  # the bearer may have expired between mint and use — drop it
            raise FhirLookupError(
                f"fhir_lookup on {connection!r}: FHIR {_redact_url(base)} returned HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise FhirLookupError(
                f"fhir_lookup on {connection!r}: FHIR {_redact_url(base)} unreachable: {exc.reason}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise FhirLookupError(
                f"fhir_lookup on {connection!r}: FHIR {_redact_url(base)} failed: {exc}"
            ) from exc

    def _parse(self, connection: str, body: str, status: int) -> dict[str, Any]:
        """Parse a 2xx reply body into a resource / searchset ``Bundle`` dict via the pure codec. PHI-safe:
        an unparseable body / error OperationOutcome names only the connection + a routing-safe issue
        code/status, never the body."""
        from messagefoundry.config.fhir_lookup import FhirLookupError

        try:
            return FhirPeek.parse(body).obj
        except FhirPeekError as exc:
            raise FhirLookupError(
                f"fhir_lookup on {connection!r}: FHIR server returned an unparseable body (HTTP {status})"
            ) from exc

    async def test_connection(self, connection: str) -> None:
        """Reachability probe: a ``GET {base}/metadata`` (the ``CapabilityStatement``) over the hardened
        opener — reaches the server without reading a clinical resource. Any HTTP response means the host
        answered; a 401/403 means the configured credentials would be rejected (mirrors
        :meth:`FhirDestination._probe`). Runs off the event loop."""
        await asyncio.to_thread(self._probe, connection)

    def _probe(self, connection: str) -> None:
        from messagefoundry.config.fhir_lookup import FhirLookupError

        base = self._base[connection]
        url = f"{base.rstrip('/')}/metadata"
        headers = dict(self._headers[connection])
        token = self._token[connection]
        if token is not None:
            headers["Authorization"] = f"Bearer {token.access_token()}"
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            url, headers=headers, method="GET"
        )
        try:
            with self._opener[connection].open(req, timeout=self._timeout[connection]) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise FhirLookupError(
                    f"FhirLookup {connection!r}: FHIR {_redact_url(base)} returned HTTP {exc.code} "
                    "(check credentials)"
                ) from exc
            return  # any other status (the host answered) → reachable
        except urllib.error.URLError as exc:
            raise FhirLookupError(
                f"FhirLookup {connection!r}: FHIR {_redact_url(base)} unreachable: {exc.reason}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise FhirLookupError(
                f"FhirLookup {connection!r}: FHIR {_redact_url(base)} failed: {exc}"
            ) from exc
