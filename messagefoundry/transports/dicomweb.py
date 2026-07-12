# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DICOMweb STOW-RS transport (ADR 0025 Phase 2): an HTTP destination that **stores** a DICOM object to
a DICOMweb service via STOW-RS.

``DicomWebDestination`` is a sibling :class:`~messagefoundry.transports.base.DestinationConnector` that
**reuses** the hardened HTTP plumbing in :mod:`messagefoundry.transports.rest` — exactly as
:mod:`messagefoundry.transports.fhir` and :mod:`messagefoundry.transports.soap` do — rather than wrapping
``RestDestination``: the no-redirect, http(s)-only, TLS-verifying opener (a 3xx can't divert a
PHI-bearing POST to an unintended host; ASVS 15.3.2), the cleartext-credential refusal, and the outbound
length limits. The fail-closed ``[egress].allowed_http`` host gate is enforced by the runner (it folds
DICOMWEB into the REST/SOAP/FHIR arm — see wiring_runner ``_allowlist_for`` / ``check_egress_allowed``).
It needs **no** ``pydicom``: the object rides as opaque bytes, so DICOMweb works without the DIMSE stack.

**STOW-RS layer (on top of REST):**
- The outgoing object is a **binary** DICOM Part-10 body, base64-carried through the str/store substrate
  (ADR 0028); the bytes are recovered via the shared
  :func:`~messagefoundry.transports.dicom.recover_dicom_object_bytes` (the one decode) and framed as a
  ``multipart/related; type="application/dicom"`` request body — **one instance per request** (a
  single-instance MVP; multi-instance batching is deferred).
- ``POST {base}/studies`` (the server assigns the study) or ``POST {base}/studies/{study_uid}`` (store
  into a known study) when a ``study_uid`` is configured. ``Accept: application/dicom+json``.
- Response classification refines the HTTP-status retry model: a 2xx whose ``application/dicom+json`` body
  carries a per-instance **FailedSOPSequence** (``00081198``) → the instance was rejected → permanent
  dead-letter; other 4xx / a 409 (all instances failed) / a refused 3xx → permanent; 5xx / 408 / 429 /
  connection-timeout → transient retry. **The HTTP status wins when in doubt; a 5xx stays transient.**

**PHI:** a STOW-RS ``dicom+json`` response can name patient/study identifiers, so it is **never** echoed
into a log/error — only the HTTP status and a redacted URL are. **Idempotency:** delivery is
at-least-once, so a retry re-stores the same object; a re-store of the same ``SOPInstanceUID`` is the
native idempotency lever (STOW-RS treats it as already-stored).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    NegativeAckError,
    register_destination,
)
from messagefoundry.transports.dicom import recover_dicom_object_bytes

# Reuse REST's hardened HTTP plumbing — same transports/ package, same no-redirect + TLS posture (NOT a
# wrapper around RestDestination; ADR 0025 §2, exactly as fhir.py / soap.py do).
from messagefoundry.transports.rest import (
    _NO_REDIRECT_OPENER,
    _RETRYABLE_4XX,
    _insecure_opener,
    _redact_url,
    InsecureHopGuard,
    enforce_outbound_length_limits,
    refuse_cleartext_credentials,
    refuse_cleartext_egress,
    refuse_verify_off,
)

__all__ = ["DicomWebDestination"]

logger = logging.getLogger(__name__)

# A per-request random multipart boundary (RFC 2046 §5.1.1), generated fresh in _multipart_body and
# verified absent from the object bytes — a collision would let a conforming STOW-RS server split the part
# early (truncating the stored PHI) or smuggle a forged part. A different boundary on a retry is harmless:
# it is transport framing, not message content, and a re-store of the same SOPInstanceUID is idempotent
# (the same posture as rest.py minting a fresh JWS/SMART credential per send).
_BOUNDARY_PREFIX = "mf-stow-"
_DICOM_PART_TYPE = "application/dicom"
_DICOM_JSON = "application/dicom+json"
# DICOM Tag (group,element) for the STOW-RS FailedSOPSequence in the dicom+json response (DICOM PS3.18).
_FAILED_SOP_SEQUENCE = "00081198"


def _reject_url_control_chars(value: str, field: str) -> None:
    """Reject a configured value that carries a C0/DEL control char before it flows into the URL path. A
    CR/LF in ``study_uid`` would let it split the request line; urllib would reject it with a bare
    ``ValueError`` at send. Surface it as a clear construction-time ``ValueError`` (caught at
    ``check``/dry-run as a ``WiringError``) — PHI-safe (names the field, never the value)."""
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"DICOMweb {field} contains an illegal control character")


def _stowrs_failed(body: str) -> bool:
    """True if the STOW-RS ``application/dicom+json`` response carries a non-empty ``FailedSOPSequence``
    — i.e. at least one instance was rejected despite a 2xx envelope. Tolerant of shape; PHI-safe (reads
    only the *presence* of the failure sequence, never its contents)."""
    try:
        obj = json.loads(body)
    except ValueError:
        return False
    # The response is a single dicom+json dataset object (defensively also accept a 1-element list).
    datasets = obj if isinstance(obj, list) else [obj]
    for ds in datasets:
        if not isinstance(ds, dict):
            continue
        failed = ds.get(_FAILED_SOP_SEQUENCE)
        if isinstance(failed, dict):
            value = failed.get("Value")
            if isinstance(value, list) and value:
                return True
    return False


def _classify_stowrs(status: int, base_url: str) -> DeliveryError:
    """Classify a non-2xx STOW-RS response. 5xx / 408 / 429 → transient :class:`DeliveryError`; other 4xx
    (incl. 409 'all instances failed') / a refused 3xx → permanent :class:`NegativeAckError`. PHI-safe:
    only the status + a redacted URL are named, never the ``dicom+json`` body."""
    if status in _RETRYABLE_4XX or 500 <= status < 600:
        return DeliveryError(f"DICOMweb {_redact_url(base_url)} returned HTTP {status}")
    return NegativeAckError(
        f"DICOMweb {_redact_url(base_url)} rejected with HTTP {status}",
        code=str(status),
        permanent=True,
    )


class DicomWebDestination(DestinationConnector):
    """Store a DICOM object to a DICOMweb service via STOW-RS (outbound only; ADR 0025 Phase 2)."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        url = s.get("url")
        if not isinstance(url, str) or not url:
            raise ValueError(
                "DICOMweb destination requires a 'url' setting (the DICOMweb service base URL)"
            )
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(
                f"DICOMweb destination 'url' must be http or https, got scheme {scheme!r}"
            )
        self.base_url = url
        study_uid = s.get("study_uid")
        self.study_uid: str | None = str(study_uid) if study_uid else None
        if self.study_uid is not None:
            _reject_url_control_chars(self.study_uid, "study_uid")  # it flows into the URL path
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.encoding: str = s.get("encoding", "utf-8")
        # ADR 0013: capture the STOW-RS dicom+json response. Default False → returns None, byte-identical.
        self.capture_response: bool = bool(s.get("capture_response", False))
        # #200 (ADR 0092): the per-connection insecure-hop attestation, keying the posture-keyed refusal.
        attested = config.tls_hop_attested
        # Captured at construction; re-asserted (zero I/O) at the byte-crossing in _post (decision 4).
        self._hop_guard: InsecureHopGuard | None = None
        self._headers = self._build_headers(s)
        # The multipart Content-Type (with the generated boundary) is set per-request in _post — it is not
        # operator-supplied, so it is excluded from the length check (which guards URL + supplied headers).
        enforce_outbound_length_limits(self.base_url, self._headers)
        refuse_cleartext_credentials(scheme, self._headers, self.base_url, attested=attested)
        # ASVS 12.2.1: the STOW-RS multipart body carries the DICOM object (PHI), so a cleartext http
        # egress to a non-loopback host is refused even without credentials (loopback byte-identical).
        self._hop_guard = refuse_cleartext_egress(scheme, self.base_url, attested=attested)
        if bool(s.get("verify_tls", True)):
            self._opener: urllib.request.OpenerDirector = _NO_REDIRECT_OPENER
        else:
            # verify_tls=false makes the https hop MITM-able — a posture-keyed insecure hop (#200).
            guard = refuse_verify_off(
                scheme, self.base_url, connector="DICOMweb destination", attested=attested
            )
            if guard is not None:
                self._hop_guard = guard
            logger.warning(
                "DICOMweb destination %s has TLS verification DISABLED (verify_tls=false)",
                _redact_url(self.base_url),
            )
            self._opener = _insecure_opener()
        self._target_url = self._resolve_target_url()

    def _resolve_target_url(self) -> str:
        """``{base}/studies`` (server assigns the study) or ``{base}/studies/{study_uid}`` when set."""
        base = self.base_url.rstrip("/")
        if self.study_uid:
            return f"{base}/studies/{self.study_uid}"
        return f"{base}/studies"

    def _build_headers(self, s: dict[str, Any]) -> dict[str, str]:
        """STOW-RS request headers: ``Accept: application/dicom+json`` + static ``headers`` + optional
        bearer/basic auth. The multipart ``Content-Type`` (with the boundary) is set per-request in
        :meth:`_post`, not here."""
        headers: dict[str, str] = {"Accept": _DICOM_JSON}
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

    @staticmethod
    def _multipart_body(dicom_bytes: bytes) -> tuple[bytes, str]:
        """Frame one DICOM instance as a ``multipart/related`` body (STOW-RS single-instance MVP), with a
        fresh random boundary **guaranteed absent** from the object bytes (RFC 2046 §5.1.1). Returns
        ``(body, boundary)`` so the caller sets the matching ``Content-Type`` boundary parameter."""
        boundary = _BOUNDARY_PREFIX + secrets.token_hex(16)
        # The delimiter a parser scans for is "\r\n--<boundary>"; regenerate (practically never) on the
        # astronomically-unlikely chance the random token collides with the binary payload.
        while b"--" + boundary.encode("ascii") in dicom_bytes:
            boundary = _BOUNDARY_PREFIX + secrets.token_hex(16)
        crlf = b"\r\n"
        delim = boundary.encode("ascii")
        body = b"".join(
            [
                b"--",
                delim,
                crlf,
                b"Content-Type: ",
                _DICOM_PART_TYPE.encode("ascii"),
                crlf,
                crlf,
                dicom_bytes,
                crlf,
                b"--",
                delim,
                b"--",
                crlf,
            ]
        )
        return body, boundary

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): unused — no per-message header knob here
        dicom_bytes = recover_dicom_object_bytes(payload, label="DICOMweb STOW-RS")
        # urllib is blocking — keep it off the event loop (the delivery worker awaits this).
        body, status = await asyncio.to_thread(self._post, dicom_bytes)
        # A non-2xx already raised inside _post (transient retry / permanent dead-letter). Here status is
        # 2xx: a body that reports a FailedSOPSequence means the instance was rejected despite the 2xx.
        if _stowrs_failed(body):
            raise NegativeAckError(
                f"DICOMweb {_redact_url(self.base_url)} returned HTTP {status} with a FailedSOPSequence "
                "(instance rejected)",
                code="failed-sop",
                permanent=True,
            )
        if not self.capture_response:
            return None
        if not body:
            return DeliveryResponse(body="", outcome="no_reply", detail=f"HTTP {status}")
        return DeliveryResponse(body=body, outcome="accepted", detail=f"HTTP {status}")

    async def test_connection(self) -> None:
        await asyncio.to_thread(self._probe)

    def _probe(self) -> None:
        # Reachability only: an OPTIONS to the studies endpoint reaches the host without storing an object.
        # Any HTTP response means the host answered; 401/403 means the configured credentials would be
        # rejected (which a real store dead-letters). Connection/DNS/TLS/timeout always fails.
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self._target_url, headers=self._headers, method="OPTIONS"
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise DeliveryError(
                    f"DICOMweb {_redact_url(self.base_url)} returned HTTP {exc.code} (check credentials)"
                ) from exc
            return  # any other status (the host answered) → reachable
        except urllib.error.URLError as exc:
            raise DeliveryError(
                f"DICOMweb {_redact_url(self.base_url)} unreachable: {exc.reason}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"DICOMweb {_redact_url(self.base_url)} failed: {exc}") from exc

    def _post(self, dicom_bytes: bytes) -> tuple[str, int]:
        # #200 (ADR 0092 decision 4): zero-I/O send-time re-assertion of a permitted insecure hop before
        # a byte crosses (a None guard — secure/loopback — is byte-identical).
        if self._hop_guard is not None:
            self._hop_guard.assert_send(
                urllib.parse.urlsplit(self.base_url).hostname or "", _redact_url(self.base_url)
            )
        data, boundary = self._multipart_body(dicom_bytes)
        headers = {
            **self._headers,
            "Content-Type": f'multipart/related; type="{_DICOM_PART_TYPE}"; boundary={boundary}',
        }
        try:
            req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
                self._target_url,
                data=data,
                headers=headers,
                method="POST",
            )
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode(self.encoding, errors="replace")
                status = int(getattr(resp, "status", 200))
                return body, status
        except urllib.error.HTTPError as exc:
            # Non-2xx: classify transient vs permanent. Raised for BOTH capturing and non-capturing — a
            # non-2xx is a transport/server failure, not a captured reply. PHI-safe: never the body.
            raise _classify_stowrs(exc.code, self.base_url) from exc
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise DeliveryError(
                f"DICOMweb {_redact_url(self.base_url)} unreachable: {exc.reason}"
            ) from exc
        except ValueError as exc:
            # urllib rejected an illegal request value (a CRLF in a header/URL slipped past the guard). A
            # retry re-sends the same request → permanent. PHI-safe: redacted url only.
            raise NegativeAckError(
                f"DICOMweb {_redact_url(self.base_url)} rejected an invalid request value",
                code="bad-request-value",
                permanent=True,
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"DICOMweb {_redact_url(self.base_url)} failed: {exc}") from exc


register_destination(ConnectorType.DICOMWEB, DicomWebDestination)
