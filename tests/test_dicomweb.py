# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DICOMweb STOW-RS destination tests (ADR 0025 Phase 2): target-URL derivation, the
``multipart/related; type="application/dicom"`` framing, the dicom+json FailedSOPSequence / HTTP-status
classification (transient retry vs permanent dead-letter), response capture, and the egress arm.

The opener is faked so nothing hits the network — and because the destination treats the object as
**opaque bytes** (no pydicom parse), these tests need **no** ``[dicom]`` extra and run on every CI leg."""

from __future__ import annotations

import email.message
import io
import json
import urllib.error
import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import DICOMweb
from messagefoundry.parsing import RawMessage
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, DeliveryResponse, NegativeAckError
from messagefoundry.transports.dicomweb import DicomWebDestination

BASE = "https://pacs.example.org/dicom-web"
# An opaque "DICOM object" — the destination never parses it, so any bytes exercise the carriage + framing.
OBJECT = b"\x00" * 128 + b"DICM" + b"synthetic-part10-bytes"
PAYLOAD = RawMessage.from_bytes(
    OBJECT, "dicom"
).encode()  # the mfb64:v1: carriage a Handler hands over

# A STOW-RS dicom+json success body (RetrievedURL + ReferencedSOPSequence, no FailedSOPSequence).
STORED_OK = json.dumps(
    {
        "00081190": {"vr": "UR", "Value": [f"{BASE}/studies/1.2.3"]},
        "00081199": {"vr": "SQ", "Value": [{}]},
    }
)
# A dicom+json body carrying a non-empty FailedSOPSequence (00081198) → an instance was rejected.
STORED_FAILED = json.dumps(
    {"00081198": {"vr": "SQ", "Value": [{"00081197": {"vr": "US", "Value": [272]}}]}}
)


def _dest(**over: object) -> DicomWebDestination:
    settings = DICOMweb(url=BASE, **over).settings  # type: ignore[arg-type]
    d = build_destination(
        Destination(name="OB_DCMWEB", type=ConnectorType.DICOMWEB, settings=settings)
    )
    assert isinstance(d, DicomWebDestination)
    return d


def _http_error(code: int, body: bytes = b"") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(BASE, code, "err", email.message.Message(), io.BytesIO(body))


class _FakeResp:
    def __init__(self, body: bytes = b"", status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _FakeOpener:
    """Records the Request, then returns a chosen response or raises a chosen error."""

    def __init__(self, exc: Exception | None = None, body: bytes = b"", status: int = 200) -> None:
        self.exc = exc
        self.body = body
        self.status = status
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResp:
        self.requests.append(req)
        if self.exc is not None:
            raise self.exc
        return _FakeResp(self.body, self.status)


def _headers(req: urllib.request.Request) -> dict[str, str]:
    return {k.lower(): v for k, v in req.header_items()}


# --- construction / validation ----------------------------------------------


def test_dicomweb_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError, match="http or https"):
        build_destination(
            Destination(
                name="OB", type=ConnectorType.DICOMWEB, settings=DICOMweb(url="ftp://x/y").settings
            )
        )


def test_dicomweb_requires_url() -> None:
    with pytest.raises(ValueError, match="requires a 'url'"):
        build_destination(
            Destination(name="OB", type=ConnectorType.DICOMWEB, settings={"study_uid": "1.2.3"})
        )


def test_dicomweb_target_url_without_study() -> None:
    assert _dest()._target_url == f"{BASE}/studies"


def test_dicomweb_target_url_with_study() -> None:
    assert _dest(study_uid="1.2.840.1")._target_url == f"{BASE}/studies/1.2.840.1"


def test_dicomweb_study_uid_control_char_rejected() -> None:
    with pytest.raises(ValueError, match="illegal control character"):
        _dest(study_uid="1.2.3\r\nHost: evil")


def test_dicomweb_cleartext_credentials_refused() -> None:
    # Basic/bearer over plain http puts the credential on the wire — refused (mirrors REST/FHIR).
    with pytest.raises(ValueError, match="cleartext"):
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.DICOMWEB,
                settings=DICOMweb(
                    url="http://pacs.example.org/dicom-web", bearer_token="t"
                ).settings,
            )
        )


# --- multipart framing -------------------------------------------------------


async def test_dicomweb_frames_multipart_related() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(body=STORED_OK.encode())  # type: ignore[assignment]
    result = await dest.send(PAYLOAD)
    assert result is None  # capture off → byte-identical None
    req = dest._opener.requests[0]  # type: ignore[attr-defined]
    headers = _headers(req)
    assert headers["accept"] == "application/dicom+json"
    ct = headers["content-type"]
    assert ct.startswith("multipart/related")
    assert 'type="application/dicom"' in ct
    assert req.get_method() == "POST"
    assert req.full_url == f"{BASE}/studies"
    # The boundary in the Content-Type header must frame the part: the body opens with --<boundary> and
    # closes with --<boundary>-- (a malformed close would be rejected by a real STOW-RS server).
    boundary = ct.split("boundary=", 1)[1].strip()
    assert boundary  # non-empty
    body = req.data
    assert isinstance(body, bytes)
    delim = boundary.encode("ascii")
    assert body.startswith(b"--" + delim + b"\r\n")
    assert body.endswith(b"--" + delim + b"--\r\n")
    assert b"Content-Type: application/dicom\r\n\r\n" in body
    assert OBJECT in body  # the exact object bytes ride the part, byte-faithfully


async def test_dicomweb_boundary_is_fresh_and_collision_safe() -> None:
    # A fresh random boundary per request (so a retry re-frames) that is guaranteed absent from the bytes.
    dest = _dest()
    dest._opener = _FakeOpener(body=STORED_OK.encode())  # type: ignore[assignment]
    await dest.send(PAYLOAD)
    await dest.send(PAYLOAD)
    reqs = dest._opener.requests  # type: ignore[attr-defined]
    b0 = _headers(reqs[0])["content-type"].split("boundary=", 1)[1]
    b1 = _headers(reqs[1])["content-type"].split("boundary=", 1)[1]
    assert b0 != b1  # fresh per request
    # If the object literally contains the delimiter, _multipart_body regenerates until absent.
    colliding = b"--" + b0.encode("ascii") + b" embedded in the object"
    body, boundary = DicomWebDestination._multipart_body(colliding)
    assert b"--" + boundary.encode("ascii") not in colliding


# --- classification ----------------------------------------------------------


async def test_dicomweb_2xx_success_delivers() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(body=STORED_OK.encode(), status=200)  # type: ignore[assignment]
    assert await dest.send(PAYLOAD) is None


async def test_dicomweb_failed_sop_sequence_is_permanent() -> None:
    # A 2xx envelope whose body reports a FailedSOPSequence → the instance was rejected → dead-letter.
    dest = _dest()
    dest._opener = _FakeOpener(body=STORED_FAILED.encode(), status=200)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.permanent is True


@pytest.mark.parametrize("code", [500, 503, 408, 429])
async def test_dicomweb_transient_statuses_retry(code: int) -> None:
    dest = _dest()
    dest._opener = _FakeOpener(exc=_http_error(code))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as exc:
        await dest.send(PAYLOAD)
    assert not isinstance(exc.value, NegativeAckError)  # transient, not a permanent dead-letter


@pytest.mark.parametrize("code", [400, 403, 409])
async def test_dicomweb_permanent_statuses_dead_letter(code: int) -> None:
    dest = _dest()
    dest._opener = _FakeOpener(exc=_http_error(code))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.permanent is True


async def test_dicomweb_unreachable_is_transient() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(exc=urllib.error.URLError("connection refused"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as exc:
        await dest.send(PAYLOAD)
    assert not isinstance(exc.value, NegativeAckError)


async def test_dicomweb_bad_carriage_is_permanent() -> None:
    dest = _dest()
    dest._opener = _FakeOpener()  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send("not-a-carriage-value")
    assert exc.value.permanent is True
    assert dest._opener.requests == []  # type: ignore[attr-defined]  # never hit the network


# --- response capture (ADR 0013) --------------------------------------------


async def test_dicomweb_capture_response() -> None:
    dest = _dest(capture_response=True)
    dest._opener = _FakeOpener(body=STORED_OK.encode(), status=200)  # type: ignore[assignment]
    resp = await dest.send(PAYLOAD)
    assert isinstance(resp, DeliveryResponse)
    assert resp.outcome == "accepted"
    assert resp.detail == "HTTP 200"
    assert resp.body == STORED_OK  # the dicom+json body is captured verbatim


async def test_dicomweb_capture_empty_response_is_no_reply() -> None:
    dest = _dest(capture_response=True)
    dest._opener = _FakeOpener(body=b"", status=200)  # type: ignore[assignment]
    resp = await dest.send(PAYLOAD)
    assert isinstance(resp, DeliveryResponse)
    assert resp.outcome == "no_reply"
    assert resp.body == ""
    assert resp.detail == "HTTP 200"


# --- test_connection / reachability probe ------------------------------------


async def test_dicomweb_probe_reachable() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(status=200)  # type: ignore[assignment]
    await dest.test_connection()  # no raise
    assert dest._opener.requests[0].get_method() == "OPTIONS"  # type: ignore[attr-defined]


@pytest.mark.parametrize("code", [401, 403])
async def test_dicomweb_probe_credential_failure(code: int) -> None:
    dest = _dest()
    dest._opener = _FakeOpener(exc=_http_error(code))  # type: ignore[assignment]
    with pytest.raises(DeliveryError, match="credentials"):
        await dest.test_connection()


async def test_dicomweb_probe_other_status_is_reachable() -> None:
    # The host answered (even a 404/405) → reachable, not an error.
    dest = _dest()
    dest._opener = _FakeOpener(exc=_http_error(404))  # type: ignore[assignment]
    await dest.test_connection()  # no raise


async def test_dicomweb_probe_unreachable_raises() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(exc=urllib.error.URLError("no route"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError, match="unreachable"):
        await dest.test_connection()
