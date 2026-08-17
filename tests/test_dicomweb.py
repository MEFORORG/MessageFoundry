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
import logging
import urllib.error
import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
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


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("headers", {"X-Site": "a\r\nX-Evil: 1"}),  # CRLF in an operator header VALUE
        ("headers", {"X-Site\r\nX-Evil": "1"}),  # CRLF in an operator header NAME
        ("headers", {"X-Site": "a\x00b"}),  # NUL in a value
        ("bearer_token", "tok\r\nX-Evil: 1"),  # CRLF in the credential -> Authorization header
    ],
)
def test_dicomweb_operator_header_control_char_rejected(
    setting: str, value: object
) -> None:  # #1241
    """`study_uid` was screened at construction; the other operator-configured settings that reach the
    same wire were not. `headers` merged straight into the request headers and `bearer_token` went
    into `Authorization` verbatim, so a CRLF in either is a header injection with nothing in front of
    it -- and unlike a URL there is no incidental neutralisation on a header value.

    Screened at CONSTRUCTION for the same reason as the sibling settings: a bad SETTING is wrong for
    every message the connection will ever send, so it must fail the connection at load rather than
    dead-letter an unbounded stream of messages that were never at fault.
    """
    with pytest.raises(ValueError, match="illegal control character"):
        _dest(**{setting: value})  # type: ignore[arg-type]


def test_dicomweb_base_url_control_char_rejected() -> None:  # #1241
    with pytest.raises(ValueError, match="illegal control character"):
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.DICOMWEB,
                settings=DICOMweb(url="https://pacs.example.org/dicom-web\r\nX-Evil: 1").settings,
            )
        )


def test_dicomweb_clean_operator_headers_still_construct() -> None:  # #1241
    """Positive control: the screen must admit what it is not screening for."""
    d = _dest(headers={"X-Site": "site-a", "X-Trace": "abc-123"})
    assert d._headers["X-Site"] == "site-a"
    assert d._headers["X-Trace"] == "abc-123"


@pytest.mark.parametrize(
    "uid",
    [
        "../../metadata",  # path traversal out of /studies/ entirely
        "1.2.3/../../metadata",  # traversal that starts out looking like a UID
        "1.2.3/series",  # a second path segment -- a different STOW-RS endpoint
        "1.2.3?bulk=1",  # a query the service would act on
        "1.2.3#frag",  # a fragment
        "user@evil.example.org",  # userinfo shape
        "1.2.3 4",  # space
        "1.2.é3",  # non-ASCII: outside the grammar, and NOT a control char
        "1..2",  # empty component -- admitted by a lazy [0-9.] class, refused by this one
        ".1.2",  # leading dot
        "1.2.",  # trailing dot
        "1.2.3" + ".9" * 40,  # 85 chars: over the PS3.5 64-character limit
    ],
)
def test_dicomweb_study_uid_grammar_rejected(uid: str) -> None:  # #1241
    """The remaining half of this item: `study_uid` had the control-char screen but NO grammar gate, so
    every value here reached `{base}/studies/{study_uid}` unaltered. `has_control_char` is a C0/DEL
    predicate -- it does not know what a path metacharacter is, and none of these carries a control
    character, so all twelve passed the only screen in front of them.

    The sharp ones are the traversals: `../../metadata` redirects a PHI-bearing STOW-RS POST off the
    study endpoint entirely, to another service on the same allow-listed host (CWE-918), which no
    egress allow-list catches because the HOST never changes.

    Refused at CONSTRUCTION, not at the URL layer -- a bad SETTING is wrong for every message the
    connection will ever send, so it must fail the connection at load rather than dead-letter an
    unbounded stream of messages that were never at fault (the same reasoning as the sibling screens).
    """
    with pytest.raises(ValueError, match="DICOM UID"):
        _dest(study_uid=uid)


@pytest.mark.parametrize(
    "uid",
    [
        "1.2.840.10008.5.1.4.1.1.2",  # a real DICOM SOP-class-shaped UID
        "1",  # single component
        "1.2.3",
        "0.0.0",  # the component "0" is legal on its own
        "1.02.3",  # leading zero: PS3.5 forbids it, this gate DELIBERATELY admits it
        "9" * 64,  # exactly at the 64-character limit, not over it
    ],
)
def test_dicomweb_valid_study_uid_still_constructs(uid: str) -> None:  # #1241
    """Positive control -- without it a gate that refused EVERYTHING would pass the test above.

    `1.02.3` is the deliberate admission: a leading zero is a PS3.5 conformance violation, not a
    security one, and refusing a real-world non-conformant UID at startup would block a legitimate
    deployment without excluding a single character the gate exists to exclude.
    """
    assert _dest(study_uid=uid)._target_url == f"{BASE}/studies/{uid}"


def test_dicomweb_uid_screen_rejects_a_trailing_newline_on_its_own() -> None:  # #1241
    """Tests the screen DIRECTLY, because via `_dest` the control-char screen would catch this first
    and the two failures are indistinguishable from outside.

    A `$`-anchored regex would have ADMITTED this -- `$` matches immediately before a trailing
    newline, which is #1240's defect exactly. The split-and-check excludes it structurally: the
    newline lands inside the final component and is not an ASCII digit. Pinned so a later rewrite back
    to a regex cannot quietly reopen it.
    """
    from messagefoundry.transports.dicomweb import _reject_non_uid

    with pytest.raises(ValueError, match="DICOM UID"):
        _reject_non_uid("1.2.3\n", "study_uid")
    _reject_non_uid("1.2.3", "study_uid")  # positive control: the clean value still passes


def test_dicomweb_study_uid_percent_encode_is_a_noop_today() -> None:  # #1241
    """The percent-encode at the sink matches the `fhir.py` path-segment treatment this file was
    asymmetric with. It is a NO-OP while the grammar holds -- digits and dots are both RFC 3986
    unreserved -- and this test pins that, so the encode can never be blamed for a changed URL.

    It is defence-in-depth against a LATER loosening of the grammar, not a control that does work
    today; the grammar gate above is what actually contains the value.
    """
    uid = "1.2.840.10008.1.1"
    assert (
        _dest(study_uid=uid)._target_url == f"{BASE}/studies/{uid}"
    )  # byte-identical, nothing encoded


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


def test_dicomweb_cleartext_http_nonloopback_refused_without_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ASVS 12.2.1: the STOW-RS body carries the DICOM object (PHI), so a cleartext http egress to a
    # non-loopback host is refused even with NO credentials, unless the explicit escape is set.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="cleartext http to a non-loopback host"):
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.DICOMWEB,
                settings=DICOMweb(url="http://pacs.example.org/dicom-web").settings,
            )
        )


def test_dicomweb_cleartext_http_loopback_allowed() -> None:
    # On-box loopback cleartext egress is not a network exposure → allowed (byte-identical posture).
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.DICOMWEB,
            settings=DICOMweb(url="http://127.0.0.1:8042/dicom-web").settings,
        )
    )
    assert isinstance(dest, DicomWebDestination)


def test_dicomweb_cleartext_http_nonloopback_allowed_when_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ADR 0153: the blunt MEFOR_ALLOW_INSECURE_TLS escape no longer influences a cleartext-hop
    # decision (decision 5). The per-connection declaration is what crosses it now — loudly, and
    # recorded in the audit trail, instead of a process-wide env var nobody sees in review.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(HopPosture(is_phi=True, enforcing=True)):
        dest = build_destination(
            Destination(
                name="OB",
                type=ConnectorType.DICOMWEB,
                settings=DICOMweb(url="http://pacs.example.org/dicom-web").settings,
                cleartext_accepted=True,
                cleartext_reason="legacy partner endpoint has no TLS",
            )
        )
    assert isinstance(dest, DicomWebDestination)  # built (warns loudly + audits), not refused


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


# --- PHI no-log regression guard (DICOM-23; parity with test_dicom_scu/scp) --

# A STOW-RS dicom+json body can name patient/study identifiers. This canary stands in for that PHI:
# it must never surface in a log record or a raised exception message (only status + redacted URL may).
_PHI_CANARY = "Secretpatient^Phicanary^DoNotLog"


async def test_dicomweb_failed_sop_response_body_not_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A 2xx FailedSOPSequence body carrying PHI -> permanent dead-letter, but the dicom+json body must
    # not reach any log record or the raised exception's message.
    failed_body = json.dumps(
        {
            "00081198": {
                "vr": "SQ",
                "Value": [
                    {
                        "00081197": {"vr": "US", "Value": [272]},
                        "00081155": {"vr": "UI", "Value": [_PHI_CANARY]},
                    }
                ],
            },
            "00100010": {"vr": "PN", "Value": [{"Alphabetic": _PHI_CANARY}]},
        }
    )
    dest = _dest()
    dest._opener = _FakeOpener(body=failed_body.encode(), status=200)  # type: ignore[assignment]
    # Root DEBUG: also covers any delivery-worker exception logging of the raised error.
    with caplog.at_level(logging.DEBUG), pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.permanent is True
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert _PHI_CANARY not in blob and "Secretpatient" not in blob
    assert _PHI_CANARY not in str(exc.value) and "Secretpatient" not in str(exc.value)


async def test_dicomweb_http_error_response_body_not_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A non-2xx STOW-RS reply whose error body carries PHI -> classified permanent, but the body must
    # not reach any log record or the raised exception's message (only status + redacted URL).
    error_body = json.dumps(
        {"00100010": {"vr": "PN", "Value": [{"Alphabetic": _PHI_CANARY}]}}
    ).encode()
    dest = _dest()
    dest._opener = _FakeOpener(exc=_http_error(409, error_body))  # type: ignore[assignment]
    with caplog.at_level(logging.DEBUG), pytest.raises(DeliveryError) as exc:
        await dest.send(PAYLOAD)
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert _PHI_CANARY not in blob and "Secretpatient" not in blob
    assert _PHI_CANARY not in str(exc.value) and "Secretpatient" not in str(exc.value)
