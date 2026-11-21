# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DICOMweb STOW-RS destination tests (ADR 0025 Phase 2): target-URL derivation, the
``multipart/related; type="application/dicom"`` framing, the dicom+json FailedSOPSequence / HTTP-status
classification (transient retry vs permanent dead-letter), response capture, and the egress arm.

The opener is faked so nothing hits the network — and because the destination treats the object as
**opaque bytes** (no pydicom parse), these tests need **no** ``[dicom]`` extra and run on every CI leg."""

from __future__ import annotations

import base64
import email.message
import http.client
import io
import json
import logging
import urllib.error
import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import DICOMweb
from messagefoundry.parsing import RawMessage
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, DeliveryResponse, NegativeAckError
from messagefoundry.transports.dicomweb import DicomWebDestination
from messagefoundry.transports.rest import HttpAuthError
from tests._malformed_reply import MALFORMED_REPLIES, RefusedAndMalformed

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
        "00081199": {"vr": "SQ", "Value": [{"00081155": {"vr": "UI", "Value": ["1.2.3.4.5"]}}]},
    }
)
# A dicom+json body carrying a non-empty FailedSOPSequence (00081198) → an instance was rejected.
STORED_FAILED = json.dumps(
    {"00081198": {"vr": "SQ", "Value": [{"00081197": {"vr": "US", "Value": [272]}}]}}
)


def _dest(**over: object) -> DicomWebDestination:
    settings = DICOMweb(url=BASE, **over).settings  # type: ignore[arg-type]
    d = build_destination(
        Destination(name="OB_DCMWEB", type=ConnectorType.DICOMWEB, settings=settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, DicomWebDestination)
    return d


def _http_error(code: int, body: bytes = b"") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(BASE, code, "err", email.message.Message(), io.BytesIO(body))


class _FakeResp:
    def __init__(self, body: bytes = b"", status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self, amt: int = -1) -> bytes:
        return self._body if amt < 0 else (self._body)[:amt]

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *a: object) -> None:
        return None


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
            ),
            egress=EgressSettings(deny_by_default=False),
        )


def test_dicomweb_requires_url() -> None:
    with pytest.raises(ValueError, match="requires a 'url'"):
        build_destination(
            Destination(name="OB", type=ConnectorType.DICOMWEB, settings={"study_uid": "1.2.3"}),
            egress=EgressSettings(deny_by_default=False),
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
        _dest(**{setting: value})


def test_dicomweb_base_url_control_char_rejected() -> None:  # #1241
    with pytest.raises(ValueError, match="illegal control character"):
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.DICOMWEB,
                settings=DICOMweb(url="https://pacs.example.org/dicom-web\r\nX-Evil: 1").settings,
            ),
            egress=EgressSettings(deny_by_default=False),
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
    with pytest.raises(ValueError, match=r"UID (limit of|for) DICOM"):
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

    with pytest.raises(ValueError, match=r"UID (limit of|for) DICOM"):
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
            ),
            egress=EgressSettings(deny_by_default=False),
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
            ),
            egress=EgressSettings(deny_by_default=False),
        )


def test_dicomweb_cleartext_http_loopback_allowed() -> None:
    # On-box loopback cleartext egress is not a network exposure → allowed (byte-identical posture).
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.DICOMWEB,
            settings=DICOMweb(url="http://127.0.0.1:8042/dicom-web").settings,
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(dest, DicomWebDestination)


def test_dicomweb_cleartext_http_nonloopback_allowed_when_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ADR 0153: the blunt MEFOR_ALLOW_INSECURE_TLS escape no longer influences a cleartext-hop
    # decision (decision 5). The per-connection declaration is what crosses it now — loudly, and
    # recorded in the audit trail, instead of a process-wide env var nobody sees in review.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(HopPosture(enforcing=True)):
        dest = build_destination(
            Destination(
                name="OB",
                type=ConnectorType.DICOMWEB,
                settings=DICOMweb(url="http://pacs.example.org/dicom-web").settings,
                cleartext_accepted=True,
                cleartext_reason="legacy partner endpoint has no TLS",
            ),
            egress=EgressSettings(deny_by_default=False),
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


# --- BACKLOG #5914: a 2xx reply that does not confirm the store is not a delivery ---------------

# Nested arrays past json's recursion limit: json.loads raises RecursionError, not ValueError.
_TOO_DEEP = "[" * 100_000 + "]" * 100_000
# Stands in for PHI in a reply body; it must never reach the refusal text.
_REPLY_CANARY = "Secretpatient^Replycanary"
_REPEATED_KEY = '{"00081198": {"vr": "SQ", "Value": [{}]}, "00081198": {"vr": "SQ", "Value": []}}'


@pytest.mark.parametrize("capture", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        "<NativeDicomModel/>",  # an XML reply, the server having ignored Accept
        "not json",
        '{"00081199": ',  # truncated
        _REPEATED_KEY,  # json.loads keeps the last (empty) FailedSOPSequence
        # The ruling refuses a repeated key at any depth, inside a sequence item too.
        '{"00081199": {"vr": "SQ", "Value": [{"00081155": 1, "00081155": 2}]}}',
        _TOO_DEEP,
    ],
    ids=["xml", "text", "truncated", "repeated-key", "nested-repeated-key", "too-deep"],
)
@pytest.mark.parametrize("status", [200, 202])
async def test_dicomweb_unparseable_2xx_reply_is_a_permanent_refusal(
    body: str, status: int, capture: bool
) -> None:
    dest = _dest(capture_response=capture)
    dest._opener = _FakeOpener(body=body.encode(), status=status)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.permanent is True
    assert exc.value.code == "unparseable-reply"
    # Raised outside any handler: no decode error, which holds the whole body, rides the chain.
    assert exc.value.__context__ is None and exc.value.__cause__ is None


def _uid_body(uid: object) -> str:
    return json.dumps({"00081199": {"vr": "SQ", "Value": [{"00081155": uid}]}})


# ReferencedSOPSequence bodies that name no stored instance, so confirm no 202 store (BACKLOG #5914):
# first by a malformed ReferencedSOPInstanceUID element, then by a malformed sequence element.
_UNCONFIRMING_BODIES = [
    pytest.param(_uid_body(uid), id=f"uid-{name}")
    for name, uid in [
        ("no-value", {"vr": "UI"}),
        ("empty-value", {"vr": "UI", "Value": []}),
        ("null-value", {"vr": "UI", "Value": None}),
        ("null-entry", {"vr": "UI", "Value": [None]}),
        ("empty-string", {"vr": "UI", "Value": [""]}),
        ("blank-string", {"vr": "UI", "Value": ["  "]}),
        ("zero-width-space", {"vr": "UI", "Value": ["\N{ZERO WIDTH SPACE}"]}),
        ("bom", {"vr": "UI", "Value": ["\N{ZERO WIDTH NO-BREAK SPACE}"]}),
        ("not-a-uid", {"vr": "UI", "Value": ["N/A"]}),
        ("empty-component", {"vr": "UI", "Value": ["1..2"]}),
        ("over-64", {"vr": "UI", "Value": ["1." * 32 + "1"]}),
        ("two-values", {"vr": "UI", "Value": ["1.2", "3.4"]}),
        ("one-blank-of-two", {"vr": "UI", "Value": ["1.2.3", ""]}),
        ("non-string", {"vr": "UI", "Value": [42]}),
        ("value-not-array", {"vr": "UI", "Value": "1.2.3.4.5"}),
        ("element-not-object", "1.2.3.4.5"),
        ("bulk-uri", {"vr": "UI", "Value": ["1.2"], "BulkDataURI": "x"}),
        ("misspelt-value", {"vr": "UI", "value": ["1.2"]}),
        ("wrong-vr", {"vr": "SQ", "Value": ["1.2"]}),
        ("no-vr", {"Value": ["1.2"]}),
    ]
] + [
    pytest.param(json.dumps({"00081199": seq}), id=f"seq-{name}")
    for name, seq in [
        ("bulk-uri", {"vr": "SQ", "BulkDataURI": "https://pacs.example.test/bulk/1"}),
        ("inline-binary", {"vr": "SQ", "InlineBinary": "AAAA"}),
    ]
]


@pytest.mark.parametrize("capture", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        pytest.param("", id="empty"),
        pytest.param("\r\n", id="whitespace"),
        pytest.param("{}", id="empty-object"),
        pytest.param(
            json.dumps({"00081190": {"vr": "UR", "Value": [f"{BASE}/studies/1.2.3"]}}),
            id="no-sequence",
        ),
        pytest.param(json.dumps({"00081199": {"vr": "SQ", "Value": []}}), id="empty-sequence"),
        pytest.param(json.dumps({"00081199": {"vr": "SQ"}}), id="no-value"),
        pytest.param(json.dumps({"00081199": {"vr": "SQ", "Value": "x"}}), id="bad-value"),
        pytest.param(
            json.dumps({"00081199": {"vr": "SQ", "Value": [None, "x"]}}), id="non-dataset-items"
        ),
        pytest.param(
            json.dumps([{"00081199": {"vr": "SQ", "Value": []}}]), id="list-empty-sequence"
        ),
        pytest.param(
            json.dumps({"00081199": {"vr": "SQ", "Value": [{}]}}), id="item-without-instance-uid"
        ),
        *_UNCONFIRMING_BODIES,
    ],
)
async def test_dicomweb_202_without_a_referenced_sop_is_a_permanent_refusal(
    body: str, capture: bool
) -> None:
    dest = _dest(capture_response=capture)
    dest._opener = _FakeOpener(body=body.encode(), status=202)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.permanent is True
    assert exc.value.code == "unconfirmed-202"


@pytest.mark.parametrize("capture", [False, True])
@pytest.mark.parametrize("body", _UNCONFIRMING_BODIES)
async def test_dicomweb_200_is_not_held_to_the_202_confirmation_rule(
    body: str, capture: bool
) -> None:
    # The ruling: a 200 whose ReferencedSOPSequence confirms nothing is still a delivery.
    dest = _dest(capture_response=capture)
    dest._opener = _FakeOpener(body=body.encode(), status=200)  # type: ignore[assignment]
    resp = await dest.send(PAYLOAD)
    if capture:
        assert isinstance(resp, DeliveryResponse)
        assert resp.outcome == "accepted"
    else:
        assert resp is None


@pytest.mark.parametrize(
    "uid",
    [
        pytest.param("1." * 31 + "12", id="exactly-64"),
        pytest.param("1.2.3\0", id="nul-pad"),
        pytest.param("1.2.3 ", id="space-pad"),
        pytest.param("1.02.3", id="leading-zero"),
    ],
)
async def test_dicomweb_202_confirms_by_a_uid_at_the_grammar_boundary(uid: str) -> None:
    body = _uid_body({"vr": "UI", "Value": [uid]})
    dest = _dest()
    dest._opener = _FakeOpener(body=body.encode(), status=202)  # type: ignore[assignment]
    assert await dest.send(PAYLOAD) is None


async def test_dicomweb_202_confirms_when_one_item_of_several_names_an_instance() -> None:
    body = json.dumps(
        {
            "00081199": {
                "vr": "SQ",
                "Value": [{}, {"00081155": {"vr": "UI", "Value": ["1.2.3.4.5"]}}],
            }
        }
    )
    dest = _dest()
    dest._opener = _FakeOpener(body=body.encode(), status=202)  # type: ignore[assignment]
    assert await dest.send(PAYLOAD) is None


async def test_dicomweb_202_with_a_referenced_sop_delivers() -> None:
    # A 202 that names the stored instance (warnings only) is a delivery, in both capture modes.
    dest = _dest()
    dest._opener = _FakeOpener(body=STORED_OK.encode(), status=202)  # type: ignore[assignment]
    assert await dest.send(PAYLOAD) is None
    dest = _dest(capture_response=True)
    dest._opener = _FakeOpener(body=STORED_OK.encode(), status=202)  # type: ignore[assignment]
    resp = await dest.send(PAYLOAD)
    assert isinstance(resp, DeliveryResponse)
    assert resp.outcome == "accepted"
    assert resp.detail == "HTTP 202"


@pytest.mark.parametrize("status", [200, 202])
async def test_dicomweb_a_leading_bom_is_not_a_refusal(status: int) -> None:
    dest = _dest()
    dest._opener = _FakeOpener(body=("\ufeff" + STORED_OK).encode(), status=status)  # type: ignore[assignment]
    assert await dest.send(PAYLOAD) is None


@pytest.mark.parametrize("body", ["\r\n", "\ufeff", "\ufeff \t\r\n"], ids=["ws", "bom", "bom-ws"])
async def test_dicomweb_a_whitespace_200_is_not_a_refusal(body: str) -> None:
    # As an empty 200 is not: neither can carry a FailedSOPSequence. Captured, it is no_reply.
    dest = _dest()
    dest._opener = _FakeOpener(body=body.encode(), status=200)  # type: ignore[assignment]
    assert await dest.send(PAYLOAD) is None
    dest = _dest(capture_response=True)
    dest._opener = _FakeOpener(body=body.encode(), status=200)  # type: ignore[assignment]
    resp = await dest.send(PAYLOAD)
    assert isinstance(resp, DeliveryResponse)
    assert resp.outcome == "no_reply"


async def test_dicomweb_unicode_space_is_not_json_whitespace() -> None:
    # A no-break space is not JSON whitespace, so the body is unparseable, not empty.
    dest = _dest()
    dest._opener = _FakeOpener(body="\N{NO-BREAK SPACE}".encode(), status=200)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.code == "unparseable-reply"


@pytest.mark.parametrize(
    "body",
    ["null", "true", '"x"', "42", "[]", "NaN", "[[" + STORED_FAILED + "]]", '[{}, "x"]'],
)
async def test_dicomweb_a_2xx_that_is_not_a_dataset_is_unparseable(body: str) -> None:
    dest = _dest()
    dest._opener = _FakeOpener(body=body.encode(), status=200)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.code == "unparseable-reply"


@pytest.mark.parametrize(
    "element",
    [
        '"garbage"',
        '{"vr": "SQ", "Value": {"a": 1}}',
        '{"vr": "SQ", "Value": null}',
        '{"vr": "SQ", "BulkDataURI": "https://pacs.example.test/bulk/1"}',
        '{"vr": "SQ", "InlineBinary": "AAAA"}',
        '{"vr": "SQ", "Value": [], "InlineBinary": "AAAA"}',
        '{"vr": "SQ", "value": [{"00081197": {"vr": "US", "Value": [272]}}]}',
    ],
    ids=[
        "not-object",
        "value-object",
        "value-null",
        "bulk-uri",
        "inline-binary",
        "value-and-bulk",
        "misspelt-value",
    ],
)
@pytest.mark.parametrize("status", [200, 202])
async def test_dicomweb_a_malformed_failed_sop_sequence_fails_closed(
    element: str, status: int
) -> None:
    # A FailedSOPSequence with bulk data in place of a Value is not an empty one (BACKLOG #5914).
    # It proves no rejection, so its code is unparseable-reply, never failed-sop.
    body = json.dumps({**json.loads(STORED_OK), "00081198": json.loads(element)})
    dest = _dest()
    dest._opener = _FakeOpener(body=body.encode(), status=status)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.code == "unparseable-reply"
    assert exc.value.permanent


@pytest.mark.parametrize(
    "element",
    [
        '{"vr": "SQ", "Value": [null]}',
        '{"vr": "SQ", "Value": ["garbage"]}',
        '{"vr": "SQ", "Value": [1]}',
        '{"vr": "SQ", "Value": [{}, null]}',
        '{"vr": "UI", "Value": ["1.2.3"]}',
        '{"vr": "UI", "Value": [{}]}',
    ],
    ids=["null-item", "text-item", "number-item", "mixed-items", "ui-text", "ui-dataset"],
)
async def test_dicomweb_a_failed_sop_sequence_of_non_datasets_proves_no_rejection(
    element: str,
) -> None:
    # BACKLOG #5914: such a sequence proves no rejection, so it is refused as unparseable, with the
    # replay advice, not as failed-sop.
    dest = _dest()
    dest._opener = _FakeOpener(body=f'{{"00081198": {element}}}'.encode(), status=200)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.code == "unparseable-reply"
    assert exc.value.permanent
    assert "before a replay" in str(exc.value)


async def test_dicomweb_a_proven_rejection_wins_over_a_malformed_sequence_elsewhere() -> None:
    # BACKLOG #5914: each dataset is judged alone, in either order.
    proven = json.loads(STORED_FAILED)
    for datasets in ([proven, {"00081198": "garbage"}], [{"00081198": "garbage"}, proven]):
        dest = _dest()
        dest._opener = _FakeOpener(body=json.dumps(datasets).encode(), status=200)  # type: ignore[assignment]
        with pytest.raises(NegativeAckError) as exc:
            await dest.send(PAYLOAD)
        assert exc.value.code == "failed-sop"


async def test_dicomweb_an_empty_failed_sop_sequence_of_another_vr_is_not_a_refusal() -> None:
    # Control: with no item there is nothing to judge, so the vr alone refuses nothing, as before.
    dest = _dest()
    dest._opener = _FakeOpener(body=b'{"00081198": {"vr": "UI"}}', status=200)  # type: ignore[assignment]
    assert await dest.send(PAYLOAD) is None


async def test_dicomweb_an_empty_failed_sop_sequence_is_not_a_refusal() -> None:
    # PS3.18 F.2.5: an element with no Value, or an empty one, is an empty sequence.
    for element in ('{"vr": "SQ"}', '{"vr": "SQ", "Value": []}'):
        dest = _dest()
        dest._opener = _FakeOpener(body=f'{{"00081198": {element}}}'.encode(), status=200)  # type: ignore[assignment]
        assert await dest.send(PAYLOAD) is None


async def test_only_the_reply_refusals_that_prove_nothing_carry_the_replay_advice() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(body=STORED_FAILED.encode(), status=200)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert "before a replay" not in str(exc.value)
    # A malformed FailedSOPSequence proves no rejection, so it carries the advice too.
    dest._opener = _FakeOpener(body=b'{"00081198": {"vr": "SQ", "value": []}}', status=200)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.code == "unparseable-reply"
    assert "before a replay" in str(exc.value)
    dest._opener = _FakeOpener(body=b"", status=202)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert "before a replay" in str(exc.value)


async def test_dicomweb_refusal_text_leads_with_its_code() -> None:
    # A stored error is cut at about 200 characters; a long base URL must not cut the code off.
    dest = _dest()
    dest.base_url = BASE + "/" + "x" * 300  # only the refusal text reads it after construction
    dest._opener = _FakeOpener(body=b"not json", status=200)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert str(exc.value).startswith("DICOMweb unparseable-reply: HTTP 200")


async def test_dicomweb_202_failed_sop_wins_over_a_referenced_sop() -> None:
    body = json.dumps({**json.loads(STORED_OK), **json.loads(STORED_FAILED)})
    dest = _dest()
    dest._opener = _FakeOpener(body=body.encode(), status=202)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.code == "failed-sop"


async def test_dicomweb_200_does_not_require_a_referenced_sop() -> None:
    # The ruling: a 200 is not held to the 202 rule; a parseable dataset without one delivers.
    dest = _dest()
    dest._opener = _FakeOpener(body=b"{}", status=200)  # type: ignore[assignment]
    assert await dest.send(PAYLOAD) is None


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        (f"<Patient>{_REPLY_CANARY}</Patient>", 200, "unparseable-reply"),
        (
            json.dumps({"00100010": {"vr": "PN", "Value": [{"Alphabetic": _REPLY_CANARY}]}}),
            202,
            "unconfirmed-202",
        ),
        (f'{{"a": "{_REPLY_CANARY}", "a": 1}}', 200, "unparseable-reply"),
    ],
    ids=["xml", "unconfirmed-202", "repeated-key"],
)
async def test_dicomweb_reply_refusals_are_content_free(body: str, status: int, code: str) -> None:
    dest = _dest(capture_response=True)
    dest._opener = _FakeOpener(body=body.encode(), status=status)  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send(PAYLOAD)
    assert exc.value.code == code  # control: the canary body reached the classifier
    assert "Secretpatient" not in str(exc.value)


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


# --- BACKLOG #1663: the ValueError arm, which had no test at any of the three sites ----------------


async def test_dicomweb_invalid_request_value_is_a_permanent_nak() -> None:
    """`_post`'s `except ValueError` arm: urllib refusing an illegal request value is a PERMANENT
    dead-letter, because a retry re-sends the byte-identical request.

    This passes at origin/main -- the arm already existed. It is NEW COVERAGE (a tree-wide grep for
    `bad-request-value` in tests/ returned zero before this change), added alongside the rest.py
    connector, whose `_post` had no such arm at all.

    Mutation: delete the `except ValueError` arm. Red: the ValueError escapes `send()` unclassified
    and `pytest.raises(NegativeAckError)` does not match."""
    dest = _dest()
    dest._opener = _FakeOpener(exc=ValueError("Invalid header name b'X-Bad\\n'"))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(PAYLOAD)
    assert ei.value.permanent is True
    assert ei.value.code == "bad-request-value"
    # PHI-safe: the redacted URL only. urllib's ValueError text quotes the offending request value,
    # so it must not be interpolated. Pinned as an equality -- a bare "not in" passes on an empty
    # message too.
    assert str(ei.value) == f"DICOMweb {BASE} rejected an invalid request value"


async def test_dicomweb_value_arm_leaves_the_transient_classes_alone() -> None:
    """Negative control for the test above, matching the pair test_fhir_transport.py keeps: a
    connection failure must STILL be a retryable DeliveryError, not swept into the permanent class
    by a widened arm."""
    dest = _dest()
    dest._opener = _FakeOpener(exc=urllib.error.URLError("connection refused"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send(PAYLOAD)
    assert not isinstance(ei.value, NegativeAckError)  # transient — it retries


# --- BACKLOG #2113: a malformed partner reply is a transport failure, not an internal error ------


async def _call_dicomweb(dest: DicomWebDestination, call: str) -> None:
    if call == "send":
        await dest.send(PAYLOAD)
    else:
        await dest.test_connection()


@pytest.mark.parametrize("exc", MALFORMED_REPLIES)
@pytest.mark.parametrize("call", ["send", "probe"])
async def test_a_malformed_dicomweb_reply_is_a_retryable_failure(call: str, exc: Exception) -> None:
    """Mutation: delete the HTTPException arm from `_post` or `_probe`. Red: the exception escapes."""
    dest = _dest()
    dest._opener = _FakeOpener(exc=exc)  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await _call_dicomweb(dest, call)
    assert not isinstance(ei.value, NegativeAckError)  # transient: it retries
    assert ei.value.__cause__ is exc
    # Pinned as an EQUALITY: the class name only, never the reply bytes the exception carries.
    assert str(ei.value) == f"DICOMweb {BASE} sent a malformed HTTP reply ({type(exc).__name__})"


@pytest.mark.parametrize("call", ["send", "probe"])
async def test_the_dicomweb_malformed_reply_arm_leaves_its_neighbours_alone(call: str) -> None:
    """Controls for the arm's placement. RemoteDisconnected is both an OSError and an
    HTTPException, so it keeps the OSError wording. InvalidURL is an HTTPException too, and keeps
    the arm #1793 gave it: a permanent dead-letter on send. Mutation: move the new arm above
    either neighbour. Red."""
    dest = _dest()
    dest._opener = _FakeOpener(exc=http.client.RemoteDisconnected("closed"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await _call_dicomweb(dest, call)
    assert not isinstance(ei.value, NegativeAckError)
    assert str(ei.value) == f"DICOMweb {BASE} failed: closed"
    dest._opener = _FakeOpener(exc=http.client.InvalidURL("bad"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await _call_dicomweb(dest, call)
    assert str(ei.value) == f"DICOMweb {BASE} rejected an invalid request value"
    assert isinstance(ei.value, NegativeAckError) == (call == "send")
    if isinstance(ei.value, NegativeAckError):
        assert ei.value.permanent is True


@pytest.mark.parametrize("call", ["send", "probe"])
async def test_a_dicomweb_reply_refusal_that_is_also_an_httpexception_passes_through(
    call: str,
) -> None:
    """Mutation: delete the matching `except EgressReplyError: raise` arm. Red: the refusal is
    retyped as a plain malformed-reply DeliveryError and loses its own type and message."""
    refusal = RefusedAndMalformed("DICOMweb reply refused: synthetic reason")
    dest = _dest()
    dest._opener = _FakeOpener(exc=refusal)  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await _call_dicomweb(dest, call)
    assert ei.value is refusal


@pytest.mark.parametrize(
    "over",
    [
        {"basic_user": "svc"},  # a user with no password would send no credential
        {"basic_password": "pw"},  # and the reverse
    ],
)
def test_dicomweb_half_basic_pair_refused(over: dict[str, str]) -> None:  # vault BACKLOG #5359
    with pytest.raises(ValueError, match="must be set together"):
        _dest(**over)


def test_dicomweb_bearer_beside_basic_refused() -> None:  # vault BACKLOG #5359
    """Basic used to overwrite the bearer silently; now the operator has to pick one."""
    with pytest.raises(ValueError, match="both bearer_token and basic_user"):
        _dest(bearer_token="t", basic_user="svc", basic_password="pw")


@pytest.mark.parametrize(
    ("over", "match"),
    [
        ({"basic_user": "svc:x", "basic_password": "pw"}, "may not contain a colon"),
        ({"basic_user": "svc\r\nX-Evil: 1", "basic_password": "pw"}, "illegal control character"),
        ({"basic_user": "svc", "basic_password": "p\x00w"}, "illegal control character"),
    ],
)
def test_dicomweb_malformed_basic_credential_refused(
    over: dict[str, str], match: str
) -> None:  # vault BACKLOG #5359
    with pytest.raises(ValueError, match=match) as exc:
        _dest(**over)
    assert "svc" not in str(exc.value) and "pw" not in str(exc.value)  # names, never values


@pytest.mark.parametrize("name", ["Authorization", "authorization", "Authorization "])
@pytest.mark.parametrize(
    "over", [{"bearer_token": "t"}, {"basic_user": "svc", "basic_password": "pw"}]
)
def test_dicomweb_authorization_header_beside_a_credential_refused(
    name: str, over: dict[str, str]
) -> None:  # vault BACKLOG #5359
    """A static Authorization entry was overwritten, or sent as a second header when spelled with
    padding the overwrite missed."""
    with pytest.raises(ValueError, match="Authorization entry in headers"):
        _dest(headers={name: "x"}, **over)


@pytest.mark.parametrize(
    ("field", "char"),
    [
        ("bearer_token", "\udcff"),
        ("bearer_token", "\u20ac"),  # latin-1 cannot write it, and the bearer goes out raw
        ("basic_user", "\udcff"),
        ("basic_password", "\udcff"),
    ],
)
def test_dicomweb_unencodable_credential_refused(
    field: str, char: str
) -> None:  # vault BACKLOG #5359
    """An unencodable character used to build and then raise UnicodeEncodeError, which names the
    code point and its offset in the secret."""
    over = {"basic_user": "svc", "basic_password": "pw"} if field != "bearer_token" else {}
    over[field] = f"se{char}cret"
    with pytest.raises(HttpAuthError, match=f"{field} holds a character the request cannot") as exc:
        _dest(**over)
    assert "cret" not in str(exc.value) and char not in str(exc.value)


def test_dicomweb_non_ascii_basic_credential_still_constructs() -> None:  # vault BACKLOG #5359
    """The control: a Basic half is UTF-8 inside base64, so a character latin-1 lacks is fine."""
    basic = _dest(basic_user="svc", basic_password="p\u20acw")._headers["Authorization"]
    assert basic == "Basic " + base64.b64encode("svc:p\u20acw".encode()).decode("ascii")


@pytest.mark.parametrize(
    "over",
    [{"basic_user": "svc"}, {"basic_user": "s\nvc", "basic_password": "pw"}],
)
def test_dicomweb_credential_refusal_names_the_connection(
    over: dict[str, str],
) -> None:  # vault BACKLOG #5359
    with pytest.raises(HttpAuthError, match=r"^connection 'OB_DCMWEB'; DICOMweb destination "):
        _dest(**over)


@pytest.mark.parametrize("over", [{"basic_user": "svc"}, {"basic_password": "pw"}])
def test_dicomweb_header_builder_sends_no_lone_basic_half(over: dict[str, str]) -> None:
    """Past the constructor's screen, a lone half still sends nothing rather than ``svc:None``
    (vault BACKLOG #5359)."""
    headers = _dest()._build_headers(dict(over))
    assert "Authorization" not in headers


def test_dicomweb_single_credentials_still_construct() -> None:  # vault BACKLOG #5359
    """Positive controls: each credential alone, and a colon in the password (RFC 7617 allows it)."""
    assert _dest(bearer_token="t")._headers["Authorization"] == "Bearer t"
    basic = _dest(basic_user="svc", basic_password="p:w")._headers["Authorization"]
    assert basic == "Basic " + base64.b64encode(b"svc:p:w").decode("ascii")
    assert "Authorization" not in _dest()._headers


def _dest_at(url: str) -> DicomWebDestination:
    d = build_destination(
        Destination(name="OB", type=ConnectorType.DICOMWEB, settings=DICOMweb(url=url).settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, DicomWebDestination)
    return d


@pytest.mark.parametrize(
    "url",
    [
        f"{BASE}?qq7=a",  # /studies would land inside the query
        f"{BASE}?",  # an empty query still swallows the appended path
        f"{BASE}#zz9",  # /studies would become a fragment the client never sends
        f"{BASE}#",
    ],
)
def test_dicomweb_base_url_query_or_fragment_refused(url: str) -> None:  # vault BACKLOG #5358
    with pytest.raises(ValueError, match="no query string or fragment") as exc:
        _dest_at(url)
    assert "qq7" not in str(exc.value) and "zz9" not in str(exc.value)


def test_dicomweb_plain_base_url_still_derives_studies() -> None:  # vault BACKLOG #5358
    assert _dest_at(BASE)._target_url == f"{BASE}/studies"
    assert _dest_at(f"{BASE}/")._target_url == f"{BASE}/studies"


_QUERY_CREDENTIAL_URL = f"{BASE}?api_key=QQ7SECRET"


def test_dicomweb_query_credential_is_not_reported_as_a_hop(
    caplog: pytest.LogCaptureFixture,
) -> None:  # vault BACKLOG #5358
    """The build refuses any url query, so these readers do not report a DICOMweb url-query
    credential: ``_http_literal_static``'s url-query label, ``query_credential_hops`` and both
    url-query WARNINGs. REST with the same url is the positive control for the label,
    ``query_credential_hops`` and the build-time WARNING."""
    from messagefoundry.config.static_credentials import _http_literal_static
    from messagefoundry.config.wiring import (
        Registry,
        Rest,
        build_outbound_connection,
        query_credential_hops,
    )
    from messagefoundry.transports.egress import (
        URL_QUERY_REFUSED_DESTINATIONS,
        warn_url_query_credentials,
        warn_url_query_credentials_before_build,
    )

    assert ConnectorType.DICOMWEB in URL_QUERY_REFUSED_DESTINATIONS
    with pytest.raises(ValueError, match="no query string or fragment"):
        _dest_at(_QUERY_CREDENTIAL_URL)

    dicomweb = DICOMweb(url=_QUERY_CREDENTIAL_URL)
    rest = Rest(url=_QUERY_CREDENTIAL_URL)
    census = "a credential in the url query"
    assert census not in _http_literal_static(
        ConnectorType.DICOMWEB, dicomweb.settings, displaced=False, env_values=None
    )
    assert census in _http_literal_static(
        ConnectorType.REST, rest.settings, displaced=False, env_values=None
    )

    registry = Registry()
    registry.outbound["OB_DW"] = build_outbound_connection("OB_DW", dicomweb)
    registry.outbound["OB_REST"] = build_outbound_connection("OB_REST", rest)
    assert [name for name, _ in query_credential_hops(registry)] == ["OB_REST"]

    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.egress"):
        warn_url_query_credentials(
            "outbound 'OB_DW'", dicomweb.settings, connector_type=ConnectorType.DICOMWEB
        )
        warn_url_query_credentials_before_build(
            "outbound 'OB_DW'",
            dicomweb.settings,
            {},
            connection="OB_DW",
            connector_type=ConnectorType.DICOMWEB,
        )
        assert not caplog.records
        warn_url_query_credentials(
            "outbound 'OB_REST'", rest.settings, connector_type=ConnectorType.REST
        )
    assert [r for r in caplog.records if "OB_REST" in r.getMessage()]


_REFUSED_CREDENTIALS: list[dict[str, object]] = [
    {"basic_user": "svc"},
    {"bearer_token": "t", "basic_user": "svc", "basic_password": "pw"},
    {"bearer_token": "t", "headers": {"Authorization ": "Bearer x"}},
    {"basic_user": "svc:x", "basic_password": "pw"},
    {"bearer_token": "t\u20acn"},
]


def _census(**over: object) -> list[str]:
    from messagefoundry.config.static_credentials import static_credential_hops
    from messagefoundry.config.wiring import Registry, build_outbound_connection

    registry = Registry()
    registry.outbound["OB_DW"] = build_outbound_connection(
        "OB_DW",
        DICOMweb(url=BASE, **over),  # type: ignore[arg-type]
    )
    return [hop.name for hop in static_credential_hops(registry=registry, settings=None)]


@pytest.mark.parametrize("over", _REFUSED_CREDENTIALS)
def test_census_leaves_out_a_dicomweb_hop_its_build_refuses(
    over: dict[str, object],
) -> None:  # vault BACKLOG #5359
    """The census reads the build's own refusal (``dicomweb_credential_problem``), so a hop that
    cannot build is not listed for an operator to opt out."""
    with pytest.raises(HttpAuthError):
        _dest(**over)
    assert _census(**over) == []


@pytest.mark.parametrize(
    "over",
    [
        {"bearer_token": "t"},
        {"basic_user": "svc", "basic_password": "pw"},
        {},  # no credential at all is a listed hop too
    ],
)
def test_census_still_lists_a_dicomweb_hop_that_builds(
    over: dict[str, object],
) -> None:  # vault BACKLOG #5359
    _dest(**over)
    assert _census(**over) == ["OB_DW"]


def test_census_resolves_env_credentials_before_judging() -> None:  # vault BACKLOG #5359
    """The serve guard and the posture route pass the instance's values; a refusal they resolve
    leaves the hop out, and so does a literal ``default=``."""
    from messagefoundry.config.static_credentials import static_credential_hops
    from messagefoundry.config.wiring import Registry, build_outbound_connection, env

    registry = Registry()
    registry.outbound["OB_DW"] = build_outbound_connection(
        "OB_DW", DICOMweb(url=BASE, bearer_token=env("tok"), basic_user="svc", basic_password="pw")
    )
    registry.outbound["OB_DEF"] = build_outbound_connection(
        "OB_DEF",
        DICOMweb(url=BASE, bearer_token=env("t2", default="t"), basic_user="s", basic_password="p"),
    )
    hops = static_credential_hops(registry=registry, settings=None, env_values={"tok": "t"})
    assert [hop.name for hop in hops] == []
    # The control: a token that resolves empty builds, as Basic alone, and is listed.
    hops = static_credential_hops(registry=registry, settings=None, env_values={"tok": ""})
    assert [hop.name for hop in hops] == ["OB_DW"]


def test_census_with_no_values_leaves_an_env_credential_unjudged() -> None:  # vault BACKLOG #5359
    """With no values, as ``messagefoundry check`` passes, an ``env()`` credential is not judged by
    its ``default=``: the instance may override it. So the hop stays listed."""
    from messagefoundry.config.static_credentials import static_credential_hops
    from messagefoundry.config.wiring import Registry, build_outbound_connection, env

    registry = Registry()
    registry.outbound["OB_DEF"] = build_outbound_connection(
        "OB_DEF",
        DICOMweb(url=BASE, bearer_token=env("t2", default="t"), basic_user="s", basic_password="p"),
    )
    hops = static_credential_hops(registry=registry, settings=None, env_values=None)
    assert [hop.name for hop in hops] == ["OB_DEF"]


def test_census_leaves_out_the_proxy_hop_of_a_refused_dicomweb() -> None:  # vault BACKLOG #5359
    over: dict[str, object] = {
        "proxy": "http://proxy.example.org:8080",
        "proxy_user": "u",
        "proxy_password": "p",
    }
    assert _census(basic_user="svc", **over) == []
    # The control: the same proxy beside a credential that builds is listed.
    assert "proxy:OB_DW" in _census(bearer_token="t", **over)


def test_census_lists_a_dicomweb_hop_it_cannot_resolve() -> None:  # vault BACKLOG #5359
    """An env() credential with no values to resolve it is not judged, so the hop stays listed."""
    from messagefoundry.config.wiring import env

    assert _census(bearer_token=env("tok"), basic_user="svc", basic_password="pw") == ["OB_DW"]
