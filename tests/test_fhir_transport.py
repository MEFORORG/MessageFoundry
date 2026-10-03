# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""FHIR REST destination (ADR 0022 §2): interaction→method/path derivation, the three conditional
knobs, OperationOutcome classification, response capture, registry resolution, and the egress arm.

The opener is faked so nothing hits the network. The async ``send`` tests make no assumption about a
fresh per-test event loop (they run cleanly on the shared session-scoped loop): they only ``await
dest.send(...)`` against a synchronous fake opener and hold no loop-bound state across tests.
"""

from __future__ import annotations

import email.message
import http.client
import io
import json
import urllib.error
import urllib.request
from typing import Any

import pytest
from _fhir_fixtures import (
    BUNDLE_TRANSACTION,
    OPERATION_OUTCOME_ERROR,
    OPERATION_OUTCOME_SUCCESS,
    OPERATION_OUTCOME_TRANSIENT,
    PATIENT_R4B,
    as_json,
)

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import FHIR, WiringError
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.egress import check_egress_allowed
from messagefoundry.transports.fhir import (
    FhirDestination,
    _capture_outcome,
    _classify_fhir,
    _resolve_read_url,
)

BASE = "https://fhir.example.org/fhir"
PATIENT = as_json(PATIENT_R4B)  # id "synthetic-001", no meta.versionId
PATIENT_VERSIONED = json.dumps(
    {"resourceType": "Patient", "id": "p-1", "meta": {"versionId": "3"}, "name": [{"family": "X"}]}
)


def _dest(**over: object) -> FhirDestination:
    settings = FHIR(url=BASE, **over).settings  # type: ignore[arg-type]
    d = build_destination(
        Destination(name="OB_FHIR", type=ConnectorType.FHIR, settings=settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, FhirDestination)
    return d


def _http_error(code: int, body: bytes = b"") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(BASE, code, "err", email.message.Message(), io.BytesIO(body))


class _FakeResp:
    def __init__(
        self, body: bytes = b"", status: int = 200, headers: email.message.Message | None = None
    ) -> None:
        self._body = body
        self.status = status
        self.headers = headers if headers is not None else email.message.Message()

    def read(self, amt: int = -1) -> bytes:
        return self._body if amt < 0 else (self._body)[:amt]

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *a: object) -> None:
        return None


class _FakeOpener:
    """Records the Request, then returns a chosen response or raises a chosen error."""

    def __init__(
        self,
        exc: Exception | None = None,
        body: bytes = b"",
        status: int = 200,
        headers: email.message.Message | None = None,
    ) -> None:
        self.exc = exc
        self.body = body
        self.status = status
        self.headers = headers
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResp:
        self.requests.append(req)
        if self.exc is not None:
            raise self.exc
        return _FakeResp(self.body, self.status, self.headers)


def _sent_bundle(req: urllib.request.Request) -> dict[str, Any]:
    """The JSON body a request carried, parsed. Used on the wrapped-update requests."""
    assert isinstance(req.data, bytes)
    parsed = json.loads(req.data)
    assert isinstance(parsed, dict)
    return parsed


# --- construction / validation ----------------------------------------------


def test_fhir_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError, match="http or https"):
        build_destination(
            Destination(
                name="OB", type=ConnectorType.FHIR, settings=FHIR(url="ftp://x/y").settings
            ),
            egress=EgressSettings(deny_by_default=False),
        )


def test_fhir_cleartext_http_nonloopback_refused_without_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ASVS 12.2.1: the FHIR resource/Bundle body is PHI, so a cleartext http egress to a non-loopback
    # host is refused even with NO credentials, unless the explicit escape is set.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="cleartext http to a non-loopback host"):
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.FHIR,
                settings=FHIR(url="http://fhir.example.org/fhir").settings,
            ),
            egress=EgressSettings(deny_by_default=False),
        )


def test_fhir_cleartext_http_loopback_allowed() -> None:
    # On-box loopback cleartext egress is not a network exposure → allowed (byte-identical posture).
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.FHIR,
            settings=FHIR(url="http://127.0.0.1:8080/fhir").settings,
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(dest, FhirDestination)


def test_fhir_cleartext_http_nonloopback_allowed_when_accepted(
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
                type=ConnectorType.FHIR,
                settings=FHIR(url="http://fhir.example.org/fhir").settings,
                cleartext_accepted=True,
                cleartext_reason="legacy partner endpoint has no TLS",
            ),
            egress=EgressSettings(deny_by_default=False),
        )
    assert isinstance(dest, FhirDestination)  # built (warns loudly + audits), not refused


def test_fhir_rejects_xml_format() -> None:
    with pytest.raises(ValueError, match="JSON only"):
        _dest(format="xml")


def test_fhir_rejects_unknown_interaction() -> None:
    with pytest.raises(ValueError, match="interaction"):
        _dest(interaction="patch")


def test_fhir_rejects_unknown_conditional() -> None:
    with pytest.raises(ValueError, match="conditional"):
        _dest(conditional="if-modified-since")


@pytest.mark.parametrize("conditional", ["if-none-exist", "conditional-update"])
def test_fhir_conditional_requires_query(conditional: str) -> None:
    with pytest.raises(ValueError, match="conditional_query"):
        _dest(conditional=conditional)


def test_fhir_conditional_incompatible_with_transaction() -> None:
    # A connection-level conditional is meaningless for a Bundle transaction/batch — refuse it at
    # construction rather than silently ignore it.
    with pytest.raises(ValueError, match="incompatible"):
        _dest(
            interaction="transaction",
            conditional="if-none-exist",
            conditional_query="identifier=x|y",
        )


def test_fhir_media_type_and_auth_headers() -> None:
    dest = _dest(bearer_token="tok", headers={"X-Source": "mf"})
    assert dest._headers["Content-Type"] == "application/fhir+json"
    assert dest._headers["Accept"] == "application/fhir+json"
    assert dest._headers["Authorization"] == "Bearer tok"
    assert dest._headers["X-Source"] == "mf"


def test_fhir_basic_auth_header() -> None:
    assert _dest(basic_user="u", basic_password="p")._headers["Authorization"] == "Basic dTpw"


# --- interaction → method/path/headers derivation (no HTTP) ------------------


def test_resolve_create() -> None:
    r = _dest(interaction="create")._resolve_request(PATIENT)
    assert r == ("POST", f"{BASE}/Patient", {}, False)


def test_resolve_update() -> None:
    # vault BACKLOG #1965: an update resolves to a relative transaction ENTRY, never a request URL.
    r = _dest(interaction="update")._resolve_request(PATIENT)
    assert r == ("PUT", "Patient/synthetic-001", {}, True)


def test_resolve_transaction_posts_to_base() -> None:
    r = _dest(interaction="transaction")._resolve_request(as_json(BUNDLE_TRANSACTION))
    assert r == ("POST", BASE, {}, False)


def test_resolve_if_none_exist_header() -> None:
    dest = _dest(conditional="if-none-exist", conditional_query="identifier=sys|val")
    r = dest._resolve_request(PATIENT)
    assert r == ("POST", f"{BASE}/Patient", {"If-None-Exist": "identifier=sys|val"}, False)


def test_resolve_conditional_update_query_in_url() -> None:
    dest = _dest(conditional="conditional-update", conditional_query="identifier=sys|val")
    r = dest._resolve_request(PATIENT)
    assert r == ("PUT", f"{BASE}/Patient?identifier=sys|val", {}, False)


def test_resolve_if_match_etag_from_version_id() -> None:
    # vault BACKLOG #1965: the ETag rides the entry; send() moves If-Match into request.ifMatch.
    r = _dest(conditional="if-match")._resolve_request(PATIENT_VERSIONED)
    assert r == ("PUT", "Patient/p-1", {"If-Match": 'W/"3"'}, True)


def test_resolve_if_match_versionid_with_control_char_is_permanent() -> None:
    # A CRLF in meta.versionId (header-injection / request-splitting attempt) must dead-letter as a
    # permanent NegativeAckError — never escape send() as a bare ValueError (ADR §2 contract).
    crlf = json.dumps(
        {"resourceType": "Patient", "id": "p-1", "meta": {"versionId": '3"\r\nX-Evil: 1'}}
    )
    with pytest.raises(NegativeAckError) as ei:
        _dest(conditional="if-match")._resolve_request(crlf)
    assert ei.value.permanent is True


@pytest.mark.parametrize(
    "value",
    [
        "identifier=x\r\nX-Evil: 1",  # CRLF -- header injection via the If-None-Exist sink
        "identifier=x\nX-Evil: 1",  # bare LF
        "identifier=x\x00",  # NUL
        "identifier=x\x7f",  # DEL
    ],
)
def test_conditional_query_control_char_is_refused_at_construction(value: str) -> None:  # #1241
    """An operator-configured `conditional_query` reaches TWO sinks with no screen between config and
    wire: an unencoded URL interpolation, and the `If-None-Exist` HEADER value.

    Screened at CONSTRUCTION, not per message, and the distinction is the point. A bad *message* is a
    permanent dead-letter -- one message fails. A bad *setting* is wrong for every message the
    connection will ever send, so it must fail the connection at load rather than dead-letter an
    unbounded stream of messages that were never at fault.

    The header sink is why this cannot be left to the send path: unlike the URL limb it has NO
    incidental neutralisation -- `urllib.parse.unwrap` strips a trailing CRLF and `Request.full_url`
    splits at '#' client-side, and neither touches a header value.
    """
    with pytest.raises(ValueError, match="control character"):
        _dest(conditional="if-none-exist", conditional_query=value)


def test_clean_conditional_query_still_constructs() -> None:  # #1241
    """Positive control for the screen: it must admit what it is not screening for."""
    d = _dest(conditional="if-none-exist", conditional_query="identifier=http://h|123")
    assert d.conditional_query == "identifier=http://h|123"


def test_base_url_control_char_is_refused_at_construction() -> None:  # #1241
    # Built directly rather than through _dest, which already supplies url=.
    bad = Destination(
        name="OB_FHIR",
        type=ConnectorType.FHIR,
        settings={"url": "https://fhir.example.org/fhir\r\nX-Evil: 1"},
    )
    with pytest.raises(ValueError, match="control character"):
        build_destination(bad, egress=EgressSettings(deny_by_default=False))


def test_invalid_url_from_urllib_is_a_permanent_dead_letter() -> None:  # #1241
    """`http.client.InvalidURL` must not escape `_post` as an unhandled exception.

    THE GAP IT CLOSES: InvalidURL derives from HTTPException, NOT ValueError and NOT OSError
    (`InvalidURL -> HTTPException -> Exception`), so it matched none of `_post`'s arms -- including
    the ValueError backstop whose own comment says it exists for "a CRLF in a header/URL that
    slipped past the control-char guard". That is precisely this exception, and it escaped the arm
    written for it. On first deployment the URL limb would surface as an internal error out of
    `send()` rather than the classified permanent dead-letter the file intends.

    The sibling arms are asserted below so this cannot pass by the whole method being widened.
    """
    dest = _dest()
    dest._opener = _FakeOpener(  # type: ignore[assignment]
        exc=http.client.InvalidURL("URL can't contain control characters")
    )
    with pytest.raises(NegativeAckError) as ei:
        dest._post(PATIENT, "POST", f"{BASE}/Patient", {})
    assert ei.value.permanent is True


def test_invalid_url_fix_did_not_widen_the_other_arms() -> None:  # #1241
    """Negative control for the test above: a connection failure must STILL be a retryable
    DeliveryError, not swept into the permanent dead-letter class."""
    dest = _dest()
    dest._opener = _FakeOpener(exc=urllib.error.URLError("connection refused"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        dest._post(PATIENT, "POST", f"{BASE}/Patient", {})
    assert not isinstance(ei.value, NegativeAckError)


def test_resolve_id_with_control_char_is_permanent() -> None:
    bad_id = json.dumps({"resourceType": "Patient", "id": "p\r\n1"})  # CRLF in the URL-path id
    with pytest.raises(NegativeAckError) as ei:
        _dest(interaction="update")._resolve_request(bad_id)
    assert ei.value.permanent is True


def test_resolve_update_without_id_is_permanent() -> None:
    no_id = json.dumps({"resourceType": "Patient", "name": [{"family": "X"}]})
    with pytest.raises(NegativeAckError) as ei:
        _dest(interaction="update")._resolve_request(no_id)
    assert ei.value.permanent is True


def test_resolve_if_match_without_version_is_permanent() -> None:
    with pytest.raises(NegativeAckError) as ei:
        _dest(conditional="if-match")._resolve_request(PATIENT)  # no meta.versionId
    assert ei.value.permanent is True


def test_resolve_no_resource_type_is_permanent() -> None:
    with pytest.raises(NegativeAckError) as ei:
        _dest(interaction="create")._resolve_request('{"id": "x"}')
    assert ei.value.permanent is True


def test_resolve_non_json_body_is_permanent() -> None:
    with pytest.raises(NegativeAckError) as ei:
        _dest(interaction="create")._resolve_request("not json")
    assert ei.value.permanent is True


# --- SSRF / path-redirection hardening (SEC-010) -----------------------------


def test_resolve_rejects_path_traversal_resource_type() -> None:
    # A resourceType carrying path metacharacters ('/', '..', '$') must dead-letter, never redirect the
    # PHI-bearing write to a different path/operation on the same allow-listed host.
    body = json.dumps({"resourceType": "Patient/../$reindex", "id": "p-1"})
    with pytest.raises(NegativeAckError) as ei:
        _dest(interaction="create")._resolve_request(body)
    assert ei.value.permanent is True


def test_resolve_rejects_metachar_id() -> None:
    for bad in ("../$reindex", "a/b", "p?_query=1", "p#frag"):
        body = json.dumps({"resourceType": "Patient", "id": bad})
        with pytest.raises(NegativeAckError) as ei:
            _dest(interaction="update")._resolve_request(body)
        assert ei.value.permanent is True


def test_resolve_encodes_segments() -> None:
    # A benign id needing no encoding under the FHIR grammar produces the expected URL (no over-encoding),
    # proving the grammar gate + quote round-trips a valid id.
    body = json.dumps({"resourceType": "Patient", "id": "abc.123-DEF"})
    r = _dest(interaction="update")._resolve_request(body)
    assert r == ("PUT", "Patient/abc.123-DEF", {}, True)
    # An id that was previously accepted (control-char-free) but carries a path separator is now rejected,
    # confirming the grammar gate closed the redirection vector.
    redir = json.dumps({"resourceType": "Patient", "id": "p/../$op"})
    with pytest.raises(NegativeAckError):
        _dest(interaction="update")._resolve_request(redir)


def test_if_match_version_rejects_metachars() -> None:
    # A meta.versionId carrying a '"' or '/' could break out of the W/"..." ETag — gate it to the id
    # grammar (control-char-free but metachar-bearing must still be rejected).
    for bad in ('3"evil', "3/../x"):
        body = json.dumps({"resourceType": "Patient", "id": "p-1", "meta": {"versionId": bad}})
        with pytest.raises(NegativeAckError) as ei:
            _dest(conditional="if-match")._resolve_request(body)
        assert ei.value.permanent is True


# --- OperationOutcome / status classification -------------------------------


def test_classify_2xx_is_delivered() -> None:
    assert _classify_fhir(200, "") is None
    assert _classify_fhir(201, as_json(OPERATION_OUTCOME_SUCCESS)) is None


def test_classify_5xx_is_transient() -> None:
    failure = _classify_fhir(503, "")
    assert isinstance(failure, DeliveryError) and not isinstance(failure, NegativeAckError)


@pytest.mark.parametrize("code", [408, 429])
def test_classify_busy_4xx_is_transient(code: int) -> None:
    assert isinstance(_classify_fhir(code, ""), DeliveryError)


def test_classify_plain_4xx_is_permanent() -> None:
    failure = _classify_fhir(400, as_json(OPERATION_OUTCOME_ERROR))
    assert isinstance(failure, NegativeAckError) and failure.permanent is True


def test_classify_transient_operation_outcome_overrides_4xx() -> None:
    # a 409 whose OperationOutcome carries a transient IssueType code → retry, not dead-letter
    failure = _classify_fhir(409, as_json(OPERATION_OUTCOME_TRANSIENT))
    assert isinstance(failure, DeliveryError) and not isinstance(failure, NegativeAckError)


def test_classify_never_leaks_outcome_body() -> None:
    body = as_json(OPERATION_OUTCOME_ERROR)  # contains "synthetic validation problem" diagnostics
    failure = _classify_fhir(400, body)
    assert failure is not None
    assert "synthetic validation problem" not in str(failure)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (lambda: as_json(OPERATION_OUTCOME_ERROR), "rejected"),
        (lambda: as_json(OPERATION_OUTCOME_SUCCESS), "accepted"),
        (lambda: as_json(PATIENT_R4B), "accepted"),
        (lambda: "<html>error</html>", "unparseable"),
        (lambda: "[1, 2, 3]", "unparseable"),
    ],
)
def test_capture_outcome(body: object, expected: str) -> None:
    assert _capture_outcome(body()) == expected  # type: ignore[operator]


# --- send() end to end (faked opener; shared-loop safe) ---------------------


async def test_send_create_posts_resource() -> None:
    dest = _dest(interaction="create")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    assert await dest.send(PATIENT) is None  # no capture → None
    assert len(opener.requests) == 1
    req = opener.requests[0]
    assert req.method == "POST"
    assert req.full_url == f"{BASE}/Patient"
    assert req.data == PATIENT.encode("utf-8")


async def test_send_capture_accepted() -> None:
    dest = _dest(capture_response=True)
    dest._opener = _FakeOpener(body=as_json(PATIENT_R4B).encode(), status=201)  # type: ignore[assignment]
    resp = await dest.send(PATIENT)
    assert resp is not None
    assert resp.outcome == "accepted"


async def test_send_capture_no_reply_on_empty_2xx() -> None:
    dest = _dest(capture_response=True)
    dest._opener = _FakeOpener(body=b"", status=200)  # type: ignore[assignment]
    resp = await dest.send(PATIENT)
    assert resp is not None and resp.outcome == "no_reply"


async def test_send_5xx_raises_transient() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(_http_error(503))  # type: ignore[assignment]
    with pytest.raises(DeliveryError):
        await dest.send(PATIENT)


async def test_send_4xx_raises_permanent() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(_http_error(422, as_json(OPERATION_OUTCOME_ERROR).encode()))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(PATIENT)
    assert ei.value.permanent is True


async def test_send_4xx_with_transient_outcome_retries() -> None:
    dest = _dest()
    err = _http_error(409, as_json(OPERATION_OUTCOME_TRANSIENT).encode())
    dest._opener = _FakeOpener(err)  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send(PATIENT)
    assert not isinstance(ei.value, NegativeAckError)


# --- vault BACKLOG #1965: update and if-match keep the id out of the URL (ASVS 14.2.1, ruling R3) ---

#: A distinctive message-derived id, so "not in the URL" cannot pass by the URL happening to lack a
#: short common substring.
ID_1965 = "mf1965-msg-id"
UPDATE_1965 = json.dumps(
    {"resourceType": "Patient", "id": ID_1965, "meta": {"versionId": "7"}, "active": True}
)


def _transaction_response(status: str, **response: object) -> bytes:
    return json.dumps(
        {
            "resourceType": "Bundle",
            "type": "transaction-response",
            "entry": [{"response": {"status": status, **response}}],
        }
    ).encode()


@pytest.mark.parametrize(
    ("over", "extra"),
    [({"interaction": "update"}, {}), ({"conditional": "if-match"}, {"ifMatch": 'W/"7"'})],
    ids=["update", "if-match"],
)
async def test_update_and_if_match_url_carries_no_message_id(
    over: dict[str, str], extra: dict[str, str]
) -> None:
    dest = _dest(**over)
    opener = _FakeOpener(body=_transaction_response("200 OK"))
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(UPDATE_1965)
    req = opener.requests[0]
    assert req.method == "POST"
    assert req.full_url == BASE
    assert ID_1965 not in req.full_url
    assert not req.has_header("If-match")
    # Positive control: the id did go somewhere, so the absence above is not a lost id.
    bundle = _sent_bundle(req)
    assert (bundle["resourceType"], bundle["type"]) == ("Bundle", "transaction")
    [entry] = bundle["entry"]
    assert entry["request"] == {"method": "PUT", "url": f"Patient/{ID_1965}", **extra}
    assert entry["resource"] == json.loads(UPDATE_1965)
    # A PUT entry's fullUrl SHALL have a value; it carries the id in the body, never the URL.
    assert entry["fullUrl"] == f"{BASE}/Patient/{ID_1965}"


def test_read_site_still_carries_the_id_in_the_path() -> None:
    # Control arm. R3 names update and if-match only; a RESTful read is GET [base]/[type]/[id] by
    # specification, and vault BACKLOG #1965 leaves this site as it was.
    url = _resolve_read_url(BASE, f"Patient/{ID_1965}")
    assert url == f"{BASE}/Patient/{ID_1965}"


async def test_create_is_not_wrapped() -> None:
    # Control arm: create puts no id in the URL, so its body still goes out exactly as given.
    dest = _dest(interaction="create")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(UPDATE_1965)
    assert opener.requests[0].full_url == f"{BASE}/Patient"
    assert opener.requests[0].data == UPDATE_1965.encode("utf-8")


async def test_wrapped_resource_is_spliced_verbatim() -> None:
    # A JSON round-trip would turn 1.50 into 1.5, and FHIR keeps a decimal's precision.
    raw = '{"resourceType":"Observation","id":"obs-1","valueQuantity":{"value":1.50}}'
    dest = _dest(interaction="update")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    # FhirPeek tolerates a leading BOM; the Bundle must not carry it.
    await dest.send("\N{ZERO WIDTH NO-BREAK SPACE}" + raw)
    data = opener.requests[0].data
    assert isinstance(data, bytes)
    assert raw.encode() in data
    assert _sent_bundle(opener.requests[0])["entry"][0]["request"]["url"] == "Observation/obs-1"


@pytest.mark.parametrize(
    ("status", "outcome", "permanent"),
    [
        ("412 Precondition Failed", None, True),
        (
            "409 Conflict",
            {"resourceType": "OperationOutcome", "issue": [{"code": "lock-error"}]},
            False,
        ),
    ],
)
async def test_failed_entry_in_a_2xx_reply_is_not_delivered(
    status: str, outcome: dict[str, object] | None, permanent: bool
) -> None:
    # A conformant server fails the whole transaction with an error status. This pins the other
    # case: a 2xx reply whose one entry failed must not be recorded as delivered.
    extra = {"outcome": outcome} if outcome is not None else {}
    dest = _dest(conditional="if-match")
    dest._opener = _FakeOpener(body=_transaction_response(status, **extra))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send(UPDATE_1965)
    assert isinstance(ei.value, NegativeAckError) is permanent
    # The status came from the entry, not the HTTP reply, and the message says so.
    assert "transaction entry status" in str(ei.value) and "HTTP" not in str(ei.value)


async def test_successful_entry_is_delivered() -> None:
    dest = _dest(interaction="update")
    dest._opener = _FakeOpener(body=_transaction_response("201 Created"))  # type: ignore[assignment]
    assert await dest.send(UPDATE_1965) is None


async def test_entry_etag_and_location_are_captured_as_headers() -> None:
    # #154 capture keeps working for an update: the values a PUT reply carried as headers now come
    # back in the entry. The entry describes the updated resource, so it wins over a reply header,
    # which describes the Bundle. A reply header the entry lacks is kept; an unsafe value is dropped.
    reply_headers = email.message.Message()
    reply_headers["Etag"] = 'W/"bundle-level"'
    reply_headers["Location"] = "from-the-real-header"
    dest = _dest(
        interaction="update",
        capture_response=True,
        capture_response_headers=["ETag", "Location", "Last-Modified"],
    )
    dest._opener = _FakeOpener(  # type: ignore[assignment]
        body=_transaction_response("200 OK", etag='W/"8"', lastModified="x\r\ny"),
        headers=reply_headers,
    )
    resp = await dest.send(UPDATE_1965)
    assert resp is not None
    assert resp.headers == {"ETag": 'W/"8"', "Location": "from-the-real-header"}


async def test_overlong_entry_etag_is_not_captured_and_hides_the_bundle_etag() -> None:
    # The entry named an ETag, so the reply's own ETag, which describes the Bundle, must not stand
    # in for it when the entry's value is dropped.
    reply_headers = email.message.Message()
    reply_headers["ETag"] = 'W/"bundle-level"'
    dest = _dest(interaction="update", capture_response=True, capture_response_headers=["ETag"])
    dest._opener = _FakeOpener(  # type: ignore[assignment]
        body=_transaction_response("200 OK", etag="x" * 9000), headers=reply_headers
    )
    resp = await dest.send(UPDATE_1965)
    assert resp is not None and resp.headers == {}


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ({"resourceType": "OperationOutcome", "issue": [{"severity": "error"}]}, "rejected"),
        ({"resourceType": "OperationOutcome", "issue": [{"severity": "warning"}]}, "accepted"),
        (None, "accepted"),
    ],
)
async def test_capture_outcome_comes_from_the_entry(
    outcome: dict[str, object] | None, expected: str
) -> None:
    # A 2xx PUT whose body was an error OperationOutcome was captured as rejected. In a
    # transaction-response that outcome sits in the entry, so it is read there.
    extra = {"outcome": outcome} if outcome is not None else {}
    dest = _dest(interaction="update", capture_response=True)
    dest._opener = _FakeOpener(body=_transaction_response("200 OK", **extra))  # type: ignore[assignment]
    resp = await dest.send(UPDATE_1965)
    assert resp is not None and resp.outcome == expected


@pytest.mark.parametrize(
    "status",
    ["HTTP/1.1 404 Not Found", "\N{SUPERSCRIPT TWO}" * 3, True, None],
    ids=["prefixed", "non-ascii-digits", "bool", "missing"],
)
async def test_unreadable_entry_status_is_delivered_with_a_warning(
    status: object, caplog: pytest.LogCaptureFixture
) -> None:
    # The server answered 2xx, so the write most likely applied; a retry of an applied if-match
    # update would 412 and dead-letter a message that landed. A non-ASCII digit must not reach
    # int() and escape as an unclassified ValueError.
    entry = {"response": {} if status is None else {"status": status}}
    body = {"resourceType": "Bundle", "type": "transaction-response", "entry": [entry]}
    dest = _dest(conditional="if-match")
    dest._opener = _FakeOpener(body=json.dumps(body).encode())  # type: ignore[assignment]
    with caplog.at_level("WARNING", logger="messagefoundry.transports.fhir"):
        assert await dest.send(UPDATE_1965) is None
    assert "no readable status" in caplog.text


@pytest.mark.parametrize("status", [404, 404.0], ids=["int", "float"])
async def test_numeric_entry_status_is_read(status: float) -> None:
    dest = _dest(interaction="update")
    body = {"resourceType": "Bundle", "entry": [{"response": {"status": status}}]}
    dest._opener = _FakeOpener(body=json.dumps(body).encode())  # type: ignore[assignment]
    with pytest.raises(NegativeAckError):
        await dest.send(UPDATE_1965)


async def test_too_deep_2xx_reply_captures_as_unparseable() -> None:
    # A capture of a too-deep reply must classify, not escape as RecursionError.
    for over in ({"interaction": "update"}, {"interaction": "create"}):
        dest = _dest(capture_response=True, **over)
        dest._opener = _FakeOpener(body=b"[" * 200_000)  # type: ignore[assignment]
        resp = await dest.send(UPDATE_1965)
        assert resp is not None and resp.outcome == "unparseable"


async def test_reply_that_is_not_a_transaction_response_is_delivered() -> None:
    # Control arm for the entry checks: a 2xx with no entry is delivered, as any 2xx was before.
    dest = _dest(interaction="update")
    dest._opener = _FakeOpener(body=b"")  # type: ignore[assignment]
    assert await dest.send(UPDATE_1965) is None


async def test_dynamic_if_match_on_plain_update_moves_into_the_entry() -> None:
    # Before the wrap, a Handler-stamped If-Match qualified the PUT. On the outer POST it would
    # qualify the Bundle, so it moves into the entry instead.
    dest = _dest(interaction="update", dynamic_headers=True)
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(UPDATE_1965, metadata={"http.header.if-match": 'W/"5"'})
    req = opener.requests[0]
    assert not req.has_header("If-match")
    assert _sent_bundle(req)["entry"][0]["request"]["ifMatch"] == 'W/"5"'


async def test_static_if_match_moves_into_the_entry_and_a_dynamic_one_overrides_it() -> None:
    dest = _dest(interaction="update", headers={"If-Match": 'W/"static"'})
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(UPDATE_1965)
    await dest.send(UPDATE_1965, metadata={"http.header.If-Match": 'W/"dynamic"'})
    for req, expected in zip(opener.requests, ('W/"static"', 'W/"dynamic"'), strict=True):
        assert not req.has_header("If-match")
        assert _sent_bundle(req)["entry"][0]["request"]["ifMatch"] == expected


def test_static_if_match_stays_a_header_on_create() -> None:
    # Control arm: only a connection whose writes are wrapped moves its static If-Match.
    assert _dest(interaction="create", headers={"If-Match": "x"})._headers["If-Match"] == "x"


async def test_connector_if_match_wins_over_every_other_case_spelling() -> None:
    # The version check is the connector's. A static If-Match and a Handler-stamped if-match in
    # another letter case must not displace it.
    dest = _dest(conditional="if-match", headers={"If-Match": 'W/"static"'}, dynamic_headers=True)
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(UPDATE_1965, metadata={"http.header.if-match": 'W/"attacker"'})
    assert _sent_bundle(opener.requests[0])["entry"][0]["request"]["ifMatch"] == 'W/"7"'


@pytest.mark.parametrize(
    ("header", "field"),
    [
        ("If-None-Match", "ifNoneMatch"),
        ("If-Modified-Since", "ifModifiedSince"),
        ("If-None-Exist", "ifNoneExist"),
    ],
)
async def test_other_conditional_headers_move_into_the_entry(header: str, field: str) -> None:
    # Each would have qualified the PUT; Bundle.entry.request has a field of the same meaning.
    for static in (True, False):
        dest = _dest(interaction="update", headers={header: "v"} if static else None)
        opener = _FakeOpener()
        dest._opener = opener  # type: ignore[assignment]
        await dest.send(UPDATE_1965, metadata=None if static else {f"http.header.{header}": "v"})
        req = opener.requests[0]
        assert not req.has_header(header.capitalize())
        assert _sent_bundle(req)["entry"][0]["request"][field] == "v"


@pytest.mark.parametrize("dots", [".", "..", "..."])
def test_resolve_rejects_a_dot_only_id(dots: str) -> None:
    # The id grammar admits these, and a path resolver reads them as this level or the parent.
    body = json.dumps({"resourceType": "Patient", "id": dots})
    with pytest.raises(NegativeAckError) as ei:
        _dest(interaction="update")._resolve_request(body)
    assert ei.value.permanent is True


async def test_deeply_nested_error_body_still_classifies() -> None:
    # A 5xx is transient without reading its body, and a 4xx body too deep to parse classifies on
    # the status rather than escaping as RecursionError.
    nested = b"[" * 200_000
    for code, permanent in ((503, False), (404, True)):
        dest = _dest(interaction="create")
        dest._opener = _FakeOpener(_http_error(code, nested))  # type: ignore[assignment]
        with pytest.raises(DeliveryError) as ei:
            await dest.send(PATIENT)
        assert isinstance(ei.value, NegativeAckError) is permanent


async def test_dynamic_if_match_on_create_stays_a_header() -> None:
    # Control arm for the move above: an unwrapped request keeps the header where it was.
    dest = _dest(interaction="create", dynamic_headers=True)
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(UPDATE_1965, metadata={"http.header.If-Match": 'W/"5"'})
    assert opener.requests[0].get_header("If-match") == 'W/"5"'


# --- registry + egress ------------------------------------------------------


def test_fhir_registered_in_registry() -> None:
    dest = build_destination(
        Destination(name="OB", type=ConnectorType.FHIR, settings=FHIR(url=BASE).settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(dest, FhirDestination)


def test_fhir_egress_allowlist_blocks_unlisted_host() -> None:
    dest = Destination(
        name="OB",
        type=ConnectorType.FHIR,
        settings=FHIR(url="https://evil.example.net/fhir").settings,
    )
    with pytest.raises(WiringError):
        check_egress_allowed(dest, EgressSettings(allowed_http=["fhir.example.org"]))


def test_fhir_egress_allowlist_permits_listed_host() -> None:
    dest = Destination(name="OB", type=ConnectorType.FHIR, settings=FHIR(url=BASE).settings)
    check_egress_allowed(dest, EgressSettings(allowed_http=["fhir.example.org"]))  # no raise


def test_fhir_egress_deny_by_default_refuses_when_unconfigured() -> None:
    # ADR §3.4 fail-closed: under deny_by_default, an empty allowed_http refuses a FHIR destination.
    # This proves FHIR is wired into _allowlist_for — a refactor dropping it would silently reopen the
    # fail-open hole (the host-check arm alone wouldn't catch an empty allowlist).
    dest = Destination(name="OB", type=ConnectorType.FHIR, settings=FHIR(url=BASE).settings)
    with pytest.raises(WiringError):
        check_egress_allowed(dest, EgressSettings(deny_by_default=True))


# --- per-message dynamic HTTP headers (BACKLOG #68) -------------------------------------------------


def test_fhir_dynamic_headers_flag_opt_in() -> None:
    assert _dest().consumes_metadata is False
    assert _dest(dynamic_headers=True).consumes_metadata is True


async def test_fhir_per_message_header_appears_on_request() -> None:
    dest = _dest(interaction="create")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(PATIENT, metadata={"http.header.X-Trace-Id": "trace-9", "note": "skip"})
    req = opener.requests[0]
    assert req.get_header("X-trace-id") == "trace-9"
    assert not req.has_header("Note")


async def test_fhir_per_message_header_overrides_static() -> None:
    dest = _dest(interaction="create", headers={"X-Trace": "static"})
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(PATIENT, metadata={"http.header.X-Trace": "dynamic"})
    assert opener.requests[0].get_header("X-trace") == "dynamic"


async def test_fhir_dynamic_header_cannot_override_if_match() -> None:
    # The connector's version check is semantically required and must win over a message-derived
    # header of the same name. Since vault BACKLOG #1965 it lives in the entry's ifMatch, and the
    # message-derived header must not ride the outer POST either.
    dest = _dest(interaction="update", conditional="if-match")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(PATIENT_VERSIONED, metadata={"http.header.If-Match": 'W/"attacker"'})
    req = opener.requests[0]
    assert not req.has_header("If-match")
    assert _sent_bundle(req)["entry"][0]["request"]["ifMatch"] == 'W/"3"'


async def test_fhir_crlf_in_header_value_is_neutralized() -> None:
    dest = _dest(interaction="create")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(PATIENT, metadata={"http.header.X-Evil": "ok\r\nX-Injected: 1"})
    req = opener.requests[0]
    assert req.get_header("X-evil") == "okX-Injected: 1"
    assert not req.has_header("X-injected")


async def test_fhir_no_metadata_is_byte_identical() -> None:
    dest = _dest(interaction="create")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(PATIENT)  # no metadata → no dynamic headers, unchanged request
    req = opener.requests[0]
    assert req.get_header("Content-type") == "application/fhir+json"


# --- BACKLOG #1663 step 3 reaches FHIR too, through the SHARED helper -----------------------------
#
# `FhirDestination.send` calls rest.py's `outbound_headers_from_metadata` (fhir.py imports it), so the
# non-Latin-1 refusal added there for #1663 governs this connector as well -- with no edit to fhir.py.
# That shared reach is exactly what this test pins: delete the guard in rest.py and THIS file reds.

#: Un-encodable as ASCII *and* as latin-1 — the encoding ``putheader`` uses on a header value.
CJK_CHAR = "患"


async def test_fhir_non_latin1_message_header_is_refused_content_free() -> None:
    """Mutation: delete the latin-1 guard from rest.py's `outbound_headers_from_metadata`. Red: the
    send completes, `UnicodeEncodeError` escapes at the wire, and this does not raise.

    Confirmed red without the fix. Note the cross-file reach -- the guard is in rest.py."""
    dest = _dest(interaction="create")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(PATIENT, metadata={"http.header.X-Note": f"ok{CJK_CHAR}"})
    assert ei.value.permanent is True
    assert ei.value.code == "encoding"  # the body path's code, not the _post arm's
    # Refused BEFORE the request is built: nothing reached the opener. This is what separates a
    # refusal from a late classification; an exception-type-only assertion passes under either.
    assert opener.requests == []
    # PHI-safe: neither the offending value nor the message-derived header name may leave.
    text = str(ei.value)
    assert CJK_CHAR not in text and "X-Note" not in text
    assert ei.value.__cause__ is None and ei.value.__context__ is None


async def test_fhir_invalid_request_value_is_a_permanent_nak() -> None:
    """NEW COVERAGE of the ValueError limb of this file's shipped `(ValueError, InvalidURL)` arm --
    #1241 pinned only the InvalidURL limb above, and `bad-request-value` had zero coverage tree-wide.
    Passes at origin/main; it is coverage, not a reproduction of #1663, which was rest.py's.

    Mutation: drop `ValueError` from the arm. Red: the ValueError escapes `_post` unclassified."""
    dest = _dest(interaction="create")
    dest._opener = _FakeOpener(exc=ValueError("Invalid header name b'X-Bad\\n'"))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(PATIENT)
    assert ei.value.permanent is True
    assert ei.value.code == "bad-request-value"
    # PHI-safe: urllib's ValueError text quotes the offending value, so it must not be interpolated.
    assert str(ei.value) == f"FHIR {BASE} rejected an invalid request value"


# --- BACKLOG #2058: a malformed partner reply is a transport failure, not an internal error ------

# The text is planted so a leak into the error message would show.
_MALFORMED_REPLIES = [
    pytest.param(http.client.BadStatusLine("SYNTHETICPLANTED"), id="bad-status-line"),
    pytest.param(http.client.LineTooLong("SYNTHETICPLANTED"), id="line-too-long"),
]


@pytest.mark.parametrize("exc", _MALFORMED_REPLIES)
async def test_a_malformed_fhir_reply_retries_from_send(exc: Exception) -> None:
    """Mutation: delete the HTTPException arm from `_post`. Red: the exception escapes send()."""
    assert not issubclass(type(exc), (OSError, urllib.error.URLError))  # the reason it is named
    dest = _dest()
    dest._opener = _FakeOpener(exc=exc)  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send(PATIENT)
    assert not isinstance(ei.value, NegativeAckError)  # transient: it retries
    assert ei.value.__cause__ is exc
    # Pinned as an EQUALITY: the class name only, never the reply bytes the exception carries.
    assert str(ei.value) == f"FHIR {BASE} sent a malformed HTTP reply ({type(exc).__name__})"


@pytest.mark.parametrize("exc", _MALFORMED_REPLIES)
async def test_a_malformed_fhir_reply_fails_the_probe(exc: Exception) -> None:
    """Mutation: delete the HTTPException arm from `_probe`. Red: the exception escapes."""
    dest = _dest()
    dest._opener = _FakeOpener(exc=exc)  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.test_connection()
    assert ei.value.__cause__ is exc
    assert str(ei.value) == f"FHIR {BASE} sent a malformed HTTP reply ({type(exc).__name__})"


async def test_the_malformed_reply_arm_leaves_its_neighbours_alone() -> None:
    """Controls for the arm's placement. RemoteDisconnected is both an OSError and an
    HTTPException, so it keeps the OSError wording; InvalidURL is an HTTPException too, and stays
    the permanent dead-letter #1241 made it. Mutation: move the new arm above either. Red."""
    dest = _dest()
    dest._opener = _FakeOpener(exc=http.client.RemoteDisconnected("closed"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError, match="failed: closed") as ei:
        await dest.send(PATIENT)
    assert not isinstance(ei.value, NegativeAckError)
    dest._opener = _FakeOpener(exc=http.client.InvalidURL("bad"))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as nak:
        await dest.send(PATIENT)
    assert nak.value.permanent is True


async def test_the_malformed_reply_arm_leaves_the_probe_neighbours_alone() -> None:
    """The same controls on `_probe`, pinned by message. Mutation: move the new arm above either
    neighbour there. Red: the message names the wrong class."""
    dest = _dest()
    dest._opener = _FakeOpener(exc=http.client.RemoteDisconnected("closed"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.test_connection()
    assert str(ei.value) == f"FHIR {BASE} failed: closed"
    dest._opener = _FakeOpener(exc=http.client.InvalidURL("bad"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.test_connection()
    assert str(ei.value) == f"FHIR {BASE} rejected an invalid request value"


# --- vault BACKLOG #2550: update_url_form="path", the listed opt-in back to PUT {base}/{type}/{id} ---


def test_update_url_form_defaults_to_transaction() -> None:
    # Control arm. The factory default and the connector default agree, and the default still
    # resolves an update to a transaction ENTRY rather than a request URL.
    assert FHIR(url=BASE).settings["update_url_form"] == "transaction"
    dest = _dest(interaction="update")
    assert dest.update_url_form == "transaction"
    assert dest._resolve_request(UPDATE_1965) == ("PUT", f"Patient/{ID_1965}", {}, True)


@pytest.mark.parametrize(
    ("over", "if_match"),
    [({"interaction": "update"}, None), ({"conditional": "if-match"}, 'W/"7"')],
    ids=["update", "if-match"],
)
async def test_path_form_sends_a_plain_put_with_the_etag_in_if_match(
    over: dict[str, str], if_match: str | None
) -> None:
    dest = _dest(update_url_form="path", **over)
    opener = _FakeOpener(body=UPDATE_1965.encode())
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(UPDATE_1965)
    [req] = opener.requests
    assert req.method == "PUT"
    assert req.full_url == f"{BASE}/Patient/{ID_1965}"
    # The resource goes out as itself, not wrapped in a Bundle.
    assert req.data == UPDATE_1965.encode("utf-8")
    assert req.get_header("If-match") == if_match


async def test_path_form_keeps_a_static_conditional_header_on_the_put() -> None:
    # The transaction form moves a static If-Match into the entry; the path form has no entry, so
    # the header stays on the request it qualifies.
    dest = _dest(interaction="update", update_url_form="path", headers={"If-Match": 'W/"1"'})
    assert dest._static_conditionals == {}
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(UPDATE_1965)
    assert opener.requests[0].get_header("If-match") == 'W/"1"'


async def test_path_form_captures_the_plain_resource_reply() -> None:
    # Capture is back to the plain-resource form: the reply is the resource, and ETag comes from
    # the reply header, as on any PUT.
    reply_headers = email.message.Message()
    reply_headers["ETag"] = 'W/"8"'
    dest = _dest(
        interaction="update",
        update_url_form="path",
        capture_response=True,
        capture_response_headers=["ETag"],
    )
    dest._opener = _FakeOpener(body=UPDATE_1965.encode(), headers=reply_headers)  # type: ignore[assignment]
    resp = await dest.send(UPDATE_1965)
    assert resp is not None
    assert (resp.outcome, resp.body, resp.headers) == ("accepted", UPDATE_1965, {"ETag": 'W/"8"'})


async def test_path_form_classifies_an_error_reply_on_the_http_status() -> None:
    dest = _dest(conditional="if-match", update_url_form="path")
    dest._opener = _FakeOpener(_http_error(412))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(UPDATE_1965)
    assert ei.value.permanent is True and "HTTP 412" in str(ei.value)


@pytest.mark.parametrize(
    "bad_id",
    [
        ".",
        "..",
        "...",
        "a/b",
        "../$reindex",
        "p?x=1",
        "p#f",
        "p 1",
        "p%2F1",
        "x" * 65,
        "p\r\n1",
        "",
    ],
)
async def test_path_form_refuses_an_id_outside_the_grammar_and_never_sends_it(bad_id: str) -> None:
    dest = _dest(interaction="update", update_url_form="path")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    body = json.dumps({"resourceType": "Patient", "id": bad_id})
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(body)
    assert ei.value.permanent is True
    assert opener.requests == []


async def test_path_form_admits_a_grammar_id_with_dots_inside() -> None:
    # Control arm for the dot-only refusal: a dot is in the id grammar, and only an id made of
    # nothing else is refused.
    dest = _dest(interaction="update", update_url_form="path")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(json.dumps({"resourceType": "Patient", "id": "a.b-1"}))
    assert opener.requests[0].full_url == f"{BASE}/Patient/a.b-1"


def test_path_form_warns_at_construction_naming_the_connection(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("WARNING", logger="messagefoundry.transports.fhir"):
        _dest(interaction="update")
    assert "update_url_form" not in caplog.text  # control: the default is silent
    with caplog.at_level("WARNING", logger="messagefoundry.transports.fhir"):
        _dest(interaction="update", update_url_form="path")
    assert "OB_FHIR" in caplog.text and "update_url_form='path'" in caplog.text
    assert "owner ruling R3" in caplog.text and "ASVS 14.2.1" in caplog.text


@pytest.mark.parametrize(
    "over",
    [
        {"interaction": "create"},
        {"interaction": "transaction"},
        {"conditional": "if-none-exist", "conditional_query": "identifier=s|v"},
        {"conditional": "conditional-update", "conditional_query": "identifier=s|v"},
    ],
    ids=["create", "transaction", "if-none-exist", "conditional-update"],
)
def test_path_form_is_refused_where_it_would_do_nothing(over: dict[str, str]) -> None:
    # Both layers refuse: the factory, so the loaded graph never holds one and `check` never names
    # one, and the connector, for settings that did not come through the factory.
    with pytest.raises(ValueError, match="update_url_form='path' applies only"):
        FHIR(url=BASE, update_url_form="path", **over)  # type: ignore[arg-type]
    settings = {**FHIR(url=BASE, **over).settings, "update_url_form": "path"}  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="update_url_form='path' applies only"):
        build_destination(
            Destination(name="OB_FHIR", type=ConnectorType.FHIR, settings=settings),
            egress=EgressSettings(deny_by_default=False),
        )


def test_unknown_update_url_form_is_refused() -> None:
    with pytest.raises(ValueError, match="update_url_form must be one of"):
        _dest(interaction="update", update_url_form="query")


def _write_feed(tmp_path: Any, body: str) -> Any:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text("from messagefoundry import FHIR, outbound\n" + body, "utf-8")
    return cfg


def test_check_names_every_path_form_connection(tmp_path: Any) -> None:
    from messagefoundry.checks import run_checks
    from messagefoundry.config.wiring import load_config, path_form_fhir_updates

    cfg = _write_feed(
        tmp_path,
        f'outbound("OB_EPIC", FHIR(url="{BASE}", interaction="update", update_url_form="path"))\n'
        f'outbound("OB_DEFAULT", FHIR(url="{BASE}", interaction="update"))\n',
    )
    assert path_form_fhir_updates(load_config(cfg)) == ["OB_EPIC"]
    [r] = [r for r in run_checks(cfg, run_lint=False).results if r.name == "fhir-update-path-form"]
    assert r.ok and not r.required and not r.skipped
    assert "OB_EPIC" in r.detail and "OB_DEFAULT" not in r.detail
    assert "owner ruling R3" in r.detail


def test_check_says_none_when_no_connection_takes_the_path_form(tmp_path: Any) -> None:
    from messagefoundry.checks import run_checks

    cfg = _write_feed(tmp_path, f'outbound("OB", FHIR(url="{BASE}", interaction="update"))\n')
    [r] = [r for r in run_checks(cfg, run_lint=False).results if r.name == "fhir-update-path-form"]
    assert "no FHIR connection sets update_url_form='path'" in r.detail
