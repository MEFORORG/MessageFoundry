# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""FHIR REST destination (ADR 0022 §2): interaction→method/path derivation, the three conditional
knobs, OperationOutcome classification, response capture, registry resolution, and the egress arm.

The opener is faked so nothing hits the network. The async ``send`` tests make no assumption about a
fresh per-test event loop (they run cleanly on the shared session-scoped loop): they only ``await
dest.send(...)`` against a synchronous fake opener and hold no loop-bound state across tests.
"""

from __future__ import annotations

import email.message
import io
import json
import urllib.error
import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import FHIR, WiringError
from messagefoundry.pipeline.wiring_runner import check_egress_allowed
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.fhir import FhirDestination, _capture_outcome, _classify_fhir

from _fhir_fixtures import (
    BUNDLE_TRANSACTION,
    OPERATION_OUTCOME_ERROR,
    OPERATION_OUTCOME_SUCCESS,
    OPERATION_OUTCOME_TRANSIENT,
    PATIENT_R4B,
    as_json,
)

BASE = "https://fhir.example.org/fhir"
PATIENT = as_json(PATIENT_R4B)  # id "synthetic-001", no meta.versionId
PATIENT_VERSIONED = json.dumps(
    {"resourceType": "Patient", "id": "p-1", "meta": {"versionId": "3"}, "name": [{"family": "X"}]}
)


def _dest(**over: object) -> FhirDestination:
    settings = FHIR(url=BASE, **over).settings  # type: ignore[arg-type]
    d = build_destination(Destination(name="OB_FHIR", type=ConnectorType.FHIR, settings=settings))
    assert isinstance(d, FhirDestination)
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


# --- construction / validation ----------------------------------------------


def test_fhir_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError, match="http or https"):
        build_destination(
            Destination(name="OB", type=ConnectorType.FHIR, settings=FHIR(url="ftp://x/y").settings)
        )


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
    method, url, extra = _dest(interaction="create")._resolve_request(PATIENT)
    assert (method, url, extra) == ("POST", f"{BASE}/Patient", {})


def test_resolve_update() -> None:
    method, url, extra = _dest(interaction="update")._resolve_request(PATIENT)
    assert (method, url, extra) == ("PUT", f"{BASE}/Patient/synthetic-001", {})


def test_resolve_transaction_posts_to_base() -> None:
    method, url, extra = _dest(interaction="transaction")._resolve_request(
        as_json(BUNDLE_TRANSACTION)
    )
    assert (method, url, extra) == ("POST", BASE, {})


def test_resolve_if_none_exist_header() -> None:
    dest = _dest(conditional="if-none-exist", conditional_query="identifier=sys|val")
    method, url, extra = dest._resolve_request(PATIENT)
    assert method == "POST"
    assert url == f"{BASE}/Patient"
    assert extra == {"If-None-Exist": "identifier=sys|val"}


def test_resolve_conditional_update_query_in_url() -> None:
    dest = _dest(conditional="conditional-update", conditional_query="identifier=sys|val")
    method, url, extra = dest._resolve_request(PATIENT)
    assert method == "PUT"
    assert url == f"{BASE}/Patient?identifier=sys|val"
    assert extra == {}


def test_resolve_if_match_etag_from_version_id() -> None:
    method, url, extra = _dest(conditional="if-match")._resolve_request(PATIENT_VERSIONED)
    assert method == "PUT"
    assert url == f"{BASE}/Patient/p-1"
    assert extra == {"If-Match": 'W/"3"'}


def test_resolve_if_match_versionid_with_control_char_is_permanent() -> None:
    # A CRLF in meta.versionId (header-injection / request-splitting attempt) must dead-letter as a
    # permanent NegativeAckError — never escape send() as a bare ValueError (ADR §2 contract).
    crlf = json.dumps(
        {"resourceType": "Patient", "id": "p-1", "meta": {"versionId": '3"\r\nX-Evil: 1'}}
    )
    with pytest.raises(NegativeAckError) as ei:
        _dest(conditional="if-match")._resolve_request(crlf)
    assert ei.value.permanent is True


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
    method, url, extra = _dest(interaction="update")._resolve_request(body)
    assert (method, url, extra) == ("PUT", f"{BASE}/Patient/abc.123-DEF", {})
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


# --- registry + egress ------------------------------------------------------


def test_fhir_registered_in_registry() -> None:
    dest = build_destination(
        Destination(name="OB", type=ConnectorType.FHIR, settings=FHIR(url=BASE).settings)
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
