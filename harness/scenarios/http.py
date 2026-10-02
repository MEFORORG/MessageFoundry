# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""HTTP family scenarios against ``harness/config/http.py``: POST through the ``Http`` inbound, then
assert what the REST, SOAP, FHIR and DICOMweb outbounds put on the wire at a harness HTTP sink.

Each delivery scenario checks, for every message it sent, that the sink saw a request with the
destination's method, path and ``Content-Type``, and a body carrying this run's control id. The
DICOMweb one goes further: it unpacks the STOW-RS ``multipart/related`` body and requires the
``application/dicom`` part to be the exact object it POSTed, byte for byte.

Each dead-letter scenario has the sink answer a non-2xx status. A ``503`` must be RETRIED (the sink
sees at least two attempts per message) and then dead-lettered; a ``400`` must be dead-lettered
after exactly ONE attempt, since a permanent rejection is not retried. Both are needed: a scenario
that only checked the dead letter could not tell retry-then-give-up from give-up-at-once.

The engine answers each POST with a ``202`` receipt carrying the ``message_id``; these scenarios
follow that id to the disposition, which is the only handle a DICOM body has (it has no MSH-10).
"""

from __future__ import annotations

import importlib.util
import io
import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from uuid import uuid4

from harness import drivers, sinks
from harness.drivers.http import ANSWERED_PREFIX, HttpDriver, message_id_of
from harness.endpoints.http import (
    DICOMWEB_BASE_PATH,
    FHIR_BASE_PATH,
    REST_PATH,
    SOAP_ACTION,
    SOAP_PATH,
)
from harness.scenarios._core import (
    _TERMINAL,
    Scenario,
    ScenarioContext,
    ScenarioResult,
    _send_error_suffix,
    _verify_dead_letter,
    _verify_disposition,
)
from harness.sinks import Record
from harness.sinks._http import HttpSink, check_status
from messagefoundry.apiclient import ApiError, EngineClient

#: The ``Content-Type`` a DICOM Part-10 POST carries.
DICOM_CONTENT_TYPE = "application/dicom"

#: Checks one request a sink recorded against the control id and payload it should carry, and
#: returns what is wrong with it, or "" when nothing is.
RequestCheck = Callable[[Record, str, bytes], str]


def synthetic_dicom(control_id: str) -> bytes:
    """A minimal, synthetic, PHI-free Basic Text SR Part-10 object whose StudyDescription carries
    ``control_id``. pydicom is the optional ``[dicom]`` extra, so it is imported here and not at
    module load: scenario discovery imports this module on installs without it."""
    from pydicom.dataset import Dataset, FileMetaDataset
    from pydicom.uid import UID, ExplicitVRLittleEndian, generate_uid

    ds = Dataset()
    ds.PatientName = "Harness^Synthetic"
    ds.PatientID = "HARNESS-0"
    ds.Modality = "SR"
    ds.SOPClassUID = UID("1.2.840.10008.5.1.4.1.1.88.11")  # Basic Text SR
    ds.SOPInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.StudyDescription = f"HARNESS {control_id}"
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = ds.SOPClassUID
    meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.file_meta = meta
    buffer = io.BytesIO()
    ds.save_as(buffer, enforce_file_format=True)
    return buffer.getvalue()


@dataclass(frozen=True)
class HttpScenario(Scenario):
    """POST ``count`` payloads to an ``Http`` inbound with a sink of ``sink`` kind answering
    ``sink_status``, expect each to reach ``expect`` (a disposition, or ``dead_letter`` for
    ``dead_letter_destination``), then hold every request the sink saw for this run to ``check``
    and to the attempt bounds.

    An HL7 run is verified by control id, through the same per-id queries every family uses. A
    DICOM body has no control id, so a DICOM run follows each ``202`` receipt's ``message_id``.

    A POST the inbound ANSWERED with a non-2xx status (a ``422`` for a body it recorded as
    ``ERROR`` and refused) reached the engine, so it is not a failure to send: an ``error``
    expectation can be verified over HTTP as it can over MLLP."""

    driver: str = "http"
    inbound: str = "http_in"
    #: "hl7" sends generated ``code^trigger`` messages; "dicom" sends :func:`synthetic_dicom` objects.
    payload: str = "hl7"
    sink_status: int = 200
    check: RequestCheck | None = field(default=None, compare=False)
    min_attempts: int = 1
    max_attempts: int | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.payload not in ("hl7", "dicom"):
            raise ValueError(f"scenario {self.name!r}: payload must be 'hl7' or 'dicom'")
        if self.sink is not None and self.check is None:
            raise ValueError(f"scenario {self.name!r} names a sink but no request check")
        check_status(self.sink_status)
        if self.min_attempts < 1:
            raise ValueError(f"scenario {self.name!r}: min_attempts must be at least 1")
        if self.max_attempts is not None and self.max_attempts < self.min_attempts:
            raise ValueError(f"scenario {self.name!r}: max_attempts is below min_attempts")

    def make_payloads(self) -> tuple[list[bytes], list[str]]:
        if self.payload == "hl7":
            return self.payloads()
        control_ids = [uuid4().hex[:20] for _ in range(self.count)]
        return [synthetic_dicom(cid) for cid in control_ids], control_ids

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        try:
            payloads, control_ids = self.make_payloads()
        except ModuleNotFoundError as exc:  # the DICOM builder needs the [dicom] extra
            return ScenarioResult(self, False, f"cannot build the payload: {exc.name} is missing")
        if self.sink is None:
            return self._post_and_verify(ctx, payloads, control_ids)
        assert self.sink_endpoint is not None
        sink = sinks.build(self.sink, ctx.endpoints, self.sink_endpoint)
        if not isinstance(sink, HttpSink):
            return ScenarioResult(self, False, f"the {self.sink} sink is not an HTTP sink")
        sink.status = self.sink_status
        with sink:
            result = self._post_and_verify(ctx, payloads, control_ids)
            if not result.ok:
                return result
            return self._verify_requests(sink, payloads, control_ids, ctx.timeout, result.detail)

    def _post_and_verify(
        self, ctx: ScenarioContext, payloads: list[bytes], control_ids: list[str]
    ) -> ScenarioResult:
        driver = drivers.build(self.driver, ctx.endpoints, self.inbound)
        if isinstance(driver, HttpDriver) and self.payload == "dicom":
            driver.content_type = DICOM_CONTENT_TYPE
        injections = driver.inject(payloads)
        send_errors = [i.error for i in injections if i.error]
        unanswered = [e for e in send_errors if not e.startswith(ANSWERED_PREFIX)]
        if len(unanswered) == self.count:
            target = ctx.endpoints.value(self.inbound)
            return ScenarioResult(
                self,
                False,
                f"could not send to {self.driver} endpoint {self.inbound!r} ({target}): "
                f"{unanswered[0]}",
            )
        message_ids = [message_id_of(i.reply) for i in injections if not i.error]
        if None in message_ids:
            return ScenarioResult(self, False, "an accepted POST carried no message_id receipt")
        if self.payload == "hl7":
            if self.expect == "dead_letter":
                return _verify_dead_letter(self, ctx.client, control_ids, ctx.timeout, send_errors)
            return _verify_disposition(self, ctx.client, control_ids, ctx.timeout, send_errors)
        wanted = [mid for mid in message_ids if mid is not None]
        if self.expect == "dead_letter":
            return _verify_dead_letter_ids(self, ctx.client, wanted, ctx.timeout, send_errors)
        return _verify_disposition_ids(self, ctx.client, wanted, ctx.timeout, send_errors)

    def _verify_requests(
        self,
        sink: HttpSink,
        payloads: Sequence[bytes],
        control_ids: Sequence[str],
        timeout: float,
        prior: str,
    ) -> ScenarioResult:
        """Every control id sent must have reached the sink at least ``min_attempts`` times (and at
        most ``max_attempts``), and every request carrying it must pass ``check``."""
        assert self.check is not None
        sent = dict(zip(control_ids, payloads, strict=True))

        def attempts(records: list[Record]) -> dict[str, list[Record]]:
            seen: dict[str, list[Record]] = {cid: [] for cid in sent}
            for record in records:
                for cid in sent:
                    if cid.encode("ascii") in record.payload:
                        seen[cid].append(record)
            return seen

        records = sink.wait_for(
            lambda rs: all(len(v) >= self.min_attempts for v in attempts(rs).values()), timeout
        )
        by_id = attempts(records)
        problems: list[str] = []
        for cid, seen in by_id.items():
            if len(seen) < self.min_attempts:
                problems.append(f"{len(seen)} attempt(s), wanted at least {self.min_attempts}")
            elif self.max_attempts is not None and len(seen) > self.max_attempts:
                problems.append(f"{len(seen)} attempt(s), wanted at most {self.max_attempts}")
            problems.extend(p for record in seen if (p := self.check(record, cid, sent[cid])))
        reached = sum(1 for seen in by_id.values() if len(seen) >= self.min_attempts)
        detail = f"{prior}; {reached}/{len(sent)} reached the {self.sink} sink"
        if self.sink_status != 200:
            detail += f" (answering {self.sink_status})"
        if problems:
            detail += f"; {len(problems)} problem(s), first: {problems[0]}"
        return ScenarioResult(self, not problems, detail)


def _verify_disposition_ids(
    scenario: HttpScenario,
    client: EngineClient,
    message_ids: list[str],
    timeout: float,
    send_errors: list[str],
) -> ScenarioResult:
    """Each receipt's message must reach ``scenario.expect`` (the message-id twin of
    :func:`~harness.scenarios._core._verify_disposition`). Each id is read directly, so no amount
    of other traffic can push this run off a page, and an id is read again only until its status
    is terminal (each read is an audited view of that one message, never of its body)."""
    wanted = set(message_ids)
    by_id: dict[str, str] = {}
    pending = set(wanted)
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        for mid in sorted(pending):
            try:
                status = client.get_message(mid).status
            except ApiError as exc:
                if exc.status == 404:
                    continue  # not visible yet; the receipt says it was committed, so look again
                return ScenarioResult(scenario, False, f"API error: {exc}")
            by_id[mid] = status
            if status in _TERMINAL:
                pending.discard(mid)
        if pending:
            time.sleep(0.3)
    matched = sum(1 for mid in wanted if by_id.get(mid) == scenario.expect)
    ok = matched == scenario.count
    detail = f"{matched}/{scenario.count} reached {scenario.expect!r}" + _send_error_suffix(
        send_errors
    )
    if not ok:
        missing = len(wanted - set(by_id))
        if missing:
            detail += f"; {missing} not found within {timeout:g}s"
        seen = sorted(set(by_id.values()))
        if seen:
            detail += f"; statuses seen: {seen}"
    return ScenarioResult(scenario, ok, detail)


def _verify_dead_letter_ids(
    scenario: HttpScenario,
    client: EngineClient,
    message_ids: list[str],
    timeout: float,
    send_errors: list[str],
) -> ScenarioResult:
    """Each receipt's message must be dead-lettered for ``scenario.dead_letter_destination``,
    matched by THIS run's message ids, never by a total (the message-id twin of
    :func:`~harness.scenarios._core._verify_dead_letter`)."""
    wanted = set(message_ids)
    matched: set[str] = set()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            dead = client.list_dead_letters(
                destination_name=scenario.dead_letter_destination, limit=500
            )
        except ApiError as exc:
            return ScenarioResult(scenario, False, f"API error: {exc}")
        matched = {d.message_id for d in dead.dead_letters if d.message_id in wanted}
        if len(matched) >= scenario.count:
            break
        time.sleep(0.3)
    ok = len(matched) >= scenario.count
    detail = (
        f"{len(matched)}/{scenario.count} of this run's messages dead-lettered for "
        f"{scenario.dead_letter_destination}" + _send_error_suffix(send_errors)
    )
    return ScenarioResult(scenario, ok, detail)


# --- per-destination request checks ------------------------------------------------------------


def _common(record: Record, method: str, path: str, content_type: str | None) -> str:
    meta = record.meta
    if meta.get("method") != method:
        return f"method {meta.get('method')!r}, wanted {method!r}"
    if meta.get("path") != path:
        return f"path {meta.get('path')!r}, wanted {path!r}"
    if content_type is not None and meta.get("content-type") != content_type:
        return f"content-type {meta.get('content-type')!r}, wanted {content_type!r}"
    return ""


def _json(record: Record) -> object:
    try:
        return json.loads(record.payload)
    except (ValueError, RecursionError):  # a deeply nested body reads as "not the JSON wanted"
        return None


def check_rest(record: Record, control_id: str, sent: bytes) -> str:
    if problem := _common(record, "POST", REST_PATH, "application/json"):
        return problem
    body = _json(record)
    if not isinstance(body, dict) or body.get("control_id") != control_id:
        return "the REST body is not the JSON object carrying this control id"
    return ""


def check_soap(record: Record, control_id: str, sent: bytes) -> str:
    if problem := _common(record, "POST", SOAP_PATH, "text/xml; charset=utf-8"):
        return problem
    if record.meta.get("header:soapaction") != f'"{SOAP_ACTION}"':
        return f"SOAPAction {record.meta.get('header:soapaction')!r}, wanted {SOAP_ACTION!r} quoted"
    text = record.payload.decode("utf-8", errors="replace")
    if not text.startswith("<soap:Envelope") or not text.endswith("</soap:Envelope>"):
        return "the SOAP body is not one envelope"
    if f"<h:ControlId>{control_id}</h:ControlId>" not in text:
        return "the SOAP envelope does not carry this control id as h:ControlId"
    return ""


def check_fhir(record: Record, control_id: str, sent: bytes) -> str:
    if problem := _common(record, "POST", f"{FHIR_BASE_PATH}/Patient", "application/fhir+json"):
        return problem
    if record.meta.get("header:accept") != "application/fhir+json":
        return f"Accept {record.meta.get('header:accept')!r}, wanted 'application/fhir+json'"
    body = _json(record)
    if not isinstance(body, dict) or body.get("resourceType") != "Patient":
        return "the FHIR body is not a Patient resource"
    identifiers = body.get("identifier")
    values = (
        [i.get("value") for i in identifiers if isinstance(i, dict)]
        if isinstance(identifiers, list)
        else []
    )
    if control_id not in values:
        return "the Patient carries no identifier with this control id"
    return ""


def multipart_parts(content_type: str, body: bytes) -> list[tuple[dict[str, str], bytes]]:
    """Split a ``multipart/related`` body into (headers, content) parts by the boundary its
    ``Content-Type`` declares. Returns [] when the type names no boundary, or the body does not
    open with the delimiter or does not end with the close delimiter (optionally followed by one
    CRLF), so a check can say the framing is wrong rather than raise."""
    boundary = ""
    for param in content_type.split(";")[1:]:
        name, _, value = param.strip().partition("=")
        if name.lower() == "boundary":
            boundary = value.strip('"')
    if not boundary:
        return []
    delimiter = b"--" + boundary.encode("ascii", errors="replace")
    close = b"\r\n" + delimiter + b"--"
    if not body.startswith(delimiter + b"\r\n"):
        return []
    if not (body.endswith(close) or body.endswith(close + b"\r\n")):
        return []  # truncated, or trailing bytes after the close delimiter
    inner = body[len(delimiter) : body.rindex(close)]
    parts: list[tuple[dict[str, str], bytes]] = []
    for chunk in inner.split(b"\r\n" + delimiter):
        head, sep, content = chunk.removeprefix(b"\r\n").partition(b"\r\n\r\n")
        if not sep:
            return []
        headers: dict[str, str] = {}
        for line in head.decode("ascii", errors="replace").split("\r\n"):
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        parts.append((headers, content))
    return parts


def check_dicomweb(record: Record, control_id: str, sent: bytes) -> str:
    if problem := _common(record, "POST", f"{DICOMWEB_BASE_PATH}/studies", None):
        return problem
    content_type = record.meta.get("content-type", "")
    if not content_type.startswith("multipart/related") or (
        'type="application/dicom"' not in content_type
    ):
        return f"content-type {content_type!r} is not multipart/related of application/dicom"
    if record.meta.get("header:accept") != "application/dicom+json":
        return f"Accept {record.meta.get('header:accept')!r}, wanted 'application/dicom+json'"
    parts = multipart_parts(content_type, record.payload)
    if len(parts) != 1:
        return f"the STOW-RS body framed {len(parts)} part(s), wanted exactly one"
    headers, content = parts[0]
    if headers.get("content-type") != DICOM_CONTENT_TYPE:
        return f"the part's content-type is {headers.get('content-type')!r}"
    if content != sent:
        return "the stored part is not the DICOM object that was POSTed, byte for byte"
    return ""


# --- the scenarios -------------------------------------------------------------------------------

#: Whether the ``[dicom]`` extra that builds the DICOM payload is installed. Without it the DICOMweb
#: scenarios are not registered at all, so the coverage report reads that outbound as uncovered
#: on that install rather than counting scenarios that could only fail there.
HAS_PYDICOM = importlib.util.find_spec("pydicom") is not None

_DESTINATIONS = (
    # kind, outbound name, sink endpoint, code, trigger, check, payload
    ("rest", "OB_Http_Rest", "http_rest", "ADT", "A04", check_rest, "hl7"),
    ("soap", "OB_Http_Soap", "http_soap", "ORM", "O01", check_soap, "hl7"),
    ("fhir", "OB_Http_FHIR", "http_fhir", "ORU", "R01", check_fhir, "hl7"),
    *(
        [("dicomweb", "OB_Http_DICOMweb", "http_dicomweb", "", "", check_dicomweb, "dicom")]
        if HAS_PYDICOM
        else []
    ),
)


def _inbound(payload: str) -> str:
    return "http_dicom_in" if payload == "dicom" else "http_in"


def _what(code: str, trigger: str) -> str:
    return f"{code}^{trigger}" if code else "a DICOM object"


SCENARIOS: tuple[HttpScenario, ...] = (
    *(
        HttpScenario(
            f"http_{kind}_delivered",
            f"{_what(code, trigger)} POSTed to {_inbound(payload)} -> PROCESSED, and the {kind} "
            f"request (method, path, content-type, body) arrives at a harness sink on {endpoint}",
            code,
            trigger,
            3 if payload == "hl7" else 2,
            "processed",
            inbound=_inbound(payload),
            sink=kind,
            sink_endpoint=endpoint,
            payload=payload,
            check=check,
        )
        for kind, _name, endpoint, code, trigger, check, payload in _DESTINATIONS
    ),
    *(
        HttpScenario(
            f"http_{kind}_retry_dead_letter",
            f"{_what(code, trigger)} to {name}, whose sink answers 503 -> retried, then "
            "dead-lettered",
            code,
            trigger,
            2,
            "dead_letter",
            inbound=_inbound(payload),
            dead_letter_destination=name,
            sink=kind,
            sink_endpoint=endpoint,
            payload=payload,
            sink_status=503,
            check=check,
            min_attempts=2,
        )
        for kind, name, endpoint, code, trigger, check, payload in _DESTINATIONS
    ),
    HttpScenario(
        "http_rest_rejected_dead_letter",
        "ADT^A04 to OB_Http_Rest, whose sink answers 400 -> dead-lettered after ONE attempt",
        "ADT",
        "A04",
        2,
        "dead_letter",
        dead_letter_destination="OB_Http_Rest",
        sink="rest",
        sink_endpoint="http_rest",
        sink_status=400,
        check=check_rest,
        min_attempts=1,
        max_attempts=1,
    ),
    HttpScenario(
        "http_unrouted",
        "SIU^S12 POSTed to http_in, which the HTTP router sends nowhere -> UNROUTED",
        "SIU",
        "S12",
        2,
        "unrouted",
    ),
)
