# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The HTTP family of the harness (vault BACKLOG #2675): the ``Http`` inbound driver, the loopback
HTTP sink the REST/SOAP/FHIR/DICOMweb outbounds deliver to, the request checks, and the
``[egress].allowed_http`` posture the family's graph is served under.

``tests/test_harness_scenarios.py`` already runs every registered scenario, these included, against
the real ``harness/config`` graph with ``allowed_http`` naming loopback. This file adds the
``serve`` posture (``[security].block_unlisted_outbound`` on), and the controls that show each
check can fail: a refused egress, a wrong check, a sink answering the wrong status.
"""

from __future__ import annotations

import dataclasses
import json
import socket
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from harness import drivers, scenarios, sinks
from harness import endpoints as harness_endpoints
from harness.__main__ import main
from harness.drivers import Driver, Injection
from harness.drivers.http import HL7_CONTENT_TYPE, HttpDriver, message_id_of
from harness.endpoints import Endpoints
from harness.endpoints.http import DICOMWEB_BASE_PATH, FHIR_BASE_PATH, REST_PATH, SOAP_PATH
from harness.scenarios import SCENARIOS, run_scenario
from harness.scenarios.http import (
    HAS_PYDICOM,
    HttpScenario,
    check_dicomweb,
    check_rest,
    check_soap,
    multipart_parts,
    synthetic_dicom,
)
from harness.sinks import Record
from harness.sinks import _http as http_sink
from harness.sinks._http import REDACTED, HttpSink
from harness.sinks.dicomweb import DICOMwebSink
from harness.sinks.fhir import FHIRSink
from harness.sinks.rest import RestSink
from harness.sinks.soap import SoapSink
from messagefoundry.apiclient import EngineClient
from messagefoundry.config.wiring import EnvRef, Registry, load_config
from messagefoundry.generators import _core, all_types  # noqa: F401  (registers message types)
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.pipeline.dryrun import dry_run
from messagefoundry.store import MessageStatus
from tests._harness_engine import (
    HARNESS_CONFIG,
    ephemeral_overrides,
    harness_egress,
    serve_harness_config,
)

_HTTP_SCENARIOS = sorted(name for name in SCENARIOS if name.startswith("http_"))
_HTTP_KINDS = ("rest", "soap", "fhir", "dicomweb")
#: The kinds with registered scenarios on this install: DICOMweb's need the [dicom] extra.
_SCENARIO_KINDS = _HTTP_KINDS if HAS_PYDICOM else _HTTP_KINDS[:3]

#: The posture ``serve`` runs under: block_unlisted_outbound on (an empty ``allowed_*`` list refuses
#: its transport), with only the loopback HTTP host listed.
_SERVE_POSTURE = (
    '[security]\nblock_unlisted_outbound = true\n[egress]\nallowed_http = ["127.0.0.1"]\n'
)


def _hl7(control_id: str, code: str = "ADT", trigger: str = "A04") -> bytes:
    raw = f"MSH|^~\\&|A|B|C|D|20260101000000||{code}^{trigger}|{control_id}|P|2.5.1\rPID|1||X\r"
    return raw.encode()


# --- the driver and the sink, paired against each other ---------------------------------------


def test_the_driver_posts_and_the_sink_records_method_path_type_and_body() -> None:
    with RestSink() as sink:
        driver = HttpDriver("127.0.0.1", sink.port, path="/a/b?x=1", timeout=5.0)
        (out,) = driver.inject([_hl7("C1")])
        records = sink.wait_for(lambda rs: len(rs) == 1, 5.0)
    assert out.error == ""
    (record,) = records
    assert record.payload == _hl7("C1")
    assert record.meta["method"] == "POST"
    assert record.meta["path"] == "/a/b?x=1"
    assert record.meta["content-type"] == HL7_CONTENT_TYPE
    assert record.meta["status"] == "200"
    assert record.meta["header:content-length"] == str(len(_hl7("C1")))


@pytest.mark.parametrize("status", [400, 503])
def test_the_sink_answers_its_configured_status_and_the_driver_reports_it(status: int) -> None:
    with RestSink(status=status, reply_body=b'{"x":1}') as sink:
        (out,) = HttpDriver("127.0.0.1", sink.port, timeout=5.0).inject([_hl7("C2")])
        (record,) = sink.wait_for(lambda rs: len(rs) == 1, 5.0)
    assert out.error == f"HTTP {status}"
    assert out.reply == b'{"x":1}'
    assert record.meta["status"] == str(status)


def test_the_sink_status_can_change_between_runs_and_refuses_a_non_final_one() -> None:
    sink = SoapSink()
    sink.status = 503
    assert sink.status == 503
    with pytest.raises(ValueError, match="final HTTP status"):
        sink.status = 101
    with pytest.raises(ValueError, match="final HTTP status"):
        RestSink(status=99)


def test_a_driver_reports_an_unreachable_port_rather_than_raising() -> None:
    with RestSink() as sink:
        closed = sink.port
    (out,) = HttpDriver("127.0.0.1", closed, timeout=2.0).inject([_hl7("C3")])
    assert out.error and out.reply is None


def test_the_sink_redacts_credential_header_values() -> None:
    with FHIRSink() as sink:
        conn = socket.create_connection(("127.0.0.1", sink.port), 5.0)
        conn.sendall(
            b"POST /fhir/Patient HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer s3cret\r\n"
            b"X-Api-Key: k3y\r\nContent-Length: 2\r\n\r\n{}"
        )
        conn.recv(4096)
        conn.close()
        (record,) = sink.wait_for(lambda rs: len(rs) == 1, 5.0)
    assert record.meta["header:authorization"] == REDACTED
    assert record.meta["header:x-api-key"] == REDACTED
    assert "s3cret" not in repr(record.meta) and "k3y" not in repr(record.meta)


_SUPERSCRIPT_TWO = chr(0xB2)  # str.isdigit() says yes; int() says no


@pytest.mark.parametrize(
    ("framing", "status"),
    [
        ("Content-Length: 99999999999", "413"),
        ("Content-Length: -1", "400"),
        (f"Content-Length: {_SUPERSCRIPT_TWO}", "400"),
        ("Transfer-Encoding: chunked", "400"),
        ("X-No-Length: 1", "411"),
        ("Content-Length: " + "9" * 5000, "400"),  # past int()'s digit limit
    ],
)
def test_the_sink_refuses_a_body_it_cannot_frame_without_reading_it(
    framing: str, status: str
) -> None:
    with DICOMwebSink() as sink:
        conn = socket.create_connection(("127.0.0.1", sink.port), 5.0)
        conn.sendall(f"POST /dicom-web/studies HTTP/1.1\r\nHost: x\r\n{framing}\r\n\r\n".encode())
        reply = conn.recv(4096)
        conn.close()
        (record,) = sink.wait_for(lambda rs: len(rs) == 1, 5.0)
    assert reply.startswith(f"HTTP/1.1 {status} ".encode())
    assert record.payload == b"" and record.meta["refused"]
    assert record.meta["status"] == status


def test_a_sender_of_an_over_cap_body_reads_the_413_rather_than_a_reset() -> None:
    """The sink answers, then discards what the sender is still sending, so a client that writes
    its whole body before reading (urllib, the engine's opener) sees the refusal."""
    big = b"x" * (DEFAULT_MAX_MESSAGE_BYTES + 1024 * 1024)
    with RestSink() as sink:
        status, _ = HttpDriver("127.0.0.1", sink.port, timeout=10.0).post(big)
        (record,) = sink.wait_for(lambda rs: len(rs) == 1, 5.0)
    assert status == 413
    assert record.meta["status"] == "413" and record.payload == b""


def test_a_stalled_body_is_answered_408_within_the_read_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(http_sink, "READ_TIMEOUT_SECONDS", 0.3)
    with SoapSink() as sink:
        conn = socket.create_connection(("127.0.0.1", sink.port), 5.0)
        conn.sendall(b"POST /soap HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nonly ten b")
        reply = conn.recv(4096)
        conn.close()
        (record,) = sink.wait_for(lambda rs: len(rs) == 1, 5.0)
    assert reply.startswith(b"HTTP/1.1 408 ")
    assert record.payload == b"" and record.meta["status"] == "408"


def test_every_http_sink_binds_loopback_whatever_the_host_endpoint_says() -> None:
    eps = Endpoints({"host": "0.0.0.0"}, environ={})  # noqa: S104  (the point of the test)
    for kind in _HTTP_KINDS:
        sink = sinks.build(kind, eps, f"http_{kind}")
        assert isinstance(sink, HttpSink) and sink.host == sinks.LOOPBACK, kind


def test_message_id_of_reads_only_a_receipt() -> None:
    assert message_id_of(b'{"status": "accepted", "message_id": "abc"}') == "abc"
    for reply in (None, b"", b"not json", b"[1]", b'{"message_id": 5}', b'{"message_id": ""}'):
        assert message_id_of(reply) is None
    assert message_id_of(b"[" * 65536) is None  # nesting deep enough to raise RecursionError


def test_discovery_registers_the_http_driver_and_one_sink_per_http_kind() -> None:
    assert isinstance(drivers.build("http", Endpoints(), "http_in"), HttpDriver)
    built = {kind: sinks.build(kind, Endpoints(), f"http_{kind}") for kind in _HTTP_KINDS}
    assert {kind: type(sink) for kind, sink in built.items()} == {
        "rest": RestSink,
        "soap": SoapSink,
        "fhir": FHIRSink,
        "dicomweb": DICOMwebSink,
    }
    assert all(isinstance(s, HttpSink) and s.kind == k for k, s in built.items())


# --- the request checks, and controls that make them fail --------------------------------------


def _record(payload: bytes, **meta: str) -> Record:
    return Record(payload, meta)


def test_check_rest_accepts_the_graph_shape_and_names_each_wrong_field() -> None:
    body = json.dumps({"control_id": "CID", "message_type": "ADT^A04"}).encode()
    good = {"method": "POST", "path": "/rest/adt", "content-type": "application/json"}
    assert check_rest(_record(body, **good), "CID", b"") == ""
    assert "method" in check_rest(_record(body, **{**good, "method": "PUT"}), "CID", b"")
    assert "path" in check_rest(_record(body, **{**good, "path": "/other"}), "CID", b"")
    assert "content-type" in check_rest(
        _record(body, **{**good, "content-type": "text/plain"}), "CID", b""
    )
    assert "control id" in check_rest(_record(body, **good), "OTHER", b"")


def test_check_soap_requires_the_quoted_soapaction_and_the_control_id_element() -> None:
    envelope = (
        b'<soap:Envelope xmlns:soap="x"><soap:Body><h:ControlId>CID</h:ControlId>'
        b"</soap:Body></soap:Envelope>"
    )
    good = {
        "method": "POST",
        "path": "/soap/HarnessService",
        "content-type": "text/xml; charset=utf-8",
        "header:soapaction": '"urn:messagefoundry:harness:Notify"',
    }
    assert check_soap(_record(envelope, **good), "CID", b"") == ""
    unquoted = {**good, "header:soapaction": "urn:messagefoundry:harness:Notify"}
    assert "SOAPAction" in check_soap(_record(envelope, **unquoted), "CID", b"")
    assert "control id" in check_soap(_record(envelope, **good), "OTHER", b"")


def _stow(obj: bytes, boundary: str = "b0und") -> tuple[str, bytes]:
    content_type = f'multipart/related; type="application/dicom"; boundary={boundary}'
    body = (
        f"--{boundary}\r\nContent-Type: application/dicom\r\n\r\n".encode()
        + obj
        + f"\r\n--{boundary}--\r\n".encode()
    )
    return content_type, body


def test_multipart_parts_unpacks_the_stow_framing_and_refuses_a_wrong_boundary() -> None:
    content_type, body = _stow(b"\x00DICM\r\n--not-the-boundary\r\nbytes")
    ((headers, content),) = multipart_parts(content_type, body)
    assert headers == {"content-type": "application/dicom"}
    assert content == b"\x00DICM\r\n--not-the-boundary\r\nbytes"
    assert multipart_parts(content_type.replace("b0und", "other"), body) == []
    assert multipart_parts("multipart/related", body) == []
    truncated = body[: -len(b"\r\n--b0und--\r\n")]
    assert multipart_parts(content_type, truncated) == []  # no close delimiter
    assert multipart_parts(content_type, body + b"trailing") == []
    assert len(multipart_parts(content_type, body.removesuffix(b"\r\n"))) == 1


def test_check_dicomweb_requires_the_exact_object_bytes() -> None:
    pytest.importorskip("pydicom")
    obj = synthetic_dicom("CID")
    assert b"HARNESS CID" in obj and obj[128:132] == b"DICM"
    content_type, body = _stow(obj)
    meta = {
        "method": "POST",
        "path": "/dicom-web/studies",
        "content-type": content_type,
        "header:accept": "application/dicom+json",
    }
    assert check_dicomweb(_record(body, **meta), "CID", obj) == ""
    tampered = obj[:-1] + bytes([obj[-1] ^ 1])
    assert "byte for byte" in check_dicomweb(_record(body, **meta), "CID", tampered)
    two = body.replace(
        b"b0und--\r\n", b"b0und\r\nContent-Type: application/dicom\r\n\r\nx\r\n--b0und--\r\n"
    )
    assert "2 part(s)" in check_dicomweb(_record(two, **meta), "CID", obj)
    plain = {**meta, "content-type": "application/octet-stream"}
    assert "multipart/related" in check_dicomweb(_record(body, **plain), "CID", obj)


def test_an_http_scenario_with_a_sink_must_name_a_check() -> None:
    with pytest.raises(ValueError, match="no request check"):
        HttpScenario("x", "", "ADT", "A04", sink="rest", sink_endpoint="http_rest")
    with pytest.raises(ValueError, match="payload must be"):
        HttpScenario("x", "", "ADT", "A04", payload="pdf")
    with pytest.raises(ValueError, match="final HTTP status"):
        HttpScenario("x", "", "ADT", "A04", sink_status=100)
    with pytest.raises(ValueError, match="at least 1"):
        HttpScenario("x", "", "ADT", "A04", min_attempts=0)
    with pytest.raises(ValueError, match="below min_attempts"):
        HttpScenario("x", "", "ADT", "A04", min_attempts=2, max_attempts=1)


def test_an_answered_refusal_reached_the_engine_and_is_not_a_failed_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 422 is the inbound answering a body it recorded as ERROR: the run goes on to the
    disposition. A refused connection never reached it: the run stops at "could not send"."""

    class Answers(Driver):
        kind = "http"

        def __init__(self, error: str) -> None:
            self.error = error

        def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
            return [Injection(error=self.error, reply=b"{}") for _ in payloads]

    class Client:
        def list_messages(self, *, control_id: str, **kwargs: object) -> object:
            return SimpleNamespace(messages=[SimpleNamespace(status="error")])

    scenario = HttpScenario("e", "", "ADT", "A04", count=2, expect="error")
    client: Any = Client()
    monkeypatch.setattr(drivers, "build", lambda kind, eps, key: Answers("HTTP 422"))
    assert run_scenario(scenario, client, timeout=1.0).ok
    monkeypatch.setattr(drivers, "build", lambda kind, eps, key: Answers("ConnectionRefusedError"))
    refused = run_scenario(scenario, client, timeout=1.0)
    assert not refused.ok and "could not send" in refused.detail


# --- served: the real harness/config graph ------------------------------------------------------


@pytest.fixture
def served(tmp_path: Path) -> Iterator[tuple[str, Endpoints]]:
    """The real graph under the ``serve`` egress posture, read by the settings loader."""
    egress = harness_egress(tmp_path, _SERVE_POSTURE)
    assert egress.deny_by_default and egress.allowed_http == ["127.0.0.1"]
    with serve_harness_config(tmp_path, ephemeral_overrides(tmp_path), egress=egress) as server:
        yield server


def test_every_http_scenario_passes_under_the_serve_egress_posture(
    served: tuple[str, Endpoints],
) -> None:
    api_url, eps = served
    assert len(_HTTP_SCENARIOS) == 2 * len(_SCENARIO_KINDS) + 2  # running fewer must not pass
    with EngineClient(api_url) as client:
        results = [
            run_scenario(SCENARIOS[name], client, timeout=20.0, endpoints=eps)
            for name in _HTTP_SCENARIOS
        ]
    assert results, "no HTTP scenario ran"  # the absence check below must not pass on none
    failed = [f"{r.scenario.name}: {r.detail}" for r in results if not r.ok]
    assert not failed, failed


def test_the_scenario_checks_can_say_no(served: tuple[str, Endpoints]) -> None:
    """Negative controls against the live graph: each one must FAIL, and say why."""
    api_url, eps = served
    rest = SCENARIOS["http_rest_delivered"]
    rest_dl = SCENARIOS["http_rest_retry_dead_letter"]
    assert isinstance(rest, HttpScenario) and isinstance(rest_dl, HttpScenario)
    controls = {
        # The REST request held to the SOAP check: the path is wrong for it.
        "wrong check": dataclasses.replace(rest, name="c1", count=1, check=check_soap),
        # The sink answers 503, so nothing is PROCESSED.
        "sink refuses": dataclasses.replace(rest, name="c2", count=1, sink_status=503),
        # A 503 is retried, so "at most one attempt" must fail.
        "retried": dataclasses.replace(rest_dl, name="c3", count=1, min_attempts=1, max_attempts=1),
        # An SIU is routed nowhere: its disposition matches, so only the sink check can say no.
        "never sent": dataclasses.replace(
            rest, name="c4", count=1, code="SIU", trigger="S12", expect="unrouted"
        ),
    }
    with EngineClient(api_url) as client:
        results = {
            label: run_scenario(s, client, timeout=4.0, endpoints=eps)
            for label, s in controls.items()
        }
    assert not results["wrong check"].ok and "path '/rest/adt'" in results["wrong check"].detail
    refused = results["sink refuses"]
    assert not refused.ok and "0/1 reached 'processed'" in refused.detail, refused.detail
    assert not results["retried"].ok and "wanted at most 1" in results["retried"].detail
    never = results["never sent"]
    assert not never.ok and "1/1 reached 'unrouted'" in never.detail, never.detail
    assert "0 attempt(s), wanted at least 1" in never.detail


@pytest.mark.parametrize(
    "posture",
    [
        pytest.param("[security]\nblock_unlisted_outbound = true\n", id="empty-list-under-serve"),
        pytest.param('[egress]\nallowed_http = ["192.0.2.1"]\n', id="list-names-another-host"),
    ],
)
def test_a_refused_egress_fails_the_delivery_scenario(tmp_path: Path, posture: str) -> None:
    """Control for the passing runs above: the scenarios pass because ``allowed_http`` admits the
    loopback host, not because nothing gates them. With the list empty under ``serve``'s posture,
    or naming another host, the engine refuses the outbound and the same scenario fails."""
    egress = harness_egress(tmp_path, posture)
    rest = SCENARIOS["http_rest_delivered"]
    assert isinstance(rest, HttpScenario)
    with serve_harness_config(tmp_path, ephemeral_overrides(tmp_path), egress=egress) as served:
        api_url, eps = served
        with EngineClient(api_url) as client:
            listing = client.connections()
            result = run_scenario(
                dataclasses.replace(rest, count=1),
                client,
                timeout=3.0,
                endpoints=eps,
            )
    outbound: dict[str, set[str]] = {}
    for row in listing:
        if row.role == "destination" and row.destination:
            outbound.setdefault(row.destination, set()).add(row.status)
    inbound = {row.channel_id: row.status for row in listing if row.role == "source"}
    for name in ("OB_Http_Rest", "OB_Http_Soap", "OB_Http_FHIR", "OB_Http_DICOMweb"):
        assert outbound[name] == {"failed"}, (name, outbound.get(name))
    assert inbound["IB_Http_HL7"] == "running"
    # It must fail BECAUSE delivery was refused: the POST reached the engine and was accepted, and
    # the message never got further. A failure to reach the inbound would prove nothing here.
    assert not result.ok
    assert "could not send" not in result.detail, result.detail
    assert "0/1 reached 'processed'" in result.detail, result.detail


# --- the graph, without an engine ----------------------------------------------------------------


def _graph() -> Registry:
    registry = load_config(HARNESS_CONFIG)
    registry.validate()
    return registry


_OUTBOUND_PATHS = {
    "OB_Http_Rest": ("http_rest", REST_PATH),
    "OB_Http_Soap": ("http_soap", SOAP_PATH),
    "OB_Http_FHIR": ("http_fhir", FHIR_BASE_PATH),
    "OB_Http_DICOMweb": ("http_dicomweb", DICOMWEB_BASE_PATH),
}


def test_the_graph_reads_the_endpoints_this_family_declares() -> None:
    """A graph may not import the harness, so its env() keys, defaults and paths are literals. This
    holds them to ``harness/endpoints/http.py``: each key is ``harness_<endpoint>``, each inbound
    default is the endpoint's default port, and each outbound URL is the loopback URL of the sink's
    default port and the path the scenarios assert."""
    registry = _graph()
    declared = harness_endpoints.registry()
    for name, key in (("IB_Http_HL7", "http_in"), ("IB_Http_DICOM", "http_dicom_in")):
        port = registry.inbound[name].spec.settings["port"]
        assert isinstance(port, EnvRef) and port.key == f"harness_{key}"
        assert port.default == int(declared[key].default)
    for name, (key, path) in _OUTBOUND_PATHS.items():
        url = registry.outbound[name].spec.settings["url"]
        assert isinstance(url, EnvRef) and url.key == f"harness_{key}", name
        assert url.cast is not None
        expected = f"http://127.0.0.1:{declared[key].default}{path}"
        assert url.default == expected == url.cast(declared[key].default), name
        assert url.cast("41095") == f"http://127.0.0.1:41095{path}"
        with pytest.raises(ValueError):
            url.cast("70000")


def test_the_graph_routes_each_message_type_to_its_destination() -> None:
    registry = _graph()

    def sends(code: str, trigger: str) -> dict[str, str]:
        result = dry_run(registry, _core.generate_message(code, trigger, 1), inbound="IB_Http_HL7")
        return {d.to: d.payload for d in result.deliveries}

    rest = sends("ADT", "A04")
    assert list(rest) == ["OB_Http_Rest"]
    assert json.loads(rest["OB_Http_Rest"])["message_type"] == "ADT^A04"
    assert list(sends("ORM", "O01")) == ["OB_Http_Soap"]
    fhir = json.loads(sends("ORU", "R01")["OB_Http_FHIR"])
    assert fhir["resourceType"] == "Patient"
    unrouted = dry_run(registry, _core.generate_message("SIU", "S12", 1), inbound="IB_Http_HL7")
    assert unrouted.disposition == MessageStatus.UNROUTED and unrouted.deliveries == []


def test_a_hostile_control_id_cannot_reshape_the_soap_envelope() -> None:
    hostile = "X</h:ControlId><evil/>&"
    raw = "MSH|^~\\&|A|B|C|D|20260101000000||ORM^O01|" + hostile + "|P|2.5.1\rPID|1||X\rORC|NW|1\r"
    (delivery,) = dry_run(_graph(), raw, inbound="IB_Http_HL7").deliveries
    assert "<evil/>" not in delivery.payload
    assert "X&lt;/h:ControlId&gt;&lt;evil/&gt;&amp;" in delivery.payload
    assert delivery.payload.count("<h:ControlId>") == 1


def test_a_control_character_cannot_make_the_soap_envelope_ill_formed() -> None:
    raw = "MSH|^~\\&|A|B|C|D|20260101000000||ORM^O01|A\x1fB\x01C|P|2.5.1\rPID|1||X\r"
    (delivery,) = dry_run(_graph(), raw, inbound="IB_Http_HL7").deliveries
    assert "<h:ControlId>ABC</h:ControlId>" in delivery.payload
    assert not any(c < " " for c in delivery.payload)


# --- coverage --------------------------------------------------------------------------------------


def test_coverage_shows_the_http_inbound_and_the_four_http_outbounds(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--coverage"]) == 0
    lines = capsys.readouterr().out.splitlines()

    def covered_by(direction: str, kind: str) -> set[str]:
        hits = [ln for ln in lines if ln.split()[:2] == [direction, kind]]
        assert len(hits) == 1, (direction, kind)
        return set(hits[0].split(None, 2)[2].split(", "))

    assert "http_unrouted" in covered_by("inbound", "http")
    for kind in _SCENARIO_KINDS:
        assert {f"http_{kind}_delivered", f"http_{kind}_retry_dead_letter"} <= covered_by(
            "outbound", kind
        )
    assert "NONE" not in covered_by("inbound", "http")


def test_the_http_scenarios_are_registered() -> None:
    assert set(_HTTP_SCENARIOS) == {
        *(f"http_{k}_delivered" for k in _SCENARIO_KINDS),
        *(f"http_{k}_retry_dead_letter" for k in _SCENARIO_KINDS),
        "http_rest_rejected_dead_letter",
        "http_unrouted",
    }
    assert all(
        isinstance(SCENARIOS[n], HttpScenario) and SCENARIOS[n] in scenarios.registry().values()
        for n in _HTTP_SCENARIOS
    )
