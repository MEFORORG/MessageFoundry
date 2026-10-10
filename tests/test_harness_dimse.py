# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness DICOM DIMSE family (vault BACKLOG #2677): the C-STORE driver and sink paired against
each other, the synthetic dataset generator, the graph's AE titles held equal to the harness's, and
the DIMSE scenarios run against the REAL ``harness/config`` graph, with negative controls that must
fail.

The registered DIMSE scenarios also run in
``tests/test_harness_scenarios.py::test_every_registered_scenario_passes_against_the_real_graph``.
Without the ``[dicom]`` extra this module is skipped with a reason, never passed.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("pydicom", reason="the harness DIMSE family needs the [dicom] extra")
pytest.importorskip("pynetdicom", reason="the harness DIMSE family needs the [dicom] extra")

from harness import drivers, endpoints, sinks  # noqa: E402
from harness.drivers import Injection  # noqa: E402
from harness.drivers.dimse import (  # noqa: E402
    ENGINE_AE_TITLE,
    MAX_ASSOCIATION_READ_BYTES,
    DimseDriver,
    dicom_extra_missing,
    status_of,
)
from harness.endpoints import Endpoints  # noqa: E402
from harness.scenarios import SCENARIOS, run_scenario  # noqa: E402
from harness.scenarios._dimse_dataset import make_datasets, sop_instance_uid  # noqa: E402
from harness.scenarios.dimse import (  # noqa: E402
    INBOUND_CONNECTION,
    OUTBOUND_CONNECTION,
    DimseScenario,
)
from harness.sinks.dimse import (  # noqa: E402
    CANNOT_UNDERSTAND,
    OUT_OF_RESOURCES,
    SINK_AE_TITLE,
    DimseSink,
)
from messagefoundry.apiclient import EngineClient  # noqa: E402
from messagefoundry.parsing import binary  # noqa: E402
from tests._harness_engine import ephemeral_overrides, serve_harness_config  # noqa: E402

_DIMSE_SCENARIOS = ("dimse_delivered", "dimse_refused_dead_letter", "dimse_retry_dead_letter")


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Endpoints]]:
    """The real harness/config graph, served on ephemeral endpoints."""
    with serve_harness_config(tmp_path, ephemeral_overrides(tmp_path)) as served:
        yield served


def _driver_for(sink: DimseSink, **kw: object) -> DimseDriver:
    return DimseDriver("127.0.0.1", sink.port, called_ae_title=SINK_AE_TITLE, timeout=5.0, **kw)  # type: ignore[arg-type]


# --- the generator ---------------------------------------------------------------------------------


def test_the_generated_objects_are_synthetic_and_carry_fresh_uids() -> None:
    from io import BytesIO

    from pydicom import dcmread

    assert dicom_extra_missing() is None
    payloads, uids = make_datasets(3)
    assert len(set(uids)) == 3
    for i, (payload, uid) in enumerate(zip(payloads, uids, strict=True), start=1):
        ds = dcmread(BytesIO(payload))
        assert str(ds.PatientName) == "HARNESS^SYNTHETIC"
        assert ds.PatientID == f"SYNTH-{i:04d}"
        assert payload[128:132] == b"DICM"  # a Part-10 object, preamble and all
        assert sop_instance_uid(payload) == uid
        # The engine stores a DICOM body as base64 carriage; the reader takes that shape too.
        assert sop_instance_uid(binary.encode(payload)) == uid
    _, again = make_datasets(3)
    assert set(again).isdisjoint(uids)  # a second run can never match the first run's rows


def test_the_uid_reader_returns_none_for_what_is_not_dicom() -> None:
    """Control for the reader above: it must be able to say no."""
    assert sop_instance_uid(b"MSH|^~\\&|not dicom") is None
    assert sop_instance_uid("not a carriage string") is None
    assert sop_instance_uid(binary.encode(b"\x00" * 200)) is None


# --- the driver and the sink, paired -----------------------------------------------------------------


def test_the_driver_and_sink_round_trip_by_sop_instance_uid() -> None:
    payloads, uids = make_datasets(2)
    with DimseSink() as sink:
        out = _driver_for(sink).inject(payloads)
        records = sink.wait_for(lambda rs: len(rs) == 2, 5.0)
    assert [o.error for o in out] == ["", ""]
    assert [o.reply for o in out] == [b"0000", b"0000"]
    assert [status_of(o) for o in out] == [0, 0]
    assert [sop_instance_uid(r.payload) for r in records] == uids
    assert [r.meta["sop_instance_uid"] for r in records] == uids
    assert {r.meta["calling_ae"] for r in records} == {"HARNESS_SCU"}
    assert {r.meta["status"] for r in records} == {"0000"}


def test_the_sink_answers_its_configured_status_and_still_records_the_attempt() -> None:
    payloads, uids = make_datasets(1)
    with DimseSink(status=OUT_OF_RESOURCES) as sink:
        (out,) = _driver_for(sink).inject(payloads)
        records = sink.wait_for(lambda rs: bool(rs), 5.0)
    assert out.error == "" and out.reply == b"A700"
    assert status_of(out) == OUT_OF_RESOURCES
    assert [r.meta["status"] for r in records] == ["A700"]
    assert sop_instance_uid(records[0].payload) == uids[0]


def _grown(payload: bytes, filler: int, *, deflated: bool = False) -> bytes:
    """``payload`` grown by one zero-filled OB element (no PHI; nothing reads it), optionally saved as
    Deflated Explicit VR LE so it is small on the wire and large once inflated."""
    from io import BytesIO

    from pydicom import dcmread
    from pydicom.uid import DeflatedExplicitVRLittleEndian

    ds = dcmread(BytesIO(payload))
    ds.EncapsulatedDocument = b"\x00" * filler  # (0042,0011) OB
    if deflated:
        ds.file_meta.TransferSyntaxUID = DeflatedExplicitVRLittleEndian
    out = BytesIO()
    ds.save_as(out, enforce_file_format=True)
    return out.getvalue()


def test_the_sink_cap_defaults_to_the_engine_message_cap() -> None:
    from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

    assert DimseSink().max_object_bytes == DEFAULT_MAX_MESSAGE_BYTES
    with pytest.raises(ValueError, match="positive"):
        DimseSink(max_object_bytes=0)


def test_the_sink_refuses_an_over_cap_object_before_decode_and_records_the_refusal() -> None:
    """ASVS 5.1.1: an object over ``max_object_bytes`` is answered CANNOT_UNDERSTAND whatever status
    the sink was told to give, recorded with an empty payload and a reason, and never decoded. The
    first object, under the cap, is the positive control on the same association settings."""
    (small,), (small_uid,) = make_datasets(1)
    (base,), (big_uid,) = make_datasets(1)
    big = _grown(base, 64 * 1024)
    with DimseSink(max_object_bytes=len(small) + 1024) as sink:
        out = _driver_for(sink).inject([small, big])
        records = sink.wait_for(lambda rs: len(rs) == 2, 5.0)
    assert [status_of(o) for o in out] == [0, CANNOT_UNDERSTAND]
    assert sop_instance_uid(records[0].payload) == small_uid and "refused" not in records[0].meta
    assert records[1].payload == b""
    assert records[1].meta["sop_instance_uid"] == big_uid
    assert records[1].meta["status"] == f"{CANNOT_UNDERSTAND:04X}"
    assert "-byte cap; not decoded" in records[1].meta["refused"]
    assert "decode_error" not in records[1].meta


def test_the_sink_charges_the_re_encoded_object_too() -> None:
    """The raw Data Set leaves out the preamble, DICM and file meta, so an object can pass the raw
    charge and still be over the cap once re-encoded; the engine's SCP charges both, and so does this."""
    (payload,), _ = make_datasets(1)
    with DimseSink(max_object_bytes=len(payload) - 1) as sink:
        (out,) = _driver_for(sink).inject([payload])
        (record,) = sink.wait_for(lambda rs: len(rs) == 1, 5.0)
    assert status_of(out) == CANNOT_UNDERSTAND
    assert record.payload == b"" and "re-encoded" in record.meta["refused"]


def test_the_sink_refuses_a_deflated_object_that_inflates_past_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Deflated object small on the wire is inflated in bounded memory before decode; one that
    inflates past the inflate ceiling is refused. The ceiling is lowered so the test object stays
    small; the sink reads it when the object arrives, as the engine's SCP does."""
    import harness.sinks.dimse as dimse_sink

    mib = 1024 * 1024
    monkeypatch.setattr(dimse_sink, "DEFAULT_MAX_INFLATED_BYTES", mib)
    (base,), _ = make_datasets(1)
    bomb = _grown(base, 2 * mib, deflated=True)
    under = _grown(base, mib // 2, deflated=True)
    assert len(bomb) < mib, "only its inflate is large"
    with DimseSink() as sink:
        out = _driver_for(sink).inject([under, bomb])
        records = sink.wait_for(lambda rs: len(rs) == 2, 10.0)
    assert [status_of(o) for o in out] == [0, CANNOT_UNDERSTAND]
    assert records[0].payload and "refused" not in records[0].meta
    assert records[1].payload == b""
    assert records[1].meta["refused"] == f"inflates past the {mib}-byte cap; not decoded"


def test_the_sink_refuses_an_association_addressed_to_another_ae() -> None:
    """Negative control: the sink requires its own AE title, so the graph's called_ae_title is
    load-bearing, not decoration."""
    payloads, _ = make_datasets(1)
    with DimseSink() as sink:
        (out,) = DimseDriver("127.0.0.1", sink.port, called_ae_title="SOMEONE_ELSE").inject(
            payloads
        )
        assert sink.records() == []
    assert out.error and "no association" in out.error
    assert status_of(out) is None


def test_the_driver_refuses_a_pdu_past_its_read_cap_without_reading_it() -> None:
    """pynetdicom reads whatever PDU length a peer announces. A peer that announces one byte past
    the driver's read cap gets a refusal, and none of that PDU is read (ASVS 5.1.1, BACKLOG #1127).
    This is also the check that pynetdicom still calls the socket hook the cap rides on."""
    with socket.create_server(("127.0.0.1", 0)) as server:
        server.settimeout(10.0)

        def oversized_accept() -> None:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(10.0)
                conn.recv(65536)  # the A-ASSOCIATE-RQ
                # An A-ASSOCIATE-AC header announcing a body one byte past the cap, then some body.
                conn.sendall(struct.pack(">BBL", 0x02, 0, MAX_ASSOCIATION_READ_BYTES + 1))
                conn.sendall(b"\0" * 4096)
                with contextlib.suppress(OSError):
                    while conn.recv(4096):  # hold the connection until the driver drops it
                        pass

        peer = threading.Thread(target=oversized_accept, daemon=True)
        peer.start()
        (out,) = DimseDriver("127.0.0.1", server.getsockname()[1], timeout=5.0).inject(
            make_datasets(1)[0]
        )
        peer.join(10.0)
    assert out.error and out.error.startswith("reply refused"), out
    assert status_of(out) is None


def test_the_driver_reports_an_unreachable_port_and_a_non_dicom_payload() -> None:
    with DimseSink() as sink:
        pass
    closed = sink.port  # stopped: nothing listens there now
    (gone,) = DimseDriver("127.0.0.1", closed, timeout=2.0).inject(make_datasets(1)[0])
    assert gone.error
    (junk,) = DimseDriver("127.0.0.1", closed, timeout=2.0).inject([b"MSH|^~\\&|not dicom"])
    assert junk.error.startswith("not a DICOM Part-10 object")
    assert status_of(Injection(reply=b"zz")) is None


def test_the_driver_reports_rather_than_raises_on_what_pynetdicom_refuses() -> None:
    """A payload with no SOPInstanceUID and an AE title over 16 characters each come back as an
    error on the Injection; inject() itself never raises (the Driver contract)."""
    from io import BytesIO

    from pydicom import dcmread

    (payload,), _ = make_datasets(1)
    ds = dcmread(BytesIO(payload))
    del ds.SOPInstanceUID
    buffer = BytesIO()
    ds.save_as(buffer, enforce_file_format=True)
    with DimseSink() as sink:
        (no_uid,) = _driver_for(sink).inject([buffer.getvalue()])
        (long_ae,) = DimseDriver("127.0.0.1", sink.port, calling_ae_title="X" * 17).inject(
            [payload]
        )
        assert sink.records() == []
    assert no_uid.error.startswith("not a DICOM Part-10 object")
    assert long_ae.error.startswith("association to 127.0.0.1")


def test_discovery_and_a_run_without_the_dicom_extra_report_it(tmp_path: Path) -> None:
    """With pydicom and pynetdicom unimportable, every harness registry still loads, the driver
    reports the missing extra per payload, and a DIMSE scenario fails saying why (never a pass)."""
    import subprocess
    import sys

    script = (
        "import sys\n"
        "sys.modules['pydicom'] = None\n"
        "sys.modules['pynetdicom'] = None\n"
        "from harness import drivers, sinks, endpoints, scenarios\n"
        "drivers.registry(); sinks.registry(); endpoints.registry()\n"
        "from harness.scenarios import SCENARIOS, ScenarioContext\n"
        "(out,) = drivers.build('dimse', endpoints.Endpoints(), 'dimse_in').inject([b'x'])\n"
        "assert 'not installed' in out.error, out\n"
        "assert 'not installed' in SCENARIOS['dimse_delivered'].unavailable()\n"
        "assert SCENARIOS['processed'].unavailable() is None\n"
        "result = SCENARIOS['dimse_delivered'].run(ScenarioContext(client=None))\n"
        "assert not result.ok and 'not installed' in result.detail, result.detail\n"
        "print('ok')\n"
    )
    repo = Path(__file__).resolve().parents[1]
    done = subprocess.run(
        [sys.executable, "-c", script], cwd=repo, capture_output=True, text=True, timeout=45
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.strip() == "ok"


def test_every_dimse_scenario_names_declared_endpoints_and_graph_connections() -> None:
    """The generic endpoint check in test_harness_scenarios.py covers only ``Scenario``; this is
    its DIMSE twin, plus the connection names the scenario polls."""
    from messagefoundry.config.wiring import load_config

    registry = load_config(str(Path(__file__).resolve().parents[1] / "harness" / "config"))
    declared = set(endpoints.registry())
    dimse = [s for s in SCENARIOS.values() if isinstance(s, DimseScenario)]
    assert {s.name for s in dimse} == set(_DIMSE_SCENARIOS)
    for scenario in dimse:
        assert {scenario.inbound, scenario.sink_endpoint} <= declared, scenario.name
        assert scenario.inbound_connection in registry.inbound, scenario.name
        assert scenario.outbound_connection in registry.outbound, scenario.name


def test_the_retry_scenario_expects_the_graphs_own_attempt_limit() -> None:
    from messagefoundry.config.wiring import load_config

    registry = load_config(str(Path(__file__).resolve().parents[1] / "harness" / "config"))
    retry = registry.outbound[OUTBOUND_CONNECTION].retry
    scenario = SCENARIOS["dimse_retry_dead_letter"]
    assert isinstance(scenario, DimseScenario)
    assert retry is not None and scenario.attempts == retry.max_attempts


def test_a_dimse_sink_binds_loopback_whatever_the_host_endpoint_says() -> None:
    eps = Endpoints({"host": "0.0.0.0"}, environ={})  # noqa: S104  (the point of the test)
    sink = sinks.build("dimse", eps, "dimse_out")
    assert isinstance(sink, DimseSink)
    assert sink.host == sinks.LOOPBACK
    driver = drivers.build("dimse", eps, "dimse_in")
    assert isinstance(driver, DimseDriver)
    assert driver.host == "0.0.0.0"  # noqa: S104  (drivers DIAL the host endpoint)


def test_the_family_registers_its_driver_sink_endpoints_and_scenarios() -> None:
    assert "dimse" in drivers.registry() and "dimse" in sinks.registry()
    assert {"dimse_in", "dimse_out"} <= set(endpoints.registry())
    assert set(_DIMSE_SCENARIOS) <= set(SCENARIOS)
    for name in _DIMSE_SCENARIOS:
        assert SCENARIOS[name].covers == {("dimse", "inbound"), ("dimse", "outbound")}


def test_the_graph_ae_titles_and_connection_names_match_the_harness() -> None:
    """``harness/config/dimse.py`` imports nothing from the harness, so the AE titles are two
    spellings of one value; they are held equal here."""
    from messagefoundry.config.wiring import load_config

    registry = load_config(str(Path(__file__).resolve().parents[1] / "harness" / "config"))
    scp = registry.inbound[INBOUND_CONNECTION].spec.settings
    scu = registry.outbound[OUTBOUND_CONNECTION].spec.settings
    assert scp["ae_title"] == ENGINE_AE_TITLE
    assert scu["called_ae_title"] == SINK_AE_TITLE
    assert scp["require_called_ae_title"] is True


# --- against the real graph --------------------------------------------------------------------------


@pytest.mark.parametrize("name", _DIMSE_SCENARIOS)
def test_each_dimse_scenario_passes_against_the_real_graph(
    server: tuple[str, Endpoints], name: str
) -> None:
    api_url, eps = server
    with EngineClient(api_url) as client:
        result = run_scenario(SCENARIOS[name], client, timeout=45.0, endpoints=eps)
    assert result.ok, result.detail


def test_a_delivery_scenario_fails_when_the_engine_cannot_reach_its_sink(
    server: tuple[str, Endpoints],
) -> None:
    """Negative control: the scenario's sink listens on a port the engine's outbound does not dial,
    so the outbound retries into nothing and dead-letters, and the scenario must say no."""
    api_url, eps = server
    with DimseSink() as elsewhere:
        pass
    moved = Endpoints(
        {**{k: eps.value(k) for k in endpoints.registry()}, "dimse_out": str(elsewhere.port)}
    )
    with EngineClient(api_url) as client:
        result = run_scenario(SCENARIOS["dimse_delivered"], client, timeout=30.0, endpoints=moved)
    assert not result.ok
    assert "0/3 rows (matched by SOPInstanceUID) reached 'processed'" in result.detail
    assert "statuses seen" in result.detail


def test_a_scenario_whose_sink_answer_cannot_lead_to_its_expectation_is_refused() -> None:
    with pytest.raises(ValueError, match="cannot lead to 'processed'"):
        DimseScenario("x", "", sink_status=CANNOT_UNDERSTAND)
    with pytest.raises(ValueError, match="cannot lead to 'dead_letter'"):
        DimseScenario("x", "", expect="dead_letter")
    with pytest.raises(ValueError, match="sent exactly once"):
        DimseScenario("x", "", attempts=3)
    with pytest.raises(ValueError, match="16-bit"):
        DimseScenario("x", "", expect="dead_letter", sink_status=0x10000)
    assert DimseScenario("x", "", sink_status=0xB000).expect == "processed"  # a Warning stores


def test_a_dead_letter_scenario_fails_on_the_wrong_attempt_count(
    server: tuple[str, Endpoints],
) -> None:
    """Negative control for the retry assertion: Out of Resources is retried three times, so a
    scenario claiming one attempt must fail on the engine's count."""
    api_url, eps = server
    wrong = DimseScenario(
        "wrong_attempts",
        "",
        count=1,
        expect="dead_letter",
        sink_status=OUT_OF_RESOURCES,
        attempts=1,
    )
    with EngineClient(api_url) as client:
        result = run_scenario(wrong, client, timeout=30.0, endpoints=eps)
    assert not result.ok
    assert "dead-letter attempts [3], expected 1" in result.detail


def test_a_dimse_scenario_fails_when_the_inbound_is_not_there(
    tmp_path: Path, server: tuple[str, Endpoints]
) -> None:
    """Negative control for the send leg: a driver aimed at a port nothing listens on commits
    nothing, and the scenario reports it rather than waiting for rows."""
    api_url, eps = server
    with DimseSink() as idle:
        pass
    dead_port = Endpoints(
        {**{k: eps.value(k) for k in endpoints.registry()}, "dimse_in": str(idle.port)}
    )
    with EngineClient(api_url) as client:
        result = run_scenario(
            SCENARIOS["dimse_delivered"], client, timeout=5.0, endpoints=dead_port
        )
    assert not result.ok
    assert result.detail.startswith("0/3 committed by the inbound SCP")
