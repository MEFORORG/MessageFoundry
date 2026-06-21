# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the pure DICOM codec (ADR 0025): DicomPeek / DicomDataset / hl7_map, the base64 carriage
round-trip (ADR 0028), fail-loud errors, the PHI rule, and the console-carve-out import purity."""

from __future__ import annotations

import subprocess
import sys

import pytest

pytest.importorskip("pydicom", reason="DICOM codec tests need the [dicom] extra")

from messagefoundry.parsing import Message, RawMessage  # noqa: E402
from messagefoundry.parsing.dicom import (  # noqa: E402
    DicomDataset,
    DicomError,
    DicomPeek,
    DicomPeekError,
    hl7_map,
)

from tests._dicom_sample import BASIC_TEXT_SR, make_sr_part10  # noqa: E402

# A patient name fabricated for the PHI-leak assertions (must never appear in an error/log message).
_PHI_NAME = "Zzyzx^Quintessa^PhiCanary"


# --- carriage round-trip (ADR 0028) ------------------------------------------


def test_raw_message_from_bytes_round_trips_dicom() -> None:
    data = make_sr_part10()
    rm = RawMessage.from_bytes(data, "dicom")
    assert rm.is_binary
    assert rm.raw.startswith("mfb64:v1:")
    assert rm.raw_bytes == data  # byte-exact through the str/TEXT carriage
    assert "\x00" not in rm.raw  # ASCII-safe (a Part-10 preamble is 128 NULs)


# --- DicomPeek (routing tier) ------------------------------------------------


def test_peek_reads_routing_fields_and_flags_sr() -> None:
    rm = RawMessage.from_bytes(make_sr_part10(), "dicom")
    peek = DicomPeek.parse(rm, calling_ae_title="MODALITY1", called_ae_title="MEFOR_SCP")
    assert peek.sop_class_uid == BASIC_TEXT_SR
    assert peek.modality == "SR"
    assert peek.study_instance_uid and peek.series_instance_uid and peek.sop_instance_uid
    assert peek.transfer_syntax_uid == "1.2.840.10008.1.2.1"  # Explicit VR Little Endian
    assert peek.calling_ae_title == "MODALITY1"
    assert peek.called_ae_title == "MEFOR_SCP"
    assert peek.is_structured_report() is True


def test_peek_accepts_raw_bytes_directly() -> None:
    peek = DicomPeek.parse(make_sr_part10())
    assert peek.is_structured_report() is True


def test_is_structured_report_keys_off_sop_class() -> None:
    # A non-SR storage class (CT Image Storage) is not a Structured Report.
    ct = DicomPeek(
        sop_class_uid="1.2.840.10008.5.1.4.1.1.2",
        sop_instance_uid="x",
        study_instance_uid=None,
        series_instance_uid=None,
        modality="CT",
        transfer_syntax_uid=None,
    )
    assert ct.is_structured_report() is False


def test_peek_fails_loud_on_non_dicom() -> None:
    with pytest.raises(DicomPeekError):
        DicomPeek.parse(b"this is not a DICOM Part-10 object at all")


# --- DicomDataset (transform tier) -------------------------------------------


def test_dataset_reads_headers() -> None:
    rm = RawMessage.from_bytes(make_sr_part10(patient_id="MRN999"), "dicom")
    ds = DicomDataset.parse(rm)
    assert ds.patient_id == "MRN999"
    assert ds.patient_name == "Doe^Jane^Q"
    assert ds.modality == "SR"
    assert ds.is_structured_report() is True
    assert ds.study_description == "Echo & Doppler"


def test_dataset_walks_sr_measurements_depth_first() -> None:
    rm = RawMessage.from_bytes(make_sr_part10(), "dicom")
    ds = DicomDataset.parse(rm)
    ms = ds.measurements()
    # One NUM at top level + one nested under a CONTAINER → the recursive walk finds both.
    assert [(m.concept_code, m.value, m.unit_code) for m in ms] == [
        ("8867-4", "72", "/min"),
        ("8480-6", "120", "mm[Hg]"),
    ]
    assert ms[0].concept_meaning == "Heart rate"
    assert ms[0].unit_scheme == "UCUM"


def test_dataset_fails_loud_on_non_dicom() -> None:
    with pytest.raises(DicomError):
        DicomDataset.parse(b"\x00\x01\x02 not dicom")


# --- hl7_map (DICOM -> HL7 v2 helpers) ---------------------------------------


def test_hl7_map_builds_oru_segments_with_escaping_round_trip() -> None:
    # patient_id 'MRN|42', accession 'ACC^7', study desc 'Echo & Doppler' all carry HL7 delimiters that
    # must be escaped by the builders and unescape cleanly via Message.field (read-back == original).
    ds = DicomDataset.parse(RawMessage.from_bytes(make_sr_part10(), "dicom"))
    msg = Message.parse("MSH|^~\\&|MEFOR|FAC|PSCRIBE|DEST|20260620101500||ORU^R01|ID1|P|2.5.1")
    msg.add_segment(hl7_map.pid_from_dataset(ds))
    msg.add_segment(hl7_map.obr_from_dataset(ds))
    for i, m in enumerate(ds.measurements(), start=1):
        msg.add_segment(hl7_map.obx_from_measurement(i, m))

    assert msg.field("PID-3.1") == "MRN|42"  # '|' escaped then unescaped, one component
    assert msg.field("PID-5.1") == "Doe"  # DICOM PN split into XPN components
    assert msg.field("PID-5.2") == "Jane"
    assert msg.field("PID-8") == "F"
    assert msg.field("OBR-3.1") == "ACC^7"  # '^' escaped/unescaped, stays one component
    assert msg.field("OBR-4.2") == "Echo & Doppler"  # '&' escaped/unescaped
    assert msg.field("OBX-3.1", occurrence=1) == "8867-4"
    assert msg.field("OBX-3.2", occurrence=1) == "Heart rate"
    assert msg.field("OBX-5", occurrence=1) == "72"
    assert msg.field("OBX-6.1", occurrence=1) == "/min"
    assert msg.field("OBX-11", occurrence=1) == "F"
    assert msg.field("OBX-3.1", occurrence=2) == "8480-6"  # the nested measurement


def test_person_name_components_splits_pn() -> None:
    assert hl7_map.person_name_components("Doe^Jane^Q") == ("Doe", "Jane", "Q")
    assert hl7_map.person_name_components("Alpha=Beta") == ("Alpha",)  # alphabetic group only
    assert hl7_map.person_name_components(None) == ()


def test_obx_builder_strips_crlf_injection() -> None:
    from messagefoundry.parsing.dicom.dataset import SrMeasurement

    m = SrMeasurement(
        concept_code="C",
        concept_scheme="LN",
        concept_meaning="evil\r\nMSH|injected",  # a CR/LF in a value must not inject a segment
        value="1",
        unit_code="u",
        unit_scheme="UCUM",
        unit_meaning="u",
    )
    line = hl7_map.obx_from_measurement(1, m)
    assert "\r" not in line and "\n" not in line


# --- PHI rule: errors carry no object bytes / element values -----------------


def test_codec_errors_are_phi_safe() -> None:
    # A corrupt body that happens to embed a PHI-looking string must not be echoed in the error message.
    poison = b"\x02\x00" + _PHI_NAME.encode() + b"\xff\xfe"
    try:
        DicomPeek.parse(poison)
    except DicomPeekError as exc:
        assert _PHI_NAME not in str(exc)
        assert "Zzyzx" not in str(exc)
    else:  # pragma: no cover - parse must fail on this
        pytest.fail("expected DicomPeekError")


# --- console carve-out: import purity (mirrors tests/test_fhir_parsing.py) ----


def test_parsing_dicom_pulls_no_heavy_engine_or_gui_modules() -> None:
    """Importing parsing.dicom must NOT pull the engine internals or the GUI (ADR 0025 §5 / CLAUDE.md §4
    carve-out): no pipeline/store/transports/api/console. (config is excluded — the root
    messagefoundry/__init__ imports config models unconditionally; the static test below proves dicom's
    own sources don't import config.)"""
    code = (
        "import sys, messagefoundry.parsing.dicom as _;"
        "heavy=('messagefoundry.pipeline','messagefoundry.store','messagefoundry.transports',"
        "'messagefoundry.api','messagefoundry.console');"
        "bad=sorted(m for m in sys.modules if m.startswith(heavy));"
        "print('\\n'.join(bad));"
        "sys.exit(1 if bad else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, (
        f"parsing.dicom pulled heavy engine/GUI modules:\n{result.stdout}"
    )


def test_parsing_dicom_does_not_eagerly_import_pydicom() -> None:
    """A bare ``import messagefoundry.parsing.dicom`` (and the DicomPeek dataclass) must NOT pull the
    optional ``[dicom]`` extra (``pydicom``) — only the ``.parse`` paths may. Keeps a console/peek-only
    import working without the extra (ADR 0025 §1/§5). Subprocess so it is import-order-independent."""
    code = (
        "import sys, messagefoundry.parsing.dicom as _;"
        "leaked=sorted(m for m in sys.modules if m.startswith(('pydicom','pynetdicom')));"
        "print('\\n'.join(leaked));"
        "sys.exit(1 if leaked else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, (
        f"parsing.dicom eagerly imported pydicom/pynetdicom:\n{result.stdout}"
    )


def test_parsing_dicom_sources_import_no_engine_packages() -> None:
    """Every parsing.dicom module must import zero engine packages — config included (the ADR's 'refer to
    the content type by the literal "dicom"' rule) — so the codec stays pure."""
    import pathlib

    import messagefoundry.parsing.dicom as pkg

    forbidden = (
        "messagefoundry.config",
        "messagefoundry.transports",
        "messagefoundry.pipeline",
        "messagefoundry.store",
        "messagefoundry.api",
        "messagefoundry.console",
    )
    offenders: list[str] = []
    for module_file in sorted(pathlib.Path(pkg.__file__).parent.glob("*.py")):
        for line in module_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            for pkg_name in forbidden:
                if stripped.startswith((f"import {pkg_name}", f"from {pkg_name}")):
                    offenders.append(f"{module_file.name}: {stripped}")
    assert not offenders, "parsing.dicom sources import engine packages:\n" + "\n".join(offenders)
