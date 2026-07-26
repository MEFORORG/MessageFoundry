# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Synthetic, **PHI-free** DICOM Structured Report fixtures for the ADR 0025 tests (and the §8 sample
generator). Not a test module (the leading underscore keeps pytest from collecting it). Importing it
requires the optional ``[dicom]`` extra (``pydicom``); callers guard with ``pytest.importorskip``."""

from __future__ import annotations

import io
import zlib

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import DeflatedExplicitVRLittleEndian, ExplicitVRLittleEndian, generate_uid

#: Basic Text SR storage SOP Class UID (an SR class DicomPeek.is_structured_report recognises).
BASIC_TEXT_SR = "1.2.840.10008.5.1.4.1.1.88.11"


def make_sr_part10(
    *,
    patient_name: str = "Doe^Jane^Q",
    patient_id: str = "MRN|42",  # the '|' exercises HL7 escaping in the OBX/PID round-trip
    accession: str = "ACC^7",
    study_description: str = "Echo & Doppler",
    measurements: tuple[tuple[str, str, str, str], ...] = (
        ("8867-4", "Heart rate", "72", "/min"),
        ("8480-6", "Systolic blood pressure", "120", "mm[Hg]"),
    ),
    sop_instance_uid: str | None = None,
) -> bytes:
    """Build a synthetic Basic Text SR Part-10 object (preamble + ``DICM`` + file meta) with a small
    ``ContentSequence`` of ``NUM`` measurements, returning its bytes. The second measurement is nested
    under a ``CONTAINER`` so the depth-first walk is exercised. All data is fabricated — never real PHI."""
    ds = Dataset()
    ds.PatientName = patient_name
    ds.PatientID = patient_id
    ds.PatientBirthDate = "19751103"
    ds.PatientSex = "F"
    ds.Modality = "SR"
    ds.SOPClassUID = BASIC_TEXT_SR
    ds.SOPInstanceUID = sop_instance_uid or generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.AccessionNumber = accession
    ds.StudyDate = "20260620"
    ds.StudyTime = "101500"
    ds.StudyDescription = study_description

    def _num(code: str, meaning: str, value: str, unit: str) -> Dataset:
        item = Dataset()
        item.ValueType = "NUM"
        concept = Dataset()
        concept.CodeValue = code
        concept.CodingSchemeDesignator = "LN"
        concept.CodeMeaning = meaning
        item.ConceptNameCodeSequence = [concept]
        measured = Dataset()
        measured.NumericValue = value
        units = Dataset()
        units.CodeValue = unit
        units.CodingSchemeDesignator = "UCUM"
        units.CodeMeaning = unit
        measured.MeasurementUnitsCodeSequence = [units]
        item.MeasuredValueSequence = [measured]
        return item

    items = [_num(*m) for m in measurements]
    content: list[Dataset] = []
    if items:
        content.append(items[0])
    if len(items) > 1:
        container = Dataset()
        container.ValueType = "CONTAINER"
        container.ContentSequence = items[1:]
        content.append(container)
    ds.ContentSequence = content

    fm = FileMetaDataset()
    fm.MediaStorageSOPClassUID = BASIC_TEXT_SR
    fm.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    fm.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.file_meta = fm

    buffer = io.BytesIO()
    ds.save_as(buffer, enforce_file_format=True)
    return buffer.getvalue()


# --- Deflated Explicit VR LE (ASVS 5.2.3 decompression-bomb) fixtures --------------------------------


def make_deflated_stream(payload: bytes) -> bytes:
    """RAW-DEFLATE-compress ``payload`` (RFC 1951, no zlib/gzip wrapper — the DICOM Deflated Explicit VR
    LE Data Set encoding, PS3.5 A.5). Compresses in chunks so a huge, highly-compressible payload never
    sits in memory whole."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    out: list[bytes] = []
    view = memoryview(payload)
    step = 1024 * 1024
    for offset in range(0, len(view), step):
        out.append(compressor.compress(view[offset : offset + step]))
    out.append(compressor.flush())
    return b"".join(out)


def make_deflated_bomb_stream(*, inflated_bytes: int = 64 * 1024 * 1024) -> bytes:
    """A raw-deflate 'bomb' stream: a few KiB compressed that inflates to ``inflated_bytes`` (a run of
    NUL bytes, so it compresses ~1000:1). The shape a C-STORE SCP holds in ``event.request.DataSet`` for a
    negotiated Deflated Explicit VR LE context. PHI-free (all zeros). Compresses a reused 1 MiB block so
    the (huge) uncompressed payload never sits in memory whole — the test's own footprint stays tiny."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    block = b"\x00" * (1024 * 1024)
    out: list[bytes] = []
    remaining = inflated_bytes
    while remaining > 0:
        n = min(len(block), remaining)
        out.append(compressor.compress(block if n == len(block) else block[:n]))
        remaining -= n
    out.append(compressor.flush())
    return b"".join(out)


def make_deflated_part10(stream: bytes) -> bytes:
    """Wrap a raw-deflate ``stream`` in a valid Part-10 header (preamble + ``DICM`` + an uncompressed
    file-meta group declaring **Deflated Explicit VR LE**), returning the full object bytes. The file-meta
    is built by ``pydicom`` (so the group length is correct); its own deflated body is discarded and
    replaced by ``stream`` — letting a caller substitute an arbitrarily-sized (bomb) Data Set."""
    ds = Dataset()
    ds.PatientName = "Bomb^Test"
    ds.PatientID = "BOMB-1"
    ds.Modality = "SR"
    ds.SOPClassUID = BASIC_TEXT_SR
    ds.SOPInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    fm = FileMetaDataset()
    fm.MediaStorageSOPClassUID = BASIC_TEXT_SR
    fm.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    fm.TransferSyntaxUID = DeflatedExplicitVRLittleEndian
    ds.file_meta = fm
    buffer = io.BytesIO()
    ds.save_as(buffer, enforce_file_format=True)
    real = buffer.getvalue()
    # (0002,0000) FileMetaInformationGroupLength value sits 8 bytes into the element at offset 132; the
    # deflated Data Set begins at 132 + 12 + group_length (end of the uncompressed file-meta group).
    group_length = int.from_bytes(real[140:144], "little")
    meta_end = 144 + group_length
    return real[:meta_end] + stream


def make_deflated_bomb_part10(*, inflated_bytes: int = 64 * 1024 * 1024) -> bytes:
    """A malicious Deflated Explicit VR LE **Part-10 file** whose Data Set inflates to ``inflated_bytes``
    from a few KiB — the shape a File source drops and the codec peek/dataset + the SCU parse. Used to
    prove the bounded-inflate guard rejects it BEFORE any ``dcmread``. PHI-free."""
    return make_deflated_part10(make_deflated_bomb_stream(inflated_bytes=inflated_bytes))


def make_deflated_ok_part10(*, patient_name: str = "Ok^Deflated") -> bytes:
    """A small, VALID Deflated Explicit VR LE Part-10 object (a real dataset, well under the guard cap) —
    proves the guard is a no-op for a legitimate deflated object and dcmread still parses it."""
    ds = Dataset()
    ds.PatientName = patient_name
    ds.PatientID = "OK-1"
    ds.Modality = "SR"
    ds.SOPClassUID = BASIC_TEXT_SR
    ds.SOPInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    fm = FileMetaDataset()
    fm.MediaStorageSOPClassUID = BASIC_TEXT_SR
    fm.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    fm.TransferSyntaxUID = DeflatedExplicitVRLittleEndian
    ds.file_meta = fm
    buffer = io.BytesIO()
    ds.save_as(buffer, enforce_file_format=True)
    return buffer.getvalue()
