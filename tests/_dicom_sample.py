# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Synthetic, **PHI-free** DICOM Structured Report fixtures for the ADR 0025 tests (and the §8 sample
generator). Not a test module (the leading underscore keeps pytest from collecting it). Importing it
requires the optional ``[dicom]`` extra (``pydicom``); callers guard with ``pytest.importorskip``."""

from __future__ import annotations

import io

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

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
