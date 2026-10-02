# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Synthetic, PHI-free DICOM objects for the DIMSE scenarios, and the one SOPInstanceUID reader they
share.

The shape follows ``tests/_dicom_sample.py`` (a Basic Text SR Part-10 object, the SR class the engine's
default SCP contexts accept), cut down to the header a C-STORE needs. The patient name and id are
plainly fabricated (``HARNESS^SYNTHETIC``, ``SYNTH-...``), never a real person. Every object gets a
fresh SOPInstanceUID, so a run can never match a previous run's rows in a long-lived store.

Needs the ``[dicom]`` extra (``pydicom``), imported inside each function so harness discovery never
fails without it; :func:`harness.drivers.dimse.dicom_extra_missing` says whether it is there.
"""

from __future__ import annotations

import io

from messagefoundry.parsing import binary
from messagefoundry.parsing.dicom import DicomError, DicomPeek

#: Basic Text SR Storage, the SOP class every object here carries.
BASIC_TEXT_SR = "1.2.840.10008.5.1.4.1.1.88.11"


def make_dataset(index: int = 1) -> tuple[bytes, str]:
    """One synthetic Basic Text SR as Part-10 bytes (preamble, ``DICM``, file meta), and its fresh
    SOPInstanceUID."""
    from pydicom.dataset import Dataset, FileMetaDataset
    from pydicom.uid import UID, ExplicitVRLittleEndian, generate_uid

    sop_class = UID(BASIC_TEXT_SR)
    ds = Dataset()
    ds.PatientName = "HARNESS^SYNTHETIC"
    ds.PatientID = f"SYNTH-{index:04d}"
    ds.Modality = "SR"
    ds.SOPClassUID = sop_class
    ds.SOPInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.StudyDescription = "HARNESS SYNTHETIC DIMSE"
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = sop_class
    meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.file_meta = meta
    buffer = io.BytesIO()
    ds.save_as(buffer, enforce_file_format=True)
    return buffer.getvalue(), str(ds.SOPInstanceUID)


def make_datasets(count: int) -> tuple[list[bytes], list[str]]:
    """``count`` fresh objects and their SOPInstanceUIDs, in the same order."""
    payloads: list[bytes] = []
    uids: list[str] = []
    for i in range(1, count + 1):
        payload, uid = make_dataset(i)
        payloads.append(payload)
        uids.append(uid)
    return payloads, uids


def sop_instance_uid(data: bytes | str) -> str | None:
    """The SOPInstanceUID of a Part-10 object, given as bytes or as the engine's base64 carriage
    (``mfb64:v1:...``, what a stored DICOM body reads as); None when it is neither."""
    try:
        raw = binary.decode(data) if isinstance(data, str) else data
        return DicomPeek.parse(raw).sop_instance_uid
    except (DicomError, ValueError):
        return None
