# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Generate a synthetic, **PHI-free** DICOM Structured Report for the radiology sample (ADR 0025 §8).

Writes two files next to it:

* ``radiology_sr.dcm`` — the Part-10 object (send it to the SCP with ``--send``, or any DICOM SCU).
* ``radiology_sr.mfb64`` — the same object in the ``mfb64:v1:`` base64-carriage form (ADR 0028), the
  shape a ``dryrun``/replay harness feeds the codec (a raw ``.dcm`` is binary and would not decode on the
  text-only ``dryrun`` path).

All values are fabricated — never real PHI. Needs the optional extra: ``pip install 'messagefoundry[dicom]'``.

    python samples/dicom/generate_sr_sample.py            # write the two fixtures
    python samples/dicom/generate_sr_sample.py --send 11112  # also C-STORE it to a local SCP on :11112
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from messagefoundry.parsing import RawMessage

BASIC_TEXT_SR = "1.2.840.10008.5.1.4.1.1.88.11"


def build_sr() -> bytes:
    """A small Basic Text SR with two NUM measurements (one nested under a CONTAINER)."""
    ds = Dataset()
    ds.PatientName = "Demo^Patient^A"
    ds.PatientID = "DEMO-MRN-0001"
    ds.PatientBirthDate = "19800101"
    ds.PatientSex = "O"
    ds.Modality = "SR"
    ds.SOPClassUID = BASIC_TEXT_SR
    ds.SOPInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.AccessionNumber = "DEMOACC1"
    ds.StudyDate = "20260620"
    ds.StudyTime = "101500"
    ds.StudyDescription = "Echocardiogram"

    def num(code: str, meaning: str, value: str, unit: str) -> Dataset:
        item = Dataset()
        item.ValueType = "NUM"
        concept = Dataset()
        concept.CodeValue, concept.CodingSchemeDesignator, concept.CodeMeaning = code, "LN", meaning
        item.ConceptNameCodeSequence = [concept]
        measured = Dataset()
        measured.NumericValue = value
        units = Dataset()
        units.CodeValue, units.CodingSchemeDesignator, units.CodeMeaning = unit, "UCUM", unit
        measured.MeasurementUnitsCodeSequence = [units]
        item.MeasuredValueSequence = [measured]
        return item

    top = num("8867-4", "Heart rate", "68", "/min")
    container = Dataset()
    container.ValueType = "CONTAINER"
    container.ContentSequence = [num("10230-1", "Left ventricular ejection fraction", "60", "%")]
    ds.ContentSequence = [top, container]

    fm = FileMetaDataset()
    fm.MediaStorageSOPClassUID = BASIC_TEXT_SR
    fm.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    fm.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.file_meta = fm

    buffer = io.BytesIO()
    ds.save_as(buffer, enforce_file_format=True)
    return buffer.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--send",
        type=int,
        metavar="PORT",
        help="also C-STORE the object to a local SCP on this port",
    )
    args = parser.parse_args()

    out_dir = Path(__file__).resolve().parent.parent / "messages"
    out_dir.mkdir(parents=True, exist_ok=True)
    data = build_sr()
    dcm_path = out_dir / "radiology_sr.dcm"
    mfb64_path = out_dir / "radiology_sr.mfb64"
    dcm_path.write_bytes(data)
    mfb64_path.write_text(RawMessage.from_bytes(data, "dicom").raw, encoding="ascii")
    print(f"wrote {dcm_path} ({len(data)} bytes)")
    print(f"wrote {mfb64_path} (mfb64:v1: carriage)")

    if args.send is not None:
        from pydicom import dcmread
        from pynetdicom import AE

        ds = dcmread(io.BytesIO(data))
        ae = AE(ae_title="RAD_MODALITY")
        ae.add_requested_context(ds.SOPClassUID, ds.file_meta.TransferSyntaxUID)
        assoc = ae.associate("127.0.0.1", args.send, ae_title="MEFOR_SR_SCP")
        if not assoc.is_established:
            raise SystemExit(f"could not associate with the SCP on :{args.send}")
        try:
            status = assoc.send_c_store(ds)
            print(f"C-STORE status: 0x{status.Status:04X}")
        finally:
            assoc.release()


if __name__ == "__main__":
    main()
