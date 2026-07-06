# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tolerant DICOM *peek* — cheap routing-field extraction (the HL7
:class:`~messagefoundry.parsing.peek.Peek` / X12 :class:`~messagefoundry.parsing.x12.peek.X12Peek` /
FHIR :class:`~messagefoundry.parsing.fhir.peek.FhirPeek` analog for DICOM).

Routing must never force a full validated parse (CLAUDE.md §8), so :class:`DicomPeek` does a **shallow
read of a handful of header tags** — ``SOPClassUID`` (the object-type discriminator, the DICOM analog
of MSH-9), ``Modality``, and the study/series/instance UIDs — via ``pydicom.dcmread`` with
``stop_before_pixels=True`` and ``specific_tags=[…]`` so **pixel data is never materialised** (no
``numpy``) and the read is bounded. The negotiated AE titles are not in the object; the SCP feeds them
in (a Router most often filters on the source modality's calling AE Title).

Pure and console-importable: works on a :class:`~messagefoundry.parsing.message.RawMessage` (decoded
via its ADR 0028 §3 ``.raw_bytes`` — the one decode) or raw ``bytes``, no I/O, no engine imports. The
DICOM content type is referred to by the literal string ``"dicom"`` (never imported from ``config``).
``pydicom`` is imported lazily (:mod:`messagefoundry.parsing.dicom._deps`), so a bare import of this
module does not require the ``[dicom]`` extra — only :meth:`DicomPeek.parse` does.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING

from messagefoundry.parsing.dicom._deps import load_dcmread, parse_error_types
from messagefoundry.parsing.dicom._util import SR_SOP_CLASS_UIDS, object_bytes, str_or_none
from messagefoundry.parsing.dicom.errors import DicomPeekError

if TYPE_CHECKING:
    from messagefoundry.parsing.message import RawMessage

__all__ = ["DicomPeek"]

# The handful of header tags the routing peek reads — keyword names pydicom resolves to tags. Pixel
# data (7FE0,0010) is excluded by stop_before_pixels; only these are decoded.
_PEEK_TAGS = [
    "SOPClassUID",
    "SOPInstanceUID",
    "StudyInstanceUID",
    "SeriesInstanceUID",
    "Modality",
]


@dataclass(frozen=True)
class DicomPeek:
    """A tolerant view over one DICOM object exposing routing fields. Construct via :meth:`parse`.

    Every field is the routing-safe identifier kind only (UIDs, ``Modality``, AE titles) — **never** a
    patient/element value; those live in :class:`~messagefoundry.parsing.dicom.dataset.DicomDataset`
    and only ever reach the secured store (ADR 0025 §1 PHI rule)."""

    sop_class_uid: str | None
    sop_instance_uid: str | None
    study_instance_uid: str | None
    series_instance_uid: str | None
    modality: str | None
    transfer_syntax_uid: str | None
    calling_ae_title: str | None = None
    called_ae_title: str | None = None

    @classmethod
    def parse(
        cls,
        raw: RawMessage | bytes,
        *,
        calling_ae_title: str | None = None,
        called_ae_title: str | None = None,
    ) -> DicomPeek:
        """Peek the DICOM object in ``raw`` (a :class:`RawMessage` — decoded via ``.raw_bytes`` — or
        raw ``bytes``). ``calling_ae_title``/``called_ae_title`` are the SCP's negotiated AE titles,
        carried through for routing (not present in the object itself).

        Raises :class:`~messagefoundry.parsing.dicom.errors.DicomPeekError` if the body is not a
        parseable DICOM Part-10 object (PHI-safe: names the failure, never the bytes). Requires the
        optional ``[dicom]`` extra; a missing extra raises :class:`RuntimeError` (not a data error)."""
        data = object_bytes(raw)
        dcmread = load_dcmread()
        try:
            ds = dcmread(
                BytesIO(data),
                stop_before_pixels=True,
                specific_tags=_PEEK_TAGS,
                force=False,
            )
        except parse_error_types() as exc:
            raise DicomPeekError("body is not a parseable DICOM Part-10 object") from exc
        file_meta = getattr(ds, "file_meta", None)
        transfer_syntax = (
            str_or_none(getattr(file_meta, "TransferSyntaxUID", None))
            if file_meta is not None
            else None
        )
        return cls(
            sop_class_uid=str_or_none(ds.get("SOPClassUID")),
            sop_instance_uid=str_or_none(ds.get("SOPInstanceUID")),
            study_instance_uid=str_or_none(ds.get("StudyInstanceUID")),
            series_instance_uid=str_or_none(ds.get("SeriesInstanceUID")),
            modality=str_or_none(ds.get("Modality")),
            transfer_syntax_uid=transfer_syntax,
            calling_ae_title=calling_ae_title,
            called_ae_title=called_ae_title,
        )

    def is_structured_report(self) -> bool:
        """Whether this is a Structured Report (its ``SOPClassUID`` is an SR storage class), so a
        Router can branch SR-vs-image without a full parse."""
        return self.sop_class_uid in SR_SOP_CLASS_UIDS
