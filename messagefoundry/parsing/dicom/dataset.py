# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Full, navigable DICOM model for transforms (the strict/slow path — the HL7
:class:`~messagefoundry.parsing.message.Message` / FHIR
:class:`~messagefoundry.parsing.fhir.resource.FhirResource` analog), backed by ``pydicom``.

Constructed **on demand inside a Handler** (never on the hot path): :meth:`DicomDataset.parse` reads
the object with ``stop_before_pixels=True`` (**headers + SR only, NO pixel data → no ``numpy``**),
exposes typed header accessors, and walks the SR ``ContentSequence`` to extract **NUM measurements**
(each measured value's concept code, value, and units) for an SR→HL7 ORU/OBX mapping. ``CODE``/``TEXT``
items are reachable via :attr:`dataset` if a Handler needs more.

Requires the optional ``[dicom]`` extra; a missing extra raises :class:`RuntimeError` (a deploy/config
error, deliberately **outside** the :class:`ValueError` dead-letter contract — a Handler's
``except ValueError`` will not catch it). Pure aside from that: no I/O, no engine imports.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING, Any

from messagefoundry.parsing.dicom._deps import load_dcmread, parse_error_types
from messagefoundry.parsing.dicom._inflate import guard_part10_deflate
from messagefoundry.parsing.dicom._util import (
    SR_SOP_CLASS_UIDS,
    first,
    object_bytes,
    str_or_none,
)
from messagefoundry.parsing.dicom.errors import DicomError

if TYPE_CHECKING:
    from messagefoundry.parsing.message import RawMessage

__all__ = ["DicomDataset", "SrMeasurement"]


@dataclass(frozen=True)
class SrMeasurement:
    """One SR ``NUM`` (numeric measurement) content item, flattened to the fields an HL7 ``OBX`` needs:
    the measured **concept** (a coded term — e.g. LOINC ``8867-4`` "Heart rate"), the numeric
    **value**, and the **units** (a coded term — typically UCUM). Any component may be None on a
    sparse item."""

    concept_code: str | None
    concept_scheme: str | None
    concept_meaning: str | None
    value: str | None
    unit_code: str | None
    unit_scheme: str | None
    unit_meaning: str | None


class DicomDataset:
    """A parsed DICOM object: typed header reads + an SR measurement walk. Construct via
    :meth:`parse`; reach the raw ``pydicom`` dataset via :attr:`dataset` for anything beyond the
    convenience accessors."""

    def __init__(self, dataset: Any) -> None:
        self._ds = dataset

    @classmethod
    def parse(cls, raw: RawMessage | bytes, *, force: bool = False) -> DicomDataset:
        """Parse the DICOM object in ``raw`` (a :class:`RawMessage` — decoded via ``.raw_bytes`` — or
        raw ``bytes``) into a navigable dataset, **headers + SR only** (``stop_before_pixels=True``).

        Raises :class:`~messagefoundry.parsing.dicom.errors.DicomError` if the body is not a parseable
        DICOM Part-10 object (PHI-safe). Requires the ``[dicom]`` extra; a missing extra raises
        :class:`RuntimeError` (not a data error)."""
        data = object_bytes(raw)
        # ASVS 5.2.3: bound a Deflated Explicit VR LE object's inflate BEFORE dcmread (which would
        # otherwise decompress the whole deflate stream into memory unbounded). Over-cap → DicomBombError
        # (a DicomError, so it dead-letters). No-op for a non-deflated object. It gets the same `force` as
        # dcmread, because a forced read inflates an object that has no preamble (BACKLOG #1926).
        # The guard sits inside the try because it replays dcmread's own header read: a header that
        # read rejects is refused here as a DicomError, whether the guard or dcmread meets it first.
        dcmread = load_dcmread()
        try:
            guard_part10_deflate(data, force=force)
            ds = dcmread(BytesIO(data), stop_before_pixels=True, force=force)
        except DicomError:
            raise  # a DicomBombError is already the verdict; ValueError below must not rewrap it
        except parse_error_types() as exc:
            raise DicomError("body is not a parseable DICOM Part-10 object") from exc
        return cls(ds)

    @property
    def dataset(self) -> Any:
        """The underlying ``pydicom`` ``Dataset`` — for reads beyond the convenience accessors."""
        return self._ds

    def _get(self, keyword: str) -> str | None:
        return str_or_none(self._ds.get(keyword))

    # --- header accessors (routing-safe + PHI; the whole object is stored, never logged) ----------

    @property
    def sop_class_uid(self) -> str | None:
        return self._get("SOPClassUID")

    @property
    def sop_instance_uid(self) -> str | None:
        return self._get("SOPInstanceUID")

    @property
    def study_instance_uid(self) -> str | None:
        return self._get("StudyInstanceUID")

    @property
    def series_instance_uid(self) -> str | None:
        return self._get("SeriesInstanceUID")

    @property
    def modality(self) -> str | None:
        return self._get("Modality")

    @property
    def accession_number(self) -> str | None:
        return self._get("AccessionNumber")

    @property
    def study_date(self) -> str | None:
        return self._get("StudyDate")

    @property
    def study_time(self) -> str | None:
        return self._get("StudyTime")

    @property
    def study_description(self) -> str | None:
        return self._get("StudyDescription")

    @property
    def referring_physician_name(self) -> str | None:
        return self._get("ReferringPhysicianName")

    @property
    def patient_id(self) -> str | None:
        return self._get("PatientID")

    @property
    def patient_name(self) -> str | None:
        """The raw DICOM ``PatientName`` (a ``^``-delimited PN — ``Family^Given^Middle^Prefix^Suffix``;
        :func:`messagefoundry.parsing.dicom.hl7_map.person_name_components` splits it for PID-5)."""
        return self._get("PatientName")

    @property
    def patient_birth_date(self) -> str | None:
        return self._get("PatientBirthDate")

    @property
    def patient_sex(self) -> str | None:
        return self._get("PatientSex")

    def is_structured_report(self) -> bool:
        """Whether this object is a Structured Report (its ``SOPClassUID`` is an SR storage class)."""
        return self.sop_class_uid in SR_SOP_CLASS_UIDS

    def measurements(self) -> list[SrMeasurement]:
        """Every SR ``NUM`` measurement, depth-first through the ``ContentSequence`` tree (an SR nests
        measurements under ``CONTAINER`` items). Empty for a non-SR object or an SR with no numeric
        content.

        Raises :class:`~messagefoundry.parsing.dicom.errors.DicomError` if the tree cannot be read.
        pydicom keeps a defined-length sequence raw until it is first read, so a malformed or deeply
        nested one fails here, after ``parse`` returned, and not inside it (BACKLOG #1599)."""
        try:
            return list(_walk_num(getattr(self._ds, "ContentSequence", None)))
        except parse_error_types() as exc:
            raise DicomError("SR content tree is not a parseable DICOM sequence") from exc


def _walk_num(content_sequence: Any) -> Iterator[SrMeasurement]:
    # Depth-first, pre-order, with an explicit stack of sibling iterators rather than recursion: the
    # nesting depth is the sender's choice, so a recursive walk would raise RecursionError on an
    # object nested past the interpreter's limit (BACKLOG #1599).
    stack: list[Iterator[Any]] = [iter(content_sequence or ())]
    while stack:
        for item in stack[-1]:
            if str_or_none(getattr(item, "ValueType", None)) == "NUM":
                yield _measurement_from(item)
            nested = getattr(item, "ContentSequence", None)
            if nested:
                stack.append(iter(nested))  # descend; this level resumes after the subtree
                break
        else:
            stack.pop()


def _measurement_from(item: Any) -> SrMeasurement:
    concept = first(getattr(item, "ConceptNameCodeSequence", None))
    measured = first(getattr(item, "MeasuredValueSequence", None))
    unit = first(getattr(measured, "MeasurementUnitsCodeSequence", None)) if measured else None
    return SrMeasurement(
        concept_code=str_or_none(getattr(concept, "CodeValue", None)),
        concept_scheme=str_or_none(getattr(concept, "CodingSchemeDesignator", None)),
        concept_meaning=str_or_none(getattr(concept, "CodeMeaning", None)),
        value=str_or_none(getattr(measured, "NumericValue", None)) if measured else None,
        unit_code=str_or_none(getattr(unit, "CodeValue", None)) if unit else None,
        unit_scheme=str_or_none(getattr(unit, "CodingSchemeDesignator", None)) if unit else None,
        unit_meaning=str_or_none(getattr(unit, "CodeMeaning", None)) if unit else None,
    )
