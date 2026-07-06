# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DICOM → HL7 v2 mapping **helpers** (ADR 0025 §1) — pure functions a code-first Handler calls to turn
a parsed :class:`~messagefoundry.parsing.dicom.dataset.DicomDataset` (or its
:class:`~messagefoundry.parsing.dicom.dataset.SrMeasurement` list) into HL7 v2 **segment lines** it then
grafts onto a :class:`~messagefoundry.parsing.message.Message` via ``add_segment`` (the Handler builds
``MSH`` itself and owns the message type / target).

These are **helpers, not a mapper**: they spare the boilerplate of the standard tag→field
correspondences, but the Handler owns every decision (which measurements, which message type, which
destination). This is the code-first replacement for Corepoint "DICOM Gear"'s GUI mapper — there is no
declarative mapping surface (CLAUDE.md §1/§12).

Builders emit **standard HL7 v2 separators by default** (pass :class:`Separators` to match the target
``MSH-1``/``MSH-2``) and **escape** every leaf value's structural delimiters so a coded term or name
that contains ``^|~&\\`` stays one component, and they **strip CR/LF** so an untrusted DICOM string
value can never inject a new segment downstream (the inverse care :meth:`Message.set` takes). Pure: no
I/O, no engine imports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, Union

from messagefoundry.parsing.dicom.dataset import DicomDataset, SrMeasurement

__all__ = [
    "Separators",
    "DEFAULT_SEPARATORS",
    "encode_segment",
    "person_name_components",
    "obx_from_measurement",
    "pid_from_dataset",
    "obr_from_dataset",
]

#: A field is either a single leaf value (one component) or an ordered list of component leaves.
Field = Union[str, Sequence[Union[str, None]]]


@dataclass(frozen=True)
class Separators:
    """The HL7 v2 encoding characters a segment is built with. Defaults are the conventional
    ``MSH-1``/``MSH-2`` set; override to match a target message's declared separators."""

    field: str = "|"
    component: str = "^"
    repetition: str = "~"
    escape: str = "\\"
    subcomponent: str = "&"


DEFAULT_SEPARATORS = Separators()


def _escape_leaf(value: str, sep: Separators) -> str:
    """Escape one leaf value so its structural delimiters are carried as data, and strip CR/LF so it
    cannot inject a segment. The escape char is replaced **first** (so the escapes we insert are not
    re-escaped)."""
    out = value.replace("\r", " ").replace("\n", " ")
    out = out.replace(sep.escape, f"{sep.escape}E{sep.escape}")
    out = out.replace(sep.field, f"{sep.escape}F{sep.escape}")
    out = out.replace(sep.component, f"{sep.escape}S{sep.escape}")
    out = out.replace(sep.repetition, f"{sep.escape}R{sep.escape}")
    out = out.replace(sep.subcomponent, f"{sep.escape}T{sep.escape}")
    return out


def _render_field(field: Field, sep: Separators) -> str:
    if isinstance(field, str):
        return _escape_leaf(field, sep)
    return sep.component.join(_escape_leaf(c, sep) if c else "" for c in field)


def encode_segment(
    segment_id: str, fields: Sequence[Field], *, sep: Separators = DEFAULT_SEPARATORS
) -> str:
    """Build a single HL7 segment line — ``segment_id`` then the field-separator-joined ``fields``,
    each field either a leaf ``str`` or a list of component leaves. Every leaf is escaped and CR/LF
    stripped, so the line is safe to pass to :meth:`Message.add_segment`. Does not build ``MSH`` (whose
    first field IS the separator); the Handler builds that."""
    rendered = [_render_field(f, sep) for f in fields]
    return segment_id + sep.field + sep.field.join(rendered)


def person_name_components(patient_name: str | None) -> tuple[str, ...]:
    """Split a DICOM ``PatientName`` (a ``^``-delimited PN — ``Family^Given^Middle^Prefix^Suffix``,
    with ``=``-separated alphabetic/ideographic/phonetic groups) into HL7 ``XPN`` components. Uses the
    alphabetic group; ``()`` for an absent name."""
    if not patient_name:
        return ()
    alphabetic = patient_name.split("=", 1)[0]
    return tuple(alphabetic.split("^"))


def obx_from_measurement(
    set_id: int,
    measurement: SrMeasurement,
    *,
    value_type: str = "NM",
    observation_status: str = "F",
    sep: Separators = DEFAULT_SEPARATORS,
) -> str:
    """One SR ``NUM`` measurement → an ``OBX`` segment line: ``OBX-3`` the coded concept
    (``code^meaning^scheme``, the analog of a LOINC observation id), ``OBX-5`` the numeric value,
    ``OBX-6`` the coded units, ``OBX-11`` the result status (default ``F`` = final)."""
    observation_id = (
        measurement.concept_code or "",
        measurement.concept_meaning or "",
        measurement.concept_scheme or "",
    )
    units = (
        measurement.unit_code or "",
        measurement.unit_meaning or "",
        measurement.unit_scheme or "",
    )
    fields: list[Field] = [
        str(set_id),  # OBX-1 set id
        value_type,  # OBX-2 value type
        observation_id,  # OBX-3 observation identifier (CWE)
        "",  # OBX-4 observation sub-id
        measurement.value or "",  # OBX-5 observation value
        units,  # OBX-6 units (CWE)
        "",  # OBX-7 references range
        "",  # OBX-8 abnormal flags
        "",  # OBX-9 probability
        "",  # OBX-10 nature of abnormal test
        observation_status,  # OBX-11 observation result status
    ]
    return encode_segment("OBX", fields, sep=sep)


def pid_from_dataset(
    dataset: DicomDataset, *, set_id: int = 1, sep: Separators = DEFAULT_SEPARATORS
) -> str:
    """DICOM header → a ``PID`` segment line: ``PID-3`` the patient id (MRN), ``PID-5`` the patient
    name (``XPN``), ``PID-7`` the birth date, ``PID-8`` the sex. The Handler may enrich it further
    (assigning authority, etc.) by editing the resulting message."""
    fields: list[Field] = [
        str(set_id),  # PID-1 set id
        "",  # PID-2 (deprecated)
        dataset.patient_id or "",  # PID-3 patient identifier list
        "",  # PID-4 (deprecated)
        person_name_components(dataset.patient_name) or "",  # PID-5 patient name (XPN)
        "",  # PID-6 mother's maiden name
        dataset.patient_birth_date or "",  # PID-7 date/time of birth
        dataset.patient_sex or "",  # PID-8 administrative sex
    ]
    return encode_segment("PID", fields, sep=sep)


def obr_from_dataset(
    dataset: DicomDataset, *, set_id: int = 1, sep: Separators = DEFAULT_SEPARATORS
) -> str:
    """DICOM header → an ``OBR`` segment line: ``OBR-3`` the accession number (filler order), ``OBR-4``
    the study description (universal service id, ``^description``), ``OBR-7`` the study date/time. The
    Handler owns ordering-provider / status / result-copies-to enrichment."""
    universal_service_id = ("", dataset.study_description or "")  # OBR-4.2 = description
    observation_datetime = (dataset.study_date or "") + (dataset.study_time or "")
    fields: list[Field] = [
        str(set_id),  # OBR-1 set id
        "",  # OBR-2 placer order number
        dataset.accession_number or "",  # OBR-3 filler order number (accession)
        universal_service_id,  # OBR-4 universal service identifier
        "",  # OBR-5 priority
        "",  # OBR-6 requested date/time
        observation_datetime,  # OBR-7 observation date/time
    ]
    return encode_segment("OBR", fields, sep=sep)
