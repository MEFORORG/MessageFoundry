# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Union

from messagefoundry.parsing._builtin_hl7 import escape_leaf
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
Field = Union[str, Sequence[str | None]]  # noqa: UP007


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
    """Escape one leaf value so its structural delimiters and control characters are carried as
    data, and strip CR/LF so it cannot inject a segment. The escaping is the HL7 model's own leaf
    escape (ADR 0205 rule 2), so a DICOM string holding an MLLP frame byte or NUL leaves as a
    ``\\Xhh\\`` hex escape, never raw."""
    out = value.replace("\r", " ").replace("\n", " ")
    return escape_leaf(
        out, (sep.field, sep.component, sep.repetition, sep.subcomponent, sep.escape)
    )


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
    with ``=``-separated alphabetic/ideographic/phonetic groups) into HL7 ``XPN`` components.

    DICOM PS3.5 (the PN value representation) orders the groups alphabetic, ideographic, phonetic,
    and lets any of them be absent. Which group to use is this project's choice, not the
    standard's: the alphabetic group is used whenever any of its family, given or middle
    components is non-blank, because it is the group most likely to stay ASCII under an ``MSH``
    that declares ASCII. Otherwise the ideographic group, then the phonetic group, is checked for a
    family name, and failing that the ideographic group, then the phonetic group, for a given or
    middle name. So an ideographic-only name is not lost, and a group holding only a prefix or
    suffix is passed over. It returns ``()`` when no group has a family, given or middle name. A
    blank (spaces-only) component is written empty. A name taken from the ideographic or phonetic group
    carries ``I`` or ``P`` in ``XPN-8`` (name representation code), which tells a receiver that
    reads ``XPN-8`` which group it is. It does not make the text decode. This helper sets no
    character set, and with ``MSH-18`` empty the message declares ASCII. For any non-ASCII name,
    from any group, the Handler that builds ``MSH`` must declare the set in ``MSH-18``, and the
    outbound connection's ``encoding``, which encodes the bytes sent, must agree with it. ``XPN``
    puts the suffix before the prefix (``Family^Given^Middle^Suffix^Prefix``), so the DICOM prefix
    and suffix swap places. A PN has five components; anything past the fifth is malformed and
    dropped rather than written into ``XPN-6`` onward, which are coded fields. Trailing blank
    components are dropped too (BACKLOG #5804)."""
    if not patient_name:
        return ()
    # Alphabetic, ideographic, phonetic; each cut to its five components, a blank one made empty.
    candidates = [
        [part if part.strip() else "" for part in (group.split("^") + [""] * 5)[:5]]
        for group in patient_name.split("=")[:3]
    ]
    # The alphabetic group first, as the one most likely to stay ASCII; a prefix or suffix alone
    # names nobody, so it never decides the choice.
    alternates = list(enumerate(candidates))[1:]
    group_index: int | None = 0 if any(candidates[0][:3]) else None
    if group_index is None:
        group_index = next((i for i, parts in alternates if parts[0]), None)
    if group_index is None:
        group_index = next((i for i, parts in alternates if any(parts[1:3])), None)
    if group_index is None:
        return ()
    parts = candidates[group_index]
    parts[3], parts[4] = parts[4], parts[3]
    if group_index:
        parts += ["", "", "IP"[group_index - 1]]  # XPN-6 and XPN-7 empty, then XPN-8
    # Every pass above chose a group with a non-empty family, given or middle component, so this
    # stops before the list is empty.
    while not parts[-1]:
        parts.pop()
    return tuple(parts)


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
