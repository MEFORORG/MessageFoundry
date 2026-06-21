# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared, pure helpers for the DICOM codec (ADR 0025) — kept here so
:mod:`~messagefoundry.parsing.dicom.peek` and :mod:`~messagefoundry.parsing.dicom.dataset` reuse them
without importing each other. No engine imports, no I/O."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Type-only: keep parsing.message out of the *runtime* imports (it is pulled by
    # parsing/__init__ already; we only need the annotation here). RawMessage's .raw_bytes is the
    # single ADR 0028 §3 decode the codec consumes.
    from messagefoundry.parsing.message import RawMessage

#: Structured Report storage SOP Class UIDs — how a Router recognises an SR object without a full
#: parse (the DICOM analog of branching on MSH-9). DICOM PS3.6 / PS3.4 (stable, well-known UIDs).
SR_SOP_CLASS_UIDS: frozenset[str] = frozenset(
    {
        "1.2.840.10008.5.1.4.1.1.88.11",  # Basic Text SR
        "1.2.840.10008.5.1.4.1.1.88.22",  # Enhanced SR
        "1.2.840.10008.5.1.4.1.1.88.33",  # Comprehensive SR
        "1.2.840.10008.5.1.4.1.1.88.34",  # Comprehensive 3D SR
        "1.2.840.10008.5.1.4.1.1.88.40",  # Procedure Log
        "1.2.840.10008.5.1.4.1.1.88.50",  # Mammography CAD SR
        "1.2.840.10008.5.1.4.1.1.88.59",  # Key Object Selection Document
        "1.2.840.10008.5.1.4.1.1.88.65",  # Chest CAD SR
        "1.2.840.10008.5.1.4.1.1.88.67",  # X-Ray Radiation Dose SR
        "1.2.840.10008.5.1.4.1.1.88.68",  # Radiopharmaceutical Radiation Dose SR
        "1.2.840.10008.5.1.4.1.1.88.69",  # Colon CAD SR
        "1.2.840.10008.5.1.4.1.1.88.70",  # Implantation Plan SR
        "1.2.840.10008.5.1.4.1.1.88.71",  # Acquisition Context SR
    }
)


def object_bytes(raw: RawMessage | bytes) -> bytes:
    """The DICOM Part-10 bytes from a Router/Handler input. ``bytes`` are used verbatim; a
    :class:`~messagefoundry.parsing.message.RawMessage` is decoded via its :attr:`raw_bytes` — the
    **one** ADR 0028 §3 decode, never ``base64`` here (consumers never hand-roll the carriage)."""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return raw.raw_bytes


def str_or_none(value: Any) -> str | None:
    """``str(value)`` stripped, or None for a missing/empty element — so absent header tags surface as
    None rather than ``""``/``"None"``."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def first(sequence: Any) -> Any | None:
    """The first item of a (DICOM) sequence, or None — tolerant of an absent/empty/odd sequence so a
    malformed SR item never raises mid-walk."""
    if not sequence:
        return None
    try:
        return sequence[0]
    except (IndexError, TypeError, KeyError):
        return None
