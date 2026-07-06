# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Minimal, vendored HL7 v2 field addressing for the tee parity comparison (#14).

A tiny, dependency-free reader of HL7 *structure* — segment/field addressing with the separators read
from MSH — used by :mod:`tee.compare`. It is **deliberately not** a full HL7 parser: the tee stays
standalone (no ``python-hl7``, no ``messagefoundry`` import), so the handful of splitting rules the diff
needs are vendored here (cf. ``tee/mllp.py``'s vendored MLLP codec).

Scope: split into segments, split a segment into HL7-numbered fields — with the MSH field-separator
quirk normalized so ``MSH-1`` is the field separator and ``MSH-2`` the encoding characters, lining MSH
up with every other segment — and read the separators from MSH (never hardcode ``|^~\\&``).
Component/subcomponent/escape decoding is intentionally out of scope: the parity diff compares whole
field values.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Separators:
    """The HL7 encoding characters, read from MSH-1/MSH-2 (never hardcoded)."""

    field: str = "|"
    component: str = "^"
    repetition: str = "~"
    escape: str = "\\"
    subcomponent: str = "&"

    @classmethod
    def from_message(cls, message: str) -> Separators:
        """Read the separators from the MSH segment — located even behind a leading blank/``\\r``
        segment (so a custom encoding isn't silently lost). Falls back to the HL7 defaults when no MSH
        segment carrying encoding characters is present."""
        for segment in split_segments(message):
            if segment[:3].upper() == "MSH" and len(segment) >= 4:
                field = segment[3]
                # MSH-2 (encoding characters) is everything up to the next field separator.
                enc = segment[4:].split(field, 1)[0]
                return cls(
                    field=field,
                    component=enc[0] if len(enc) > 0 else "^",
                    repetition=enc[1] if len(enc) > 1 else "~",
                    escape=enc[2] if len(enc) > 2 else "\\",
                    subcomponent=enc[3] if len(enc) > 3 else "&",
                )
        return cls()


@dataclass(frozen=True)
class Segment:
    """One parsed segment. ``fields[0]`` is the segment id and ``fields[n]`` addresses ``<id>-n`` in
    HL7 field numbering — including ``MSH-1`` (the field separator), normalized back in so MSH
    addresses line up with every other segment."""

    id: str
    fields: tuple[str, ...]

    def field(self, n: int) -> str:
        """``<id>-n`` (HL7 1-based field number), or ``""`` if absent."""
        return self.fields[n] if 0 <= n < len(self.fields) else ""


def split_segments(message: str) -> list[str]:
    """Split a message into non-empty segment strings, tolerating ``\\r``, ``\\n`` or ``\\r\\n``."""
    unified = message.replace("\r\n", "\r").replace("\n", "\r")
    return [seg for seg in unified.split("\r") if seg]


def parse(message: str, separators: Separators | None = None) -> list[Segment]:
    """Parse into :class:`Segment`\\ s addressable by HL7 field number. Separators are read from MSH
    unless supplied."""
    seps = separators or Separators.from_message(message)
    segments: list[Segment] = []
    for raw in split_segments(message):
        parts = raw.split(seps.field)
        seg_id = parts[0]
        # MSH-1 *is* the field separator, so a naive split drops it; reinsert it so MSH-n obeys the
        # universal "fields[n] == <id>-n" rule (MSH-2 = encoding chars, MSH-3 = sending app, ...).
        if seg_id.upper() == "MSH":
            parts = [parts[0], seps.field, *parts[1:]]
        segments.append(Segment(id=seg_id, fields=tuple(parts)))
    return segments


def split_repetitions(value: str, separators: Separators) -> list[str]:
    """Split a field value into its repetitions (HL7 ``~``)."""
    return value.split(separators.repetition)


def split_components(value: str, separators: Separators) -> list[str]:
    """Split a field (or repetition) into its components (HL7 ``^``)."""
    return value.split(separators.component)
