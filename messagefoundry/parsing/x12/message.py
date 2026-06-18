# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A mutable X12 message — read and set elements by path, then re-encode (the HL7
:class:`~messagefoundry.parsing.message.Message` analog for X12 EDI).

Field paths use ``SEG-EE[.CC]`` syntax: a 2–3 char segment id, the 1-based element index (element 0
is the segment tag, so ``NM1-03`` is the 3rd element of an ``NM1``; ``ISA-06`` the interchange sender
id), and an optional 1-based component index. Reads/writes address the **first** occurrence of a
segment unless ``occurrence=`` is given. All structure is rebuilt with the interchange's **own**
discovered delimiters (never hardcoded), and a write rejects values carrying a delimiter so it can't
inject new structure. Re-encoding uses the discovered delimiters only, so it is **not** guaranteed
byte-identical when the source carried cosmetic whitespace between segments (the store keeps the raw
verbatim — this model is for transforms). Pure: no I/O, no engine imports.
"""

from __future__ import annotations

import re

from messagefoundry.parsing.x12.delimiters import (
    Delimiters,
    discover_delimiters,
    find_isa_start,
)
from messagefoundry.parsing.x12.errors import X12PeekError

__all__ = ["X12Message"]

# SEG-EE[.CC] — segment id (2–3 chars, alpha then alphanumerics), 1-based element, optional component.
_X12_PATH = re.compile(r"^(?P<seg>[A-Z][A-Z0-9]{1,2})-(?P<elem>\d+)(?:\.(?P<comp>\d+))?$")
_WHITESPACE = " \t\r\n\x0b\x0c"
# Segment ids whose addition/removal would corrupt the interchange envelope.
_ENVELOPE_SEGMENTS = {"ISA", "IEA"}


def _parse_path(path: str) -> tuple[str, int, int | None]:
    m = _X12_PATH.match(path)
    if not m:
        raise X12PeekError(f"invalid X12 field path: {path!r}")
    elem = int(m["elem"])
    if elem < 1:
        raise X12PeekError(f"X12 element index is 1-based (>= 1): {path!r}")
    comp = int(m["comp"]) if m["comp"] else None
    if comp is not None and comp < 1:
        raise X12PeekError(f"X12 component index is 1-based (>= 1): {path!r}")
    return m["seg"], elem, comp


class X12Message:
    """A parsed X12 interchange you can read (``msg["NM1-03"]``), mutate (``msg["BHT-06"] = "RP"``),
    and re-encode (``msg.encode()``)."""

    def __init__(self, segments: list[list[str]], delimiters: Delimiters) -> None:
        self._segments = segments
        self._delims = delimiters

    @classmethod
    def parse(cls, raw: str | bytes) -> X12Message:
        """Parse the interchange starting ``raw`` (after leading whitespace/BOM) into a mutable model.

        Raises :class:`X12PeekError` if the ISA header is not parseable."""
        if isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw).decode("utf-8", "replace")
        isa = find_isa_start(raw)
        delims = discover_delimiters(raw, isa)
        segments: list[list[str]] = []
        for chunk in raw[isa:].split(delims.segment):
            stripped = chunk.lstrip(_WHITESPACE)
            if not stripped:
                continue
            segments.append(stripped.split(delims.element))
            if segments[-1][0] == "IEA":
                break
        return cls(segments, delims)

    @property
    def delimiters(self) -> Delimiters:
        return self._delims

    # --- read ----------------------------------------------------------------

    def get(self, path: str, *, occurrence: int = 1) -> str | None:
        """Value at ``path`` (``"ISA-06"``, ``"NM1-03"``, ``"NM1-03.1"``), or None if absent/empty.
        ``occurrence`` (1-based) selects which segment of that id to read."""
        seg_id, elem, comp = _parse_path(path)
        seg = self._nth_segment(seg_id, occurrence)
        if seg is None or elem >= len(seg):
            return None
        value = seg[elem]
        if comp is None:
            return value or None
        comps = value.split(self._delims.component)
        return (comps[comp - 1] or None) if comp <= len(comps) else None

    def __getitem__(self, path: str) -> str | None:
        return self.get(path)

    def segment_ids(self) -> list[str]:
        """Ordered segment ids, e.g. ``["ISA", "GS", "ST", "BHT", …, "IEA"]``."""
        return [seg[0] for seg in self._segments]

    def count_segments(self, segment_id: str) -> int:
        """How many segments of ``segment_id`` the interchange has (0 if none)."""
        return sum(1 for seg in self._segments if seg[0] == segment_id)

    # --- mutate --------------------------------------------------------------

    def set(self, path: str, value: str, *, occurrence: int = 1) -> None:
        """Write ``value`` at ``path``, extending the element/components as needed.

        ``value`` may not contain a delimiter (element/component/repetition separator or a segment
        terminator character, incl. CR/LF) — that would inject new structure — and raises ``ValueError``
        if it does. Raises ``KeyError`` if the target segment occurrence is absent."""
        seg_id, elem, comp = _parse_path(path)
        self._reject_delimiters(value, whole_element=comp is None)
        seg = self._nth_segment(seg_id, occurrence)
        if seg is None:
            where = f"{seg_id!r}" + (f" occurrence {occurrence}" if occurrence > 1 else "")
            raise KeyError(f"cannot set absent segment {where}")
        while len(seg) <= elem:
            seg.append("")
        if comp is None:
            seg[elem] = value
            return
        comps = seg[elem].split(self._delims.component) if seg[elem] else []
        while len(comps) < comp:
            comps.append("")
        comps[comp - 1] = value
        seg[elem] = self._delims.component.join(comps)

    def __setitem__(self, path: str, value: str) -> None:
        self.set(path, value)

    def add_segment(self, line: str, *, index: int | None = None) -> None:
        """Add a whole segment from a raw ``line`` like ``"REF*EI*123456789"`` (split on the
        interchange's own element separator). It must be a single segment (no terminator/CR/LF) with a
        valid 2–3 char id, and may not be an envelope segment (``ISA``/``IEA``). Appended by default;
        pass a 1-based ``index`` to insert earlier. Raises ``ValueError`` on a malformed line/index."""
        for ch in self._delims.segment + "\r\n":
            if ch in line:
                raise ValueError("add_segment takes one segment line (no terminator/CR/LF)")
        fields = line.split(self._delims.element)
        seg_id = fields[0]
        if not re.fullmatch(r"[A-Z][A-Z0-9]{1,2}", seg_id):
            raise ValueError(f"segment must begin with a 2-3 char id, got {seg_id!r}")
        if seg_id in _ENVELOPE_SEGMENTS:
            raise ValueError(f"refusing to add an envelope segment {seg_id!r}")
        if index is None:
            self._segments.append(fields)
            return
        if index < 1 or index > len(self._segments):
            raise ValueError(f"index {index} out of range (1..{len(self._segments)})")
        self._segments.insert(index, fields)

    def delete_segments(self, segment_id: str) -> int:
        """Remove every segment with ``segment_id`` and return how many were removed. Refuses to delete
        an envelope segment (``ISA``/``IEA``)."""
        if segment_id in _ENVELOPE_SEGMENTS:
            raise ValueError(f"refusing to delete envelope segment {segment_id!r}")
        before = len(self._segments)
        self._segments = [seg for seg in self._segments if seg[0] != segment_id]
        return before - len(self._segments)

    # --- encode --------------------------------------------------------------

    def encode(self) -> str:
        """Serialize back to a delimited X12 string (each segment closed by the terminator)."""
        element, terminator = self._delims.element, self._delims.segment
        body = terminator.join(element.join(seg) for seg in self._segments)
        return body + terminator if body else body

    def __str__(self) -> str:
        return self.encode()

    # --- internals -----------------------------------------------------------

    def _nth_segment(self, segment_id: str, occurrence: int) -> list[str] | None:
        if occurrence < 1:
            raise ValueError("occurrence is 1-based (>= 1)")
        seen = 0
        for seg in self._segments:
            if seg[0] == segment_id:
                seen += 1
                if seen == occurrence:
                    return seg
        return None

    def _reject_delimiters(self, value: str, *, whole_element: bool) -> None:
        forbidden = {self._delims.element, "\r", "\n"}
        forbidden.update(self._delims.segment)
        if self._delims.repetition:
            forbidden.add(self._delims.repetition)
        if not whole_element:
            forbidden.add(self._delims.component)
        present = sorted(ch for ch in forbidden if ch in value)
        if present:
            raise ValueError(
                f"X12 value may not contain delimiter character(s) {present!r}; "
                "it would inject new structure"
            )
