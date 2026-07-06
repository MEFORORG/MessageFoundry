# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Offline normalize + diff of two HL7 v2 messages for parallel-run reconciliation.

Two engines (MessageFoundry vs Corepoint) processing the *same* inbound message legitimately differ in:
engine-stamped timestamps (``MSH-7``), regenerated control ids (``MSH-10``), live ``db_lookup`` results
(provider NPI, etc. — accepted-by-design per ADR 0010), and the order of non-semantic repetitions or
segments. This module blanks/sorts those before diffing so only *real* discrepancies surface.

Design rules (CLAUDE.md §8): separators are read from the message's own ``MSH`` header — never hardcode
``|^~\\&``. The comparison is **read-only** (we split on the declared separators to compare; we never
mutate via string slicing). Pure + stdlib + the read-only ``messagefoundry.parsing`` library only.

Field indexing follows HL7: ``MSH-1`` is the field separator itself and ``MSH-2`` the encoding
characters, so an ``MSH`` field number ``N`` lands at split index ``N-1``; every other segment's field
``N`` is at split index ``N`` (index 0 being the segment id). :func:`_field_index` hides this quirk.
"""

from __future__ import annotations

from dataclasses import dataclass

from messagefoundry.parsing.peek import normalize as _normalize_line_endings

#: Fields that are non-deterministic between engines for *every* connection and are blanked by default.
#: ``MSH-7`` (date/time of message) and ``MSH-10`` (message control id) — both engine-generated.
DEFAULT_BLANK_FIELDS: frozenset[tuple[str, int]] = frozenset({("MSH", 7), ("MSH", 10)})


class ReconcileError(ValueError):
    """Raised when input is not a parseable HL7 message (no ``MSH`` header)."""


@dataclass(frozen=True)
class Separators:
    """The five HL7 separators, read from a message's ``MSH-1``/``MSH-2``."""

    field: str
    component: str
    repetition: str
    escape: str
    subcomponent: str

    @classmethod
    def from_message(cls, message: str) -> "Separators":
        """Read the separators from the ``MSH`` header (``MSH-1`` = field sep, ``MSH-2`` = enc chars)."""
        norm = _normalize_line_endings(message)
        if not norm.startswith("MSH") or len(norm) < 5:
            raise ReconcileError("not an HL7 message (no MSH header)")
        field_sep = norm[3]
        # MSH-2 (encoding characters) runs from just after MSH-1 to the next field separator.
        end = norm.find(field_sep, 4)
        enc = norm[4:end] if end != -1 else norm[4:]
        return cls(
            field=field_sep,
            component=enc[0] if len(enc) > 0 else "^",
            repetition=enc[1] if len(enc) > 1 else "~",
            escape=enc[2] if len(enc) > 2 else "\\",
            subcomponent=enc[3] if len(enc) > 3 else "&",
        )


@dataclass(frozen=True)
class NormalizeRules:
    """What to ignore before diffing, so engine-non-determinism doesn't read as a real difference.

    - ``blank_fields``: ``(segment_id, field_no)`` pairs blanked on both sides (defaults +
      per-connection additions, e.g. a ``db_lookup``-derived ``ROL-4`` NPI).
    - ``sort_repetition_fields``: ``(segment_id, field_no)`` whose ``~``-repetitions have no semantic
      order — sorted before compare.
    - ``sort_segments``: segment ids whose occurrences have no semantic order (e.g. ``NK1``) — the set
      of occurrences is sorted before positional alignment.
    - ``ignore_segments``: segment ids dropped from both sides entirely (e.g. ``ZZ`` debug segments).
    """

    blank_fields: frozenset[tuple[str, int]] = DEFAULT_BLANK_FIELDS
    sort_repetition_fields: frozenset[tuple[str, int]] = frozenset()
    sort_segments: frozenset[str] = frozenset()
    ignore_segments: frozenset[str] = frozenset()

    def with_blanks(self, *fields: tuple[str, int]) -> "NormalizeRules":
        """Return a copy with extra blanked fields added (keeps the defaults)."""
        return NormalizeRules(
            blank_fields=self.blank_fields | frozenset(fields),
            sort_repetition_fields=self.sort_repetition_fields,
            sort_segments=self.sort_segments,
            ignore_segments=self.ignore_segments,
        )


@dataclass(frozen=True)
class Difference:
    """One real discrepancy between two messages, after normalization."""

    segment: str
    occurrence: int  # 1-based ordinal of this segment id within the message
    field_no: int | None  # None for whole-segment differences
    left: str | None
    right: str | None
    kind: str  # "field" | "left-only-segment" | "right-only-segment" | "field-count"

    def describe(self) -> str:
        loc = f"{self.segment}[{self.occurrence}]" + (f"-{self.field_no}" if self.field_no else "")
        return f"{self.kind} @ {loc}: left={self.left!r} right={self.right!r}"


def _field_index(segment_id: str, field_no: int) -> int:
    """Map an HL7 field number to its split index (MSH-1 = the separator → MSH is off by one)."""
    return field_no - 1 if segment_id == "MSH" else field_no


def _segments(message: str, sep: Separators) -> list[list[str]]:
    """Split a message into segments, each a list of fields, on the message's own separators."""
    norm = _normalize_line_endings(message)
    out: list[list[str]] = []
    for line in norm.split("\r"):
        if line.strip():
            out.append(line.split(sep.field))
    return out


def normalize(message: str, rules: NormalizeRules | None = None) -> list[list[str]]:
    """Return the message as canonical ``[[field, ...], ...]`` segments with the rules applied.

    Blanks non-deterministic fields, sorts non-semantic repetitions, drops ignored segments, and sorts
    non-semantic segment occurrences — so two normalized messages compare equal iff they are
    *semantically* equal under the rules. Pure; the input is never mutated.
    """
    rules = rules or NormalizeRules()
    sep = Separators.from_message(message)
    segs = _segments(message, sep)

    canon: list[list[str]] = []
    for fields in segs:
        seg_id = fields[0] if fields else ""
        if seg_id in rules.ignore_segments:
            continue
        row = list(fields)
        for f_seg, f_no in rules.blank_fields:
            if f_seg == seg_id:
                idx = _field_index(seg_id, f_no)
                if 0 <= idx < len(row):
                    row[idx] = ""
        for r_seg, r_no in rules.sort_repetition_fields:
            if r_seg == seg_id:
                idx = _field_index(seg_id, r_no)
                if 0 <= idx < len(row):
                    reps = row[idx].split(sep.repetition)
                    row[idx] = sep.repetition.join(sorted(reps))
        canon.append(row)

    if rules.sort_segments:
        canon = _sort_segment_runs(canon, rules.sort_segments)
    return canon


def _sort_segment_runs(canon: list[list[str]], sort_ids: frozenset[str]) -> list[list[str]]:
    """Sort contiguous runs of a sort-eligible segment id by their field tuple (stable elsewhere)."""
    out: list[list[str]] = []
    i = 0
    n = len(canon)
    while i < n:
        seg_id = canon[i][0] if canon[i] else ""
        if seg_id in sort_ids:
            j = i
            while j < n and (canon[j][0] if canon[j] else "") == seg_id:
                j += 1
            out.extend(sorted(canon[i:j], key=lambda r: tuple(r)))
            i = j
        else:
            out.append(canon[i])
            i += 1
    return out


def diff(left: str, right: str, rules: NormalizeRules | None = None) -> list[Difference]:
    """Normalize both messages and return the list of real differences (empty == reconciled).

    Segments are aligned by ``(segment_id, ordinal occurrence)``: the Nth ``PID`` on the left is
    compared to the Nth ``PID`` on the right. A segment id present a different number of times on each
    side yields ``left-only-segment``/``right-only-segment`` rows for the surplus.
    """
    rules = rules or NormalizeRules()
    lsegs = normalize(left, rules)
    rsegs = normalize(right, rules)

    left_by_id = _group_by_id(lsegs)
    right_by_id = _group_by_id(rsegs)

    out: list[Difference] = []
    for seg_id in sorted(left_by_id.keys() | right_by_id.keys()):
        l_occ = left_by_id.get(seg_id, [])
        r_occ = right_by_id.get(seg_id, [])
        for k in range(max(len(l_occ), len(r_occ))):
            occ = k + 1
            if k >= len(r_occ):
                out.append(
                    Difference(seg_id, occ, None, sep_join(l_occ[k]), None, "left-only-segment")
                )
            elif k >= len(l_occ):
                out.append(
                    Difference(seg_id, occ, None, None, sep_join(r_occ[k]), "right-only-segment")
                )
            else:
                out.extend(_diff_fields(seg_id, occ, l_occ[k], r_occ[k]))
    return out


def _group_by_id(segs: list[list[str]]) -> dict[str, list[list[str]]]:
    grouped: dict[str, list[list[str]]] = {}
    for fields in segs:
        seg_id = fields[0] if fields else ""
        grouped.setdefault(seg_id, []).append(fields)
    return grouped


def _diff_fields(seg_id: str, occ: int, left: list[str], right: list[str]) -> list[Difference]:
    out: list[Difference] = []
    width = max(len(left), len(right))
    for idx in range(width):
        lv = left[idx] if idx < len(left) else None
        rv = right[idx] if idx < len(right) else None
        if lv == rv:
            continue
        # Report by HL7 field number (inverse of _field_index): MSH split idx N → field N+1; else N.
        field_no = idx + 1 if seg_id == "MSH" else idx
        kind = "field" if (lv is not None and rv is not None) else "field-count"
        out.append(Difference(seg_id, occ, field_no, lv, rv, kind))
    return out


def sep_join(fields: list[str]) -> str:
    """A readable single-line rendering of a segment's fields (for diff messages, not re-encoding)."""
    return "|".join(fields)
