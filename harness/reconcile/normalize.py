# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

from collections import Counter
from dataclasses import dataclass, replace

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
    def from_message(cls, message: str) -> Separators:
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
    - ``any_position_segments``: segment ids whose POSITION in the message carries no meaning (e.g. a
      ``Z`` segment one engine writes before ``PV1`` and the other after). Their content is still
      compared, occurrence by occurrence; only the order check leaves them out.
    """

    blank_fields: frozenset[tuple[str, int]] = DEFAULT_BLANK_FIELDS
    sort_repetition_fields: frozenset[tuple[str, int]] = frozenset()
    sort_segments: frozenset[str] = frozenset()
    ignore_segments: frozenset[str] = frozenset()
    any_position_segments: frozenset[str] = frozenset()

    def with_blanks(self, *fields: tuple[str, int]) -> NormalizeRules:
        """Return a copy with extra blanked fields added (keeps the defaults)."""
        return replace(self, blank_fields=self.blank_fields | frozenset(fields))


@dataclass(frozen=True)
class Difference:
    """One real discrepancy between two messages, after normalization."""

    segment: str
    occurrence: int  # 1-based ordinal of this segment id within the message
    field_no: int | None  # None for whole-segment differences
    left: str | None
    right: str | None
    # "field" | "left-only-segment" | "right-only-segment" | "field-count" | "segment-order" |
    # "order-unchecked". A "segment-order" row names one segment both sides hold, whole, in a
    # different place; left/right are its content, the same on both sides. An "order-unchecked" row
    # says the messages were too large to align, so the order was not checked; it fails the
    # comparison rather than pass it, and its left/right are None.
    kind: str

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

    Blanks non-deterministic fields, sorts non-semantic repetitions, drops ignored segments, moves
    ``any_position_segments`` to the end (keeping their own order), and sorts non-semantic segment
    occurrences — so two normalized messages compare equal iff they are *semantically* equal under
    the rules. Moving the any-position segments first means one can no longer split a
    ``sort_segments`` run on one side only. Pure; the input is never mutated.
    """
    rules = rules or NormalizeRules()
    sep = Separators.from_message(message)
    segs = _segments(message, sep)

    canon: list[list[str]] = []
    for fields in segs:
        seg_id = _seg_id(fields)
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

    if rules.any_position_segments:
        anywhere = rules.any_position_segments
        canon = [r for r in canon if _seg_id(r) not in anywhere] + [
            r for r in canon if _seg_id(r) in anywhere
        ]
    if rules.sort_segments:
        canon = _sort_segment_runs(canon, rules.sort_segments)
    return canon


def _sort_segment_runs(canon: list[list[str]], sort_ids: frozenset[str]) -> list[list[str]]:
    """Sort contiguous runs of a sort-eligible segment id by their field tuple (stable elsewhere)."""
    out: list[list[str]] = []
    i = 0
    n = len(canon)
    while i < n:
        seg_id = _seg_id(canon[i])
        if seg_id in sort_ids:
            j = i
            while j < n and _seg_id(canon[j]) == seg_id:
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

    That alignment alone cannot see WHERE a segment sits, so an ``NTE`` or ``OBX`` moved from one
    ``OBR`` group to another would compare equal although its clinical owner changed (BACKLOG
    #5569). So the order of the segments is compared too: see :func:`_diff_order`. :func:`normalize`
    has already sorted each ``sort_segments`` run and moved each ``any_position_segments`` segment to
    the end, so neither reads as a move, and the order check leaves any-position segments out.
    """
    rules = rules or NormalizeRules()
    lsegs = normalize(left, rules)
    rsegs = normalize(right, rules)

    left_by_id = _group_by_id(lsegs)
    right_by_id = _group_by_id(rsegs)

    out: list[Difference] = _diff_order(lsegs, rsegs, rules.any_position_segments)
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


def _seg_id(fields: list[str]) -> str:
    return fields[0] if fields else ""


#: The largest middle, in table cells, :func:`_matched` aligns. The table is quadratic in time and
#: memory and its size is set by message content, so past this the order check reports
#: ``order-unchecked`` rather than run it: about a second and some tens of MB in CPython.
_LCS_MAX_CELLS = 1_000_000

_Key = tuple[str, ...]


def _matched(left: list[_Key], right: list[_Key]) -> set[int] | None:
    """Indices of ``left`` on one longest common subsequence of the two lists.

    The common prefix and suffix are always on some longest one, so only the middle runs the
    quadratic table; two messages that differ by one move or insertion keep that middle small.
    ``None`` when the middle is past :data:`_LCS_MAX_CELLS`.
    """
    n, m = len(left), len(right)
    lo = 0
    while lo < n and lo < m and left[lo] == right[lo]:
        lo += 1
    hi = 0
    while hi < n - lo and hi < m - lo and left[n - 1 - hi] == right[m - 1 - hi]:
        hi += 1
    lm, rm = left[lo : n - hi], right[lo : m - hi]
    if len(lm) * len(rm) > _LCS_MAX_CELLS:
        return None
    # table[i][j] = LCS length of lm[i:] and rm[j:].
    table = [[0] * (len(rm) + 1) for _ in range(len(lm) + 1)]
    for i in range(len(lm) - 1, -1, -1):
        for j in range(len(rm) - 1, -1, -1):
            table[i][j] = (
                table[i + 1][j + 1] + 1 if lm[i] == rm[j] else max(table[i + 1][j], table[i][j + 1])
            )
    l_hit = set(range(lo)) | set(range(n - hi, n))
    i = j = 0
    while i < len(lm) and j < len(rm):
        if lm[i] == rm[j]:
            l_hit.add(lo + i)
            i += 1
            j += 1
        elif table[i + 1][j] >= table[i][j + 1]:
            i += 1
        else:
            j += 1
    return l_hit


def _first_shared(keys: list[_Key], other: Counter[_Key]) -> list[_Key]:
    """``keys`` keeping, per key, only as many occurrences as ``other`` holds, the earliest first."""
    seen: Counter[_Key] = Counter()
    out: list[_Key] = []
    for k in keys:
        seen[k] += 1
        if seen[k] <= other[k]:
            out.append(k)
    return out


def _diff_order(
    lsegs: list[list[str]], rsegs: list[list[str]], any_position: frozenset[str]
) -> list[Difference]:
    """A ``segment-order`` row for each segment both sides hold, whole, in a different place.

    Segments whose id is in ``any_position`` are left out entirely, so their place is never compared,
    not even against each other. Read on whole segments, so a moved segment is told apart from
    another of its id: an ``NTE``
    re-parented beside a new ``NTE`` of the same id is still found. A segment only one side holds,
    or whose content changed, is the ``(id, ordinal)`` pairing's to report, and inserting or deleting
    one must not also read as a move, wherever it sits. So the test is whether one longest common
    subsequence of the two lists keeps every segment both sides hold: if it does, nothing moved. If
    it does not, each segment it cannot keep is reported, with its id and ordinal on the left and its
    content, which is the same on both sides.

    Past :data:`_LCS_MAX_CELLS` the alignment is not run. Then a cheap check that proves the order
    unchanged is tried, and where it cannot, one ``order-unchecked`` row is returned: the gate fails
    closed rather than pass a move it did not look for.
    """
    lsegs = [s for s in lsegs if _seg_id(s) not in any_position]
    rsegs = [s for s in rsegs if _seg_id(s) not in any_position]
    l_keys = [tuple(s) for s in lsegs]
    r_keys = [tuple(s) for s in rsegs]
    if l_keys == r_keys:
        return []
    l_count, r_count = Counter(l_keys), Counter(r_keys)
    if _first_shared(l_keys, r_count) == _first_shared(r_keys, l_count):
        # Every shared segment in one order on both sides: a common subsequence holding them all.
        return []
    matched = _matched(l_keys, r_keys)
    if matched is None:
        # The sides differ somewhere inside the shorter one, or the cheap check above returned.
        first = next(i for i, (a, b) in enumerate(zip(l_keys, r_keys, strict=False)) if a != b)
        seg = _seg_id(lsegs[first])
        occ = sum(1 for s in lsegs[: first + 1] if _seg_id(s) == seg)
        return [Difference(seg, occ, None, None, None, "order-unchecked")]
    l_hit = matched
    paired = Counter(l_keys[p] for p in l_hit)
    # Per segment, the occurrences no alignment keeps although both sides hold them.
    excess = {k: min(c, r_count[k]) - paired[k] for k, c in l_count.items()}
    out: list[Difference] = []
    ordinal: Counter[str] = Counter()
    for p, k in enumerate(l_keys):
        seg = _seg_id(lsegs[p])
        ordinal[seg] += 1
        if p not in l_hit and excess.get(k, 0) > 0:
            excess[k] -= 1
            text = sep_join(lsegs[p])
            out.append(Difference(seg, ordinal[seg], None, text, text, "segment-order"))
    return out


def _group_by_id(segs: list[list[str]]) -> dict[str, list[list[str]]]:
    grouped: dict[str, list[list[str]]] = {}
    for fields in segs:
        grouped.setdefault(_seg_id(fields), []).append(fields)
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
