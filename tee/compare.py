# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure HL7 parity diff for the tee compare tool (#14).

Given two HL7 messages — MEFOR's transformed output and Corepoint's output for the same input —
classify them as ``exact`` (identical bar segment-terminator trivia), ``semantic`` (identical once a
configurable ignore-list of legitimately-divergent fields is blanked), or ``mismatch`` (a material
field differs), and enumerate the field-level differences.

Pure and dependency-free (separators read from each message's MSH via :mod:`tee.hl7_fields`); no I/O,
no ``messagefoundry`` import. The ``kind`` verdict and counts are **PHI-safe**; the per-field ``left``/
``right`` values in the diffs carry message content (PHI), so callers gate that detail (test-data-only).
"""

from __future__ import annotations

from dataclasses import dataclass

from tee.hl7_fields import Segment, Separators, parse, split_segments

# Fields that legitimately differ between two conformant engines for the same input — skipped by
# default when deciding ``semantic`` vs ``mismatch``. Keyed (segment id, HL7 field number).
DEFAULT_IGNORE_FIELDS: frozenset[tuple[str, int]] = frozenset(
    {
        ("MSH", 3),  # sending application
        ("MSH", 4),  # sending facility
        ("MSH", 7),  # message date/time
        ("MSH", 10),  # message control id
    }
)


@dataclass(frozen=True)
class CompareConfig:
    """Tunable comparison policy. ``ignore_fields`` are the ``(segment id, field number)`` pairs
    treated as legitimately-divergent (default: MSH sending app/facility, datetime, control id)."""

    ignore_fields: frozenset[tuple[str, int]] = DEFAULT_IGNORE_FIELDS


@dataclass(frozen=True)
class FieldDiff:
    """One differing field, or a whole-segment presence difference. ``location`` is an HL7 address like
    ``PID-5`` / ``MSH-10`` (a repeated segment's occurrence is appended as ``#2``, ``#3``, …; a
    whole-segment difference omits the field number). ``ignored`` marks a difference in an ignore-list
    field — surfaced for transparency but not counted as a mismatch."""

    location: str
    left: str
    right: str
    ignored: bool


@dataclass(frozen=True)
class CompareResult:
    """The verdict for one message pair. ``kind`` and the diff *count* are PHI-safe; ``diffs`` carry
    field values (PHI)."""

    kind: str  # "exact" | "semantic" | "mismatch"
    diffs: tuple[FieldDiff, ...]

    @property
    def material_diffs(self) -> tuple[FieldDiff, ...]:
        """The non-ignored differences — the ones that make a pair a ``mismatch``."""
        return tuple(d for d in self.diffs if not d.ignored)


def _canonical(message: str) -> str:
    """Segment-terminator-normalized form, for the byte-exact check (CR/LF/CRLF trivia removed)."""
    return "\r".join(split_segments(message))


def _indexed(segs: list[Segment]) -> dict[tuple[str, int], Segment]:
    """Map each segment to a ``(id, occurrence)`` key so repeated segments (OBX, NK1, …) align by
    their order of appearance rather than absolute position."""
    out: dict[tuple[str, int], Segment] = {}
    counts: dict[str, int] = {}
    for seg in segs:
        occ = counts.get(seg.id, 0)
        counts[seg.id] = occ + 1
        out[(seg.id, occ)] = seg
    return out


def _key_order(
    left: dict[tuple[str, int], Segment], right: dict[tuple[str, int], Segment]
) -> list[tuple[str, int]]:
    """A stable union of segment keys: left's order first, then any keys only on the right."""
    order = list(left)
    order.extend(key for key in right if key not in left)
    return order


def _loc(seg_id: str, occ: int, n: int | None = None) -> str:
    base = seg_id if occ == 0 else f"{seg_id}#{occ + 1}"
    return base if n is None else f"{base}-{n}"


def _serialize(seg: Segment, seps: Separators) -> str:
    """Re-join a segment for whole-segment diff display, folding MSH-1 (the separator) back out so the
    rendering matches the original wire form."""
    if seg.id.upper() == "MSH" and len(seg.fields) >= 2:
        return seg.fields[0] + seg.fields[1] + seps.field.join(seg.fields[2:])
    return seps.field.join(seg.fields)


def compare(left: str, right: str, config: CompareConfig | None = None) -> CompareResult:
    """Compare two HL7 messages and classify them. ``left`` is conventionally MEFOR's output, ``right``
    Corepoint's; separators are read from each message's own MSH."""
    cfg = config or CompareConfig()
    left_seps = Separators.from_message(left)
    right_seps = Separators.from_message(right)
    li = _indexed(parse(left, left_seps))
    ri = _indexed(parse(right, right_seps))

    diffs: list[FieldDiff] = []
    for seg_id, occ in _key_order(li, ri):
        lseg = li.get((seg_id, occ))
        rseg = ri.get((seg_id, occ))
        if lseg is None or rseg is None:
            # A whole segment present on one side only — a structural (material) difference.
            diffs.append(
                FieldDiff(
                    location=_loc(seg_id, occ),
                    left="" if lseg is None else _serialize(lseg, left_seps),
                    right="" if rseg is None else _serialize(rseg, right_seps),
                    ignored=False,
                )
            )
            continue
        for n in range(
            1, max(len(lseg.fields), len(rseg.fields))
        ):  # field 0 is the id (equal here)
            lv, rv = lseg.field(n), rseg.field(n)
            if lv != rv:
                diffs.append(
                    FieldDiff(
                        location=_loc(seg_id, occ, n),
                        left=lv,
                        right=rv,
                        ignored=(seg_id, n) in cfg.ignore_fields,
                    )
                )

    material = any(not d.ignored for d in diffs)
    if _canonical(left) == _canonical(right):
        kind = "exact"
    elif not material:
        kind = "semantic"
    else:
        kind = "mismatch"
    return CompareResult(kind=kind, diffs=tuple(diffs))
