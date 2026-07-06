# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Group-scoped structural editing on top of the flat :class:`~messagefoundry.parsing.message.Message`.

Real HL7 feeds carry **repeating order/observation groups**: an ORU is a header (MSH/PID/…) followed
by one or more ``OBR`` runs, each owning the ``OBX`` (and ``NTE``…) segments that belong to *that*
order. The flat Message API addresses segments by id and occurrence (``OBX`` occurrence 2), but it
can't say "the OBX segments belonging to the **2nd** OBR" or "rebuild **this** order's body" — the
operations Corepoint expresses as per-OrderGroup ``ItemNew``/``ItemClear``/per-OBR rebuilds.

A :class:`SegmentGroup` is a **view** over a contiguous run of segments in the parent message: it
begins at a **boundary** segment (default ``OBR``; pass ``ORC`` etc.) and runs up to — but not
including — the next boundary (or end of message). Segments before the first boundary are the
message *header* and belong to no group. The view is computed from the current segment order at the
moment :meth:`Message.groups` is called; a mutating call recomputes the live span first, so the
position never goes stale even after an earlier group was edited.

Every mutation routes through the existing Message primitives (``add_segment(index=)``,
delete-by-position) and re-encodes — never raw string slicing — and reads the message's own
separators (MSH-1/MSH-2), never hardcoded ``|^~\\&``. The module is **pure** (no I/O, no engine
state), so the console may import it for client-side rendering just like the rest of ``parsing/``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid a runtime import cycle — SegmentGroup only *refers back* to Message
    from messagefoundry.parsing.message import Message

#: The default boundary segment. ORU-style result feeds open each order with an ``OBR``; an
#: order-control feed may instead group on ``ORC`` — hence the caller-overridable boundary.
DEFAULT_BOUNDARY = "OBR"


class SegmentGroup:
    """A live view over one order/observation group — the boundary segment plus the segments that
    follow it up to the next boundary.

    Do not construct directly; obtain instances from :meth:`Message.groups`. A group is addressed by
    its **ordinal** — the Nth boundary segment — and its row span is re-derived on every call, so a
    *non-deleting* edit to a sibling group (append/clear that only shifts rows) never leaves this
    view pointing at the wrong span.

    **Ordinals re-index after a whole-group delete.** Because a group is positional (the Nth
    boundary), deleting the group at ordinal *k* makes the former ordinal *k+1* become *k*; a view
    held on the old top ordinal then raises :class:`LookupError` (its boundary no longer exists). A
    :class:`SegmentGroup` is therefore a positional cursor, not a stable handle to a specific order:
    after any structural :meth:`delete`, discard your views and re-fetch :meth:`Message.groups`.

    Mutations operate on the parent :class:`~messagefoundry.parsing.message.Message` in place; call
    :meth:`Message.encode` on the parent afterwards to serialize.
    """

    def __init__(self, message: Message, boundary: str, ordinal: int) -> None:
        """``ordinal`` is the 1-based index of this group's boundary *among boundary segments* (the
        Nth ``OBR``). Storing the ordinal rather than a raw row index is what lets the group survive
        edits to earlier/later groups: the live span is re-derived from it on demand."""
        self._m = message
        self._boundary = boundary
        self._ordinal = ordinal

    # --- span resolution -----------------------------------------------------

    def _span(self) -> tuple[int, int]:
        """Current ``(start, end)`` row indices of this group, end-exclusive, into the parent's
        segment list — re-derived every call so it reflects any intervening edits.

        ``start`` is the boundary segment's row; ``end`` is the next boundary's row (or the segment
        count). Raises :class:`LookupError` if the group no longer exists (e.g. it was deleted),
        which is the honest signal that a stale view is being used."""
        ids = self._m.segments()
        seen = 0
        start = -1
        for i, seg_id in enumerate(ids):
            if seg_id == self._boundary:
                seen += 1
                if seen == self._ordinal:
                    start = i
                    break
        if start == -1:
            raise LookupError(
                f"group {self._ordinal} of boundary {self._boundary!r} no longer exists"
            )
        end = len(ids)
        for j in range(start + 1, len(ids)):
            if ids[j] == self._boundary:
                end = j
                break
        return start, end

    # --- read ----------------------------------------------------------------

    @property
    def boundary(self) -> str:
        """The boundary segment id that opens this group (e.g. ``OBR``)."""
        return self._boundary

    @property
    def ordinal(self) -> int:
        """This group's 1-based position among the boundary segments (the Nth ``OBR``)."""
        return self._ordinal

    def segment_ids(self) -> list[str]:
        """The ids of every segment in the group, boundary first — e.g. ``["OBR", "OBX", "OBX"]``.

        Mirrors :meth:`Message.segments` but scoped to this group, so a caller can see a single
        order's shape without scanning the whole message."""
        start, end = self._span()
        return self._m.segments()[start:end]

    def __len__(self) -> int:
        """Number of segments in the group (boundary included)."""
        start, end = self._span()
        return end - start

    def count(self, segment_id: str) -> int:
        """How many segments of ``segment_id`` are in this group — e.g. the OBX count for *this*
        order, which the flat :meth:`Message.count_segments` (whole-message) can't give."""
        return sum(1 for sid in self.segment_ids() if sid == segment_id)

    def field(self, path: str, *, occurrence: int = 1, repetition: int | None = None) -> str | None:
        """Read a field within this group, with ``occurrence`` scoped to the group.

        ``path``'s segment must be a segment *of this group* (the boundary or one of its members);
        ``occurrence`` (1-based) selects the Nth such segment **within the group**, so
        ``group.field("OBX-5", occurrence=2)`` reads the 2nd OBX of *this* order, not the message.
        Delegates to :meth:`Message.field` translated to the message-wide occurrence, so all the
        separator/escaping/repetition behavior is identical. Returns None if absent."""
        if occurrence < 1:
            raise ValueError("occurrence is 1-based (>= 1)")
        seg = self._segment_of_path(path)
        global_occurrence = self._to_global_occurrence(seg, occurrence)
        if global_occurrence is None:
            return None
        return self._m.field(path, occurrence=global_occurrence, repetition=repetition)

    # --- mutate --------------------------------------------------------------

    def append_segment(self, line: str) -> None:
        """Add a raw segment ``line`` (``"OBX|3|NM|K^Potassium||4.1"``) at the **end of this group**.

        Inserts just before the next group's boundary (or at end of message for the last group) so
        the new segment belongs to *this* order rather than drifting into the following one — the
        group-scoped analogue of :meth:`Message.add_segment`. Delegates to ``Message.add_segment`` so
        the line is split on the message's own separators and re-parses into real components."""
        _start, end = self._span()
        # Message.add_segment uses 1-based positions where index 1 is *after* MSH (i.e. row index 1
        # == position 1). The end row index is end-exclusive, so it is exactly the position at which
        # an inserted segment lands as the group's new last member.
        self._m.add_segment(line, index=end)

    def clear(self) -> int:
        """Remove the group's **non-boundary** segments (keep the boundary), returning the count
        removed — Corepoint ``ItemClear``: empty an order's observations but keep the order header.

        Deletes back-to-front by position so indices stay valid; uses the parent's positional delete
        primitive, never string slicing."""
        start, end = self._span()
        # Everything after the boundary row, removed back-to-front so earlier positions don't shift.
        removed = 0
        for row in range(end - 1, start, -1):
            self._m._delete_segment_at(row)
            removed += 1
        return removed

    def delete(self) -> int:
        """Remove the **entire** group, boundary included, returning the count removed — drop a whole
        order. After this the view is stale; calling another method raises :class:`LookupError`."""
        start, end = self._span()
        removed = 0
        for row in range(end - 1, start - 1, -1):
            self._m._delete_segment_at(row)
            removed += 1
        return removed

    def rebuild(self, lines: list[str]) -> None:
        """Replace the group's **body** (non-boundary segments) with ``lines``, in order — the
        per-OBR "rebuild this order's segments" operation as one atomic call.

        The boundary segment is preserved; every other segment is cleared, then each raw line is
        appended within the group. Equivalent to :meth:`clear` followed by an
        :meth:`append_segment` per line, but expressed as one intent so a reviewer sees a rebuild,
        not a clear-that-happens-to-be-followed-by-adds. Each line goes through
        :meth:`Message.add_segment` (own-separator split, re-parse), never string slicing."""
        self.clear()
        for line in lines:
            self.append_segment(line)

    # --- internals -----------------------------------------------------------

    def _segment_of_path(self, path: str) -> str:
        """The segment id of an HL7 field ``path`` (e.g. ``"OBX-5"`` -> ``"OBX"``), validated."""
        from messagefoundry.parsing.peek import parse_path

        seg, _fld, _comp, _sub = parse_path(path)
        return seg

    def _to_global_occurrence(self, segment_id: str, group_occurrence: int) -> int | None:
        """Translate a 1-based occurrence *within this group* into the message-wide occurrence the
        flat :meth:`Message.field` expects, or None if the group has fewer than ``group_occurrence``
        such segments.

        Counts how many ``segment_id`` segments precede this group's span, then adds the in-group
        offset — so a group-scoped read maps cleanly onto the existing flat primitive instead of
        duplicating field-extraction logic."""
        start, end = self._span()
        ids = self._m.segments()
        before = sum(1 for sid in ids[:start] if sid == segment_id)
        in_group = sum(1 for sid in ids[start:end] if sid == segment_id)
        if group_occurrence > in_group:
            return None
        return before + group_occurrence


def groups_of(message: Message, boundary: str = DEFAULT_BOUNDARY) -> list[SegmentGroup]:
    """Every :class:`SegmentGroup` in ``message`` for ``boundary``, in document order.

    Backs :meth:`Message.groups`. One group per boundary segment; the header (segments before the
    first boundary) is intentionally **not** a group. Returns ``[]`` when no boundary segment is
    present. Kept as a free function (not a Message method body) so the grouping logic lives beside
    the view it produces; Message just forwards to it."""
    if boundary == "MSH":
        # MSH is the singleton header; treating it as a boundary would make the whole message one
        # "group" and contradicts the header-belongs-to-no-group rule.
        raise ValueError("MSH cannot be a group boundary")
    count = message.count_segments(boundary)
    return [SegmentGroup(message, boundary, ordinal) for ordinal in range(1, count + 1)]
