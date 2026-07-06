# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A mutable HL7 v2 message — read and set fields by path, then re-encode.

Wraps a ``python-hl7`` parse. Field paths use the same ``SEG-F[.C[.S]]`` syntax as
:class:`~messagefoundry.parsing.peek.Peek` and the declarative transforms. Components and
subcomponents are rebuilt at the *string* level (split on the message's own separators, modify,
re-join, assign the whole field) — which avoids a python-hl7 quirk where assigning to a component
of a not-yet-componentized field raises.

By default a read/write addresses the **first** segment of an id and (for a component) the **first**
repetition of a field — the common case. Real-world feeds also need to **iterate field repetitions** (PID-3 identifier lists, repeating OBX/IN1) and
to **address, add, and remove whole segments** (e.g. rebuilding a repeating ODS/OBX block). Those are
the ``occurrence=``/``repetition=`` keywords on :meth:`field`/:meth:`set`, plus :meth:`repetitions`,
:meth:`add_repetition`, :meth:`count_segments`, :meth:`add_segment`, and :meth:`delete_segments`.
Every one of them reads the message's own separators (MSH-1/MSH-2), never hardcoded defaults.

This is the read/mutate primitive that code-first **Routers** and **Handlers** work against (and
that the declarative transforms now reuse). Never string-slice raw HL7 — go through here and
re-encode.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING, Any

import hl7
from defusedxml.ElementTree import fromstring as _xml_fromstring

import messagefoundry.parsing._backend as _backend
import messagefoundry.parsing._builtin_hl7 as _builtin_hl7
import messagefoundry.parsing.binary as _binary
from messagefoundry.parsing.peek import normalize, parse_path
from messagefoundry.timezone import age_from_dob, length_of_stay

logger = logging.getLogger(__name__)

if TYPE_CHECKING:  # the SegmentGroup view imports Message back; keep the cycle out of runtime
    from xml.etree.ElementTree import (  # nosec B405 — type-only import; all XML parsing goes through defusedxml
        Element,
    )

    from messagefoundry.parsing.groups import SegmentGroup

# A segment id is exactly three chars: an upper-case letter then two alphanumerics (HL7 §2.5),
# e.g. ``MSH``/``PID``/``ZAL``. Used to validate :meth:`Message.add_segment` input.
_SEG_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{2}$")


class Message:
    """A parsed HL7 message you can read (``msg["MSH-9.2"]``), mutate (``msg["MSH-3"] = …``),
    and re-encode (``msg.encode()``)."""

    #: Symmetry with :class:`RawMessage` — a Router/Handler can branch on ``msg.content_type``.
    content_type = "hl7v2"

    def __init__(self, message: hl7.Message | _builtin_hl7.ParsedMessage) -> None:
        # ``message`` is either a legacy python-hl7 ``hl7.Message`` or a built-ins
        # ``ParsedMessage`` dict (ADR 0054). All mutate/read helpers dispatch on ``_builtin``.
        # Stored as ``Any`` because the python-hl7 path indexes/mutates it dynamically (no stubs);
        # the built-ins path narrows it back via :meth:`_pm`.
        self._m: Any = message
        self._builtin: bool = isinstance(message, dict)

    @classmethod
    def parse(cls, raw: str | bytes) -> Message:
        """Parse ``raw`` (line endings normalized to ``\\r``) into a mutable message.

        Uses the built-ins parser (ADR 0054) when ``_backend.USE_BUILTIN`` is on (the default); an
        unexpected internal built-ins fault falls back to python-hl7 and is logged (Phase-1 fallback
        guard), so a connection is never crashed by a parser bug — the proven path takes over.
        """
        norm = normalize(raw)
        if _backend.use_builtin():
            try:
                return cls(_builtin_hl7.parse(norm))
            except hl7.ParseException:
                # The no-MSH-leading rejection is the built-ins parser deliberately matching
                # python-hl7's contract (not an internal fault), so re-raise it as-is rather than
                # falling back — the python-hl7 path would only raise the identical error again.
                raise
            except Exception:  # noqa: BLE001 — fallback guard: any unexpected built-ins error
                logger.warning(
                    "built-ins HL7 parse failed; falling back to python-hl7", exc_info=True
                )
        return cls(hl7.parse(norm))

    # --- read ----------------------------------------------------------------

    def field(self, path: str, *, occurrence: int = 1, repetition: int | None = None) -> str | None:
        """Value at ``path`` (``"MSH-9"``, ``"MSH-9.1"``, ``"PID-3.1.1"``), or None if absent/empty.

        A whole-field read returns the raw (structural) text, **including** any repetitions. A
        component/subcomponent read is taken from the **first repetition** (matching
        :class:`~messagefoundry.parsing.peek.Peek`) and is **unescaped** so HL7 escape sequences
        (e.g. ``\\S\\``) round-trip back to their literal value (the inverse of :meth:`set`'s
        escaping).

        ``occurrence`` (1-based) selects which segment of that id to read — ``occurrence=2`` reads
        the **second** ``OBX``, etc. ``repetition`` (1-based) scopes the read to one field
        repetition: when given, a whole-field read returns just that repetition's text and a
        component read takes that repetition's component (default ``None`` keeps the behavior above —
        all reps for a whole field, first rep for a component). Returns None if the occurrence or
        repetition is absent."""
        if occurrence < 1:
            raise ValueError("occurrence is 1-based (>= 1)")
        if repetition is not None and repetition < 1:
            raise ValueError("repetition is 1-based (>= 1)")
        seg, fld, comp, sub = parse_path(path)
        text = self._raw_field(seg, fld, occurrence)
        _field_sep, comp_sep, rep_sep, _esc, sub_sep = self._encoding_chars()
        if comp is None:
            if repetition is None:
                return text or None  # whole field: every repetition (review H-9)
            reps = text.split(rep_sep)
            return (reps[repetition - 1] or None) if repetition <= len(reps) else None
        # Component/subcomponent: one repetition (the first unless asked otherwise), so a read of a
        # repeating field (e.g. PID-3 "111^^^A~222^^^B") returns a single rep's component, not
        # cross-repetition text (review H-9).
        reps = text.split(rep_sep)
        rep_index = 1 if repetition is None else repetition
        if rep_index > len(reps):
            return None
        return self._extract(reps[rep_index - 1], comp, sub, comp_sep, sub_sep)

    def __getitem__(self, path: str) -> str | None:
        return self.field(path)

    def repetitions(self, path: str, *, occurrence: int = 1) -> list[str | None]:
        """Every repetition of the field at ``path``, in order (``[]`` if the field is absent/empty).

        For a whole-field path each element is that repetition's full text; for a component/
        subcomponent path each element is that part **within** each repetition (unescaped), with
        None where a repetition lacks it. This is the iterate-the-``~``-list primitive — e.g.
        ``msg.repetitions("PID-3.1")`` → every identifier's first component. ``occurrence`` selects
        the segment as in :meth:`field`."""
        if occurrence < 1:
            raise ValueError("occurrence is 1-based (>= 1)")
        seg, fld, comp, sub = parse_path(path)
        text = self._raw_field(seg, fld, occurrence)
        if not text:
            return []
        _field_sep, comp_sep, rep_sep, _esc, sub_sep = self._encoding_chars()
        if comp is None:
            return [rep or None for rep in text.split(rep_sep)]
        return [self._extract(rep, comp, sub, comp_sep, sub_sep) for rep in text.split(rep_sep)]

    def count_segments(self, segment_id: str) -> int:
        """How many segments of ``segment_id`` the message has (0 if none)."""
        if self._builtin:
            return sum(1 for sid in _builtin_hl7.segment_ids(self._m) if sid == segment_id)
        return sum(1 for seg in self._m if str(seg[0]) == segment_id)

    @property
    def message_code(self) -> str | None:
        return self.field("MSH-9.1")

    @property
    def trigger_event(self) -> str | None:
        return self.field("MSH-9.2")

    @property
    def message_type(self) -> str | None:
        return self.field("MSH-9")

    @property
    def control_id(self) -> str | None:
        return self.field("MSH-10")

    def segments(self) -> list[str]:
        """Ordered segment ids, e.g. ``["MSH", "EVN", "PID"]``."""
        if self._builtin:
            return _builtin_hl7.segment_ids(self._m)
        return [str(seg[0]) for seg in self._m]

    # --- derived HL7 timestamp values ---------------------------------------
    #
    # Thin, convenience wrappers over the pure helpers in messagefoundry.timezone, reading the
    # conventional fields (PID-7 DOB, PV1-44/PV1-45 admit/discharge). They keep a Handler from
    # re-implementing HL7 timestamp math; for an unusual field a Handler can read it with field()/
    # repetitions() and call age_from_dob()/length_of_stay() directly.

    def age(
        self,
        asof: str | date | datetime | None = None,
        *,
        path: str = "PID-7",
        occurrence: int = 1,
    ) -> int | None:
        """The patient's age in completed years from the DOB at ``path`` (default PID-7).

        Reads the timestamp's first component (HL7 DTM/TS), tolerating partial precision (a year- or
        year+month-only DOB), and returns whole years as of ``asof`` (an HL7 timestamp string, a
        :class:`datetime.date`/:class:`datetime.datetime`, or — the default — today's local date).
        Returns None when the field is absent/empty. ``occurrence`` selects the segment as elsewhere.

        Raises:
            ValueError: the DOB (or an ``asof`` string) is a malformed HL7 timestamp, or the DOB is
                after the reference date.
        """
        dob = self.field(f"{path}.1", occurrence=occurrence) or self.field(
            path, occurrence=occurrence
        )
        if not dob:
            return None
        return age_from_dob(dob, asof)

    def length_of_stay(
        self,
        *,
        admit_path: str = "PV1-44",
        discharge_path: str = "PV1-45",
        occurrence: int = 1,
    ) -> timedelta | None:
        """The encounter length of stay as a :class:`~datetime.timedelta`, from the admit and discharge
        timestamps (default PV1-44 / PV1-45).

        Reads each field's first component, parses both at whatever precision they carry, and returns
        the elapsed time (use ``.days`` for whole inpatient days). Returns None if **either** timestamp
        is absent/empty (an open, not-yet-discharged encounter). ``occurrence`` selects the segment.

        Raises:
            ValueError: a timestamp is malformed, exactly one carries a zone offset, or the discharge
                precedes the admit.
        """
        admit = self.field(f"{admit_path}.1", occurrence=occurrence) or self.field(
            admit_path, occurrence=occurrence
        )
        discharge = self.field(f"{discharge_path}.1", occurrence=occurrence) or self.field(
            discharge_path, occurrence=occurrence
        )
        if not admit or not discharge:
            return None
        return length_of_stay(admit, discharge)

    # --- mutate --------------------------------------------------------------

    def set(
        self, path: str, value: str, *, occurrence: int = 1, repetition: int | None = None
    ) -> None:
        """Write ``value`` at ``path``, extending the field/components as needed.

        ``value`` may never contain a **segment separator** (CR/LF) — that would inject a new segment
        downstream — and a **whole-field** write may not contain the **field separator** (it would
        split into extra fields); both raise ``ValueError`` (XFORM-1, review M-12). A component/
        subcomponent write **escapes** the value's structural delimiters (``| ^ ~ & \\``) so they are
        carried as data, not new structure (e.g. ``PID-5.1 = "O^Brien"`` stays one component), while
        non-delimiter characters — incl. CJK/accented names — pass through intact (review M-13).

        ``occurrence`` (1-based) selects which segment of that id to write — ``occurrence=2`` edits
        the **second** ``OBX``. ``repetition`` (1-based) scopes the write to one field repetition: a
        component write edits that repetition (padding earlier reps if needed) and preserves the
        others (default — and ``repetition=1`` — edit the first, preserve the rest; review H-9); a
        whole-field write with ``repetition`` replaces just that repetition's text (and the value may
        then not contain the repetition separator). Without ``repetition``, a whole-field write
        assigns the caller's text verbatim (their structure, repetitions and all). Raises
        ``KeyError`` if the target segment (occurrence) isn't present."""
        if "\r" in value or "\n" in value:
            raise ValueError("HL7 field value may not contain a segment separator (CR/LF)")
        if occurrence < 1:
            raise ValueError("occurrence is 1-based (>= 1)")
        if repetition is not None and repetition < 1:
            raise ValueError("repetition is 1-based (>= 1)")
        seg, fld, comp, sub = parse_path(path)
        if not self._segment_present(seg, occurrence):
            where = f"{seg!r}" + (f" occurrence {occurrence}" if occurrence > 1 else "")
            raise KeyError(f"cannot set absent segment {where}")

        field_sep, comp_sep, rep_sep, esc, sub_sep = self._encoding_chars()

        if comp is None:
            # Whole-field write assigns the caller's structure verbatim — but the field separator
            # would split it into extra fields downstream, so reject it (review M-12). Components and
            # repetitions are the caller's intended structure and remain allowed.
            if field_sep in value:
                raise ValueError(
                    f"HL7 field value may not contain the field separator {field_sep!r}; "
                    "write structured values via a component/subcomponent path"
                )
            if repetition is None:
                self._assign_field(seg, fld, occurrence, value)
                return
            # Repetition-scoped whole-field write: replace just that rep, keep the others. The value
            # targets one repetition, so it may not itself carry the repetition separator.
            if rep_sep in value:
                raise ValueError(
                    f"a repetition-scoped value may not contain the repetition separator {rep_sep!r}"
                )
            current = self._raw_field(seg, fld, occurrence)
            reps = current.split(rep_sep) if current else [""]
            while len(reps) < repetition:
                reps.append("")
            reps[repetition - 1] = value
            self._assign_field(seg, fld, occurrence, rep_sep.join(reps))
            return

        escaped = self._escape_leaf(value, field_sep, comp_sep, rep_sep, esc, sub_sep)
        current = self._raw_field(seg, fld, occurrence)
        # Edit one repetition (the first unless asked otherwise), matching the read side; preserve
        # any further reps (H-9).
        rep_index = 1 if repetition is None else repetition
        reps = current.split(rep_sep) if current else [""]
        while len(reps) < rep_index:
            reps.append("")
        comps = reps[rep_index - 1].split(comp_sep) if reps[rep_index - 1] else []
        while len(comps) < comp:
            comps.append("")
        if sub is None:
            comps[comp - 1] = escaped
        else:
            subs = comps[comp - 1].split(sub_sep) if comps[comp - 1] else []
            while len(subs) < sub:
                subs.append("")
            subs[sub - 1] = escaped
            comps[comp - 1] = sub_sep.join(subs)
        reps[rep_index - 1] = comp_sep.join(comps)
        self._assign_field(seg, fld, occurrence, rep_sep.join(reps))

    def __setitem__(self, path: str, value: str) -> None:
        self.set(path, value)

    def add_repetition(self, path: str, value: str, *, occurrence: int = 1) -> None:
        """Append a new ``~`` repetition carrying ``value`` to the field at ``path``.

        ``path`` must be a **whole-field** path (no component) — a repetition is a field-level unit;
        ``value`` is the new repetition's structure (components with ``^`` are kept as the caller's
        intent), so it may not contain the field or repetition separator or a CR/LF. If the field is
        currently empty the value becomes its first repetition. ``occurrence`` selects the segment.
        Raises ``KeyError`` if the segment (occurrence) is absent, ``ValueError`` on a component path
        or an illegal separator in ``value``."""
        if "\r" in value or "\n" in value:
            raise ValueError("HL7 field value may not contain a segment separator (CR/LF)")
        if occurrence < 1:
            raise ValueError("occurrence is 1-based (>= 1)")
        seg, fld, comp, _sub = parse_path(path)
        if comp is not None:
            raise ValueError("add_repetition takes a whole-field path (no component)")
        if not self._segment_present(seg, occurrence):
            where = f"{seg!r}" + (f" occurrence {occurrence}" if occurrence > 1 else "")
            raise KeyError(f"cannot add a repetition to absent segment {where}")
        field_sep, _comp_sep, rep_sep, _esc, _sub_sep = self._encoding_chars()
        if field_sep in value:
            raise ValueError(
                f"a repetition value may not contain the field separator {field_sep!r}"
            )
        if rep_sep in value:
            raise ValueError(
                f"a repetition value may not contain the repetition separator {rep_sep!r}; "
                "call add_repetition once per repetition"
            )
        current = self._raw_field(seg, fld, occurrence)
        self._assign_field(seg, fld, occurrence, f"{current}{rep_sep}{value}" if current else value)

    def add_segment(self, line: str, *, index: int | None = None) -> None:
        """Add a whole segment from a raw ``line`` like ``"ODS|R|^ODS123|GEN^Regular^Diet"``.

        The line is split on the message's **own** field separator and grafted in so it re-encodes
        byte-for-byte and re-parses into real components. It must be a **single** segment (no CR/LF)
        beginning with a 3-char segment id. By default the segment is appended at the end; pass
        ``index`` (1-based position among segments, ``1`` = just after MSH) to insert it earlier.
        Adding an ``MSH`` is refused (there is exactly one). Raises ``ValueError`` on a malformed
        line or out-of-range ``index``."""
        if "\r" in line or "\n" in line:
            raise ValueError(
                "add_segment takes one segment line (no CR/LF); call it once per segment"
            )
        field_sep, *_ = self._encoding_chars()
        tokens = line.split(field_sep)
        segment_id = tokens[0]
        if not _SEG_ID_RE.match(segment_id):
            raise ValueError(f"segment must begin with a 3-char segment id, got {segment_id!r}")
        if segment_id == "MSH":
            raise ValueError("refusing to add a second MSH segment")
        if self._builtin:
            seg_count = len(_builtin_hl7.segment_ids(self._m))
            if index is not None and (index < 1 or index > seg_count):
                raise ValueError(
                    f"index {index} out of range (1..{seg_count}); index 1 is after MSH"
                )
            _builtin_hl7.add_segment_line(self._m, segment_id, tokens, index)
            return
        new_segment = self._m.create_segment([self._m.create_field([tok]) for tok in tokens])
        if index is None:
            self._m.append(new_segment)
            return
        if index < 1 or index > len(self._m):
            raise ValueError(
                f"index {index} out of range (1..{len(self._m)}); index 1 is after MSH"
            )
        self._m.insert(index, new_segment)

    def delete_segments(self, segment_id: str) -> int:
        """Remove every segment with ``segment_id`` and return how many were removed.

        Deleting ``MSH`` is refused — the message must keep its header. Common for clearing a
        repeating block (e.g. ``delete_segments("ODS")``) before rebuilding it with
        :meth:`add_segment`."""
        if segment_id == "MSH":
            raise ValueError("refusing to delete the MSH segment")
        removed = 0
        if self._builtin:
            ids = _builtin_hl7.segment_ids(self._m)
            for i in range(len(ids) - 1, -1, -1):  # back-to-front keeps indices valid
                if ids[i] == segment_id:
                    _builtin_hl7.delete_segment_at(self._m, i)
                    removed += 1
            return removed
        for i in range(len(self._m) - 1, -1, -1):  # back-to-front keeps indices valid
            if str(self._m[i][0]) == segment_id:
                del self._m[i]
                removed += 1
        return removed

    def _delete_segment_at(self, position: int) -> None:
        """Remove the segment at 1-based ``position`` among segments (``1`` = just after MSH,
        matching :meth:`add_segment`'s ``index``).

        This is the positional delete that group-scoped edits use: a group addresses its members by
        position, not by id (an ``OBX`` may belong to any order), so id-based
        :meth:`delete_segments` can't target one order's segments. Deleting MSH (position 0) is
        refused so the header always survives. Raises ``ValueError`` on an out-of-range position."""
        if self._builtin:
            seg_count = len(_builtin_hl7.segment_ids(self._m))
            if position < 1 or position >= seg_count:
                raise ValueError(
                    f"position {position} out of range (1..{seg_count - 1}); position 1 is after MSH"
                )
            _builtin_hl7.delete_segment_at(self._m, position)
            return
        if position < 1 or position >= len(self._m):
            raise ValueError(
                f"position {position} out of range (1..{len(self._m) - 1}); position 1 is after MSH"
            )
        del self._m[position]

    # --- group-scoped structural view ----------------------------------------

    def groups(self, boundary: str = "OBR") -> list[SegmentGroup]:
        """The message's order/observation groups for ``boundary`` (default ``OBR``), in order.

        A group is a contiguous run starting at a boundary segment and ending just before the next
        boundary (or end of message); segments before the first boundary are the header and form no
        group. Use it to scope structural edits to **one** order — per-OBR rebuilds, per-group
        OBX prune/renumber — which the flat (by-id, by-occurrence) API can't address. Returns ``[]``
        if the message has no boundary segment. See :class:`SegmentGroup`."""
        from messagefoundry.parsing.groups import groups_of

        return groups_of(self, boundary)

    # --- encode --------------------------------------------------------------

    def encode(self) -> str:
        """Serialize back to a ``\\r``-delimited HL7 string."""
        if self._builtin:
            return _builtin_hl7.encode(self._m)
        return str(self._m)

    def __str__(self) -> str:
        return self.encode()

    # --- internals -----------------------------------------------------------

    def _raw_field(self, seg: str, fld: int, occurrence: int = 1) -> str:
        """Raw field text (``""`` if the segment/field/occurrence is absent) — for component
        rebuilds. ``occurrence`` (1-based) picks which segment of that id."""
        if self._builtin:
            return _builtin_hl7.raw_field(self._m, seg, fld, occurrence)
        segment = self._segment_obj(seg, occurrence)
        if segment is None:
            return ""
        try:
            return str(segment[fld])
        except (KeyError, IndexError):
            return ""

    def _segment_present(self, segment_id: str, occurrence: int = 1) -> bool:
        """Whether the ``occurrence``-th (1-based) segment with ``segment_id`` exists — backend-
        agnostic presence check used by the write/repetition guards."""
        if self._builtin:
            seen = 0
            for sid in _builtin_hl7.segment_ids(self._m):
                if sid == segment_id:
                    seen += 1
                    if seen == occurrence:
                        return True
            return False
        return self._segment_obj(segment_id, occurrence) is not None

    def _segment_obj(self, segment_id: str, occurrence: int = 1) -> Any:
        """The ``occurrence``-th (1-based) segment object with ``segment_id``, or None if absent.

        python-hl7 backend only — the built-ins backend has no per-segment object (presence is
        checked via :meth:`_segment_present`)."""
        seen = 0
        for segment in self._m:
            if str(segment[0]) == segment_id:
                seen += 1
                if seen == occurrence:
                    return segment
        return None

    def _assign_field(self, seg: str, fld: int, occurrence: int, raw_value: str) -> None:
        """Write the whole raw field text at ``seg``/``fld`` for the given segment ``occurrence``.

        Occurrence 1 uses python-hl7's accessor, which auto-extends the field list; a later
        occurrence is written on its segment object directly, padding empty fields up to ``fld``
        first (a bare index assignment past the end raises). The string content (components,
        repetitions) round-trips verbatim and re-parses into structure either way."""
        if self._builtin:
            # The built-ins backend stores the raw field verbatim and auto-extends the field list,
            # for any occurrence, mirroring python-hl7's auto-extend on assignment.
            _builtin_hl7.set_field(self._m, seg, fld, raw_value, occurrence)
            return
        if occurrence == 1:
            self._m[f"{seg}.F{fld}"] = raw_value
            return
        segment = self._segment_obj(seg, occurrence)
        if segment is None:  # pragma: no cover - callers check first
            raise KeyError(f"cannot set absent segment {seg!r} occurrence {occurrence}")
        while len(segment) <= fld:
            segment.append(self._m.create_field([""]))
        segment[fld] = self._m.create_field([raw_value])

    def _extract(
        self, rep_text: str, comp: int, sub: int | None, comp_sep: str, sub_sep: str
    ) -> str | None:
        """The component/subcomponent value within a single repetition's text, unescaped, or None
        if that part is absent."""
        if self._builtin:
            # Built-ins ``extract_part`` is the same string-level split with byte-parity unescape,
            # reading the message's own separators (in built-ins order: field, comp, rep, sub, esc).
            return _builtin_hl7.extract_part(rep_text, comp, sub, _builtin_hl7.separators(self._m))
        comps = rep_text.split(comp_sep)
        if comp > len(comps):
            return None
        value = comps[comp - 1]
        if sub is None:
            return self._m.unescape(value) or None
        subs = value.split(sub_sep)
        return (self._m.unescape(subs[sub - 1]) or None) if sub <= len(subs) else None

    def _encoding_chars(self) -> tuple[str, str, str, str, str]:
        """The message's ``(field, component, repetition, escape, subcomponent)`` delimiters, read
        from its **own** MSH-1 (field separator) + MSH-2 (the other four).

        Derived from the actual encoding characters, not hardcoded defaults — so a custom-delimiter
        message isn't split on the wrong characters. Raises ``ValueError`` if they can't be determined
        rather than guess (XFORM-2/3). ``self._m.unescape`` uses the same MSH-2-derived characters, so
        write-escaping and read-unescaping stay consistent."""
        field_sep = self._raw_field("MSH", 1)  # MSH-1 is the field separator itself
        enc = self._raw_field("MSH", 2)  # e.g. "^~\&": component, repetition, escape, subcomponent
        if len(field_sep) != 1 or len(enc) < 4:
            raise ValueError(f"cannot determine HL7 separators: MSH-1={field_sep!r}, MSH-2={enc!r}")
        return field_sep, enc[0], enc[1], enc[2], enc[3]

    @staticmethod
    def _escape_leaf(
        value: str, field_sep: str, comp_sep: str, rep_sep: str, esc: str, sub_sep: str
    ) -> str:
        """Escape ONLY the structural delimiters (and the escape char) so a leaf value carries them
        as data, not new structure. Every other character — including code points above U+00FF
        (CJK/Cyrillic/Greek names) — passes through untouched and round-trips via ``unescape``;
        python-hl7's own ``escape()`` instead hex-encodes those as byte pairs that ``unescape()``
        then mis-decodes, silently corrupting them (review M-13)."""
        out = value.replace(esc, f"{esc}E{esc}")  # the escape char first, so we don't double-escape
        out = out.replace(field_sep, f"{esc}F{esc}")
        out = out.replace(comp_sep, f"{esc}S{esc}")
        out = out.replace(rep_sep, f"{esc}R{esc}")
        out = out.replace(sub_sep, f"{esc}T{esc}")
        return out


class RawMessage:
    """A **non-HL7** inbound payload (ADR 0004) — what a code-first Router/Handler receives when the
    inbound connection's ``content_type`` is not ``hl7v2`` (a database row, a JSON/SOAP body, …).

    The body is committed and routed **verbatim** (no HL7 parse). Read it via :attr:`raw` / :attr:`text`,
    branch on :attr:`content_type`, or :meth:`json` it; a Handler then builds an output **string** and
    returns ``Send(to, that_string)`` (the built destinations accept a ``str`` payload). It deliberately
    has **no** HL7 ``msg["MSH-9.1"]`` API — that surface is HL7-only."""

    def __init__(self, raw: str, content_type: str) -> None:
        self.raw = raw
        self.content_type = content_type

    @classmethod
    def from_bytes(cls, data: bytes, content_type: str) -> RawMessage:
        """Carry raw ``data`` over the ``str``/TEXT ingress+store as base64 (ADR 0028 §3 — **the one
        encode**). A SourceConnector handling a byte-oriented payload builds the ``RawMessage`` through
        this factory, so :attr:`raw` is the self-describing ``mfb64:v1:<base64>`` carriage form that
        survives the TEXT columns and the store cipher unchanged. Recover the bytes via
        :attr:`raw_bytes`."""
        return cls(_binary.encode(data), content_type)

    @property
    def text(self) -> str:
        """The body as text (alias for :attr:`raw`)."""
        return self.raw

    def json(self) -> Any:
        """Parse the body as JSON. Raises ``json.JSONDecodeError`` on malformed input — a Handler can
        return ``None`` (FILTERED) or let it raise (ERROR / dead-letter)."""
        return json.loads(self.raw)

    def xml(self) -> Element:
        """Parse the body as XML, **hardened against XXE / entity-expansion** (ADR 0004, BACKLOG #31).

        Backed by ``defusedxml`` with ``forbid_dtd`` / ``forbid_entities`` / ``forbid_external`` all
        **ON** — the same no-DTD, external-entities-OFF posture as
        :func:`messagefoundry.transports.soap._assert_well_formed_fragment`. Inbound XML is
        attacker-influenceable, PHI-bearing data, so a DOCTYPE is **rejected, not parsed**: a
        billion-laughs or external-entity (``file://`` / ``http://``) payload **raises** instead of
        expanding entities or fetching a resource. The forbidden-construct errors subclass
        ``ValueError`` (``defusedxml.common.DefusedXmlException``), and malformed XML raises
        ``xml.etree.ElementTree.ParseError`` — so a Handler can return ``None`` (FILTERED) or let it
        raise (ERROR / dead-letter), symmetric with :meth:`json`."""
        parsed: Element = _xml_fromstring(
            self.raw, forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
        return parsed

    @property
    def is_binary(self) -> bool:
        """Whether :attr:`raw` is a base64 carriage value (ADR 0028) — i.e. :attr:`raw_bytes` will
        decode it. Lets the console/replay/dead-letter raw-view detect a binary body without a
        ``content_type`` registry (symmetric with the store cipher's ``is_encrypted``)."""
        return _binary.is_marked(self.raw)

    @property
    def raw_bytes(self) -> bytes:
        """The carried bytes (ADR 0028 §3 — **the one decode**): strips the ``mfb64:v1:`` marker and
        base64-decodes :attr:`raw`. A binary codec (e.g. DICOM) calls this, **never** ``base64``
        itself. Raises :class:`~messagefoundry.parsing.binary.BinaryCarriageError` if :attr:`raw` is
        not a carriage value or its base64 is corrupt — so the message dead-letters (``ERROR``) rather
        than yielding a silently-truncated body."""
        return _binary.decode(self.raw)

    def binary(self) -> bytes:
        """The carried bytes — method form of :attr:`raw_bytes`, symmetric with :meth:`json`/:meth:`xml`."""
        return self.raw_bytes

    def encode(self) -> str:
        """The body verbatim — symmetry with :meth:`Message.encode` so a pass-through ``Send`` works."""
        return self.raw

    def __str__(self) -> str:
        return self.raw
