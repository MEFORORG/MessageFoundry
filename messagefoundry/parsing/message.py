# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A mutable HL7 v2 message — read and set fields by path, then re-encode.

Wraps a parse by the built-in parser (:mod:`messagefoundry.parsing._builtin_hl7`, ADR 0054). Field
paths use the same ``SEG-F[.C[.S]]`` syntax as :class:`~messagefoundry.parsing.peek.Peek` and the
declarative transforms. Components and subcomponents are rebuilt at the *string* level (split on the
message's own separators, modify, re-join, assign the whole field).

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

import copy
import json
import re
from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING, Any

import messagefoundry.parsing._builtin_hl7 as _builtin_hl7
import messagefoundry.parsing.binary as _binary
from messagefoundry._vendor.defusedxml.ElementTree import fromstring as _xml_fromstring
from messagefoundry.parsing.peek import (
    drop_blank_segments,
    enforce_expansion_budget,
    normalize,
    parse_or_refuse,
    parse_path,
)
from messagefoundry.timezone import (
    DstEdgePolicy,
    _check_los_options,
    age_from_dob,
    length_of_stay,
)

if TYPE_CHECKING:  # the SegmentGroup view imports Message back; keep the cycle out of runtime
    from xml.etree.ElementTree import (  # nosec B405 — type-only import; all XML parsing goes through defusedxml
        Element,
    )

    from messagefoundry.parsing.groups import SegmentGroup

# A segment id is exactly three chars: an upper-case letter then two alphanumerics (HL7 §2.5),
# e.g. ``MSH``/``PID``/``ZAL``. Used to validate :meth:`Message.add_segment` input.
_SEG_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{2}$")

# The characters a write that takes the caller's text as STRUCTURE refuses beside CR and LF (ADR 0205
# rule 3): MLLP's start and end bytes and NUL. A leaf write escapes them instead (rule 2); a
# whole-field write, ``add_repetition`` and ``add_segment`` cannot escape the caller's structure.
# Written as literals because ``parsing`` may not import ``messagefoundry.framing`` (its import
# allowlist in tests/test_dependency_boundaries.py); MLLP's bytes are fixed by the standard.
_STRUCTURE_REFUSED = ("\x0b", "\x1c", "\x00")


def _refuse_frame_bytes(value: str) -> None:
    """Raise ``ValueError`` if ``value`` holds an MLLP frame byte or NUL (ADR 0205 rule 3)."""
    for char in _STRUCTURE_REFUSED:
        if char in value:
            raise ValueError(
                f"HL7 value may not contain the control character U+{ord(char):04X} "
                "(an MLLP frame byte or NUL); write it through a component path to escape it"
            )


class Message:
    """A parsed HL7 message you can read (``msg["MSH-9.2"]``), mutate (``msg["MSH-3"] = …``),
    and re-encode (``msg.encode()``)."""

    #: Symmetry with :class:`RawMessage` — a Router/Handler can branch on ``msg.content_type``.
    content_type = "hl7v2"

    def __init__(self, message: _builtin_hl7.ParsedMessage) -> None:
        self._m: _builtin_hl7.ParsedMessage = message
        # Copy-on-write flag (ADR 0104): True while this message shares its backing tree with a
        # :meth:`copy` snapshot/clone. A mutator calls :meth:`_ensure_owned` first, which deepcopies the
        # tree the first time either side is mutated — so a snapshot that is never further changed (the
        # common copy-on-Send path) is zero-copy.
        self._shared: bool = False

    @classmethod
    def parse(cls, raw: str | bytes) -> Message:
        """Parse ``raw`` (line endings normalized to ``\\r``) into a mutable message.

        Raises :class:`~messagefoundry.parsing.peek.HL7PeekError` when:

        * the text does not start with an ``MSH``, ``FHS`` or ``BHS`` segment;
        * the message's HL7 escapes could expand past the aggregate budget (ASVS 1.3.3) — the same
          check, on the same normalized text, that :meth:`Peek.parse` runs, so the two surfaces can
          never disagree about a body; or
        * the parser itself faults. That is a parser bug, not a property of the message. It is
          refused and logged by exception type only, so the message takes the ``ERROR`` path of
          whoever called this and is never accepted and dropped (ADR 0054 amendment).
        """
        norm = normalize(raw)
        enforce_expansion_budget(norm)
        # Empty segment lines go before the parse, exactly as in Peek.parse (BACKLOG #1594). Kept, one
        # would make every whole-field set raise IndexError, so a blank-line feed the listener ACKed
        # would then fail in every Handler that edits it.
        return cls(parse_or_refuse(drop_blank_segments(norm)))

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
        _field_sep, _comp_sep, rep_sep, _esc, _sub_sep = self._encoding_chars()
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
        return self._extract(reps[rep_index - 1], comp, sub)

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
        _field_sep, _comp_sep, rep_sep, _esc, _sub_sep = self._encoding_chars()
        if comp is None:
            return [rep or None for rep in text.split(rep_sep)]
        return [self._extract(rep, comp, sub) for rep in text.split(rep_sep)]

    def count_segments(self, segment_id: str) -> int:
        """How many segments of ``segment_id`` the message has (0 if none).

        A fieldless bare line such as ``PID`` (no field separator) is not counted, as no read or
        write numbers it as an occurrence (BACKLOG #5917), so ``range(1, count + 1)`` visits every
        segment a write can reach. :meth:`segments` still lists it."""
        return _builtin_hl7.count_segments(self._m, segment_id)

    def _addressable_segment_ids(self) -> list[str | None]:
        """:meth:`segments` with each fieldless bare line as ``None``: positional like
        :meth:`segments`, but an entry matches an id only where a by-occurrence read or write counts
        that line. Group views number their member occurrences from it (BACKLOG #5917)."""
        return _builtin_hl7.addressable_segment_ids(self._m)

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
        """Ordered segment ids, e.g. ``["MSH", "EVN", "PID"]``.

        Positional, one entry per line, so it lists a fieldless bare line too, as ``Peek.segments``
        does; a position here is the one :meth:`add_segment`'s ``index`` uses. It is not an
        occurrence count: :meth:`count_segments` and every by-occurrence read and write skip a
        fieldless line (BACKLOG #5917)."""
        return _builtin_hl7.segment_ids(self._m)

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
        zone: str | None = None,
        on_dst_edge: DstEdgePolicy = "raise",
    ) -> timedelta | None:
        """The encounter length of stay as a :class:`~datetime.timedelta`, from the admit and discharge
        timestamps (default PV1-44 / PV1-45).

        Reads each field's first component, parses both at whatever precision they carry, and returns
        the elapsed time (use ``.days`` for whole inpatient days). Returns None if **either** timestamp
        is absent/empty (an open, not-yet-discharged encounter). ``occurrence`` selects the segment.

        **Pass ``zone`` (an IANA name such as ``"America/Chicago"``) for any feed whose PV1-44/PV1-45
        can arrive without an offset.** Without it, a pair is refused when a time of day lacks an
        offset or when only one stamp has an offset, because a bare wall-clock difference reports a
        stay spanning a daylight-saving change as an hour too long or too short. A pair of date-only
        stamps with no offset needs no zone. The rules are in
        :func:`messagefoundry.timezone.length_of_stay`, which this wraps. ``zone`` and
        ``on_dst_edge`` are checked even for an open encounter, so a misspelt zone fails at once.

        Raises:
            ValueError: a timestamp is malformed, ``on_dst_edge`` is not a known policy, no ``zone``
                was given for a pair that needs one, or the discharge precedes the admit. A stamp on a
                daylight-saving edge of ``zone`` raises a
                :class:`~messagefoundry.timezone.DstTransitionError` subclass (also a ``ValueError``)
                unless ``on_dst_edge`` names a resolution.
            zoneinfo.ZoneInfoNotFoundError: ``zone`` is unknown.
        """
        _check_los_options(zone, on_dst_edge)
        admit = self.field(f"{admit_path}.1", occurrence=occurrence) or self.field(
            admit_path, occurrence=occurrence
        )
        discharge = self.field(f"{discharge_path}.1", occurrence=occurrence) or self.field(
            discharge_path, occurrence=occurrence
        )
        if not admit or not discharge:
            return None
        return length_of_stay(admit, discharge, zone=zone, on_dst_edge=on_dst_edge)

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
        non-delimiter characters — incl. CJK/accented names — pass through intact (review M-13). A
        component/subcomponent write also carries each C0 control character and DEL except TAB as a
        ``\\Xhh\\`` hex escape, and a whole-field write refuses ``0x0B``, ``0x1C`` and NUL, so no
        write emits a raw MLLP frame byte (ADR 0205 rules 2 and 3).

        ``occurrence`` (1-based) selects which segment of that id to write — ``occurrence=2`` edits
        the **second** ``OBX``. It counts as :meth:`field` and :meth:`count_segments` do, and
        occurrence 1 is the segment ``Peek.field`` reads (see ``_builtin_hl7.segment_index`` for a
        fieldless bare line). ``repetition`` (1-based) scopes the write to one field repetition: a
        component write edits that repetition (padding earlier reps if needed) and preserves the
        others (default — and ``repetition=1`` — edit the first, preserve the rest; review H-9); a
        whole-field write with ``repetition`` replaces just that repetition's text (and the value may
        then not contain the repetition separator). Without ``repetition``, a whole-field write
        assigns the caller's text verbatim (their structure, repetitions and all). Raises
        ``KeyError`` if the target segment (occurrence) isn't present.

        ``MSH-1`` and ``MSH-2``, and fields 1 and 2 of a ``BHS`` or ``FHS`` header, are the message's
        delimiters, which the parser read once from the first line and every other line is written
        in. A write to one of them that would change a delimiter raises ``ValueError``, so a write
        there cannot leave a header advertising delimiters its body is not written in (BACKLOG
        #5972). Accepted there: a value equal to what :meth:`field` reads at that path; at field
        2, a whole-field value that keeps the four encoding characters and adds, drops or changes
        only the one v2.7 truncation character after them; and, on the leading header's short
        field 2, the four characters the parser filled it with, which declares them. To send under other delimiters, re-encode the whole message, as
        a per-outbound ``encoding_characters`` does."""
        self._write(path, value, occurrence, repetition, as_data=False)

    def _write(
        self, path: str, value: str, occurrence: int, repetition: int | None, *, as_data: bool
    ) -> None:
        """The one write behind :meth:`set` and :meth:`set_data`, so both check the same things in
        the same order and fail the same way. ``as_data`` escapes a whole-field value as one leaf
        once the target is known to exist. ``MSH-1`` and ``MSH-2`` (and ``BHS``/``FHS`` fields 1 and
        2) hold the delimiters themselves, so :meth:`_write_delimiter_field` takes them, unescaped."""
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
        field_sep, comp_sep, rep_sep, esc, sub_sep = self._write_encoding_chars()
        if _builtin_hl7.is_delimiter_field(seg, fld):
            self._write_delimiter_field(path, seg, fld, occurrence, value, comp, repetition)
            return

        if comp is None:
            if as_data:
                value = self._escape_leaf(value, field_sep, comp_sep, rep_sep, esc, sub_sep)
            # Whole-field write assigns the caller's structure verbatim — but the field separator
            # would split it into extra fields downstream, so reject it (review M-12). Components and
            # repetitions are the caller's intended structure and remain allowed.
            _refuse_frame_bytes(value)
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

    def set_data(
        self, path: str, value: str, *, occurrence: int = 1, repetition: int | None = None
    ) -> None:
        """Write ``value`` at ``path`` as DATA at every level, a whole field included (ADR 0206).

        :meth:`set` takes whole-field text as the caller's structure, so ``"A^B"`` becomes two
        components. That is right for text the author wrote and wrong for a value read back with
        :meth:`field` from a component or subcomponent, which is decoded: its escaped separators
        come back as plain characters, and a whole-field :meth:`set` would make them live structure.
        This write escapes the value as one leaf first, so it lands as the first component of the
        field (or of the repetition ``repetition`` names) and reads back unchanged. At a component
        or subcomponent path it is exactly :meth:`set`, which escapes there already. Use it whenever
        the value came from a message rather than from the author::

            msg.set_data("PV1-19", msg.field("PID-3.1") or "")

        It raises exactly what :meth:`set` raises for the same arguments, ``ValueError`` on a CR or
        LF and ``KeyError`` on an absent segment among them, because both are one implementation.
        ``MSH-1`` and ``MSH-2``, and ``BHS``/``FHS`` fields 1 and 2, hold the delimiters themselves,
        have no escaped form, and are written, or refused, exactly as :meth:`set` writes them. A
        dry-run trace records the value as passed here, as it records the value passed to
        :meth:`set`, never the escaped text."""
        self._write(path, value, occurrence, repetition, as_data=True)

    def __setitem__(self, path: str, value: str) -> None:
        self.set(path, value)

    def add_repetition(self, path: str, value: str, *, occurrence: int = 1) -> None:
        """Append a new ``~`` repetition carrying ``value`` to the field at ``path``.

        ``path`` must be a **whole-field** path (no component) — a repetition is a field-level unit;
        ``value`` is the new repetition's structure (components with ``^`` are kept as the caller's
        intent), so it may not contain the field or repetition separator or a CR/LF. If the field is
        currently empty the value becomes its first repetition. ``occurrence`` selects the segment.
        Raises ``KeyError`` if the segment (occurrence) is absent, ``ValueError`` on a component path,
        an illegal separator in ``value``, or a header's delimiter field (``MSH-1``/``MSH-2``, or
        field 1 or 2 of ``BHS``/``FHS``)."""
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
        if _builtin_hl7.is_delimiter_field(seg, fld):
            raise self._delimiter_write_refusal(seg, fld, repetition=True)
        _refuse_frame_bytes(value)
        field_sep, _comp_sep, rep_sep, _esc, _sub_sep = self._write_encoding_chars()
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
        Adding an ``MSH`` is refused (there is exactly one), and so is a ``BHS`` or ``FHS`` header,
        whose delimiter fields a split line cannot number. Raises ``ValueError`` on a malformed
        line or out-of-range ``index``."""
        if "\r" in line or "\n" in line:
            raise ValueError(
                "add_segment takes one segment line (no CR/LF); call it once per segment"
            )
        _refuse_frame_bytes(line)
        field_sep, *_ = self._write_encoding_chars()
        tokens = line.split(field_sep)
        segment_id = tokens[0]
        if not _SEG_ID_RE.match(segment_id):
            raise ValueError(f"segment must begin with a 3-char segment id, got {segment_id!r}")
        if segment_id in _builtin_hl7.HEADER_IDS:
            # There is exactly one MSH; and any header line keeps its delimiters in fields 1 and 2,
            # where a line split on the field separator puts MSH-3's numbering, so it would encode
            # as a garbled line (BACKLOG #5972).
            raise ValueError(
                "refusing to add a second MSH segment"
                if segment_id == "MSH"
                else f"refusing to add a {segment_id} header segment"
            )
        # A bare segment id (no field separator -> a single token) would graft a fieldless segment,
        # which no read, count or write numbers as an occurrence (BACKLOG #5917), so a later set()
        # would raise "cannot set absent segment". Normalize a bare id to a settable empty segment
        # (id + one empty field), identical to add_segment("TXA|").
        if len(tokens) == 1:
            tokens.append("")
        self._ensure_owned()  # copy-on-write before mutating (ADR 0104)
        seg_count = len(_builtin_hl7.segment_ids(self._m))
        if index is not None and (index < 1 or index > seg_count):
            raise ValueError(f"index {index} out of range (1..{seg_count}); index 1 is after MSH")
        _builtin_hl7.add_segment_line(self._m, segment_id, tokens, index)

    def delete_segments(self, segment_id: str) -> int:
        """Remove every segment with ``segment_id`` and return how many were removed.

        Deleting ``MSH`` is refused — the message must keep its header — and so is deleting the
        ``BHS`` or ``FHS`` that leads the message, whose delimiters every line is read and
        written in (BACKLOG #5972). Common for clearing a
        repeating block (e.g. ``delete_segments("ODS")``) before rebuilding it with
        :meth:`add_segment`. A fieldless bare line of that id is removed and counted too, though
        :meth:`count_segments` skips it, so a delete leaves no stray bare line behind."""
        if segment_id == "MSH":
            raise ValueError("refusing to delete the MSH segment")
        if segment_id in _builtin_hl7.HEADER_IDS and self._m["segments"][0]["id"] == segment_id:
            raise ValueError(
                f"refusing to delete the {segment_id} header that leads the message, whose "
                "delimiters every line is read and written in"
            )
        self._ensure_owned()  # copy-on-write before mutating (ADR 0104)
        removed = 0
        ids = _builtin_hl7.segment_ids(self._m)
        for i in range(len(ids) - 1, -1, -1):  # back-to-front keeps indices valid
            if ids[i] == segment_id:
                _builtin_hl7.delete_segment_at(self._m, i)
                removed += 1
        return removed

    def _delete_segment_at(self, position: int) -> None:
        """Remove the segment at 1-based ``position`` among segments (``1`` = just after MSH,
        matching :meth:`add_segment`'s ``index``).

        This is the positional delete that group-scoped edits use: a group addresses its members by
        position, not by id (an ``OBX`` may belong to any order), so id-based
        :meth:`delete_segments` can't target one order's segments. Deleting MSH (position 0) is
        refused so the header always survives, and so is deleting an ``MSH`` anywhere, as
        :meth:`delete_segments` refuses it: in a ``BHS``- or ``FHS``-led message the MSH sits past
        position 0 (BACKLOG #5972). Raises ``ValueError`` on an out-of-range position."""
        refusal = self._positional_delete_refusal(position)
        if refusal is not None:
            raise refusal
        self._ensure_owned()  # copy-on-write before mutating (ADR 0104)
        _builtin_hl7.delete_segment_at(self._m, position)

    def _positional_delete_refusal(self, position: int) -> ValueError | None:
        """The ``ValueError`` :meth:`_delete_segment_at` raises for ``position``, or None if it
        would delete it. A caller deleting several positions checks every one first, so a refusal
        leaves the message unchanged."""
        segments = self._m["segments"]
        if position < 1 or position >= len(segments):
            return ValueError(
                f"position {position} out of range (1..{len(segments) - 1}); position 1 is after MSH"
            )
        if segments[position]["id"] == "MSH":
            return ValueError("refusing to delete the MSH segment")
        return None

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
        return _builtin_hl7.encode(self._m)

    def encode_raw_separators(self) -> str:
        """Serialize like :meth:`encode`, but emit the four reserved HL7 **structural** separators as RAW
        bytes instead of their ``\\F\\ \\S\\ \\R\\ \\T\\`` escape sequences (BACKLOG #107).

        The default serialize path (:meth:`encode`) always escapes structural delimiters; this is the
        opt-in escape-hatch a per-outbound ``hl7_raw_separators`` override uses to feed a partner that
        cannot decode HL7 escapes. Reserved chars are read from this message's own MSH (never hardcoded)
        and the transform runs over the parsed model, not by string-slicing the raw. When the body carries
        no structural escapes the output is byte-identical to :meth:`encode`; when it does, the output is
        deliberately **non-conformant** (that is the point). See
        :func:`messagefoundry.parsing._builtin_hl7.encode_raw_separators`."""
        return _builtin_hl7.encode_raw_separators(self._m)

    def copy(self) -> Message:
        """An independent, mutable **structural clone** of this message's current in-memory state
        (ADR 0104) — the primitive behind copy-on-Send and the explicit ``msg.copy()`` sugar.

        Deep-clones the backing parse tree and wraps it in a fresh :class:`Message`. Deliberately **not**
        ``Message.parse(self.encode())``: an encode→parse round-trip would make clone fidelity depend on
        that round-trip being byte-stable, and would drop state such as a blank segment held in a tree
        built without :meth:`parse`. Pure: no clock/RNG/I/O, and the ingress raw is never touched. Note it
        does **not** re-run the hl7apy strict tier — a clone of a strict-validated inbound is not
        re-validated (by design).

        **Copy-on-write (ADR 0104):** the clone SHARES the backing tree until either side is first
        mutated, at which point the mutator (:meth:`_ensure_owned`) takes the private deepcopy. Still an
        independent, mutable clone — a later mutation of either message never leaks into the other — but a
        clone that is never further changed (the common copy-on-Send snapshot) costs **no** deepcopy."""
        self._shared = True
        clone = Message(self._m)
        clone._shared = True
        return clone

    def __copy__(self) -> Message:
        # copy.copy shares the tree, so both sides take the copy-on-write flag, or a write would
        # reach both. Built on type(self) from the instance __dict__ (slots are not copied).
        new = object.__new__(type(self))
        new.__dict__.update(self.__dict__)
        self._shared = new._shared = True
        return new

    def __deepcopy__(self, memo: dict[int, object]) -> Message:
        # A deep copy shares nothing and leaves the source's flag alone. The tree goes through
        # clone(): copy.deepcopy would walk a _lazy a reader of a clone may be splitting (#5801).
        new = object.__new__(type(self))
        memo[id(self)] = new
        for name, value in self.__dict__.items():
            if name == "_m":
                value = _builtin_hl7.clone(value)
            elif name == "_shared":
                value = False
            else:
                value = copy.deepcopy(value, memo)
            setattr(new, name, value)
        return new

    def _ensure_owned(self) -> None:
        """Copy-on-write hook — every mutator calls this before touching ``self._m``. If the backing tree
        is still shared with a :meth:`copy` snapshot/clone, take a private deepcopy now (and clear the
        flag) so the mutation lands only on this message; if already owned it is a cheap no-op."""
        if self._shared:
            # Not copy.deepcopy: a reader of the other side may be splitting this tree (#5801).
            self._m = _builtin_hl7.clone(self._m)
            self._shared = False

    def __str__(self) -> str:
        return self.encode()

    # --- internals -----------------------------------------------------------

    def _raw_field(self, seg: str, fld: int, occurrence: int = 1) -> str:
        """Raw field text (``""`` if the segment/field/occurrence is absent) — for component
        rebuilds. ``occurrence`` (1-based) picks which segment of that id."""
        return _builtin_hl7.raw_field(self._m, seg, fld, occurrence)

    def _segment_present(self, segment_id: str, occurrence: int = 1) -> bool:
        """Whether the ``occurrence``-th (1-based) segment with ``segment_id`` exists — the presence
        check used by the write/repetition guards."""
        # The scan the write resolves through, so the guard and the write cannot disagree on which
        # segment is the ``occurrence``-th (BACKLOG #5917).
        return _builtin_hl7.segment_index(self._m, segment_id, occurrence) is not None

    def _assign_field(self, seg: str, fld: int, occurrence: int, raw_value: str) -> None:
        """Write the whole raw field text at ``seg``/``fld`` for the given segment ``occurrence``.

        The field is stored verbatim and the field list auto-extends, for any occurrence. The string
        content (components, repetitions) re-parses into structure on the next read."""
        self._ensure_owned()  # copy-on-write before mutating (ADR 0104)
        _builtin_hl7.set_field(self._m, seg, fld, raw_value, occurrence)

    def _extract(self, rep_text: str, comp: int, sub: int | None) -> str | None:
        """The component/subcomponent value within a single repetition's text, unescaped, or None
        if that part is absent. Reads the message's own separators."""
        return _builtin_hl7.extract_part(rep_text, comp, sub, _builtin_hl7.separators(self._m))

    def _write_delimiter_field(
        self,
        path: str,
        seg: str,
        fld: int,
        occurrence: int,
        value: str,
        comp: int | None,
        repetition: int | None,
    ) -> None:
        """Write a header's field 1 or 2, or refuse a write that would change a delimiter.

        A value equal to what :meth:`field` reads at the same path, repetition and occurrence is a
        no-op, so a read-then-write copy of the header still works. At field 2, a whole-field value
        (or repetition 1) holding the line's own four encoding characters, alone or followed by one
        v2.7 truncation character, is assigned: the delimiters do not move, so the rest of the
        message stays written in them. The truncation character must be printable, not a space and
        not a delimiter, as :func:`~messagefoundry.parsing._builtin_hl7.encode_with_separators`
        requires of a batch header's. Anything else raises."""
        current = self._raw_field(seg, fld, occurrence)
        whole = comp is None and repetition in (None, 1)
        if whole and value == current:
            return
        # field() reads an empty part as None, which a copy writes back as "".
        if (comp is not None or repetition is not None) and value == (
            self.field(path, occurrence=occurrence, repetition=repetition) or ""
        ):
            return
        # A short field 2 on the leading header may be completed to the four characters the
        # parser filled it with, so the header declares the delimiters every line is read and
        # written in; nothing moves.
        completion = ""
        if (
            whole
            and fld == 2
            and len(current) < 4
            and occurrence == 1
            and self._m["segments"][0]["id"] == seg
        ):
            _f, comp_sep, rep_sep, esc, sub_sep = self._encoding_chars()
            completion = comp_sep + rep_sep + esc + sub_sep
            if value == completion:
                self._assign_field(seg, fld, occurrence, value)
                return
        truncation = whole and fld == 2 and len(current) >= 4
        if truncation and value[:4] == current[:4]:
            tail = value[4:]
            delimiters = self._raw_field(seg, 1, occurrence) + current[:4]
            if not tail or (
                len(tail) == 1
                and tail.isprintable()
                and not tail.isspace()
                and tail not in delimiters
            ):
                self._assign_field(seg, fld, occurrence, value)
                return
        raise self._delimiter_write_refusal(seg, fld, truncation=truncation, completion=completion)

    @staticmethod
    def _delimiter_write_refusal(
        seg: str,
        fld: int,
        *,
        truncation: bool = False,
        repetition: bool = False,
        completion: str = "",
    ) -> ValueError:
        """The refusal of a write that would change a header's delimiter field (BACKLOG #5972). The
        parser reads the message's separators once, from the first line, and splits and re-encodes
        every other line on them, so a changed delimiter field would advertise delimiters the rest
        of the message is not written in.

        The text names what :meth:`_write_delimiter_field` accepts for the refused write's shape,
        so it stays true of that write. ``truncation`` is True when the write could have changed
        the v2.7 truncation character instead: a whole-field (or repetition 1) write at field 2 of
        a header whose field 2 holds all four encoding characters. ``repetition`` is for
        :meth:`add_repetition`, which accepts nothing there. ``completion`` is the four encoding
        characters the parser filled a short field 2 of the leading header with, the one other
        value that write accepts."""
        if repetition:
            accepted = "a repetition cannot be added to it"
        elif completion:
            accepted = (
                "a write there must leave it reading as it does, or complete it to "
                f"{completion!r}, the four encoding characters the parser filled it with"
            )
        elif truncation:
            accepted = (
                "a write there must leave it reading as it does, or keep its four encoding "
                "characters and add, drop or change only the one v2.7 truncation character after "
                "them, which must be printable, not a space and not a delimiter"
            )
        else:
            accepted = "a write there must leave it reading as it does"
        return ValueError(
            f"{seg}-{fld} holds the message's delimiters, which every other line is written in; "
            f"{accepted}. Re-encode the whole message to send it under other delimiters"
        )

    def _encoding_chars(self) -> tuple[str, str, str, str, str]:
        """The message's ``(field, component, repetition, escape, subcomponent)`` delimiters: the
        ones the parser read from the first line (an ``MSH``, ``BHS`` or ``FHS`` header) and split
        every other line on.

        Derived from the actual encoding characters, not hardcoded defaults — so a custom-delimiter
        message isn't split on the wrong characters (XFORM-2/3). A short field 2 has its missing
        characters filled exactly as the parser filled them (``^``, ``~``, ``\\``, ``&``), so a read
        here agrees with the split, and with ``Peek.field``, on every message the parser accepts:
        reading them from ``MSH-2`` instead refused a short ``MSH-2``, or a ``BHS`` or ``FHS`` with
        no ``MSH``, that the parser had already split (BACKLOG #5972). The header's delimiter fields
        cannot be rewritten through this API (:meth:`_write_delimiter_field`), so the parser's read
        stays the message's. The read-side unescape uses the same characters, so write-escaping and
        read-unescaping stay consistent."""
        field_sep, comp_sep, rep_sep, sub_sep, esc = _builtin_hl7.separators(self._m)
        return field_sep, comp_sep, rep_sep, esc, sub_sep

    def _write_encoding_chars(self) -> tuple[str, str, str, str, str]:
        """:meth:`_encoding_chars` for a write, which refuses a message whose first line names too
        few encoding characters and has a default filled in for one that is already another of its
        separators, as ``MSH|~|`` or ``MSH^^`` (BACKLOG #5972). Two structures there share one
        character, so a value joined on one would read back as the other. A read of such a message
        is not refused: it reads what the sender sent, as ``Peek`` does, and a message that is only
        read, routed or acknowledged never comes here."""
        if self._delimiters_collide():
            raise ValueError(
                "the message header names too few encoding characters, and a default filled in "
                "for one is already another of its delimiters, so a write could not be read back "
                "as written; the message can be read but not written"
            )
        return self._encoding_chars()

    def _delimiters_collide(self) -> bool:
        """Whether the first line fills a delimiter it does not declare with a default that is
        already another of its delimiters (:func:`~messagefoundry.parsing._builtin_hl7.filled_default_collides`),
        read from the header's parsed fields 1 and 2, never from a slice of the raw text."""
        first = self._m["segments"][0]["fields"]
        field_sep = _builtin_hl7._field_text(first[1])
        encoding = _builtin_hl7._field_text(first[2]) if len(first) > 2 else ""
        return _builtin_hl7.filled_default_collides(
            _builtin_hl7._field_text(first[0]) + field_sep + encoding + field_sep
        )

    @staticmethod
    def _escape_leaf(
        value: str, field_sep: str, comp_sep: str, rep_sep: str, esc: str, sub_sep: str
    ) -> str:
        """Escape the structural delimiters, the escape char and the C0/DEL control characters
        (TAB excepted) so a leaf value carries them as data, not new structure or a frame byte (ADR
        0205 rule 2). Every other character — including code points above U+00FF
        (CJK/Cyrillic/Greek names) — passes through untouched and round-trips via ``unescape``;
        python-hl7's ``escape()``, used before the built-in parser, hex-encoded those as byte pairs
        that ``unescape()`` then mis-decoded, silently corrupting them (review M-13). The one
        implementation is :func:`~messagefoundry.parsing._builtin_hl7.escape_leaf`."""
        return _builtin_hl7.escape_leaf(value, (field_sep, comp_sep, rep_sep, sub_sep, esc))


def emit_raw_separators(payload: str) -> str:
    """Re-serialize an HL7 v2 ``payload`` with the four reserved **structural** separators emitted as RAW
    bytes instead of ``\\F\\ \\S\\ \\R\\ \\T\\`` escape sequences (BACKLOG #107).

    The deliberate per-outbound escape-hatch for a partner that cannot decode HL7 escapes. ``payload`` is
    parsed with its OWN separators (read from MSH-1/MSH-2, never assumed ``|^~\\&``) and re-joined via the
    parsed model — never by string-slicing the raw. A body with no structural escapes round-trips
    **byte-identically** to a normal encode. Raises :class:`~messagefoundry.parsing.peek.HL7PeekError`
    if ``payload`` has no leading ``MSH``/``BHS``/``FHS`` (not parseable HL7), so a caller can fail the
    delivery loud rather than ship a corrupted frame."""
    return Message.parse(payload).encode_raw_separators()


def reencode_with_separators(payload: str, target: tuple[str, str, str, str, str]) -> str:
    """Re-serialize an HL7 v2 ``payload`` with a different set of delimiters (an outbound's MSH
    encoding-character override).

    ``target`` is ``(field, component, repetition, subcomponent, escape)``. ``payload`` is parsed with
    its OWN separators (read from MSH-1/MSH-2) and re-joined via the parsed model, never by
    string-slicing the raw; see :func:`messagefoundry.parsing._builtin_hl7.encode_with_separators`.
    The text is parsed as it is, so a blank segment line survives the rewrite.

    Raises :class:`~messagefoundry.parsing._builtin_hl7.HL7ParseError` (a ``ValueError``) with no
    leading ``MSH``/``BHS``/``FHS``, ``ValueError`` when the header's own separators repeat, and
    ``IndexError`` on a header too short to read them."""
    return _builtin_hl7.encode_with_separators(_builtin_hl7.parse(normalize(payload)), target)


def snapshot_payload(payload: Message | RawMessage | str) -> Message | RawMessage | str:
    """Copy-on-Send dispatch (ADR 0104): return an independent snapshot of ``payload`` so a ``Send``
    constructed now is decoupled from a later mutation of the same object within the handler.

    A :class:`Message` becomes a structural :meth:`Message.copy`; a :class:`RawMessage` becomes a
    :meth:`RawMessage.copy` (re-capturing its ``raw`` string); a ``str`` is immutable and returned
    **as-is** (identity preserved), so the caller can detect "no snapshot needed" via ``is``."""
    if isinstance(payload, Message):
        return payload.copy()
    if isinstance(payload, RawMessage):
        return payload.copy()
    return payload


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
        return ``None`` (FILTERED) or let it raise (ERROR / dead-letter).

        That includes a body nested past the decoder's depth limit, which ``json`` reports as a
        ``RecursionError`` (a ``RuntimeError``, not a ``ValueError``); it is converted here so the
        documented type is the only one (BACKLOG #1600).

        The raised error never holds the body, which can be PHI (BACKLOG #2085). json's own error
        keeps the whole body on ``.doc``, so a copy is raised in its place: the same text, ``msg``,
        ``pos``, ``lineno`` and ``colno``, an empty ``doc``, and no chain, since it is raised after
        the handler. The depth-limit case carries position 0 and chains the ``RecursionError``,
        which holds no input."""
        try:
            return json.loads(self.raw)
        except json.JSONDecodeError as exc:
            refused = json.JSONDecodeError(exc.msg, "", 0)
            refused.args = exc.args  # json's rendered "msg: line L column C (char P)", no body
            refused.pos, refused.lineno, refused.colno = exc.pos, exc.lineno, exc.colno
        except RecursionError as exc:
            raise json.JSONDecodeError("JSON body is nested too deeply to parse", "", 0) from exc
        raise refused

    def xml(self) -> Element:
        """Parse the body as XML, **hardened against XXE / entity-expansion** (ADR 0004, BACKLOG #31).

        Backed by ``defusedxml`` with ``forbid_dtd`` / ``forbid_entities`` / ``forbid_external`` all
        **ON** — the same no-DTD, external-entities-OFF posture as
        :func:`messagefoundry.transports.soap._assert_well_formed_fragment`. Inbound XML is
        attacker-influenceable, PHI-bearing data, so a DOCTYPE is **rejected, not parsed**: a
        billion-laughs or external-entity (``file://`` / ``http://``) payload **raises** instead of
        expanding entities or fetching a resource. The forbidden-construct errors subclass
        ``ValueError`` (``DefusedXmlException``, from the engine's vendored copy in
        ``messagefoundry/_vendor/defusedxml/``, so catch ``ValueError`` rather than importing the
        upstream package's class), and malformed XML raises ``xml.etree.ElementTree.ParseError`` —
        so a Handler can return ``None`` (FILTERED) or let it raise (ERROR / dead-letter), symmetric
        with :meth:`json`."""
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

    def copy(self) -> RawMessage:
        """A snapshot of this payload at copy-on-Send time (ADR 0104): re-capture the current ``raw``
        (an immutable ``str``) into a fresh :class:`RawMessage`. This closes the **within-handler**
        duplicate-delivery case — a ``Send`` built now is decoupled from a later ``rm.raw = …`` in the
        same handler. It does **not** address the **cross-handler** leak (one ``RawMessage`` is shared
        across a message's sibling handlers), which is a separate scan-gated fast-follow (freeze
        ``RawMessage.raw``); do not treat ``RawMessage`` as immutable."""
        return RawMessage(self.raw, self.content_type)

    def __str__(self) -> str:
        return self.raw
