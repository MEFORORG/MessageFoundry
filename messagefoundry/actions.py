# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Typed action vocabulary — small, pure helpers over the mutable :class:`~messagefoundry.parsing.message.Message`.

The analyst-facing half of ADR 0076 (phase 1): a bounded set of composable helpers mirroring the
Corepoint action classes (``ItemCopy``/``ItemReplace``/``ItemFormatDate``/…), mapped onto the existing
:class:`Message` read/mutate API. A code-first Handler calls them like any other Python, so a
vocabulary-authored transform reads as ordinary idiomatic code — the lens (ADR 0076 §3–§4) then
recognizes these calls as typed *action* rows.

Rules (ADR 0076 §2):

* **Pure** — every helper does **message-in-place mutation only**, no I/O (no file/socket/DB/network).
  This keeps the at-least-once reliability invariant (a re-run re-derives identical output) untouched.
  The sanctioned live lookups (``db_lookup``/``fhir_lookup``) are *not* wrapped here — the lens
  recognizes them directly.
* **Control flow stays native Python.** The vocabulary deliberately adds **no** ``if``/``for``
  wrappers; use plain Python (``if msg[…]:``, ``for grp in msg.groups()``) — that is what keeps a
  vocabulary-authored Handler diffable, reviewable code.
* Every path uses the same ``SEG-F[.C[.S]]`` grammar as :class:`Message`, which reads the message's own
  MSH encoding characters — never hardcoded delimiters — and re-encodes structurally (never string
  slicing).
* A **closed-set** argument (``convert_case`` mode, ``pad_field`` side, ``arith_field`` op,
  ``date_diff_field`` unit) is typed ``Literal[...]`` **and** kept behind its runtime ``ValueError``
  guard: the type layer rejects a wrong literal at author time (and lets ``lens schema`` project it as an
  ``enum`` dropdown, BACKLOG #1760), while the guard still catches a dynamically-supplied bad value at run
  time — the overlap is intentional, two layers guarding different callers, not a restated check.
"""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta
from typing import Literal

from messagefoundry.parsing import _builtin_hl7
from messagefoundry.parsing._builtin_hl7 import _HEX_ESCAPED_CONTROLS
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import parse_path
from messagefoundry.timezone import _TIME_PRECISIONS, _offset_to_timedelta, parse_hl7_timestamp

__all__ = [
    "copy_field",
    "set_field",
    "append_to_field",
    "trim_field",
    "substring_field",
    "pad_field",
    "replace_literal",
    "convert_case",
    "arith_field",
    "format_date",
    "date_diff_field",
    "split_field",
    "code_lookup",
    "copy_segment",
    "delete_segment",
]

# Sentinel distinguishing "no default supplied" from an explicit ``default=None`` in ``code_lookup``.
_UNSET: object = object()


def _writer(msg: Message, src: str) -> Callable[[str, str], None]:
    """The write for a value read from ``src``: :meth:`Message.set_data` when ``src`` is a component
    or subcomponent, whose read is decoded (ADR 0206 rule 1). A whole field's read is raw text: it
    goes into a whole-field destination through :meth:`Message.set`, as the structure it already
    is. A component write would escape it, escape sequences included, a second time (BACKLOG
    #5821), so a component or subcomponent destination gets it as one leaf's raw text instead
    (:func:`_as_one_leaf`), spliced into the field. Either way, a
    component or subcomponent of field 1 or 2 of ``MSH``, ``BHS`` or ``FHS`` is refused, and a
    whole-field write there that would change a delimiter is refused by :meth:`Message.set`."""
    from_leaf = parse_path(src)[2] is not None

    def write(dst: str, value: str) -> None:
        seg, fld, comp, sub = parse_path(dst)
        if comp is not None:
            _refuse_delimiter_field(seg, fld, dst)
        if from_leaf:
            msg.set_data(dst, value)
        elif comp is None:
            msg.set(dst, value)
        else:
            seps = _seps(msg)
            whole = _whole_field(dst)
            leaf = _as_one_leaf(value, seps)
            msg.set(whole, _splice_part(msg.field(whole) or "", comp, sub, leaf, seps))

    return write


def copy_field(msg: Message, src: str, dst: str) -> None:
    """Copy the value at ``src`` into ``dst`` (Corepoint ``ItemCopy``).

    An absent/empty ``src`` copies an empty value (clearing ``dst``). A component or subcomponent
    ``src`` is read decoded, so it is written as data at every ``dst`` level, a whole field included:
    a value carrying a ``^``, ``~`` or ``&`` rides across as data, not new structure (ADR 0206). A
    whole-field ``src`` is raw text, structure and all, and is copied as it is into a whole-field
    ``dst``. Into a component or subcomponent ``dst`` it is written as one leaf that reads back as
    the field's leaves, each decoded, joined by its separators read as data: a field sent as
    ``O\\S\\Brien`` reads back as ``O^Brien``, not as its escape sequence, and one sent as ``A^B``
    reads back as ``A^B``. An escape sequence holding a raw control character that decodes to a CR
    or LF, which no component carries, reads back as sent instead. A component or subcomponent
    ``dst`` in field 1 or 2 of ``MSH``, ``BHS`` or ``FHS`` raises :class:`ValueError`, whatever
    ``src`` is, and so does a whole-field one there that would change a delimiter."""
    _writer(msg, src)(dst, msg.field(src) or "")


def set_field(msg: Message, path: str, value: str) -> None:
    """Set ``path`` to ``value`` (Corepoint ``ItemReplace``) — a named wrapper over :meth:`Message.set`."""
    msg.set(path, value)


def append_to_field(msg: Message, path: str, suffix: str) -> None:
    """Append ``suffix`` to the current value at ``path`` (Corepoint ``ItemAppend``).

    An absent field is treated as empty, so the result is just ``suffix``. On a component or
    subcomponent path ``suffix`` is written as data after the value's last leaf, and the value's
    escape sequences are kept as sent rather than decoded and written back (BACKLOG #5928). On a
    whole-field path ``suffix`` is appended to the raw text, as the structure a whole-field
    :meth:`Message.set` takes. A component or subcomponent path raises :class:`ValueError` on field
    1 or 2 of ``MSH``, ``BHS`` or ``FHS``, and so does a whole-field path there whose result would
    change a delimiter."""
    seg, fld, comp, _sub = parse_path(path)
    if comp is not None:
        _refuse_delimiter_field(seg, fld, path)
    current = msg.field(path)
    if current is not None and not suffix:
        return
    if current is None or comp is None:
        msg.set(path, (current or "") + suffix)
        return
    _edit_value(
        msg, path, lambda value, seps: _append_after_last_leaf(value, suffix, seps), scope="value"
    )


def convert_case(msg: Message, path: str, mode: Literal["upper", "lower", "title"]) -> None:
    """Upper/lower/title-case the value at ``path`` in place (Corepoint ``ItemConvert``/``ItemFormat``).

    ``mode`` is one of ``"upper"`` / ``"lower"`` / ``"title"``. Each leaf of the value is cased on
    its own, so a whole-field path keeps its components, repetitions and subcomponents. Only the
    literal text is cased: an escape sequence such as ``\\.br\\`` or ``\\S\\`` is kept as sent, and so
    is the text a hex escape carries. Title case still reads the character before a letter to
    decide whether it starts a word: an escape's decoded text, except that where ``MSH-18`` is
    empty or ``UNICODE UTF-8`` the bytes of a run of adjacent hex escapes are read as UTF-8 where
    they end in a valid UTF-8 character. A no-op on an absent field; raises :class:`ValueError` on
    an unknown mode (fail loud rather than silently leaving the value), or on field 1 or 2 of
    ``MSH``, ``BHS`` or ``FHS``, which hold the delimiters themselves."""
    # A tuple test, not a dict one, so an unhashable mode from config raises the documented
    # ValueError rather than a TypeError.
    if mode not in tuple(_CASE_CONVERTERS):
        raise ValueError(f"convert_case mode must be 'upper', 'lower', or 'title', got {mode!r}")
    convert = _CASE_CONVERTERS[mode]
    # Only title case reads the character before a run, and only an empty or UTF-8 MSH-18 says
    # how to read a hex escape's bytes as more than one character each.
    utf8_hex = mode == "title" and (msg.field("MSH-18.1") or "").strip() in ("", "UNICODE UTF-8")
    _edit_value(
        msg,
        path,
        lambda raw, seps: _case_leaf(raw, convert, seps, utf8_hex=utf8_hex),
        scope="leaves",
    )


# Each converter also takes whether the character before the run is cased. Only title case
# needs it: str.title upper-cases a letter unless the character before it is cased, so a
# one-character prefix carries that state into the run and is dropped again.
_CASE_CONVERTERS: dict[str, Callable[[str, bool], str]] = {
    "upper": lambda text, _after_cased: text.upper(),
    "lower": lambda text, _after_cased: text.lower(),
    "title": lambda text, after_cased: (("a" if after_cased else " ") + text).title()[1:],
}


def format_date(msg: Message, path: str, out_fmt: str, *, in_fmt: str | None = None) -> None:
    """Reformat the timestamp at ``path`` to ``out_fmt`` (Corepoint ``ItemFormatDate``/``ItemTransformDate``).

    With ``in_fmt=None`` (default) the current value is parsed as a tolerant HL7 v2 timestamp (variable
    precision, via :func:`~messagefoundry.timezone.parse_hl7_timestamp`); otherwise it is parsed with
    :meth:`datetime.datetime.strptime` using ``in_fmt``. The result is rendered with
    :meth:`datetime.datetime.strftime` and ``out_fmt``. A no-op on an absent field; a value that does
    not match the input format raises :class:`ValueError` (route it to the error/dead-letter path),
    never a silently wrong date."""
    value = msg.field(path)
    if value is None:
        return
    if in_fmt is None:
        parsed, _precision, _offset = parse_hl7_timestamp(value)
    else:
        parsed = datetime.strptime(value, in_fmt)  # noqa: DTZ007 — HL7 timestamps carry their own zone
    msg.set(path, parsed.strftime(out_fmt))


def split_field(msg: Message, src: str, sep: str, dests: Sequence[str]) -> None:
    """Split the value at ``src`` on ``sep`` and write each piece to the matching path in ``dests``
    (Corepoint ``ItemSplit``).

    Positional: piece *i* goes to ``dests[i]``. Fewer pieces than destinations clears the trailing
    ``dests`` (written empty); extra pieces beyond ``dests`` are dropped. An absent ``src`` clears every
    destination. Pieces of a component or subcomponent ``src`` are decoded data, so each is written as
    data at every destination level, as :func:`copy_field` does (ADR 0206). A whole-field ``src`` is
    split as raw text, and each piece is written as :func:`copy_field` writes a whole-field
    ``src``."""
    write = _writer(msg, src)
    parts = (msg.field(src) or "").split(sep)
    for i, dest in enumerate(dests):
        write(dest, parts[i] if i < len(parts) else "")


def code_lookup(
    msg: Message, path: str, table: Mapping[str, object], *, default: object = _UNSET
) -> None:
    """Translate the value at ``path`` through ``table`` in place (Corepoint ``ItemCodeLookup``).

    ``table`` is any read-only mapping — pass a captured
    :class:`~messagefoundry.config.code_sets.CodeSet` (``GENDER = code_set("gender")``, which *is* a
    ``Mapping``) or a literal ``dict``. Keeping the table an **explicit argument** is what makes this
    helper pure and I/O-free: it never loads a code-set file itself, so the reliability invariant (ADR
    0076 §2) is untouched — a re-run reads the same in-memory table and re-derives the same value.

    On a hit, ``path`` is set to ``str(table[value])``. On a miss, ``path`` is set to ``str(default)``
    when a ``default`` is supplied, else left unchanged (mirroring ``CodeSet.get``/``dict.get``)."""
    value = msg.field(path)
    if value is not None and value in table:
        translated: object = table[value]
    elif default is not _UNSET:
        translated = default
    else:
        return
    msg.set(path, str(translated))


def trim_field(msg: Message, path: str) -> None:
    """Strip leading/trailing whitespace from the value at ``path`` (Corepoint ``ItemConvert`` trim).

    Whitespace is read from the **decoded** value, at the start of its first leaf and the end of its
    last, so a whole-field or component path keeps its structure. An escape sequence wholly inside
    the stripped whitespace, such as a trailing ``\\.br\\``, goes with it, and one the strip cuts,
    such as a leading ``\\X2041\\`` (a space and an ``A``), is written as the data it keeps, or kept
    whole, as sent, when that data holds a CR or LF. Every
    other escape is kept as sent rather than decoded and written back (BACKLOG #5928), and one that
    decodes to nothing, such as ``\\.fi\\``, is kept wherever it sits unless the leaf is left empty.
    A no-op where a read of ``path`` returns ``None``, as it does for field 1 or 2 of an absent
    ``BHS`` or ``FHS``. Otherwise raises :class:`ValueError` on field 1 or 2 of ``MSH``, ``BHS`` or
    ``FHS``."""
    if msg.field(path) is None:
        return
    _edit_value(msg, path, _trim_value, scope="value")


def substring_field(msg: Message, path: str, start: int, end: int | None = None) -> None:
    """Replace the value at ``path`` with its ``[start:end]`` slice (Corepoint ``ItemConvert`` substring).

    ``start``/``end`` index the **decoded** field value with ordinary Python slice semantics (negatives
    count from the end; ``end=None`` runs to the end), so an escape sequence counts as the characters
    it decodes to, and one wholly inside the slice is kept as sent. An escape that decodes to nothing,
    such as ``\\.fi\\``, is kept wherever it sits. A no-op on an absent field. The value must be one
    leaf: a field or component holding a component, repetition or subcomponent separator raises
    :class:`ValueError`, since a slice of it has no single meaning, so address the part to cut
    instead (``PID-5.1``). It also raises on field 1 or 2 of ``MSH``, ``BHS`` or ``FHS``, and on a
    slice that cuts an escape such as ``\\.sp2\\`` so that a bare CR or LF would remain."""

    def cut(raw: str, seps: _Seps) -> str:
        leaf = _Leaf(raw, seps)
        lo, hi, _step = slice(start, end).indices(leaf.total)
        hi = max(lo, hi)
        # The cut removes text; an escape outside the slice that decodes to nothing stays, unless
        # nothing is left for it to apply to.
        if lo == hi:
            return ""
        return leaf.keep(lo, hi)

    _edit_value(msg, path, cut, scope="leaf")


def pad_field(
    msg: Message, path: str, width: int, *, fill: str = "0", side: Literal["left", "right"] = "left"
) -> None:
    """Pad the value at ``path`` to ``width`` with ``fill`` on ``side`` (Corepoint ``ItemConvert`` pad).

    ``side="left"`` right-justifies (e.g. zero-pad an MRN); ``side="right"`` left-justifies. ``width``
    counts the **decoded** value, so an escape sequence counts as the characters it decodes to, and
    ``fill`` is written as data: a ``fill`` of ``^`` pads with an escaped ``^``, never a new
    component. A value already ``>= width`` is left unchanged. A no-op on an absent field. Raises
    :class:`ValueError` on an unknown ``side`` (fail loud rather than silently leaving the value),
    whether or not the field is present; and, once the value is read, on a ``fill`` holding a CR or
    LF that padding would write, on field 1 or 2 of ``MSH``, ``BHS`` or ``FHS``, and on a field or
    component holding a component, repetition or subcomponent separator, as :func:`substring_field`
    does."""
    if side not in ("left", "right"):
        raise ValueError(f"pad_field side must be 'left' or 'right', got {side!r}")

    def pad(raw: str, seps: _Seps) -> str:
        leaf = _Leaf(raw, seps)
        # rjust refuses a fill that is not one character even when nothing needs padding, as the
        # old value.rjust(width, fill) did.
        padding = "".rjust(width - leaf.total, fill)
        if not padding:
            return raw
        # Rebuilt rather than ``raw``, so an unclosed trailing escape cannot pair with the filler.
        body = leaf.keep(0, leaf.total)
        filler = _escape_data(padding, seps)
        return filler + body if side == "left" else body + filler

    _edit_value(msg, path, pad, scope="leaf")


def replace_literal(msg: Message, path: str, old: str, new: str) -> None:
    """Replace every literal occurrence of ``old`` with ``new`` at ``path`` (Corepoint ``ItemReplace``
    find/replace).

    Literal substring replacement with :meth:`str.replace` semantics — **not** a regex, so the result
    is deterministic and carries no pattern mini-language (which would drift toward the declined
    declarative layer, ADR 0106 §7). It matches each leaf's **decoded** text on its own, so a
    whole-field path keeps its structure. An ``old`` holding a component, repetition or subcomponent
    separator matches only an escaped one inside a leaf, never across two leaves, and text inside an
    escape sequence is never matched as if it were data. ``new`` is written as data, as
    :meth:`~messagefoundry.parsing.message.Message.set_data` writes it (ADR 0206), so a ``new``
    holding ``^`` cannot create a component. ``old`` is decoded text too, so to replace a line break
    sent as ``\\.br\\``, pass ``"\\r"``, never the escape's spelling. A no-op on an absent field or
    when nothing matches. Raises :class:`ValueError` on field 1 or 2 of ``MSH``, ``BHS`` or ``FHS``,
    on a ``new`` holding a CR or LF once a match would write it, and on a match that cuts an escape
    such as ``\\.sp2\\`` so that a bare CR or LF would remain. An escape that decodes to nothing,
    such as ``\\.fi\\``, is kept even inside a match, just before ``new``, unless the leaf is left
    empty."""
    _edit_value(msg, path, lambda raw, seps: _replace_leaf(raw, old, new, seps), scope="leaves")


def arith_field(
    msg: Message,
    path: str,
    op: Literal["+", "-", "*", "/"],
    operand: float,
    *,
    ndigits: int | None = None,
) -> None:
    """Apply a bounded arithmetic operation to the numeric value at ``path`` (Corepoint ``ItemExpr``).

    Reads the field as a number, applies ``op`` — one of ``"+"`` / ``"-"`` / ``"*"`` / ``"/"`` — with the
    scalar ``operand``, rounds via :func:`round` (banker's rounding: to an integer when ``ndigits`` is
    ``None``, else to ``ndigits`` decimal places), and writes the result back. The common use is unit
    conversion (``op="*"``, e.g. kg→lb with ``operand=2.20462``, ``ndigits=1``).

    ``op`` is validated against the closed set above with an explicit ``if``/``elif`` chain and raises
    :class:`ValueError` on anything else — it is deliberately **not** an expression string / ``eval`` /
    operator-table lookup, so there is no mini-language and no non-deterministic drift; the arithmetic is
    IEEE-754-deterministic, so the reliability invariant holds. A no-op on an absent/empty field. A
    non-numeric value raises :class:`ValueError`, and division by zero raises :class:`ValueError` — route
    either to the error/dead-letter path (Corepoint's *Abort* error action)."""
    value = msg.field(path)
    if not value:
        return
    number = float(value)
    if op == "+":
        result = number + operand
    elif op == "-":
        result = number - operand
    elif op == "*":
        result = number * operand
    elif op == "/":
        if operand == 0:
            raise ValueError("arith_field division by zero")
        result = number / operand
    else:
        raise ValueError(f"arith_field op must be '+', '-', '*', or '/', got {op!r}")
    msg.set(path, str(round(result) if ndigits is None else round(result, ndigits)))


def date_diff_field(
    msg: Message,
    start_path: str,
    end_path: str,
    dst: str,
    *,
    unit: Literal["days", "years", "hours", "minutes"] = "days",
) -> None:
    """Write the whole-number interval between two message timestamps to ``dst`` (Corepoint ``ItemDiffDate``).

    Parses the tolerant HL7 v2 timestamps at ``start_path`` and ``end_path`` (via
    :func:`~messagefoundry.timezone.parse_hl7_timestamp`) and writes ``end - start`` — length-of-stay
    (``PV1-45`` − ``PV1-44``) or age-at-event (event − ``PID-7``). ``unit`` is ``"days"`` (default),
    ``"years"`` (whole calendar years), ``"hours"``, or ``"minutes"``.

    A whole-field path reads the field's **first component**, so a composite ``TS`` such as
    ``20260101120000^S`` (HL7 v2.3's time plus degree of precision) reads as its time; when that
    component is empty its whole first repetition is read, as :meth:`Message.age` reads the whole
    field, so ``^D`` raises as an unparseable timestamp. A degree-of-precision code coarser than the time is
    the precision the time holds, so ``198807050000^D`` is read as the date ``19880705``; a
    component path reads only the component it names, with no code. A whole field raises
    :class:`ValueError` when component 2 holds anything but a degree-of-precision code no finer than
    its time, or a later component is not empty (``20260101^S`` and a range ``20260101^20260201``
    both raise); trailing empty components, and trailing empty subcomponents after the time's own
    component, are ignored, so ``20260101^&`` reads as ``20260101`` (a subcomponent separator in
    the time's own component, ``20260101&``, still raises). Once both fields are present, either path
    raises when its field holds more than one repetition, ignoring trailing ones that hold nothing
    but component or subcomponent separators, so
    ``~20270101`` and ``20260101~~20270101`` raise and ``20260101~`` reads as ``20260101``: a
    timestamp field holds one value.

    Every ``±HHMM`` offset present is validated. ``"years"`` counts on each stamp's own stated date,
    as an age does (a birthday is a local date), offsets or not. ``"days"``, ``"hours"`` and
    ``"minutes"`` take two date-only stamps as their calendar difference; otherwise, when **both**
    carry an offset they are compared as UTC instants. When only one does, :class:`ValueError` is
    raised if the other has a time of day (there is no instant to compare it with); if the other is
    date-only, a date of birth beside an event time say, both are read as the dates and wall clocks
    they state, the calendar count, as ``"years"`` reads it. When neither carries an offset they are
    read as the wall clocks they state, so a span that crosses a daylight-saving change is an hour
    off: use :func:`~messagefoundry.timezone.length_of_stay` with a ``zone`` where that matters. The
    interval is **truncated toward zero** in every unit, so swapping the two fields negates it: an
    end 12 hours before the start is ``0`` days, not ``-1``, and a span a day short of a year either
    way is ``0`` years.

    **Field-to-field only** — it never reads the wall clock, so a re-run re-derives an identical value
    (the at-least-once invariant holds; now-relative age stays native Python by design). A no-op if
    either field is absent/empty; a value that does not parse as an HL7 timestamp, an offset out of
    range on either stamp, or a UTC instant outside years 1 to 9999 raises :class:`ValueError` (route
    it to the error/dead-letter path); an unknown ``unit`` raises :class:`ValueError`, whether or
    not the fields are present."""
    if unit not in ("days", "years", "hours", "minutes"):
        raise ValueError(
            f"date_diff_field unit must be 'days', 'years', 'hours', or 'minutes', got {unit!r}"
        )
    fields = {path: msg.repetitions(_whole_field(path)) for path in (start_path, end_path)}
    if not all(fields.values()):
        return
    for path, reps in fields.items():
        if _held_repetitions(reps, _seps(msg)) > 1:
            raise ValueError(
                f"date_diff_field: {_whole_field(path)} repeats; a timestamp field holds one value"
            )
    start_raw = _timestamp_value(msg, start_path)
    end_raw = _timestamp_value(msg, end_path)
    if not start_raw or not end_raw:
        return
    start_dt, start_prec, start_off = parse_hl7_timestamp(start_raw)
    end_dt, end_prec, end_off = parse_hl7_timestamp(end_raw)
    start_dt, start_prec = _check_ts_field(msg, start_path, start_dt, start_prec)
    end_dt, end_prec = _check_ts_field(msg, end_path, end_dt, end_prec)
    start_shift = None if start_off is None else _offset_shift(start_off)
    end_shift = None if end_off is None else _offset_shift(end_off)
    both_dates = start_prec not in _TIME_PRECISIONS and end_prec not in _TIME_PRECISIONS
    if unit != "years" and not both_dates:
        if start_shift is not None and end_shift is not None:
            try:
                start_dt, end_dt = start_dt - start_shift, end_dt - end_shift
            except OverflowError as exc:
                raise ValueError(
                    "date_diff_field: a timestamp falls outside years 1 to 9999 in UTC"
                ) from exc
        elif (start_shift is None) != (end_shift is None) and (
            start_prec if start_shift is None else end_prec
        ) in _TIME_PRECISIONS:
            raise ValueError(
                f"date_diff_field: only one of {start_path} and {end_path} carries an offset, and "
                "the other has a time of day, so the two cannot be compared as instants"
            )
    # Count forwards from the earlier stamp and apply the sign last, so every unit truncates toward
    # zero and a swapped pair is the exact negation (BACKLOG #5822).
    sign = -1 if end_dt < start_dt else 1
    early, late = (end_dt, start_dt) if sign < 0 else (start_dt, end_dt)
    delta = late - early
    if unit == "days":
        interval = delta.days
    elif unit == "hours":
        interval = delta // timedelta(hours=1)
    elif unit == "minutes":
        interval = delta // timedelta(minutes=1)
    else:  # "years": whole calendar years, one fewer while the anniversary is still ahead
        interval = late.year - early.year - ((late.month, late.day) < (early.month, early.day))
    msg.set(dst, str(sign * interval))


def _offset_shift(offset: str) -> timedelta:
    """An HL7 ``±HHMM`` offset as a :class:`timedelta`, refusing minutes of 60 or more (the shared
    parser's rule) and a magnitude of a day or more, which no zone has."""
    shift = _offset_to_timedelta(offset)
    if abs(shift) >= timedelta(days=1):
        raise ValueError(f"HL7 timestamp offset is out of range: {offset!r}")
    return shift


def _whole_field(path: str) -> str:
    seg, fld, _comp, _sub = parse_path(path)
    return f"{seg}-{fld}"


def _held_repetitions(reps: list[str | None], seps: _Seps) -> int:
    """How many repetitions count, ignoring trailing ones that hold nothing but separators."""
    empty = seps[1] + seps[3]
    count = len(reps)
    while count and not (reps[count - 1] or "").strip(empty):
        count -= 1
    return count


def _timestamp_value(msg: Message, path: str) -> str | None:
    """The timestamp text at ``path``: a component path as read; a whole field's first component,
    so a composite ``TS`` (``time^degree-of-precision``) parses rather than being refused whole,
    falling back to the first repetition's whole text when that is empty, as :meth:`Message.age`
    falls back to the whole field."""
    if parse_path(path)[2] is not None:
        return msg.field(path)
    return msg.field(f"{path}.1") or msg.field(path, repetition=1)


#: HL7 v2.3 ``TS`` degree-of-precision codes (component 2), as :func:`parse_hl7_timestamp`'s tokens.
_DEGREE_OF_PRECISION = {
    "Y": "year",
    "L": "month",
    "D": "day",
    "H": "hour",
    "M": "minute",
    "S": "second",
}

#: :func:`parse_hl7_timestamp`'s precision tokens, coarsest first.
_PRECISIONS = tuple(_DEGREE_OF_PRECISION.values())


def _check_ts_field(
    msg: Message, path: str, stamp_dt: datetime, precision: str
) -> tuple[datetime, str]:
    """Raise unless the whole field ``path`` addresses holds one timestamp, rather than silently
    reading a part of it, and return the stamp and its precision as the field's degree-of-precision
    code states them. The caller has refused a second repetition already.

    A whole field may hold only its time plus, in component 2, a degree-of-precision code, with any
    trailing empty components, and trailing empty subcomponents after component 1, dropped
    (``20260101^`` and ``20260101^&`` read as ``20260101``, BACKLOG #5822). A range
    (``start^end``) raises, and so does a code finer than the stamp (``20260101^S``). A code
    coarser than the stamp is the precision HL7 v2.3 says the stamp holds, so ``198807050000^D`` is
    read as the date ``19880705``. A component path is returned as it is."""
    if parse_path(path)[2] is not None:
        return stamp_dt, precision
    # The raw text must be exactly the time, or the time, one separator and the code: nothing in a
    # later component, and no escape sequence, which decoding would otherwise hide (main parsed the
    # raw field, so it refused both).
    seps = _seps(msg)
    # Trailing empty subcomponents hold nothing, as trailing empty components do, so "20260101^&"
    # and "20260101^D&" drop them (BACKLOG #5822 added item 3).
    raw = (msg.field(path, repetition=1) or "").rstrip(seps[1] + seps[3])
    stamp = msg.field(f"{path}.1") or ""
    degree = msg.field(f"{path}.2")
    if degree is not None:
        degree = degree.rstrip(seps[3]) or None
    exact = (
        raw == stamp
        if degree is None
        else len(raw) == len(stamp) + 1 + len(degree)
        and raw.startswith(stamp)
        and raw.endswith(degree)
    )
    stated = precision if degree is None else _DEGREE_OF_PRECISION.get(degree)
    if not exact or stated is None or _PRECISIONS.index(stated) > _PRECISIONS.index(precision):
        raise ValueError(
            f"date_diff_field: {path} holds more than a timestamp and a degree of precision no "
            "finer than its time"
        )
    if stated == precision:
        return stamp_dt, precision
    # Keep the stated fields and reset the rest to their floor, as parse_hl7_timestamp fills them.
    keep = _PRECISIONS.index(stated)
    return (
        datetime(
            stamp_dt.year,
            stamp_dt.month if keep >= 1 else 1,
            stamp_dt.day if keep >= 2 else 1,
            stamp_dt.hour if keep >= 3 else 0,
            stamp_dt.minute if keep >= 4 else 0,
        ),
        stated,
    )


def copy_segment(
    msg: Message, segment_id: str, *, occurrence: int = 1, index: int | None = None
) -> None:
    """Duplicate an existing segment (Corepoint segment copy; maps to :meth:`Message.add_segment`).

    Reads the ``occurrence``-th (1-based) ``segment_id`` from the message and re-adds an identical
    segment. The copy is appended by default, or inserted at 1-based ``index`` among segments (``1`` =
    just after MSH). Raises :class:`KeyError` if the source segment/occurrence is absent, and
    :class:`ValueError` (from :meth:`Message.add_segment`) for an ``MSH``, ``BHS`` or ``FHS`` copy
    or an out-of-range ``index``."""
    line = _segment_line(msg, segment_id, occurrence)
    if line is None:
        where = segment_id + (f" occurrence {occurrence}" if occurrence > 1 else "")
        raise KeyError(f"cannot copy absent segment {where}")
    msg.add_segment(line, index=index)


def delete_segment(msg: Message, segment_id: str) -> int:
    """Remove every ``segment_id`` segment and return how many were removed (Corepoint segment delete).

    A named wrapper over :meth:`Message.delete_segments`; deleting ``MSH`` is refused there."""
    return msg.delete_segments(segment_id)


def _segment_line(msg: Message, segment_id: str, occurrence: int) -> str | None:
    """The raw HL7 line of the ``occurrence``-th (1-based) ``segment_id``, or None if absent.

    The occurrence resolves through :func:`~messagefoundry.parsing._builtin_hl7.segment_index`, the
    scan every ``Message`` read and write and ``Peek`` use, so a fieldless bare line is no occurrence
    here either, and a :meth:`Message.count_segments` loop copies every segment it counts (BACKLOG
    #5917). The line is read from the canonical re-encoding, which holds one line per segment in
    order, and round-trips through :meth:`Message.add_segment` byte-for-byte (same field
    separator)."""
    if occurrence < 1:
        raise ValueError("occurrence is 1-based (>= 1)")
    index = _builtin_hl7.segment_index(msg._m, segment_id, occurrence)
    if index is None:
        return None
    return msg.encode().split("\r")[index]


# --- decoded-value editing (BACKLOG #5928) -------------------------------------------------------
#
# A value read with Message.field is decoded, and writing a decoded value back loses data: ``\.br\``
# decodes to a CR, which a write refuses, and ``\H\`` decodes to "_", which writes back as "_". So
# these helpers edit the wire text instead. They split it into leaves on the message's own
# separators and each leaf into literal runs and escape sequences, transform what the decoded value
# calls for, and keep every escape they do not cut as sent. The result goes back as the whole
# field's raw text, which Message.set takes as the structure it already is.

#: Separators in the ``_builtin_hl7`` order, ``(field, component, repetition, subcomponent, escape)``.
_Seps = tuple[str, str, str, str, str]

#: One piece of a leaf: its raw text, what it decodes to, and its kind. ``"lit"`` is literal text
#: (raw and decoded are equal and hold no escape character); ``"esc"`` is one closed escape sequence;
#: ``"open"`` is a trailing escape character no second one closes, which decodes to itself.
_Unit = tuple[str, str, Literal["lit", "esc", "open"]]


def _seps(msg: Message) -> _Seps:
    """The separators a :meth:`Message.field` read decodes a value with: the first header line's,
    which are a ``BHS`` or ``FHS`` header's in a batch, so an edit decodes a value as a read of it
    does (BACKLOG #5928). :meth:`Message.set` and the repetition split of a read use the same set
    (BACKLOG #5972); this keeps the parser's tuple order."""
    return _builtin_hl7.separators(msg._m)


def _refuse_delimiter_field(seg: str, fld: int, path: str) -> None:
    if _builtin_hl7.is_delimiter_field(seg, fld):
        raise ValueError(f"cannot transform {path}: fields 1 and 2 hold the delimiters themselves")


def _splice_part(text: str, comp: int, sub: int | None, part: str, seps: _Seps) -> str:
    """The field text ``text`` with the first repetition's component ``comp`` (or its subcomponent
    ``sub``) replaced by the raw text ``part``, padding absent ones as :meth:`Message.set` does."""
    _field_sep, comp_sep, rep_sep, sub_sep, _esc = seps
    reps = text.split(rep_sep) if text else [""]
    comps = reps[0].split(comp_sep) if reps[0] else []
    comps += [""] * (comp - len(comps))
    if sub is None:
        comps[comp - 1] = part
    else:
        subs = comps[comp - 1].split(sub_sep) if comps[comp - 1] else []
        subs += [""] * (sub - len(subs))
        subs[sub - 1] = part
        comps[comp - 1] = sub_sep.join(subs)
    reps[0] = comp_sep.join(comps)
    return rep_sep.join(reps)


def _as_one_leaf(raw: str, seps: _Seps) -> str:
    """A whole field's raw text as one leaf's raw text that reads back as the field's leaves, each
    decoded, joined by its separators read as data. An escape sequence is kept as sent unless it
    holds a control character: a component write never carries a raw control (ADR 0205 rule 2), and
    a hex escape cannot sit inside another sequence, so such a sequence is written as the data it
    decodes to, or, where that holds a CR or LF, which no component carries, as its raw text
    written as data, so it reads back as sent. Literal text, the separators between leaves and an
    unclosed trailing escape character are written as data, with their control characters
    hex-escaped."""
    out: list[str] = []
    for index, token in enumerate(_split_leaves(raw, seps)):
        if index % 2:
            out.append(_escape_data(token, seps))
            continue
        for unit_raw, decoded, kind in _leaf_units(token, seps):
            if kind == "esc" and not any(ch in unit_raw for ch in _HEX_ESCAPED_CONTROLS):
                out.append(unit_raw)
            elif kind == "esc" and ("\r" in decoded or "\n" in decoded):
                out.append(_escape_data(unit_raw, seps))
            else:
                out.append(_escape_data(decoded, seps))
    return "".join(out)


def _edit_value(
    msg: Message,
    path: str,
    edit: Callable[[str, _Seps], str],
    *,
    scope: Literal["leaf", "leaves", "value"],
) -> None:
    """Apply ``edit`` to the raw text of the value at ``path`` and write the field back.

    The value is the part a :meth:`Message.field` read of ``path`` returns, from the first repetition
    for a component or subcomponent path. With ``scope="leaf"`` the value must be one leaf, and
    ``edit`` gets it whole. With ``"leaves"`` ``edit`` gets each leaf in turn, and the separators
    between them are kept. With ``"value"`` ``edit`` gets the whole value, separators and all, and
    :func:`_split_leaves` finds its leaves. A no-op when the value is absent or empty, or when
    nothing changed."""
    seg, fld, comp, sub = parse_path(path)
    _refuse_delimiter_field(seg, fld, path)
    seps = _seps(msg)
    _field_sep, comp_sep, rep_sep, sub_sep, _esc = seps
    whole = f"{seg}-{fld}"
    text = msg.field(whole)
    if not text:
        return
    # The read side's own split: the first repetition, then the component, then the subcomponent.
    reps = text.split(rep_sep)
    comps = reps[0].split(comp_sep)
    splitters: tuple[str, ...]
    if comp is None:
        value, splitters = text, (rep_sep, comp_sep, sub_sep)
    elif comp > len(comps):
        return
    elif sub is None:
        value, splitters = comps[comp - 1], (sub_sep,)
    else:
        subs = comps[comp - 1].split(sub_sep)
        if sub > len(subs):
            return
        value, splitters = subs[sub - 1], ()
    if not value:
        return
    if scope == "leaf":
        held = [sep for sep in (comp_sep, rep_sep, sub_sep) if sep in value]
        if held:
            raise ValueError(
                f"cannot transform {path} as one value: it holds the separator {held[0]!r}; "
                "address one component or subcomponent instead"
            )
        if not _builtin_hl7.unescape(value, seps):
            return  # decodes to nothing, so a read of it is None: nothing to cut or pad
        edited = edit(value, seps)
    elif scope == "value":
        edited = edit(value, seps)
    else:
        edited = _map_leaves(value, splitters, lambda leaf: edit(leaf, seps))
    if edited == value:
        return
    msg.set(whole, edited if comp is None else _splice_part(text, comp, sub, edited, seps))


def _map_leaves(text: str, splitters: tuple[str, ...], edit: Callable[[str], str]) -> str:
    """``text`` with ``edit`` applied to each leaf, split on ``splitters`` outermost first."""
    if not splitters:
        return edit(text)
    return splitters[0].join(
        _map_leaves(part, splitters[1:], edit) for part in text.split(splitters[0])
    )


def _split_leaves(value: str, seps: _Seps) -> list[str]:
    """``value``'s leaves with the separators between them, ``[leaf, sep, leaf, ...]``.

    A value read at any level holds only the separators below that level, so splitting on all
    three finds its leaves wherever it was read from."""
    _field_sep, comp_sep, rep_sep, sub_sep, _esc = seps
    tokens: list[str] = []
    start = 0
    for pos, char in enumerate(value):
        if char in (comp_sep, rep_sep, sub_sep):
            tokens += [value[start:pos], char]
            start = pos + 1
    tokens.append(value[start:])
    return tokens


def _trim_value(value: str, seps: _Seps) -> str:
    """``value`` with the decoded whitespace at the start of its first leaf and the end of its
    last stripped, as :meth:`str.strip` strips the decoded value: a separator is not whitespace, so
    the strip stops at the first leaf that holds anything else."""
    tokens = _split_leaves(value, seps)
    tokens[0] = _strip_leaf(tokens[0], seps, left=True, right=len(tokens) == 1)
    if len(tokens) > 1:
        tokens[-1] = _strip_leaf(tokens[-1], seps, left=False, right=True)
    return "".join(tokens)


def _strip_leaf(raw: str, seps: _Seps, *, left: bool, right: bool) -> str:
    """One leaf with its decoded whitespace stripped at the ends asked for, as :meth:`str.strip`
    strips the decoded leaf. An escape sequence the strip cuts, such as ``\\X2041\\`` (a space and
    an ``A``), is written as the data it keeps, so ``\\X2041\\`` at the start becomes ``A``, unless
    that data holds a CR or LF, which no data write carries: that sequence is kept whole, as sent."""
    leaf = _Leaf(raw, seps)
    decoded = _decoded(leaf.units)
    lo = len(decoded) - len(decoded.lstrip()) if left else 0
    hi = len(decoded.rstrip()) if right else leaf.total
    for (_raw, unit_text, kind), unit_lo, unit_hi in zip(
        leaf.units, leaf.los, leaf.his, strict=True
    ):
        cut = unit_lo < lo < unit_hi or unit_lo < hi < unit_hi
        kept = unit_text[max(lo, unit_lo) - unit_lo : min(hi, unit_hi) - unit_lo]
        if kind == "esc" and cut and ("\r" in kept or "\n" in kept):
            lo, hi = min(lo, unit_lo), max(hi, unit_hi)
    if (lo, hi) == (0, leaf.total):
        return raw
    if lo >= hi:
        return ""
    return leaf.keep(lo, hi)


def _append_after_last_leaf(value: str, suffix: str, seps: _Seps) -> str:
    """``value`` with ``suffix`` written as data after its last leaf, which is rebuilt so an
    unclosed trailing escape cannot pair with the suffix."""
    tokens = _split_leaves(value, seps)
    leaf = _Leaf(tokens[-1], seps)
    tokens[-1] = leaf.keep(0, leaf.total) + _escape_data(suffix, seps)
    return "".join(tokens)


def _leaf_units(raw: str, seps: _Seps) -> list[_Unit]:
    """Split one leaf's raw text into literal runs and escape sequences, as ``unescape`` walks it."""
    esc = seps[4]
    units: list[_Unit] = []
    pos = 0
    while pos < len(raw):
        opener = raw.find(esc, pos)
        if opener == -1:
            units.append((raw[pos:], raw[pos:], "lit"))
            break
        if opener > pos:
            units.append((raw[pos:opener], raw[pos:opener], "lit"))
        closer = raw.find(esc, opener + 1)
        if closer == -1:
            units.append((raw[opener:], raw[opener:], "open"))
            break
        sequence = raw[opener : closer + 1]
        units.append((sequence, _builtin_hl7.unescape(sequence, seps), "esc"))
        pos = closer + 1
    return units


def _decoded(units: Sequence[_Unit]) -> str:
    return "".join(decoded for _raw, decoded, _kind in units)


def _refuse_crlf(value: str) -> None:
    """Refuse a CR or LF in text written as data, as :meth:`Message.set` refuses it."""
    if "\r" in value or "\n" in value:
        raise ValueError("HL7 field value may not contain a segment separator (CR/LF)")


def _escape_data(text: str, seps: _Seps) -> str:
    """The raw form of a leaf that decodes to ``text``: the delimiters and controls escaped by the
    one leaf escaper. A CR or LF, which here only a cut-up escape such as ``\\.sp2\\`` yields, is
    refused, as every leaf write refuses it (ADR 0205 rule 2)."""
    _refuse_crlf(text)
    return _builtin_hl7.escape_leaf(text, seps)


class _Leaf:
    """One leaf's units with each unit's decoded offsets, so a range finds its units by bisection
    and a pass over many ranges stays linear in the leaf."""

    def __init__(self, raw: str, seps: _Seps) -> None:
        self.raw = raw
        self.seps = seps
        self.units = _leaf_units(raw, seps)
        self.los: list[int] = []
        self.his: list[int] = []
        pos = 0
        for _raw, decoded, _kind in self.units:
            self.los.append(pos)
            pos += len(decoded)
            self.his.append(pos)
        self.total = pos

    def span(self, start: int, end: int) -> str:
        """Raw text that decodes to ``decoded[start:end]``, with the escapes that decode to nothing
        and start inside the range.

        A literal run is cut as it is, and an escape sequence wholly inside the range is kept as
        sent. An escape the range cuts, and an unclosed trailing escape character, are written as
        escaped data, so text placed after them cannot pair with them."""
        out: list[str] = []
        index = bisect_left(self.los, start)
        if index > 0 and self.his[index - 1] > start:
            index -= 1  # the unit that straddles ``start``
        while index < len(self.units) and self.los[index] < end:
            raw, decoded, kind = self.units[index]
            lo, hi = self.los[index], self.his[index]
            index += 1
            cut_lo, cut_hi = max(lo, start), min(hi, end)
            if lo == hi or (kind == "esc" and (cut_lo, cut_hi) == (lo, hi)):
                out.append(raw)
            elif kind == "lit":
                out.append(raw[cut_lo - lo : cut_hi - lo])
            else:
                out.append(_escape_data(decoded[cut_lo - lo : cut_hi - lo], self.seps))
        return "".join(out)

    def keep(self, start: int, end: int) -> str:
        """Raw text that decodes to ``decoded[start:end]``, with every escape that decodes to
        nothing kept wherever it sits. ``keep(0, total)`` is the leaf rebuilt, so an unclosed
        trailing escape is written as data and text placed after it cannot pair with it."""
        return (
            self.zero_width(0, start) + self.span(start, end) + self.zero_width(end, self.total + 1)
        )

    def zero_width(self, start: int, end: int) -> str:
        """The escapes that decode to nothing and start in ``[start, end)``, as sent. A cut or a
        match removes text, and these carry none (``\\.fi\\``, a ``\\C..\\`` charset switch), so
        they are kept wherever they sit."""
        out: list[str] = []
        index = bisect_left(self.los, start)
        while index < len(self.units) and self.los[index] < end:
            if self.los[index] == self.his[index]:
                out.append(self.units[index][0])
            index += 1
        return "".join(out)


def _case_leaf(
    raw: str, convert: Callable[[str, bool], str], seps: _Seps, *, utf8_hex: bool
) -> str:
    """One leaf with its literal text cased by ``convert`` and its escape sequences kept as sent.

    ``convert`` also gets whether the character before the run is cased, which title case needs at
    the start of a run. That character is the last one a unit decodes to. ``unescape`` decodes a
    hex escape one byte to one character (ADR 0205, *The hex escape's meaning*), so the last byte
    of a UTF-8 letter, such as the ``A9`` of ``\\XC3A9\\`` (e-acute), would read as a character
    of its own, cased or not by accident. With ``utf8_hex``, which the caller sets from ``MSH-18``,
    the last bytes of a run of adjacent hex escapes are read as UTF-8 where they end in a valid
    UTF-8 character instead. This departs from the ADR's reading only for the word-start test: the
    escapes are kept as sent, and a read of the value is unchanged."""
    out: list[str] = []
    after_cased = False
    hex_tail = b""  # the last bytes of the current run of adjacent hex escapes
    for unit_raw, decoded, kind in _leaf_units(raw, seps):
        if kind == "esc":
            out.append(unit_raw)
        else:
            cased = convert(decoded, after_cased)
            out.append(unit_raw if cased == decoded else _escape_data(cased, seps))
        last = decoded[-1:]
        if utf8_hex and kind == "esc" and unit_raw[1:2] == "X" and decoded:
            # unescape's hex output is U+0000 to U+00FF, so latin-1 gives back the bytes sent.
            hex_tail = (hex_tail + decoded[-4:].encode("latin-1"))[-4:]
            last = _last_utf8_char(hex_tail) or last
        else:
            hex_tail = b""  # any other unit, one that decodes to nothing included, ends the run
        if last:
            # str.title's own test: a following "a" stays lower case only after a cased character.
            after_cased = (last + "a").title()[-1] == "a"
    return "".join(out)


def _last_utf8_char(data: bytes) -> str | None:
    """The character ``data``'s last bytes encode in UTF-8, or ``None`` where they end in none."""
    # ``data`` may start inside a character, which decodes to replacement characters before it.
    last = data.decode("utf-8", "replace")[-1:]
    return None if last in ("", "\ufffd") else last


def _replace_leaf(raw: str, old: str, new: str, seps: _Seps) -> str:
    """One leaf with each non-overlapping ``old`` in its decoded text replaced by ``new`` as data,
    left to right as :meth:`str.replace` does, an empty ``old`` included."""
    leaf = _Leaf(raw, seps)
    decoded = _decoded(leaf.units)
    if old not in decoded:
        return raw
    starts: list[int] = []
    if old:
        found = decoded.find(old)
        while found != -1:
            starts.append(found)
            found = decoded.find(old, found + len(old))
    else:
        starts = list(range(leaf.total + 1))
    replacement = _escape_data(new, seps)
    out: list[str] = []
    prev = 0
    for found in starts:
        out.append(leaf.span(prev, found))
        # A match removes text; an escape inside it that decodes to nothing stays, before ``new``.
        out.append(leaf.zero_width(found, found + len(old)))
        out.append(replacement)
        prev = found + len(old)
    out.append(leaf.span(prev, leaf.total))
    out.append(leaf.zero_width(leaf.total, leaf.total + 1))
    if not new and old and len(starts) * len(old) == leaf.total:
        return ""  # every character went, so the escapes that decode to nothing go with them
    return "".join(out)
