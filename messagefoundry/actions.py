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

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Literal

from messagefoundry.parsing import _builtin_hl7
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import parse_path
from messagefoundry.timezone import parse_hl7_timestamp

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
    or subcomponent, whose read is decoded (ADR 0206 rule 1), otherwise :meth:`Message.set`, which
    takes a whole field's raw text as the structure it already is."""
    return msg.set_data if parse_path(src)[2] is not None else msg.set


def copy_field(msg: Message, src: str, dst: str) -> None:
    """Copy the value at ``src`` into ``dst`` (Corepoint ``ItemCopy``).

    An absent/empty ``src`` copies an empty value (clearing ``dst``). A component or subcomponent
    ``src`` is read decoded, so it is written as data at every ``dst`` level, a whole field included:
    a value carrying a ``^``, ``~`` or ``&`` rides across as data, not new structure (ADR 0206). A
    whole-field ``src`` is raw text, structure and all, and is copied as it is."""
    _writer(msg, src)(dst, msg.field(src) or "")


def set_field(msg: Message, path: str, value: str) -> None:
    """Set ``path`` to ``value`` (Corepoint ``ItemReplace``) — a named wrapper over :meth:`Message.set`."""
    msg.set(path, value)


def append_to_field(msg: Message, path: str, suffix: str) -> None:
    """Append ``suffix`` to the current value at ``path`` (Corepoint ``ItemAppend``).

    An absent field is treated as empty, so the result is just ``suffix``."""
    msg.set(path, (msg.field(path) or "") + suffix)


def convert_case(msg: Message, path: str, mode: Literal["upper", "lower", "title"]) -> None:
    """Upper/lower/title-case the value at ``path`` in place (Corepoint ``ItemConvert``/``ItemFormat``).

    ``mode`` is one of ``"upper"`` / ``"lower"`` / ``"title"``. Each leaf of the value is cased on
    its own, so a whole-field path keeps its components, repetitions and subcomponents. Only the
    literal text is cased: an escape sequence such as ``\\.br\\`` or ``\\S\\`` is kept as sent, and so
    is the text a hex escape carries, though title case still reads what an escape decodes to when
    it decides whether the next letter starts a word. A no-op on an absent field; raises
    :class:`ValueError` on an unknown mode (fail loud rather than silently leaving the value), or on
    ``MSH-1`` or ``MSH-2``, which hold the delimiters themselves."""
    convert = _CASE_CONVERTERS.get(mode)
    if convert is None:
        raise ValueError(f"convert_case mode must be 'upper', 'lower', or 'title', got {mode!r}")
    _edit_value(msg, path, lambda raw, seps: _case_leaf(raw, convert, seps), whole_value=False)


# Each converter also takes whether the decoded character before the run is cased. Only title case
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
    data at every destination level, as :func:`copy_field` does (ADR 0206)."""
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

    A no-op on an absent field; the trimmed value re-encodes structurally."""
    value = msg.field(path)
    if value is None:
        return
    msg.set(path, value.strip())


def substring_field(msg: Message, path: str, start: int, end: int | None = None) -> None:
    """Replace the value at ``path`` with its ``[start:end]`` slice (Corepoint ``ItemConvert`` substring).

    ``start``/``end`` index the **decoded** field value with ordinary Python slice semantics (negatives
    count from the end; ``end=None`` runs to the end), so an escape sequence counts as the characters
    it decodes to, and one wholly inside the slice is kept as sent. A no-op on an absent field. The
    value must be one leaf: a field or component holding a component, repetition or subcomponent
    separator raises :class:`ValueError`, since a slice of it has no single meaning, so address the
    part to cut instead (``PID-5.1``). ``MSH-1`` and ``MSH-2`` raise :class:`ValueError` too."""

    def cut(raw: str, seps: _Seps) -> str:
        units = _leaf_units(raw, seps)
        total = len(_decoded(units))
        lo, hi, _step = slice(start, end).indices(total)
        return _span(units, lo, max(lo, hi), total, seps)

    _edit_value(msg, path, cut, whole_value=True)


def pad_field(
    msg: Message, path: str, width: int, *, fill: str = "0", side: Literal["left", "right"] = "left"
) -> None:
    """Pad the value at ``path`` to ``width`` with ``fill`` on ``side`` (Corepoint ``ItemConvert`` pad).

    ``side="left"`` right-justifies (e.g. zero-pad an MRN); ``side="right"`` left-justifies. ``width``
    counts the **decoded** value, so an escape sequence counts as the characters it decodes to, and
    ``fill`` is written as data: a ``fill`` of ``^`` pads with an escaped ``^``, never a new
    component. A value already ``>= width`` is left unchanged. A no-op on an absent field. Raises
    :class:`ValueError` on an unknown ``side`` (fail loud rather than silently leaving the value), on
    a ``fill`` holding a CR or LF, on ``MSH-1`` or ``MSH-2``, and on a field or component holding a
    component, repetition or subcomponent separator, as :func:`substring_field` does."""
    if side not in ("left", "right"):
        raise ValueError(f"pad_field side must be 'left' or 'right', got {side!r}")
    _refuse_crlf(fill)

    def pad(raw: str, seps: _Seps) -> str:
        units = _leaf_units(raw, seps)
        total = len(_decoded(units))
        # rjust refuses a fill that is not one character even when nothing needs padding, as the
        # old value.rjust(width, fill) did.
        padding = "".rjust(width - total, fill)
        if not padding:
            return raw
        body = _span(units, 0, total, total, seps)
        filler = _escape_data(padding, seps)
        return filler + body if side == "left" else body + filler

    _edit_value(msg, path, pad, whole_value=True)


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
    holding ``^`` cannot create a component. A no-op on an absent field. Raises :class:`ValueError`
    on a ``new`` holding a CR or LF, and on ``MSH-1`` or ``MSH-2``."""
    _refuse_crlf(new)
    _edit_value(msg, path, lambda raw, seps: _replace_leaf(raw, old, new, seps), whole_value=False)


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

    **Field-to-field only** — it never reads the wall clock, so a re-run re-derives an identical value
    (the at-least-once invariant holds; now-relative age stays native Python by design). A no-op if
    either field is absent/empty; a value that does not parse as an HL7 timestamp raises
    :class:`ValueError` (route it to the error/dead-letter path); an unknown ``unit`` raises
    :class:`ValueError`."""
    start_raw = msg.field(start_path)
    end_raw = msg.field(end_path)
    if not start_raw or not end_raw:
        return
    start_dt, _sp, _so = parse_hl7_timestamp(start_raw)
    end_dt, _ep, _eo = parse_hl7_timestamp(end_raw)
    delta = end_dt - start_dt
    if unit == "days":
        interval = delta.days
    elif unit == "hours":
        interval = int(delta.total_seconds() // 3600)
    elif unit == "minutes":
        interval = int(delta.total_seconds() // 60)
    elif unit == "years":
        interval = (
            end_dt.year
            - start_dt.year
            - ((end_dt.month, end_dt.day) < (start_dt.month, start_dt.day))
        )
    else:
        raise ValueError(
            f"date_diff_field unit must be 'days', 'years', 'hours', or 'minutes', got {unit!r}"
        )
    msg.set(dst, str(interval))


def copy_segment(
    msg: Message, segment_id: str, *, occurrence: int = 1, index: int | None = None
) -> None:
    """Duplicate an existing segment (Corepoint segment copy; maps to :meth:`Message.add_segment`).

    Reads the ``occurrence``-th (1-based) ``segment_id`` from the message and re-adds an identical
    segment. The copy is appended by default, or inserted at 1-based ``index`` among segments (``1`` =
    just after MSH). Raises :class:`KeyError` if the source segment/occurrence is absent, and
    :class:`ValueError` (from :meth:`Message.add_segment`) for an ``MSH`` copy or an out-of-range
    ``index``."""
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
#: ``Message._encoding_chars`` puts the escape before the subcomponent separator; :func:`_seps` swaps
#: them.
_Seps = tuple[str, str, str, str, str]

#: One piece of a leaf: its raw text, what it decodes to, and its kind. ``"lit"`` is literal text
#: (raw and decoded are equal and hold no escape character); ``"esc"`` is one closed escape sequence;
#: ``"open"`` is a trailing escape character no second one closes, which decodes to itself.
_Unit = tuple[str, str, Literal["lit", "esc", "open"]]


def _seps(msg: Message) -> _Seps:
    field_sep, comp_sep, rep_sep, esc, sub_sep = msg._encoding_chars()
    return field_sep, comp_sep, rep_sep, sub_sep, esc


def _edit_value(
    msg: Message, path: str, edit: Callable[[str, _Seps], str], *, whole_value: bool
) -> None:
    """Apply ``edit`` to the raw text of the value at ``path`` and write the field back.

    The value is the part a :meth:`Message.field` read of ``path`` returns, from the first repetition
    for a component or subcomponent path. With ``whole_value`` the value must be one leaf, and
    ``edit`` gets it whole. Otherwise ``edit`` gets each leaf in turn, and the separators between
    them are kept. A no-op when the value is absent or empty, or when nothing changed."""
    seg, fld, comp, sub = parse_path(path)
    if seg == "MSH" and fld in (1, 2):
        raise ValueError(f"cannot transform {path}: MSH-1 and MSH-2 hold the delimiters themselves")
    seps = _seps(msg)
    _field_sep, comp_sep, rep_sep, sub_sep, _esc = seps
    whole = f"{seg}-{fld}"
    text = msg.field(whole)
    if not text:
        return
    # The read side's own split: the first repetition, then the component, then the subcomponent.
    reps = text.split(rep_sep)
    comps = reps[0].split(comp_sep)
    subs: list[str] = []
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
    if whole_value:
        held = [sep for sep in (comp_sep, rep_sep, sub_sep) if sep in value]
        if held:
            raise ValueError(
                f"cannot transform {path} as one value: it holds the separator {held[0]!r}; "
                "address one component or subcomponent instead"
            )
        edited = edit(value, seps)
    else:
        edited = _map_leaves(value, splitters, lambda leaf: edit(leaf, seps))
    if edited == value:
        return
    if comp is None:
        new_text = edited
    else:
        if sub is None:
            comps[comp - 1] = edited
        else:
            subs[sub - 1] = edited
            comps[comp - 1] = sub_sep.join(subs)
        reps[0] = comp_sep.join(comps)
        new_text = rep_sep.join(reps)
    msg.set(whole, new_text)


def _map_leaves(text: str, splitters: tuple[str, ...], edit: Callable[[str], str]) -> str:
    """``text`` with ``edit`` applied to each leaf, split on ``splitters`` outermost first."""
    if not splitters:
        return edit(text)
    return splitters[0].join(
        _map_leaves(part, splitters[1:], edit) for part in text.split(splitters[0])
    )


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
    """The raw form of a leaf that decodes to ``text``: the delimiters and controls escaped, and a CR
    or LF, which here only a cut-up escape such as ``\\.sp2\\`` yields, as a hex escape."""
    esc = seps[4]
    escaped = _builtin_hl7.escape_leaf(text, seps)
    return escaped.replace("\r", f"{esc}X0D{esc}").replace("\n", f"{esc}X0A{esc}")


def _span(units: Sequence[_Unit], start: int, end: int, total: int, seps: _Seps) -> str:
    """Raw text that decodes to ``decoded[start:end]`` of the leaf ``units`` make up.

    A literal run is cut as it is, and an escape sequence wholly inside the range is kept as sent.
    An escape the range cuts, and an unclosed trailing escape character, are written as escaped
    data, so text placed after them cannot pair with them. An escape that decodes to nothing belongs
    to the range that starts at it, or to the range that ends the leaf."""
    out: list[str] = []
    pos = 0
    for raw, decoded, kind in units:
        lo, hi = pos, pos + len(decoded)
        pos = hi
        if lo == hi:
            if start <= lo and (lo < end or lo == end == total):
                out.append(raw)
            continue
        cut_lo, cut_hi = max(lo, start), min(hi, end)
        if cut_lo >= cut_hi:
            continue
        if kind == "lit":
            out.append(raw[cut_lo - lo : cut_hi - lo])
        elif kind == "esc" and (cut_lo, cut_hi) == (lo, hi):
            out.append(raw)
        else:
            out.append(_escape_data(decoded[cut_lo - lo : cut_hi - lo], seps))
    return "".join(out)


def _case_leaf(raw: str, convert: Callable[[str, bool], str], seps: _Seps) -> str:
    """One leaf with its literal text cased by ``convert`` and its escape sequences kept as sent.

    ``convert`` also gets whether the decoded character before the run is cased, which title case
    needs at the start of a run."""
    out: list[str] = []
    after_cased = False
    for unit_raw, decoded, kind in _leaf_units(raw, seps):
        if kind == "esc":
            out.append(unit_raw)
        else:
            cased = convert(decoded, after_cased)
            out.append(unit_raw if cased == decoded else _escape_data(cased, seps))
        if decoded:
            # str.title's own test: a following "a" stays lower case only after a cased character.
            after_cased = (decoded[-1] + "a").title()[-1] == "a"
    return "".join(out)


def _replace_leaf(raw: str, old: str, new: str, seps: _Seps) -> str:
    """One leaf with each non-overlapping ``old`` in its decoded text replaced by ``new`` as data,
    left to right as :meth:`str.replace` does, an empty ``old`` included."""
    units = _leaf_units(raw, seps)
    decoded = _decoded(units)
    if old not in decoded:
        return raw
    total = len(decoded)
    starts: list[int] = []
    if old:
        found = decoded.find(old)
        while found != -1:
            starts.append(found)
            found = decoded.find(old, found + len(old))
    else:
        starts = list(range(total + 1))
    replacement = _escape_data(new, seps)
    out: list[str] = []
    prev = 0
    for found in starts:
        out.append(_span(units, prev, found, total, seps))
        out.append(replacement)
        prev = found + len(old)
    out.append(_span(units, prev, total, total, seps))
    return "".join(out)
