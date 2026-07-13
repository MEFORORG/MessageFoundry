# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from messagefoundry.parsing.message import Message
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


def copy_field(msg: Message, src: str, dst: str) -> None:
    """Copy the value at ``src`` into ``dst`` (Corepoint ``ItemCopy``).

    An absent/empty ``src`` copies an empty value (clearing ``dst``). The write escapes structural
    delimiters exactly as :meth:`Message.set`, so a component value carrying a ``^``/``&`` rides across
    as data, not new structure."""
    msg.set(dst, msg.field(src) or "")


def set_field(msg: Message, path: str, value: str) -> None:
    """Set ``path`` to ``value`` (Corepoint ``ItemReplace``) — a named wrapper over :meth:`Message.set`."""
    msg.set(path, value)


def append_to_field(msg: Message, path: str, suffix: str) -> None:
    """Append ``suffix`` to the current value at ``path`` (Corepoint ``ItemAppend``).

    An absent field is treated as empty, so the result is just ``suffix``."""
    msg.set(path, (msg.field(path) or "") + suffix)


def convert_case(msg: Message, path: str, mode: str) -> None:
    """Upper/lower/title-case the value at ``path`` in place (Corepoint ``ItemConvert``/``ItemFormat``).

    ``mode`` is one of ``"upper"`` / ``"lower"`` / ``"title"``. A no-op on an absent field; raises
    :class:`ValueError` on an unknown mode (fail loud rather than silently leaving the value)."""
    value = msg.field(path)
    if value is None:
        return
    if mode == "upper":
        result = value.upper()
    elif mode == "lower":
        result = value.lower()
    elif mode == "title":
        result = value.title()
    else:
        raise ValueError(f"convert_case mode must be 'upper', 'lower', or 'title', got {mode!r}")
    msg.set(path, result)


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
    destination."""
    parts = (msg.field(src) or "").split(sep)
    for i, dest in enumerate(dests):
        msg.set(dest, parts[i] if i < len(parts) else "")


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
    count from the end; ``end=None`` runs to the end). A no-op on an absent field."""
    value = msg.field(path)
    if value is None:
        return
    msg.set(path, value[start:end])


def pad_field(msg: Message, path: str, width: int, *, fill: str = "0", side: str = "left") -> None:
    """Pad the value at ``path`` to ``width`` with ``fill`` on ``side`` (Corepoint ``ItemConvert`` pad).

    ``side="left"`` right-justifies (e.g. zero-pad an MRN); ``side="right"`` left-justifies. A value
    already ``>= width`` is left unchanged. A no-op on an absent field; raises :class:`ValueError` on an
    unknown ``side`` (fail loud rather than silently leaving the value)."""
    value = msg.field(path)
    if value is None:
        return
    if side == "left":
        result = value.rjust(width, fill)
    elif side == "right":
        result = value.ljust(width, fill)
    else:
        raise ValueError(f"pad_field side must be 'left' or 'right', got {side!r}")
    msg.set(path, result)


def replace_literal(msg: Message, path: str, old: str, new: str) -> None:
    """Replace every literal occurrence of ``old`` with ``new`` at ``path`` (Corepoint ``ItemReplace``
    find/replace).

    Literal substring replacement via :meth:`str.replace` — **not** a regex, so the result is
    deterministic and carries no pattern mini-language (which would drift toward the declined declarative
    layer, ADR 0106 §7). A no-op on an absent field."""
    value = msg.field(path)
    if value is None:
        return
    msg.set(path, value.replace(old, new))


def arith_field(
    msg: Message, path: str, op: str, operand: float, *, ndigits: int | None = None
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
    msg: Message, start_path: str, end_path: str, dst: str, *, unit: str = "days"
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

    Read from the canonical re-encoding: an HL7 segment id is exactly the first three characters of its
    line (HL7 §2.5), so ``line[:3]`` identifies the segment for every id including ``MSH``. The line
    round-trips through :meth:`Message.add_segment` byte-for-byte (same field separator)."""
    if occurrence < 1:
        raise ValueError("occurrence is 1-based (>= 1)")
    seen = 0
    for line in msg.encode().split("\r"):
        if line[:3] == segment_id:
            seen += 1
            if seen == occurrence:
                return line
    return None
