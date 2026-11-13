# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Splitting a single inbound payload into many messages (Corepoint-style "message split").

Two independent splits, both pure (no I/O, no engine state) so they can run on the hot path and be
reused by the dry-run / Test Bench:

* :func:`split_batch` — a **batch** file (an ``FHS``/``BHS`` batch or just several ``MSH`` messages
  concatenated) becomes one message per ``MSH`` boundary, in file order. This is the canonical
  splitter the File source uses at ingress and that :func:`~messagefoundry.pipeline.dryrun.split_messages`
  delegates to, so the live engine and a dry-run split identically (single source of truth).

* :func:`split_by_obr` — one HL7 order message (an ORM/ORU carrying several ``OBR`` order groups)
  becomes one message per ``OBR`` group, each re-attached to the shared header. This is the
  handler-side equivalent of Corepoint's ``ItemSplit`` — a pure helper a Handler calls to fan one
  order message out into per-order messages.

Both read the message's **own** separators (MSH-1/MSH-2) and go through the :class:`Message`
primitive — never raw string-slicing of structured HL7.
"""

from __future__ import annotations

import codecs
import itertools
import re
from dataclasses import dataclass

from messagefoundry.parsing._builtin_hl7 import _SEPARATOR_HEAD, _extract_separators
from messagefoundry.parsing.binary import _FIRST_MSH
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import normalize, starts_with_msh
from messagefoundry.parsing.sniff import _LEADING_WS_STR

__all__ = [
    "encode_batch",
    "split_batch",
    "split_batch_bytes",
    "one_message_bytes",
    "split_by_obr",
]

# The message boundary: a line that starts with ``MSH``, or with byte order marks and then ``MSH``
# (BACKLOG #5918). It is matched *without* the trailing field separator so a batch whose MSH-1
# isn't ``|`` (e.g. ``MSH^...``) still splits per-message instead of being read as one giant
# message — after a line break a segment id is always exactly three chars, so only an ``MSH``
# segment starts with "MSH". Every reading in this module finds it through the one predicate,
# :func:`_next_boundary`, and a :class:`_Boundary` says how the text each is given spells it.
# Each reading still reads its own lead (whitespace, a byte order mark, an
# FHS/BHS header, or none), so keep the leads in step by hand. AC-7's test in
# tests/test_one_frame_one_message.py compares the delivery reading with the ingress one on a
# handful of shapes, not every input, and tests/test_msh_boundary_parity.py holds each reading to
# its answer before the BACKLOG #3759 refactor, as BACKLOG #5918 widened it.
_MSH = "MSH"
_MSH_BYTES = _MSH.encode("ascii")

#: The byte order mark, U+FEFF, named rather than written so the source stays ASCII.
_BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"


@dataclass(frozen=True, slots=True)
class _Boundary[S: (str, bytes)]:
    """How one kind of text spells a boundary, for :func:`_next_boundary`: ``pattern`` matches a
    whole boundary, a line break, then any run of byte order marks, then ``msh``."""

    msh: S
    pattern: re.Pattern[S]


#: :data:`_BOM` as UTF-8 writes it, a literal so the bytes pattern below stays static.
_BOM_BYTES = b"\xef\xbb\xbf"

# A later ``MSH`` line that byte order marks lead is a boundary in every reading, as two texts read
# without stripping their marks would join it (ADR 0206 rule 5, ADR 0209, BACKLOG #5918). Each
# pattern opens with a line break, which no mark contains, so a search tries each break once and
# reads each run of marks once: linear. ``MSH`` and the mark hold no regex metacharacter, so they
# go in unescaped: the static ReDoS scanner in tests/test_security_static.py resolves a pattern
# composed from literal constants, but not one passed through ``re.escape`` or ``.encode``.

#: Text :func:`~messagefoundry.parsing.peek.normalize` wrote, which ends every line with CR alone.
_NORMALIZED = _Boundary(_MSH, re.compile("\r" + _BOM + "*" + _MSH))
#: An outbound payload, which is not normalized, so a line may end with LF too.
_OUTBOUND = _Boundary(_MSH, re.compile(r"[\r\n]" + _BOM + "*" + _MSH))
#: A received file's bytes, before any decode, so a line may end with LF too. The mark is UTF-8's,
#: read as any run of its three bytes: a class repeats at C speed where a group does not, and a
#: wider match only costs a decode, after which :func:`split_batch` reads the real marks.
_RAW_BYTES = _Boundary(_MSH_BYTES, re.compile(rb"[\r\n][" + _BOM_BYTES + rb"]*MSH"))


def _next_boundary[S: (str, bytes)](text: S, start: int, boundary: _Boundary[S]) -> int:
    """The index of the line break that begins the earliest boundary in ``text`` whose line break
    is at ``start`` or later, or -1 when there is none.

    Every boundary ends with an ``MSH`` past ``start``, so one C-level scan for ``MSH`` settles a
    text holding none, the common single message, before the pattern is searched."""
    if text.find(boundary.msh, start + 1) < 0:
        return -1
    found = boundary.pattern.search(text, start)
    return -1 if found is None else found.start()


#: The first character the parser keeps: it strips the whitespace around a body before it reads it.
_FIRST_KEPT = re.compile(r"\S")


def _holds_more_than_one_message(text: str) -> bool:
    """Whether normalized (``\\r``-delimited) ``text`` holds more than one ``MSH`` segment, by the
    parser's own reading: it strips the whitespace around the body, then treats every line whose
    first three characters are ``MSH`` as a header. A later line that byte order marks lead before
    its ``MSH`` counts too, which the parser does not read as a header but a receiver that drops
    the marks does (BACKLOG #5918). The ingress guard's reading (ADR 0206 rule 5). The boundary is
    the one :func:`split_batch` splits on, so a File source hands that guard one message at a
    time."""
    first = _FIRST_KEPT.search(text)
    if first is None:
        return False
    start = first.start()
    later = _next_boundary(text, start, _NORMALIZED)
    if later < 0:
        return False
    # Led by MSH, one later MSH line makes two messages; otherwise it takes two.
    return text.startswith(_MSH, start) or _next_boundary(text, later + 1, _NORMALIZED) >= 0


#: ``MSH`` after whitespace and any byte order mark. Wider than the parser's ``_LEADS_WITH_MSH`` by
#: the mark alone, which :func:`split_batch` reads past too: a receiver that drops the mark reads
#: the messages behind it.
_LEADS_WITH_MSH_PAST_BOM = re.compile(r"[\s" + _BOM + r"]*" + _MSH)


def _sends_more_than_one_message(payload: str) -> bool:
    """Whether an outbound ``payload`` opens with ``MSH``, past whitespace and a byte order mark,
    and holds another line that starts with ``MSH``, or with marks and then ``MSH`` (ADR 0209). The
    payload is not normalized, so a line break is a CR or an LF, and on an ``MSH``-led payload with
    no mark in its lead the answer is :func:`_holds_more_than_one_message`'s on the normalized
    text. A payload not led by ``MSH`` answers False. A payload with no ``MSH`` after its lead
    pays one scan."""
    lead = _LEADS_WITH_MSH_PAST_BOM.match(payload)
    return lead is not None and _next_boundary(payload, lead.end(), _OUTBOUND) >= 0


#: A UTF-8 byte order mark after the leading whitespace the content sniff tolerates. A match, not a
#: strip, so a file led by whitespace is not copied whole to look at its first bytes. In a bytes
#: pattern ``\s`` is exactly the bytes of ``sniff._LEADING_WS``; a test pins the two.
_LEADING_BOM = re.compile(rb"\s*" + _BOM_BYTES)

#: The batch-envelope header lines a first chunk may open with; neither is a message.
_ENVELOPE_HEADERS = ("FHS", "BHS")

#: Codecs (by ``codecs.lookup`` name) that write every ASCII character as that one byte and use no
#: ASCII byte for anything else, so a byte scan for a later ``MSH`` answers what a decode would.
_ASCII_SAFE_CODECS = frozenset({"utf-8", "ascii"})
_ASCII_SAFE_PREFIXES = ("iso8859-", "cp125")


def split_batch(raw: str | bytes) -> list[str]:
    """Split a possibly-batched HL7 payload into individual messages on ``MSH`` boundaries.

    A real file connection delivers each ``MSH``-delimited message separately; mirror that so a
    batch file (or an ``FHS``/``BHS`` envelope wrapping several messages) yields every message, in
    file order, not just the first. A later ``MSH`` line that byte order marks lead is a boundary
    too, and the cut is past those marks, so the message starts with ``MSH`` (BACKLOG #5918). Each
    returned message is ``\r``-delimited. The leading ``FHS``/``BHS`` envelope header lines before
    the first ``MSH`` are dropped, since each split message is routed on its own and the batch
    framing has no per-message meaning.

    **No message is dropped.** Only the first chunk can come before an ``MSH``. It is read past
    whitespace, a byte order mark (U+FEFF) and those envelope header lines. What remains is a
    message when it starts with ``MSH``, and is otherwise kept as one too, so the parser records its
    ``ERROR`` rather than the split discarding what the sender sent.

    A payload with a single message round-trips unchanged (a one-element list); an empty/whitespace
    payload yields the normalized text as the sole element (the caller — e.g. the parser — then
    reports it as malformed rather than silently dropping it).
    """
    text = normalize(raw)  # \r-delimited, decoupled from the inbound line endings
    bounds: list[int] = []
    at = _next_boundary(text, 0, _NORMALIZED)
    while at >= 0:
        bounds.append(at)
        at = _next_boundary(text, at + 1, _NORMALIZED)
    bounds.append(len(text))
    # Each later message runs from past its boundary's own CR, and any marks after it, so it starts
    # with MSH, up to the next boundary.
    messages = [text[cut + 1 : end].lstrip(_BOM) for cut, end in itertools.pairwise(bounds)]
    # The leading noise the content sniff tolerates.
    head = text[: bounds[0]].lstrip(_LEADING_WS_STR)
    while head.startswith(_ENVELOPE_HEADERS):
        head = head.partition("\r")[2].lstrip(_LEADING_WS_STR)
    if head.strip():  # a chunk of other whitespace alone is not a message either
        messages.insert(0, head)
    return messages or [text]


def split_batch_bytes(raw: bytes, encoding: str) -> list[bytes]:
    """Split a received HL7 file's bytes into one byte string per message, for a source that reads
    whole files and hands each message over on its own (ADR 0206 rule 5).

    The bytes are decoded with the connection's declared ``encoding`` at ``errors="strict"`` so the
    ``MSH`` boundaries are found in the right characters, split by :func:`split_batch`, and each
    message is re-encoded in the same ``encoding``. A file holding one message is handed over as
    :func:`one_message_bytes` says: as its own bytes, unless the parser would refuse what leads them.
    A file that does not decode (or names an unknown codec) comes back as ``[raw]`` untouched, so
    the listener's own strict decode records its ``ERROR``. Every message :func:`split_batch` finds
    is handed back.

    A file holding no ``MSH`` after a line break, with or without byte order marks between them,
    is one message the parser reads as it is. Under UTF-8 only, it must also not open with a byte
    order mark, which the split reads past. Under a single-byte charset the mark's bytes are three
    characters the split keeps. Where a byte scan can tell (:func:`_needs_a_decode`), such a file
    is returned without a decode or a split, so the common single-message file pays one scan."""
    if not _needs_a_decode(raw, encoding):
        return [raw]
    try:
        text = raw.decode(encoding)
    except (UnicodeError, LookupError):
        # UnicodeError, not only UnicodeDecodeError: a codec that refuses every conversion, such as
        # "undefined", raises the bare base class, and it too must reach the listener's decode,
        # which records it as an ERROR row, rather than escape the hand-off (BACKLOG #5102).
        return [raw]
    messages = split_batch(text)
    if len(messages) == 1:
        return [one_message_bytes(raw, text, messages[0], encoding)]
    return [message.encode(encoding) for message in messages]


def one_message_bytes(raw: bytes, text: str, message: str, encoding: str) -> bytes:
    """What a whole-file source hands over for a file :func:`split_batch` read as one ``message``,
    where ``text`` is ``raw`` decoded with ``encoding``.

    ``raw`` itself, byte for byte, when the parser reads ``text`` as it is: ``text`` starts with
    ``MSH`` after whitespace, or the split found no ``MSH``-led message in it either. Otherwise the
    split read the message past leading noise the parser refuses, a byte order mark or an
    ``FHS``/``BHS`` envelope header, so ``message`` is handed over re-encoded, as each member of a
    batch is. Without this, one such message was an ``ERROR`` where the same message in a batch of
    two was recorded."""
    if starts_with_msh(text) or not message.startswith(_MSH):
        return raw
    return message.encode(encoding)


def _needs_a_decode(raw: bytes, encoding: str) -> bool:
    """Whether ``raw`` may hold an ``MSH`` after a line break, with or without UTF-8 byte order
    marks between them, or, under UTF-8, may open with a byte order mark the split reads past. It
    answers False only for an encoding that writes each ASCII character as that one byte and uses
    no ASCII byte for anything else, with neither shape present. Any other encoding answers True,
    so the caller decodes. Under a single-byte charset the mark's bytes are three characters the
    split keeps, so a leading one needs no decode, and a later one costs a decode that finds one
    message."""
    try:
        name = codecs.lookup(encoding).name
    except LookupError:
        return True
    if name not in _ASCII_SAFE_CODECS and not name.startswith(_ASCII_SAFE_PREFIXES):
        return True
    if name == "utf-8" and _LEADING_BOM.match(raw):
        return True
    return _next_boundary(raw, 0, _RAW_BYTES) >= 0


def encode_batch(messages: list[Message | str], *, control_id: str, timestamp: str) -> str:
    """Frame N HL7 messages into one ``BHS``…``BTS`` batch envelope — the encode-side inverse of
    :func:`split_batch` (BACKLOG #134 / ADR 0082).

    Used by the outbound delivery stage to coalesce a claimed FIFO head-prefix of N rows into a single
    partner send. It is **pure and deterministic**: it derives nothing from a clock — the caller passes
    ``timestamp`` (the head row's re-run-stable ingest time, ADR 0009) and ``control_id`` (the head
    row's sequence, ADR 0082 ratified decision #3), so a crash re-run that re-claims the same prefix
    re-derives the **byte-identical** envelope (the at-least-once purity requirement).

    The ``BHS`` header is built from the **head member's own** MSH-1 (field separator) and MSH-2
    (encoding characters) — never hardcoded ``|^~\\&`` — so a custom-delimiter feed frames correctly:

    * ``BHS-1`` = the field separator (the literal char after ``BHS``), ``BHS-2`` = the encoding chars,
    * ``BHS-7`` = ``timestamp`` (batch creation date/time), ``BHS-11`` = ``control_id`` (batch control
      id); ``BHS-3``…``BHS-6`` and ``BHS-8``…``BHS-10`` are empty placeholders so the two land at the
      correct field indices,
    * ``BTS-1`` = the framed message count ``N`` (HL7 validators reject a mismatch).

    Member payloads are carried **verbatim** — only line endings are normalized to ``\\r`` (never
    ``\\n``/``\\r\\n``) and one trailing ``\\r`` is kept per segment — so the transform's exact output
    bytes are preserved (no re-parse/re-escape). ``\\r`` is the sole segment terminator. Members must be
    HL7v2 (``str``/:class:`Message`); non-HL7 batching is out of scope (ADR 0082).
    """
    if not messages:
        raise ValueError("encode_batch requires at least one message")
    # Read the batch separators from the HEAD member's own MSH (never hardcode |^~\&). The head drives
    # the whole envelope's framing; mixed-delimiter members in one batch are not a real feed shape.
    head = messages[0]
    if isinstance(head, Message):
        field_sep, comp_sep, rep_sep, esc, sub_sep = head._encoding_chars()
    else:
        field_sep, comp_sep, rep_sep, esc, sub_sep = _head_separators(head)
    enc = (
        comp_sep + rep_sep + esc + sub_sep
    )  # MSH-2 / BHS-2: component^repetition~escape\subcomponent
    # BHS-3..BHS-11 field VALUES (BHS-1 is the separator literal, BHS-2 is `enc`, appended above).
    bhs_tail = ["", "", "", "", timestamp, "", "", "", control_id]  # BHS-3, -4, -5, -6, -7, …, -11
    bhs = "BHS" + field_sep + enc + field_sep + field_sep.join(bhs_tail)
    bts = "BTS" + field_sep + str(len(messages))
    # Every piece carries its own trailing CR, so the one join is the only copy of a member: a strip
    # of each member and a CR added to the joined envelope each copied it again (BACKLOG #5919).
    pieces = [bhs, "\r"]
    for m in messages:
        pieces.extend(_framed(m.encode() if isinstance(m, Message) else normalize(m)))
    pieces += [bts, "\r"]
    return "".join(pieces)


#: A line break in a member that is not normalized.
_LINE_BREAK = re.compile(r"[\r\n]")


def _head_separators(head: str) -> tuple[str, str, str, str, str]:
    """The ``(field, component, repetition, escape, subcomponent)`` delimiters of a batch's ``head``
    member, as :meth:`Message._encoding_chars` reads them, from its first ``MSH`` line's first
    :data:`_SEPARATOR_HEAD` characters alone (BACKLOG #5919). A full parse of a large hydrated head
    to read eight characters cost its whole size in time and memory.

    The ``MSH`` line is the one the head opens with, past whitespace and any byte order mark, as
    :func:`split_batch` reads a member; or, past an ``FHS``/``BHS`` envelope header, the first line
    that starts with ``MSH``, as the parser reads one. Raises ``ValueError``, as
    ``_encoding_chars`` does, when there is no such line or it holds no field separator or fewer
    than four encoding characters, rather than guess."""
    lead = _LEADS_WITH_MSH_PAST_BOM.match(head)
    if lead is not None:
        start = lead.end() - len(_MSH)
    else:
        first = _FIRST_KEPT.search(head)
        later = None
        if first is not None and head.startswith(_ENVELOPE_HEADERS, first.start()):
            later = _FIRST_MSH.search(head, first.start())
        if later is None:
            raise ValueError("cannot determine HL7 separators: the head member holds no MSH line")
        start = later.start() + 1
    # The window is a few characters, so neither cut copies the member.
    line = _LINE_BREAK.split(head[start : start + _SEPARATOR_HEAD], maxsplit=1)[0]
    # _extract_separators fills a short MSH-2 with defaults, where _encoding_chars refuses one, so
    # the window must hold MSH-1 and four encoding characters with no field separator among them.
    if len(line) < _SEPARATOR_HEAD or line.find(line[3], 4) != -1:
        raise ValueError(f"cannot determine HL7 separators: the head's MSH line opens {line!r}")
    field_sep, comp_sep, rep_sep, sub_sep, esc = _extract_separators(line)
    return field_sep, comp_sep, rep_sep, esc, sub_sep


def _framed(text: str) -> tuple[str, ...]:
    """The pieces that frame one member's ``text`` in a batch: its segments with no leading or
    trailing CR, then one CR. ``text`` itself when it already has that shape, so the common
    member, which ends with one CR, is not copied."""
    lo, hi = 0, len(text)
    while lo < hi and text[lo] == "\r":
        lo += 1
    while hi > lo and text[hi - 1] == "\r":
        hi -= 1
    if lo == 0 and hi == len(text):
        return text, "\r"
    if lo == 0 and hi == len(text) - 1:
        return (text,)
    return text[lo:hi], "\r"


def _non_blank(lines: list[str]) -> list[str]:
    """``lines`` without the empty ones (an empty segment carries nothing to re-attach)."""
    return [line for line in lines if line]


def split_by_obr(message: Message | str | bytes) -> list[str]:
    """Split one HL7 order message into one message per ``OBR`` order group (Corepoint ``ItemSplit``).

    **Grouping rule.** Everything *before the first* ``OBR`` is the shared **header** (``MSH`` plus
    any patient-/visit-level segments — ``EVN``/``PID``/``PV1``/``ORC``/``NTE``…). Each ``OBR`` begins
    a new **order group** that runs up to (but not including) the next ``OBR``; its group carries that
    ``OBR`` and every segment after it (``OBX``/``NTE``/``SPM``…) until the next order. Each produced
    message is ``header segments + that one order group``, re-encoded through :class:`Message` so it
    re-parses cleanly.

    **MSH-10 (control id) handling.** Splitting one message into N would otherwise emit N messages
    sharing the original control id, breaking de-dup/correlation downstream. So each split message's
    MSH-10 is **suffixed with its 1-based order index** using the message's own component separator
    is *not* involved — the suffix is appended to the existing control id with a literal ``-`` (e.g.
    ``MSG1`` → ``MSG1-1``, ``MSG1-2``). The first split is *not* special-cased (it too becomes
    ``…-1``) so every emitted message is uniquely and predictably identifiable, and a 1-OBR message
    that is "split" still gets ``…-1`` — a deliberate, documented contract a reviewer can rely on. A
    message with **no** MSH-10 is left untouched (nothing to suffix).

    **0 or 1 OBR.** A message with **one** ``OBR`` returns a single-element list (the whole message,
    with MSH-10 suffixed ``-1`` per above). A message with **zero** ``OBR`` is *not* an order message
    to split, so it is returned **as parsed** (``msg.encode()``) in a single-element list with its
    control id **unchanged** (no suffix) — the natural no-op for a non-order message. For text input
    that is the text without any empty segment lines, which :meth:`Message.parse` drops.

    **Blank segments.** :meth:`Message.parse` drops empty segment lines, so text input never
    carries one here. A :class:`Message` built straight from a parse tree still can. Such a segment
    counts as a segment when the groups are found, so every order keeps its own observations, and it
    is then left out of the parts, since it carries nothing (BACKLOG #1597).

    Accepts a :class:`Message`, or a raw ``str``/``bytes`` (parsed here), matching how the other
    parsing helpers take input. Returns re-encoded ``\r``-delimited HL7 strings.
    """
    msg = message if isinstance(message, Message) else Message.parse(message)
    segments = msg.segments()
    obr_count = segments.count("OBR")

    # No order groups: not a splittable order message — return it as parsed (control id untouched).
    if obr_count == 0:
        return [msg.encode()]

    # Index of each OBR among all segments (0-based positions in segment order). The shared header is
    # every segment before the first OBR; each group spans one OBR up to the next.
    obr_positions = [i for i, seg in enumerate(segments) if seg == "OBR"]
    header_end = obr_positions[0]
    boundaries = [*obr_positions, len(segments)]  # group i = [obr_positions[i], boundaries[i+1])

    # Work from the raw segment *lines* so each group is re-attached to the header verbatim and
    # re-parsed — no field-level reconstruction, and the original encoding characters are preserved.
    # encode() writes exactly one line per segment plus a trailing "" after the final \r, so line i
    # IS segment i. Truncate to the segment count; never filter, because an empty segment (a \r\r)
    # is a segment too, and dropping its line shifted every later slice by one (BACKLOG #1597).
    seg_lines = msg.encode().split("\r")[: len(segments)]
    header_lines = _non_blank(seg_lines[:header_end])

    out: list[str] = []
    control_id = msg.control_id
    for idx, start in enumerate(obr_positions, start=1):
        end = boundaries[idx]  # next OBR position (or end of message)
        # Empty lines go only AFTER the positional slice: they carry nothing, and a re-parsed part
        # holding one would raise on the MSH-10 set below (the whole-field set is a raising scan).
        group_lines = _non_blank(seg_lines[start:end])
        part = Message.parse("\r".join([*header_lines, *group_lines]) + "\r")
        # Suffix the control id so the N split messages stay individually correlatable downstream;
        # set() goes through the Message primitive (separator-aware, never raw slicing).
        if control_id is not None:
            part.set("MSH-10", f"{control_id}-{idx}")
        out.append(part.encode())
    return out
