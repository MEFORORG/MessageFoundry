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
import re

from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import normalize
from messagefoundry.parsing.sniff import _LEADING_WS, _LEADING_WS_STR

__all__ = [
    "encode_batch",
    "split_batch",
    "split_batch_bytes",
    "one_message_bytes",
    "split_by_obr",
]

# Split a normalized (``\r``-delimited) payload before each non-leading ``MSH`` segment. We match
# ``\rMSH`` *without* the trailing field separator so a batch whose MSH-1 isn't ``|`` (e.g.
# ``MSH^...``) still splits per-message instead of being read as one giant message — after a ``\r`` a
# segment id is always exactly three chars, so only an ``MSH`` segment starts with the literal "MSH".
_MSH_BOUNDARY = re.compile(r"(?=\rMSH)")

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
    file order, not just the first. Each returned message is ``\r``-delimited. The leading
    ``FHS``/``BHS`` envelope header lines before the first ``MSH`` are dropped, since each split
    message is routed on its own and the batch framing has no per-message meaning.

    **No message is dropped.** Only the first chunk can come before an ``MSH``. It is read past
    whitespace, a byte order mark (U+FEFF) and those envelope header lines. What remains is a
    message when it starts with ``MSH``, and is otherwise kept as one too, so the parser records its
    ``ERROR`` rather than the split discarding what the sender sent.

    A payload with a single message round-trips unchanged (a one-element list); an empty/whitespace
    payload yields the normalized text as the sole element (the caller — e.g. the parser — then
    reports it as malformed rather than silently dropping it).
    """
    text = normalize(raw)  # \r-delimited, decoupled from the inbound line endings
    first, *rest = _MSH_BOUNDARY.split(text)
    # Every later chunk is the boundary's own CR, then MSH.
    messages = [chunk[1:] for chunk in rest]
    head = first.lstrip(_LEADING_WS_STR)  # the leading noise the content sniff tolerates
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

    A file holding no ``MSH`` after a line break, and no leading UTF-8 byte order mark, is one
    message the parser reads as it is. Where a byte scan can tell (:func:`_may_hold_a_later_msh`),
    such a file is returned without a decode or a split, so the common single-message file pays one
    scan."""
    if not _may_hold_a_later_msh(raw, encoding) and not raw.lstrip(_LEADING_WS).startswith(
        codecs.BOM_UTF8
    ):
        return [raw]
    try:
        text = raw.decode(encoding)
    except (UnicodeDecodeError, LookupError):
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
    if text.lstrip().startswith("MSH") or not message.startswith("MSH"):
        return raw
    return message.encode(encoding)


def _may_hold_a_later_msh(raw: bytes, encoding: str) -> bool:
    """Whether ``raw`` may hold an ``MSH`` after a line break. It answers False only for an encoding
    that writes each ASCII character as that one byte and uses no ASCII byte for anything else, with
    neither byte sequence present. Any other encoding answers True, so the caller decodes."""
    try:
        name = codecs.lookup(encoding).name
    except LookupError:
        return True
    if name not in _ASCII_SAFE_CODECS and not name.startswith(_ASCII_SAFE_PREFIXES):
        return True
    return b"\rMSH" in raw or b"\nMSH" in raw


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
    head = messages[0] if isinstance(messages[0], Message) else Message.parse(messages[0])
    field_sep, comp_sep, rep_sep, esc, sub_sep = head._encoding_chars()
    enc = (
        comp_sep + rep_sep + esc + sub_sep
    )  # MSH-2 / BHS-2: component^repetition~escape\subcomponent
    # BHS-3..BHS-11 field VALUES (BHS-1 is the separator literal, BHS-2 is `enc`, appended above).
    bhs_tail = ["", "", "", "", timestamp, "", "", "", control_id]  # BHS-3, -4, -5, -6, -7, …, -11
    bhs = "BHS" + field_sep + enc + field_sep + field_sep.join(bhs_tail)
    bts = "BTS" + field_sep + str(len(messages))
    parts = [bhs]
    for m in messages:
        text = m.encode() if isinstance(m, Message) else normalize(m)
        parts.append(
            text.strip("\r")
        )  # the member's segments, no leading/trailing CR (kept verbatim otherwise)
    parts.append(bts)
    return "\r".join(parts) + "\r"


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
