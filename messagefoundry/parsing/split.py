# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

import re

from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import normalize

__all__ = ["split_batch", "split_by_obr"]

# Split a normalized (``\r``-delimited) payload before each non-leading ``MSH`` segment. We match
# ``\rMSH`` *without* the trailing field separator so a batch whose MSH-1 isn't ``|`` (e.g.
# ``MSH^...``) still splits per-message instead of being read as one giant message — after a ``\r`` a
# segment id is always exactly three chars, so only an ``MSH`` segment starts with the literal "MSH".
_MSH_BOUNDARY = re.compile(r"(?=\rMSH)")


def split_batch(raw: str | bytes) -> list[str]:
    """Split a possibly-batched HL7 payload into individual messages on ``MSH`` boundaries.

    A real file connection delivers each ``MSH``-delimited message separately; mirror that so a
    batch file (or an ``FHS``/``BHS`` envelope wrapping several messages) yields every message, in
    file order — not just the first. Each returned message is ``\r``-delimited and starts at its
    ``MSH`` (any ``FHS``/``BHS``/``FTS``/``BTS`` batch-envelope lines around the messages are dropped,
    since each split message is routed on its own and the batch framing has no per-message meaning).

    A payload with a single message round-trips unchanged (a one-element list); an empty/whitespace
    payload yields the normalized text as the sole element (the caller — e.g. the parser — then
    reports it as malformed rather than silently dropping it).
    """
    text = normalize(raw)  # \r-delimited, decoupled from the inbound line endings
    chunks = _MSH_BOUNDARY.split(text)
    # Keep only the MSH-led chunks: a leading FHS/BHS envelope (or stray whitespace) before the first
    # MSH is not itself a message. ``lstrip("\r")`` strips the boundary's own leading CR; a chunk that
    # isn't MSH-led after stripping (the batch header) is dropped.
    messages = [c.lstrip("\r") for c in chunks if c.strip() and c.lstrip("\r").startswith("MSH")]
    return messages or [text]


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
    to split, so it is returned **as-is** in a single-element list with its control id **unchanged**
    (no suffix) — the natural no-op for a non-order message.

    Accepts a :class:`Message`, or a raw ``str``/``bytes`` (parsed here), matching how the other
    parsing helpers take input. Returns re-encoded ``\r``-delimited HL7 strings.
    """
    msg = message if isinstance(message, Message) else Message.parse(message)
    segments = msg.segments()
    obr_count = segments.count("OBR")

    # No order groups: not a splittable order message — return it verbatim (control id untouched).
    if obr_count == 0:
        return [msg.encode()]

    # Index of each OBR among all segments (0-based positions in segment order). The shared header is
    # every segment before the first OBR; each group spans one OBR up to the next.
    obr_positions = [i for i, seg in enumerate(segments) if seg == "OBR"]
    header_end = obr_positions[0]
    boundaries = [*obr_positions, len(segments)]  # group i = [obr_positions[i], boundaries[i+1])

    # Work from the raw segment *lines* so each group is re-attached to the header verbatim and
    # re-parsed — no field-level reconstruction, and the original encoding characters are preserved.
    lines = msg.encode().split("\r")
    # encode() may leave a trailing "" after the final \r; align line count to the segment count so
    # positional slicing matches segments() exactly.
    seg_lines = [ln for ln in lines if ln]
    header_lines = seg_lines[:header_end]

    out: list[str] = []
    control_id = msg.control_id
    for idx, start in enumerate(obr_positions, start=1):
        end = boundaries[idx]  # next OBR position (or end of message)
        group_lines = seg_lines[start:end]
        part = Message.parse("\r".join([*header_lines, *group_lines]) + "\r")
        # Suffix the control id so the N split messages stay individually correlatable downstream;
        # set() goes through the Message primitive (separator-aware, never raw slicing).
        if control_id is not None:
            part.set("MSH-10", f"{control_id}-{idx}")
        out.append(part.encode())
    return out
