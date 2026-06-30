# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""base64 binary-carriage codec (ADR 0028) — carry arbitrary bytes over the str/TEXT ingress+store.

MessageFoundry's non-HL7 ingress and all three store backends are ``str``/TEXT end-to-end (the
identity cipher binds the body *verbatim* into a TEXT column). Raw bytes cannot ride that safely: a
``NUL`` (``U+0000``) byte is rejected by Postgres at bind and silently truncates SQLite / SQL Server,
so a latin-1 "byte view" reintroduces exactly that corruption (ADR 0028 §Context). The fix is to
encode bytes to **unbroken standard base64** — an ASCII-safe alphabet (``A-Za-z0-9+/=``) with no
``NUL``, no HL7 delimiter (``|^~\\&``), and no ``CR``/``LF`` — at the source boundary, behind a
self-describing ``mfb64:v1:`` marker, and decode them back on demand.

This module is **pure** (stdlib ``base64`` only, no engine imports) so the console may import it under
the parsing/ carve-out, mirroring ``parsing/x12`` and ``parsing/fhir``. The headline contract is
exposed on :class:`~messagefoundry.parsing.message.RawMessage`
(:meth:`~messagefoundry.parsing.message.RawMessage.from_bytes` /
:attr:`~messagefoundry.parsing.message.RawMessage.raw_bytes` /
:meth:`~messagefoundry.parsing.message.RawMessage.binary` /
:attr:`~messagefoundry.parsing.message.RawMessage.is_binary`) — consumers use those, not the bare
functions here: **exactly one encode** (at the source) and **one decode** (at the codec).

**Two markers, one alphabet** (ADR 0028 §7): ``mfb64:v1:`` is the *substrate* marker for a whole
binary payload sitting in the TEXT store; the HL7 OBX-5 ``ED`` ``Encoding`` component (``"Base64"``)
is HL7's own *in-band* marker for a document embedded inside a field. They never nest — the OBX-5 ED
helpers below carry **no** ``mfb64:`` wrapper.
"""

from __future__ import annotations

import base64
import binascii
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Type-only import: keep parsing.message out of this module's *runtime* imports so the dependency
    # is one-way (message.py imports binary.py, never the reverse) and there is no import cycle.
    from messagefoundry.parsing.message import Message

#: The self-describing carriage marker. ``v1`` versions the *algorithm* (standard base64); a future
#: carrier (e.g. base85, if the ~33% inflation ever bites) would ship as ``v2`` without ambiguity.
#: Distinct from the store cipher's ``mfenc:`` envelope — an independent *outer* layer — so the two
#: never collide and a value is never double-decoded.
MARKER = "mfb64:v1:"

#: The self-describing *pruned-document tombstone* marker (#47, ADR 0042). After retention strips an
#: embedded document in place, the bulky base64 is replaced by ``mfdoc:v1:pruned:<bytes>:<content-type>:
#: <iso-ts>`` — a small, ASCII-safe placeholder that records the evicted document's size + content-type +
#: prune timestamp without leaking any content. Distinct from :data:`MARKER` so a tombstone is NOT a
#: carriage value (``is_marked`` / ``RawMessage.is_binary`` go False) and is never re-decoded as binary.
DOC_TOMBSTONE_MARKER = "mfdoc:v1:pruned:"

__all__ = [
    "MARKER",
    "DOC_TOMBSTONE_MARKER",
    "BinaryCarriageError",
    "encode",
    "decode",
    "is_marked",
    "embed_obx_document",
    "extract_obx_document",
    "is_document_tombstone",
    "make_document_tombstone",
    "strip_documents",
    "strip_documents_in_hl7",
]


class BinaryCarriageError(ValueError):
    """A value could not be decoded as binary carriage (ADR 0028): a missing ``mfb64:v1:`` marker, or
    base64 that fails to decode (bad padding / non-alphabet content). Subclasses ``ValueError`` so a
    Router/Handler can let it propagate to the **error/dead-letter** path (status ``ERROR``) rather
    than yielding a silently-truncated body — honoring the count-and-log invariant (CLAUDE.md §2)."""


def _b64encode_unbroken(data: bytes) -> str:
    """Standard base64 on a single line. ``base64.b64encode`` never inserts line breaks, whereas
    ``base64.encodebytes`` wraps at 76 chars (RFC 2045) and plants a ``\\n`` — which, inside an HL7
    segment, a tolerant parser may read as a terminator and truncate the field. Always use this,
    **never** ``encodebytes``."""
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: str) -> bytes:
    """Decode standard base64, tolerating incidental whitespace/``CR``/``LF`` a partner may have
    inserted but **failing loud** on genuine corruption. Whitespace is stripped first, then
    ``validate=True`` makes bad padding or non-alphabet content raise (wrapped as
    :class:`BinaryCarriageError`)."""
    compact = "".join(text.split())
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BinaryCarriageError(f"invalid base64: {exc}") from exc


def encode(data: bytes) -> str:
    """Bytes → the canonical ``mfb64:v1:<unbroken-base64>`` carriage string (ADR 0028 §3 — the one
    encode). Prefer :meth:`RawMessage.from_bytes`, which calls this at the source boundary."""
    return MARKER + _b64encode_unbroken(data)


def is_marked(text: str) -> bool:
    """Whether ``text`` is a carriage string (carries the ``mfb64:v1:`` marker). Mirrors the store
    cipher's ``is_encrypted`` test — lets a raw-view detect a binary body with no ``content_type``
    registry."""
    return text.startswith(MARKER)


def decode(text: str) -> bytes:
    """A carriage string → its bytes (ADR 0028 §3 — the one decode). Raises
    :class:`BinaryCarriageError` if ``text`` is not a carriage string or its base64 is corrupt. Prefer
    :attr:`RawMessage.raw_bytes`."""
    if not is_marked(text):
        raise BinaryCarriageError(
            "not a binary-carriage value (missing mfb64:v1: marker); check .is_binary first"
        )
    return _b64decode(text[len(MARKER) :])


# --- HL7 OBX-5 ED embedding (secondary, ADR 0028 §7) -------------------------------------------------
# A document embedded *inside* an HL7 v2 message rides OBX-5 with OBX-2 = "ED" (Encapsulated Data).
# The ED components are <source-app>^<type-of-data>^<data-subtype>^<Encoding="Base64">^<Data>; the
# "Base64" Encoding component is HL7's own in-band marker, so these helpers carry NO mfb64: wrapper.
# They go through the Message API (which reads the message's own separators — never hardcoded ^|~&) and
# emit UNBROKEN base64, so no CR/LF lands in the segment. Single-OBX only; multi-OBX chunking for
# oversized documents is deferred (ADR 0028 § Out of scope).

_ED_ENCODING = "Base64"


def embed_obx_document(
    message: Message,
    data: bytes,
    *,
    type_of_data: str = "Application",
    data_subtype: str,
    occurrence: int = 1,
) -> None:
    """Embed ``data`` as a base64 OBX-5 ED document on the ``occurrence``-th OBX of ``message``
    (ADR 0028 §7): sets ``OBX-2`` = ``"ED"`` and ``OBX-5`` to ``^<type_of_data>^<data_subtype>^Base64^
    <unbroken-base64>``. The base64 alphabet contains no HL7 delimiter, so the data component survives
    the message's escaping untouched, and it is emitted **unbroken** (no MIME line wrap) so no
    ``CR``/``LF`` splits the segment. The OBX segment must already exist (``Message.set`` raises
    ``KeyError`` for an absent segment); a Handler builds it with ``add_segment`` first.
    Recover the bytes with :func:`extract_obx_document`."""
    message.set("OBX-2", "ED", occurrence=occurrence)
    message.set("OBX-5.2", type_of_data, occurrence=occurrence)
    message.set("OBX-5.3", data_subtype, occurrence=occurrence)
    message.set("OBX-5.4", _ED_ENCODING, occurrence=occurrence)
    message.set("OBX-5.5", _b64encode_unbroken(data), occurrence=occurrence)


def extract_obx_document(message: Message, *, occurrence: int = 1) -> bytes:
    """Extract the base64 OBX-5 ED document from the ``occurrence``-th OBX of ``message`` (ADR 0028
    §7). Reads the ``Encoding`` component (``OBX-5.4``), requires it to be ``"Base64"``
    (case-insensitive), then decodes the data component (``OBX-5.5``). Raises
    :class:`BinaryCarriageError` if ``OBX-2`` is not ``ED``, the encoding is not ``Base64``, or the
    data is corrupt — so a Handler can dead-letter rather than mis-decode."""
    obx2 = message.field("OBX-2", occurrence=occurrence)
    if (obx2 or "").upper() != "ED":
        raise BinaryCarriageError(f"OBX-2 is {obx2!r}, not 'ED' — not an embedded document")
    encoding = message.field("OBX-5.4", occurrence=occurrence)
    if (encoding or "").strip().lower() != _ED_ENCODING.lower():
        raise BinaryCarriageError(f"OBX-5 Encoding component is {encoding!r}, not '{_ED_ENCODING}'")
    return _b64decode(message.field("OBX-5.5", occurrence=occurrence) or "")


# --- embedded-document pruning (#47, ADR 0042) ------------------------------------------------------
# Retention can strip a bulky embedded document *in place* after a per-connection window, replacing the
# base64 with a small self-describing tombstone while keeping the surrounding message parseable. The
# strip targets BOTH carriage forms — a whole-body mfb64:v1: carriage value and HL7 OBX-5 ED embeds —
# and ALWAYS goes through the codec / parsed model (never string-slices raw HL7, CLAUDE.md §8). The
# functions here are pure (a raw string in, a stripped string + counts out); the store backends and the
# RetentionRunner drive them.

#: When no content-type is known for an evicted blob (a bare mfb64 body carries none), the tombstone
#: records this placeholder so the field never reads as empty.
_UNKNOWN_CONTENT_TYPE = "application/octet-stream"


def _iso(ts: float) -> str:
    """A UTC ``YYYYMMDDThhmmssZ`` timestamp for the tombstone — compact, ASCII, no separators that
    could re-split an HL7 field (no ``|^~\\&`` / ``:`` issues inside the value component, which is
    escaped on write anyway)."""
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(ts))


def make_document_tombstone(size_bytes: int, content_type: str, pruned_at: float) -> str:
    """Build the self-describing pruned-document tombstone (#47, ADR 0042):
    ``mfdoc:v1:pruned:<bytes>:<content-type>:<iso-ts>``. Records the evicted document's **size** +
    **content-type** + **prune timestamp** and nothing else (no content → no PHI). ``content_type`` is
    sanitized of the structural characters (``:`` and HL7 delimiters) that would corrupt the tombstone /
    re-split the field, so an arbitrary ED ``type-of-data`` can't break it."""
    safe_ct = (content_type or _UNKNOWN_CONTENT_TYPE).strip() or _UNKNOWN_CONTENT_TYPE
    for bad in ":|^~&\\\r\n":
        safe_ct = safe_ct.replace(bad, "_")
    return f"{DOC_TOMBSTONE_MARKER}{max(size_bytes, 0)}:{safe_ct}:{_iso(pruned_at)}"


def is_document_tombstone(text: str) -> bool:
    """Whether ``text`` is already a pruned-document tombstone — so a strip pass is idempotent (a
    re-run never re-strips an already-evicted blob, and the ``documents_pruned`` flag is stable)."""
    return text.startswith(DOC_TOMBSTONE_MARKER)


def strip_documents(
    raw: str,
    *,
    pruned_at: float | None = None,
    min_bytes: int = 0,
    content_type: str | None = None,
) -> tuple[str, int, int]:
    """Strip embedded documents from a stored ``raw`` body in place, returning
    ``(new_raw, documents_stripped, bytes_reclaimed)`` (#47, ADR 0042).

    Two carriage forms are handled, codec-driven (never raw string-slicing):

    * a **whole-body ``mfb64:v1:`` carriage value** (ADR 0028) → the whole body becomes a tombstone;
    * an **HL7 message carrying OBX-5 ED embeds** → each qualifying OBX-5 value is tombstoned via the
      parsed :class:`Message` model and the message is re-encoded (so it re-parses cleanly).

    Anything else (plain HL7 with no ED, JSON/XML/text, an already-stripped tombstone) is returned
    unchanged with ``(raw, 0, 0)`` — so the caller can skip a no-op write and the pass is idempotent.

    ``min_bytes`` skips a document whose decoded size is below the threshold (small embeds aren't worth
    evicting; ``0`` = strip every embed). ``content_type`` (the connection's declared format) labels a
    bare-mfb64 tombstone; an OBX-5 ED tombstone is labelled from the segment's own ED type component.
    ``bytes_reclaimed`` is the *base64* length removed (the stored, on-disk cost), not the decoded
    size."""
    pruned_at = time.time() if pruned_at is None else pruned_at
    if is_document_tombstone(raw):
        return raw, 0, 0  # already stripped — idempotent
    if is_marked(raw):
        return _strip_whole_body_mfb64(raw, pruned_at, min_bytes, content_type)
    if "OBX" in raw and "MSH" in raw[:8]:
        # Only attempt the HL7/OBX path on something that looks like an HL7 message (starts with MSH).
        # A non-HL7 body that merely contains the substring "OBX" is left untouched by the parse guard
        # below (a parse failure / no OBX-5 ED → returned unchanged).
        return _strip_obx_ed(raw, pruned_at, min_bytes)
    return raw, 0, 0


def _strip_whole_body_mfb64(
    raw: str, pruned_at: float, min_bytes: int, content_type: str | None
) -> tuple[str, int, int]:
    """Strip a whole-body ``mfb64:v1:`` carriage value (ADR 0028) to a tombstone."""
    b64 = raw[len(MARKER) :]
    try:
        size = len(_b64decode(b64))
    except BinaryCarriageError:
        # A corrupt carriage value: leave it for the operator to see rather than guess its size.
        return raw, 0, 0
    if size < min_bytes:
        return raw, 0, 0
    tombstone = make_document_tombstone(size, content_type or _UNKNOWN_CONTENT_TYPE, pruned_at)
    return tombstone, 1, len(raw) - len(tombstone)


def strip_documents_in_hl7(
    message: "Message", *, pruned_at: float | None = None, min_bytes: int = 0
) -> tuple[int, int]:
    """Strip every qualifying OBX-5 ED embedded document from a parsed :class:`Message` **in place**,
    returning ``(documents_stripped, bytes_reclaimed)``. The message is mutated through its own API
    (reads its MSH-2 separators, escapes the tombstone as a leaf value) so a re-encode round-trips and
    re-parses. Used by :func:`strip_documents` and directly testable against a parsed message."""
    pruned_at = time.time() if pruned_at is None else pruned_at
    stripped = 0
    reclaimed = 0
    count = message.count_segments("OBX")
    for occ in range(1, count + 1):
        if (message.field("OBX-2", occurrence=occ) or "").upper() != "ED":
            continue
        if (message.field("OBX-5.4", occurrence=occ) or "").strip().lower() != _ED_ENCODING.lower():
            continue  # not Base64-encoded ED — leave it
        data_b64 = message.field("OBX-5.5", occurrence=occ) or ""
        if not data_b64 or is_document_tombstone(data_b64):
            continue  # empty or already-stripped — idempotent
        try:
            size = len(_b64decode(data_b64))
        except BinaryCarriageError:
            continue  # corrupt base64 — leave it for the operator to see
        if size < min_bytes:
            continue
        # Label the tombstone from the ED type-of-data component (OBX-5.2), e.g. "Application".
        ed_type = message.field("OBX-5.2", occurrence=occ) or _UNKNOWN_CONTENT_TYPE
        tombstone = make_document_tombstone(size, ed_type, pruned_at)
        # Replace the data component and drop the Base64 encoding marker, so a reader no longer treats
        # OBX-5.5 as decodable base64 (extract_obx_document would now raise — the document is gone).
        before = len(data_b64)
        message.set("OBX-5.5", tombstone, occurrence=occ)
        message.set("OBX-5.4", "", occurrence=occ)
        stripped += 1
        reclaimed += before - len(tombstone)
    return stripped, reclaimed


def _strip_obx_ed(raw: str, pruned_at: float, min_bytes: int) -> tuple[str, int, int]:
    """Parse ``raw`` as HL7, strip its OBX-5 ED embeds, and re-encode. Returns the original unchanged on
    a parse failure or when nothing was stripped (so the caller skips the write)."""
    # Local import keeps the one-way dependency (message.py imports binary.py, never the reverse) — the
    # cycle is broken by importing inside the function, not at module top.
    from messagefoundry.parsing.message import Message

    try:
        message = Message.parse(raw)
    except Exception:
        # A malformed body that merely looked like HL7 — never crash a retention pass on it.
        return raw, 0, 0
    stripped, reclaimed = strip_documents_in_hl7(message, pruned_at=pruned_at, min_bytes=min_bytes)
    if stripped == 0:
        return raw, 0, 0
    return message.encode(), stripped, reclaimed
