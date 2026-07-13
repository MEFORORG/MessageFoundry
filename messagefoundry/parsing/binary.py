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
from typing import TYPE_CHECKING, Awaitable, Callable, Iterator

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

#: The self-describing *live document-handle* marker (#149, ADR 0105). When a very-large document is
#: detached from a message into a content-addressed attachment (in-store chunks, or a #94 external
#: BLOB), the bulky value is replaced by ``mfdoc:v1:ref:<sha256>:<content-type>`` — a small, ASCII-safe
#: **live handle** that dereferences to the real bytes (contrast the ``mfdoc:v1:pruned:`` *tombstone*,
#: a DEAD placeholder for an evicted document). One pointer format + one deref seam serves both the
#: in-store chunked attachment and #94's external-BLOB offload (ADR 0105 §"unified with #94"). It shares
#: the ``mfdoc:v1:`` family prefix with the tombstone but its own ``ref:`` discriminator, so
#: :func:`is_doc_ref` and :func:`is_document_tombstone` never confuse the two.
DOC_REF_MARKER = "mfdoc:v1:ref:"

#: A content address is a lowercase-hex SHA-256 — 64 hex chars, no ``:`` — so ``mfdoc:v1:ref:<sha256>:
#: <content-type>`` splits unambiguously on the FIRST ``:`` after the marker (the hash can never contain
#: one). Validated on build + parse so a malformed handle fails loud rather than dereferencing garbage.
_SHA256_HEX_LEN = 64

__all__ = [
    "MARKER",
    "DOC_TOMBSTONE_MARKER",
    "DOC_REF_MARKER",
    "BinaryCarriageError",
    "DocRefError",
    "encode",
    "decode",
    "is_marked",
    "embed_obx_document",
    "extract_obx_document",
    "is_document_tombstone",
    "make_document_tombstone",
    "is_doc_ref",
    "make_doc_ref",
    "parse_doc_ref",
    "iter_obx_documents",
    "chunk_b64",
    "DETACH_CHUNK_BYTES",
    "strip_documents",
    "strip_documents_in_hl7",
    "reattach_documents_in_hl7",
]

#: Slice size (in base64 characters) the ingress detach cuts an oversized OBX-5.5 document into before
#: handing the pieces to the store's ``put_attachment`` (#149, ADR 0105 Phase 1a). Each slice is sealed
#: independently (a bounded plaintext window per AES-GCM seal — the whole document is never materialized
#: to seal it), and because the content address is the sha256 of the concatenated slices the chunk
#: boundary is invisible to dedup (any slicing of the same bytes yields the same ref). 1 MiB is a
#: comfortable seal window; a base64 char is one ASCII byte, so this is ~1 MiB of stored ciphertext.
DETACH_CHUNK_BYTES = 1024 * 1024


class BinaryCarriageError(ValueError):
    """A value could not be decoded as binary carriage (ADR 0028): a missing ``mfb64:v1:`` marker, or
    base64 that fails to decode (bad padding / non-alphabet content). Subclasses ``ValueError`` so a
    Router/Handler can let it propagate to the **error/dead-letter** path (status ``ERROR``) rather
    than yielding a silently-truncated body — honoring the count-and-log invariant (CLAUDE.md §2)."""


class DocRefError(ValueError):
    """A value could not be parsed as a live document handle (#149, ADR 0105): a missing
    ``mfdoc:v1:ref:`` marker, or a malformed body (a content address that is not a 64-hex SHA-256).
    Subclasses ``ValueError`` so a mis-formed handle propagates to the error/dead-letter path rather
    than dereferencing garbage."""


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


# --- live document handle (#149, ADR 0105) ----------------------------------------------------------
# A very-large document detached from a message is replaced in place by a small LIVE handle
# `mfdoc:v1:ref:<sha256>:<content-type>` (contrast the DEAD `mfdoc:v1:pruned:` tombstone above). These
# pure helpers just carry the exact bytes — under Approach B (owner ruling, ADR 0105) the attachment
# holds the OBX-5.5 value VERBATIM, so there is NO decode/encode here: the stored bytes ARE the value;
# the handle only names the content address + content-type the detach/inflate wiring (Phase 1) resolves
# through the store's `read_attachment` (in-store chunks) or #94's external-BLOB deref (one seam, both).


def is_doc_ref(value: str) -> bool:
    """Whether ``value`` is a live document handle (carries the ``mfdoc:v1:ref:`` marker). False for a
    ``mfdoc:v1:pruned:`` tombstone (a DEAD placeholder — its ``pruned:`` discriminator differs) and for
    a plain value, so the three are cleanly distinguished (mirrors :func:`is_marked` /
    :func:`is_document_tombstone`)."""
    return value.startswith(DOC_REF_MARKER)


def make_doc_ref(sha256: str, content_type: str) -> str:
    """Build a live document handle ``mfdoc:v1:ref:<sha256>:<content-type>`` (#149, ADR 0105) for a
    detached, content-addressed document. ``sha256`` is the content address (the SHA-256 hex of the
    VERBATIM document bytes — the store's ``attachment`` id, or a #94 external-BLOB key), validated to be
    64 lowercase-hex chars. ``content_type`` is sanitized of the structural characters (``:`` and HL7
    delimiters) that would re-split the field or corrupt the handle, mirroring
    :func:`make_document_tombstone`, so an arbitrary declared content-type can't break the round-trip.
    Recover the parts with :func:`parse_doc_ref`."""
    h = (sha256 or "").strip().lower()
    if len(h) != _SHA256_HEX_LEN or any(c not in "0123456789abcdef" for c in h):
        raise DocRefError(
            f"content address must be a {_SHA256_HEX_LEN}-hex SHA-256, got {sha256!r}"
        )
    safe_ct = (content_type or _UNKNOWN_CONTENT_TYPE).strip() or _UNKNOWN_CONTENT_TYPE
    for bad in ":|^~&\\\r\n":
        safe_ct = safe_ct.replace(bad, "_")
    return f"{DOC_REF_MARKER}{h}:{safe_ct}"


def parse_doc_ref(value: str) -> tuple[str, str]:
    """A live document handle → ``(sha256, content_type)`` (#149, ADR 0105). Raises :class:`DocRefError`
    if ``value`` is not a ``mfdoc:v1:ref:`` handle or the content address is not a 64-hex SHA-256. The
    content address contains no ``:``, so the remainder after the first ``:`` is the (verbatim)
    content-type — a content-type that somehow carried a ``:`` was sanitized away on
    :func:`make_doc_ref`, so this split is unambiguous."""
    if not is_doc_ref(value):
        raise DocRefError(
            "not a live document handle (missing mfdoc:v1:ref: marker); check is_doc_ref first"
        )
    body = value[len(DOC_REF_MARKER) :]
    sha256, sep, content_type = body.partition(":")
    sha256 = sha256.lower()
    if len(sha256) != _SHA256_HEX_LEN or any(c not in "0123456789abcdef" for c in sha256):
        raise DocRefError(f"malformed document handle: bad content address in {value!r}")
    if not sep or not content_type:
        raise DocRefError(f"malformed document handle: missing content-type in {value!r}")
    return sha256, content_type


# --- ingress document detach (#149, ADR 0105 Phase 1a) ----------------------------------------------
# The INGRESS-side mechanism: identify each oversized OBX-5 ED base64 document in a parsed Message so the
# pipeline can DETACH it into the store's attachment substrate (put_attachment) and replace it in place
# with a small `mfdoc:v1:ref:` handle (make_doc_ref). This is the VERBATIM (Approach B) sibling of
# strip_documents_in_hl7's tombstone strip: it reuses the SAME OBX-5 ED iteration + Message-model replace,
# but the value it lifts out is stored byte-for-byte (no decode/encode) so a later delivery can splice the
# exact bytes back. These helpers stay PURE (Message read/iterate + base64 slicing) — the async store
# put_attachment + the OBX-5.5 replace are orchestrated by the ingress path (pipeline/), which owns the
# store. The value returned per document IS the exact OBX-5.5 base64 string: the base64 alphabet carries
# no HL7 delimiter, so the message's own escaping is a no-op on it and Message.field yields it verbatim.


def iter_obx_documents(
    message: "Message", *, min_b64_len: int = 0
) -> Iterator[tuple[int, str, str]]:
    """Yield ``(occurrence, verbatim_base64, content_type)`` for every OBX-5 ED **Base64** document in
    ``message`` whose base64 length is at least ``min_b64_len`` (#149, ADR 0105 Phase 1a).

    Mirrors :func:`strip_documents_in_hl7`'s qualifying-embed scan (``OBX-2 == "ED"``, ``OBX-5.4`` is
    ``"Base64"``, ``OBX-5.5`` non-empty and not already a tombstone **or** a live ``mfdoc:v1:ref:``
    handle — a re-scan of an already-detached skeleton yields nothing, so a re-run is a no-op). The
    ``content_type`` is the ED type-of-data component (``OBX-5.2``), the same label the tombstone uses.
    Pure and read-only — the caller does the ``put_attachment`` + ``message.set("OBX-5.5", handle)``."""
    count = message.count_segments("OBX")
    for occ in range(1, count + 1):
        if (message.field("OBX-2", occurrence=occ) or "").upper() != "ED":
            continue
        if (message.field("OBX-5.4", occurrence=occ) or "").strip().lower() != _ED_ENCODING.lower():
            continue  # not Base64-encoded ED — leave it
        data_b64 = message.field("OBX-5.5", occurrence=occ) or ""
        if not data_b64 or is_document_tombstone(data_b64) or is_doc_ref(data_b64):
            continue  # empty / already-stripped / already-detached — idempotent
        if len(data_b64) < min_b64_len:
            continue
        ed_type = message.field("OBX-5.2", occurrence=occ) or _UNKNOWN_CONTENT_TYPE
        yield occ, data_b64, ed_type


def chunk_b64(b64: str, chunk_len: int = DETACH_CHUNK_BYTES) -> Iterator[str]:
    """Slice a verbatim base64 document into ``chunk_len``-char pieces for ``put_attachment`` (#149, ADR
    0105 Phase 1a) — a bounded plaintext window per AES-GCM seal, so the whole document is never
    materialized to seal it. Concatenating the pieces reconstructs the exact input, so the store's
    content address (sha256 of the concatenation) is invariant to ``chunk_len``. ``chunk_len`` must be
    positive; a non-empty document yields at least one piece (an empty one yields none — the caller
    skips empty OBX-5.5 values via :func:`iter_obx_documents`)."""
    if chunk_len <= 0:
        raise ValueError("chunk_len must be positive")
    for i in range(0, len(b64), chunk_len):
        yield b64[i : i + chunk_len]


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


# --- delivery document re-attach (#149, ADR 0105 Phase 1b) ------------------------------------------
# The DELIVERY-side inverse of the ingress detach: re-materialize each `mfdoc:v1:ref:` handle in an HL7
# skeleton back into the full inline document just before it hits the wire, so a partner (Epic's inline
# MLLP MDM receiver — no frame cap) receives the exact document the sender sent. Under Approach B (owner
# ruling, ADR 0105) the attachment holds the OBX-5.5 value VERBATIM, so this splices the exact stored
# base64 back with NO decode/encode — byte-for-byte fidelity, and a re-run/retry re-derives an identical
# frame (the attachment is immutable + content-addressed). This mirrors `strip_documents_in_hl7`'s OBX-5
# iteration + Message-model replace, but the `reader` that supplies the bytes is INJECTED so the function
# stays PURE (no store/I/O import) and unit-testable — the pipeline supplies the async `read_attachment`.


async def reattach_documents_in_hl7(
    text: str, reader: Callable[[str], Awaitable[str | None]]
) -> str:
    """Re-materialize every detached document handle in an HL7 body — the delivery-side inverse of the
    ingress detach (#149, ADR 0105 Phase 1b, Approach B — VERBATIM).

    Scans each ``OBX-5.5``; for every value that is a live ``mfdoc:v1:ref:`` handle (:func:`is_doc_ref`)
    it parses the content address (:func:`parse_doc_ref`), ``await``\\ s ``reader(sha256)`` for the stored
    VERBATIM base64 string, and splices it back into ``OBX-5.5`` **byte-for-byte** (no decode/encode — the
    exact bytes the partner sent; the base64 alphabet carries no HL7 delimiter, so the message's own
    escaping is a no-op on it). Returns the fully re-materialized HL7 text.

    ``reader`` is an INJECTED ``async`` callable (``sha256 -> verbatim base64``) so this function stays
    PURE and unit-testable: the caller (``pipeline/``) supplies the async store ``read_attachment`` read
    (run off the event loop like every store read). **Fail-loud** (owner invariant): if a value LOOKS
    like a handle but ``reader`` raises **or** returns ``None`` (the attachment is missing / GC'd), a
    :class:`DocRefError` propagates — the raw ``mfdoc:v1:ref:`` text is **never** emitted (delivering it
    into a partner's ``OBX-5.5`` would be silent corruption). A malformed handle likewise fails loud via
    :func:`parse_doc_ref`. A body with **no** handle is returned UNCHANGED (byte-identical), mirroring
    :func:`strip_documents` — so a below-threshold / no-detach delivery is untouched."""
    # Local import keeps the one-way dependency (message.py imports binary.py, never the reverse) — the
    # cycle is broken by importing inside the function, exactly as _strip_obx_ed does.
    from messagefoundry.parsing.message import Message

    message = Message.parse(text)
    reattached = 0
    count = message.count_segments("OBX")
    for occ in range(1, count + 1):
        value = message.field("OBX-5.5", occurrence=occ) or ""
        if not is_doc_ref(value):
            continue
        sha256, _content_type = parse_doc_ref(
            value
        )  # DocRefError on a malformed handle → fail loud
        verbatim = await reader(sha256)
        if verbatim is None:
            # The handle names a document the store no longer has (missing / GC'd). Fail loud rather
            # than deliver the raw handle text into the partner's OBX-5.5 (silent corruption).
            raise DocRefError(
                f"attachment {sha256!r} not found for re-attach (missing / GC'd); refusing to "
                "deliver an un-hydrated document handle"
            )
        message.set("OBX-5.5", verbatim, occurrence=occ)
        reattached += 1
    if reattached == 0:
        # No handle in any OBX-5.5 — return the ORIGINAL text unchanged (byte-identical). The caller's
        # DOC_REF_MARKER substring gate may pass on a marker sitting outside an OBX-5.5 ED value; that is
        # not a detached document, so it is carried through verbatim (mirrors strip's no-op return).
        return text
    return message.encode()
