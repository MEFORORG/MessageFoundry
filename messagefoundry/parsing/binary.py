# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import re
import time
from collections.abc import Awaitable, Callable, Collection, Iterable, Iterator
from itertools import islice
from typing import TYPE_CHECKING, Literal

from messagefoundry.parsing._builtin_hl7 import (
    _HEX_ESCAPED_CONTROLS,
    _SEPARATOR_HEAD,
    HEADER_IDS,
    CollidingDelimitersRefused,
    _extract_separators,
    _whitespace_end,
    escape_leaf,
    escape_leaf_alters,
    header_line_head,
)

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

#: A content address: ``_SHA256_HEX_LEN`` lowercase hex characters. Written as a literal so the
#: static ReDoS scan reads it.
_HEX64 = re.compile(r"[0-9a-f]{64}")

#: A content address in either case, as :func:`parse_doc_ref` accepts one, since it lowercases
#: first. Only the copy scan uses it, so a copy whose address was uppercased still counts as a
#: copy (BACKLOG #5099). A literal, for the same scan.
_HEX64_ANYCASE = re.compile(r"[0-9a-fA-F]{64}")

#: The standard base64 alphabet and its padding character: every character an ``OBX-5.5`` ED
#: Base64 value, and a handle's content address, is written in. A message that names one of them
#: as a delimiter is refused wherever a document would be detached or set back (BACKLOG #5099);
#: :func:`_delimits_with_base64` states the rule.
_BASE64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

__all__ = [
    "MARKER",
    "DOC_TOMBSTONE_MARKER",
    "DOC_REF_MARKER",
    "BinaryCarriageError",
    "DocRefError",
    "EscapedDocumentError",
    "InboundDocRefError",
    "NonVerbatimDocumentError",
    "CollidingDelimitersError",
    "CollidingDelimitersRefused",
    "Base64DelimiterError",
    "UnreattachableDocumentError",
    "encode",
    "decode",
    "is_marked",
    "embed_obx_document",
    "extract_obx_document",
    "is_document_tombstone",
    "make_document_tombstone",
    "is_doc_ref",
    "may_hold_doc_ref",
    "marker_under_base64_delimiters",
    "marker_under_colliding_delimiters",
    "colliding_marker_verdict",
    "later_header_forms_over_limit",
    "MarkerVerdict",
    "HeaderFormsLimitError",
    "make_doc_ref",
    "parse_doc_ref",
    "iter_obx_documents",
    "chunk_b64",
    "DETACH_CHUNK_BYTES",
    "strip_documents",
    "strip_documents_in_hl7",
    "doc_ref_addresses_in_hl7",
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
    """A value could not be decoded as binary carriage (ADR 0028). At least: a missing ``mfb64:v1:``
    marker, base64 that fails to decode (bad padding / non-alphabet content), and, from
    :func:`extract_obx_document`, an OBX that is not a Base64 ED document. Subclasses ``ValueError``
    so a Router/Handler can let it propagate to the **error/dead-letter** path (status ``ERROR``)
    rather than yielding a silently-truncated body — honoring the count-and-log invariant
    (CLAUDE.md §2)."""


class DocRefError(ValueError):
    """A value could not be parsed as a live document handle (#149, ADR 0105): a missing
    ``mfdoc:v1:ref:`` marker, or a malformed body (a content address that is not a 64-hex SHA-256).
    Subclasses ``ValueError`` so a mis-formed handle propagates to the error/dead-letter path rather
    than dereferencing garbage."""


class EscapedDocumentError(ValueError):
    """An OBX-5 ED Base64 document's ``OBX-5.5`` holds the message's HL7 escape character, so it
    cannot be detached verbatim (vault BACKLOG #2809). The read decodes an escape such as ``\\X0D\\``
    to the character it names, so the stored value would not be the sender's bytes, and a decoded CR
    would make every later re-attach raise. Base64 needs no escape, so the ingress detach refuses the
    message instead. The text names the OBX occurrence only, never a byte of the value."""


class InboundDocRefError(ValueError):
    """A received body's ``OBX-5.5`` already holds a live ``mfdoc:v1:ref:`` document handle
    (BACKLOG #5099). Only the engine's own detach writes a handle, after the body is received, so
    one that arrives with the body is the sender's text. The ingress detach refuses the message
    rather than treat the value as already detached. The detach raises it too for the handle
    marker elsewhere in a body it would detach a document from, and for the marker anywhere in a
    body whose header leaves two delimiters one character, where an ``OBX-5.5`` handle may not
    read as one (BACKLOG #5972). The text names at most the OBX occurrence, never a byte of the
    body."""


class HeaderFormsLimitError(InboundDocRefError):
    """A received body's later headers give more distinct forms of the handle marker than the
    detach looks for (:data:`_LATER_HEADER_FORMS_LIMIT`), so it does not
    look for each in the text and refuses the body as if it held one (BACKLOG #5972). Each form costs a substring scan of the whole body, so
    looking for every one would make the check quadratic in the body. A subclass of
    :class:`InboundDocRefError`, so both listeners refuse it the same way. The text names no byte
    of the body. The listeners' shared check runs first on the same text and refuses every body
    past the limit (:func:`later_header_forms_over_limit`), so from them this is a defensive
    refusal for a caller of the detach that skipped that check."""


class NonVerbatimDocumentError(ValueError):
    """A received body has a document to detach that delivery's splice would not set back verbatim
    under the body's own delimiters (BACKLOG #5099). ``Message.set`` escapes each character
    :meth:`Message._escape_leaf` changes, such as the subcomponent separator ``&`` or a control
    character in a value that is not base64, so the partner would get a document that is not the
    sender's. Refused at the detach, before anything is stored and before the ACK, as
    :class:`EscapedDocumentError` is. The text names the OBX occurrence only, never a byte of the
    value."""


class CollidingDelimitersError(NonVerbatimDocumentError, CollidingDelimitersRefused):
    """A received body claims a document, an OBX whose ``OBX-2`` is ``ED``, and its header names
    too few encoding characters while a default filled in for one is already another of its
    delimiters, as
    ``MSH|^~&|`` does: ``&`` is declared its escape character and filled in as its subcomponent
    separator (BACKLOG #5972). ``Message`` refuses every write to such a message, so the detach
    could not set its handle in, nor delivery set the document back. Refused at the detach,
    before anything is stored and before the ACK. A subclass of :class:`NonVerbatimDocumentError`,
    so both listeners refuse it the same way, and of :class:`CollidingDelimitersRefused`, the
    refusal ``Message``'s writes and ``extract_obx_document`` raise for the same header, so one
    ``except`` catches the header's refusal from any of them. The text names no byte of the body.

    Raised once for a body under such a header when any of its OBX segments has ``OBX-2``
    ``ED``, whether or not its OBX-5 components still read: under ``MSH|~|`` none does, so the
    scan finds no document, and the claim is refused rather than ACKed and carried undetached.
    A body under such a header that holds the handle marker, raw or as its headers' delimiters
    escape it, is refused first, as :class:`InboundDocRefError`, so a received handle in an
    ``OBX-5.5``, raw or so escaped, is refused as one whether or not that ``OBX-5.5`` reads. One
    hidden behind a hex escape is not looked for in the text, so under an ED claim it meets this
    refusal instead."""


class Base64DelimiterError(InboundDocRefError):
    """A received body would have a document detached, and its MSH-1 or MSH-2 names a character of
    the base64 alphabet as a delimiter (BACKLOG #5099). ``Message.set`` escapes that character
    when delivery sets the stored value back, so the partner would get a document that is not the
    sender's. Refused at the detach, before anything is stored and before the ACK. Checked on the
    delimiters rather than on each value, since a field, component or repetition separator splits
    the value before a value check could see it. A subclass of :class:`InboundDocRefError`, so
    both listeners refuse it the same way. The text names no byte of the body."""


class UnreattachableDocumentError(ValueError):
    """The payload itself stops a re-attach (vault BACKLOG #2809, BACKLOG #5099). At least these
    shapes: the parser refuses the payload as not HL7 (an ``HL7PeekError`` without ``parser_fault``
    set); an ``OBX-5.5`` handle is malformed; a
    handle names an attachment its own message does not hold; a handle sits somewhere the
    re-attach does not splice, such as ``NTE-3`` or a second ``OBX-5.5`` repetition; or a
    delimiter is a character of the base64 alphabet while a handle, or the marker, is in the
    payload (:func:`_delimits_with_base64`); or the splice would escape a character of a stored
    value under the payload's delimiters, so the partner would not get it verbatim. The same
    payload fails the same way on every attempt, so the delivery path refuses it permanently.
    Every other
    ``ValueError`` in the re-attach may be an engine fault and stays the outbound's internal-error
    policy to judge, at least a parser fault and a stored document that holds a CR or LF. The
    ingress detach refuses an escape and a raw LF ends the segment, so no payload can leave a stored
    CR or LF. The text names the step, never a byte of the payload."""


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


def _b64decoded_size(text: str) -> int:
    """Size normal base64 without allocating its decoded document.

    Keep the decoder as the authority for noncanonical forms, including surplus
    padding accepted by some Python versions. Whitespace matches _b64decode.
    """
    compact = "".join(text.split())
    if len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
        padding = 2 if compact.endswith("==") else int(compact.endswith("="))
        return len(compact) // 4 * 3 - padding
    return len(_b64decode(text))


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
    data is corrupt — so a Handler can dead-letter rather than mis-decode.

    Raises :class:`CollidingDelimitersRefused`, a ``ValueError`` and not a
    :class:`BinaryCarriageError`, when that OBX's ``OBX-2`` is ``ED`` and the message's short
    MSH-2 leaves its separators not distinct (BACKLOG #5972): under ``MSH|~|`` no OBX-5
    component reads where it was written, so a Handler that skips a ``BinaryCarriageError``
    would drop the document with no trace, where this error escapes to ``ERROR``. ``OBX-2`` is
    a whole field, split on the field separator before any other, so it reads as written under
    such a header too. An OBX that is absent or not ``ED`` is refused as it is in any message,
    with a ``BinaryCarriageError``."""
    if not _obx_is_ed(message, occurrence):
        obx2 = message.field("OBX-2", occurrence=occurrence)
        raise BinaryCarriageError(f"OBX-2 is {obx2!r}, not 'ED' — not an embedded document")
    if message._delimiters_collide():
        raise CollidingDelimitersRefused(
            "the message header leaves two of its delimiters one character, so its OBX-5 "
            "components cannot be read as written; refusing rather than report no document"
        )
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


#: Every character of the handle marker. A payload whose MSH-1 or MSH-2 names one of them as a
#: separator or the escape character carries an engine handle escaped, so the marker is not in its
#: raw text (BACKLOG #5099).
_DOC_REF_MARKER_CHARS = frozenset(DOC_REF_MARKER)

#: The characters a header line after the first follows. A Handler can wrap an MSH-led payload
#: in an FHS or BHS envelope of other delimiters, or nest a BHS in an FHS, and any of those
#: headers' own may then have escaped the handle. The gate finds each header id with
#: ``str.find``, one scan per id, and checks the character before it: one regex scan of a large
#: payload cost some twenty times the marker's own substring test.
#: The same two characters end the parser's read of a header line.
_SEGMENT_BREAKS = frozenset("\r\n")

#: The re-attach's refusal of a payload whose later headers give more distinct forms of the
#: handle marker than :data:`_LATER_HEADER_FORMS_LIMIT`, so it does not look for each (BACKLOG
#: #5972).
_TOO_MANY_HEADER_FORMS_TO_REATTACH = (
    "the later headers name delimiters that escape the document handle marker in more distinct "
    "ways than are looked for, so the re-attach cannot check it"
)

#: The re-attach's refusal of a payload whose later header names other delimiters than its
#: first line, and holds the handle marker as those escape it (BACKLOG #5972).
_MIXED_HEADER_HANDLE = (
    "a header after the first names other delimiters, and the payload holds the document "
    "handle marker as they escape it, so the re-attach cannot read that handle"
)

#: The most distinct forms of the handle marker, as the later headers of one body escape it,
#: that the marker checks look for in its text, whatever its size (BACKLOG #5972): the
#: listeners' shared check, the ingress detach and the delivery re-attach. Each form costs a
#: substring scan of the whole body, the listeners' on the event loop and the re-attach's on
#: every delivery attempt, so a body whose headers give more is judged without those scans and
#: refused (fail closed), and each check stays linear in the body
#: (:func:`later_header_forms_over_limit`). The limit does not depend on the length, and the
#: count is read from the header lines alone, which the detach does not change, so a skeleton
#: the detach grew past its received body gives the re-attach the count the listeners
#: admitted. A form differs from the first line's only where a later header names other
#: delimiters that escape a character of the marker, so an ordinary batch gives none.
_LATER_HEADER_FORMS_LIMIT = 4

#: The verdict of the marker test the checks before the ACK share (:func:`_body_marker_verdict`):
#: ``"held"`` when the text holds the marker in a form looked for, and ``"over-limit"`` when the
#: later headers give more forms than :data:`_LATER_HEADER_FORMS_LIMIT` and none of the
#: first line's forms was found, so the rest were not looked for.
MarkerVerdict = Literal["held", "over-limit"]

#: The detach's refusal of a body whose later headers give more marker forms than it looks for.
_TOO_MANY_HEADER_FORMS = (
    "the later headers name delimiters that escape the document handle marker in more distinct "
    "ways than are looked for; refusing the body as if it held the marker"
)

#: The re-attach's refusal of a handle in a payload whose header fills a delimiter it does not
#: name with one it already uses: no write to it can be read back (BACKLOG #5972).
_COLLIDING_HANDLE = (
    "the payload's header fills a delimiter it does not name with one it already uses, so a "
    "document cannot be set back"
)

#: The re-attach's refusal of a handle marker the splice did not resolve (BACKLOG #5099).
_UNSPLICED_HANDLE = "a document handle marker was left that the re-attach splice did not resolve"

#: The re-attach's refusal of a handle it would set back under base64 delimiters (BACKLOG #5099).
_BASE64_DELIMITED_HANDLE = (
    "the payload's delimiters include a base64 character, so a document cannot be set back verbatim"
)


def _delimits_with_base64(separators: Iterable[str]) -> bool:
    """Whether any of a message's five delimiters, read as ``Message._encoding_chars`` reads them
    (the ones the parser read from the first line), is a character of
    :data:`_BASE64_ALPHABET` (BACKLOG #5099).

    The one delimiter-class rule. ``Message.set`` escapes a delimiter wherever it occurs in a
    value, so a subcomponent separator in the alphabet is escaped inside a document set back into
    ``OBX-5.5``, and any of them may be inside a copied content address, which then may not read
    as one. A field, component or repetition separator in the alphabet instead splits a document
    across fields, components or repetitions, so the detach would store a fragment of it. ADR
    0105 records where the rule is applied. Ordinary delimiters, ``|^~\\&`` and the common
    variants, hold no base64 character and are untouched."""
    return not _BASE64_ALPHABET.isdisjoint(separators)


def _marker_forms(separators: tuple[str, str, str, str, str]) -> tuple[str, ...]:
    """The handle marker as ``Message.set`` writes it under ``separators`` (a handle the engine
    wrote, or a Handler copied into a component), and the raw marker, which a whole-field set
    leaves unescaped where the delimiters would escape it. One entry when the two agree."""
    from messagefoundry.parsing.message import Message

    marker = Message._escape_leaf(DOC_REF_MARKER, *separators)
    return (marker, DOC_REF_MARKER) if marker != DOC_REF_MARKER else (marker,)


def _holds_marker(text: str, separators: tuple[str, str, str, str, str]) -> bool:
    """Whether ``text`` holds the handle marker in any of :func:`_marker_forms`: one substring scan
    per form, and no copy."""
    return any(m in text for m in _marker_forms(separators))


def marker_under_base64_delimiters(message: Message, text: str) -> bool:
    """Whether a received HL7 body names a base64 character as a delimiter
    (:func:`_delimits_with_base64`) and holds the handle marker, raw or as its delimiters escape
    it (BACKLOG #5099). Both listeners refuse such a body before the ACK, whatever its size: the
    delivery re-attach refuses any marker under these delimiters, so it would be ACKed and then
    dead-letter on every outbound.

    ``message`` is ``text`` parsed. For ordinary delimiters the cost is the delimiter read alone; otherwise at most two substring scans of ``text``. A marker hidden behind
    a hex escape is not looked for: the engine never writes one, so it is the sender's text."""
    separators = message._encoding_chars()
    return _delimits_with_base64(separators) and _holds_marker(text, separators)


def marker_under_colliding_delimiters(message: Message, text: str) -> bool:
    """Whether the colliding-header rule refuses a received HL7 body: its first line fills a
    delimiter it does not name with one it already uses (``Message._delimiters_collide``, as
    ``MSH|~|`` does) and the body holds the handle marker, raw or as its first line's or a later
    header's delimiters escape it, or its later headers give more forms than are looked for
    (:func:`_body_marker_verdict`; :func:`colliding_marker_verdict` says which, BACKLOG #5972).
    Both listeners refuse such a body before the ACK, whatever its size. ``Message`` refuses every write to it, so no document of it is ever
    detached, and under some such headers no ``OBX-5.5`` reads, so a sender's handle there is not
    read as one: the re-attach then refuses a copy naming a content address on every outbound,
    after the ACK. The rule judges the text, not where in it the marker sits, so it refuses a bare
    marker too, under every such header, those whose ``OBX-5`` components still read included,
    although delivery carries a bare marker that names no content address: where a header hides
    the components, no read tells whether a marker sits where a handle would.

    ``message`` is ``text`` parsed. For a header that does not collide the cost is the header
    read alone; otherwise up to two substring scans of ``text``, plus one per distinct marker form
    a later header naming other delimiters gives, at most :data:`_LATER_HEADER_FORMS_LIMIT`.
    A body whose later headers give more is refused without those scans
    (fail closed), so the check stays linear in the body. A
    marker hidden behind a hex escape is not looked for, as in
    :func:`marker_under_base64_delimiters`."""
    return colliding_marker_verdict(message, text) is not None


def colliding_marker_verdict(message: Message, text: str) -> MarkerVerdict | None:
    """Why :func:`marker_under_colliding_delimiters` refuses ``text``, or ``None`` where it does
    not: ``"held"`` where the body holds the handle marker in a form looked for, and
    ``"over-limit"`` where its later headers give more forms than are looked for and the first
    line's were not found (:data:`MarkerVerdict`, BACKLOG #5972). One call reads the header fields
    once and costs what that function's docstring says, so a caller choosing a reason by it does
    not run the test twice."""
    if not message._delimiters_collide():
        return None
    return _body_marker_verdict(message, text)


def later_header_forms_over_limit(message: Message) -> bool:
    """Whether the later header lines of ``message`` give more distinct forms of the handle
    marker than :data:`_LATER_HEADER_FORMS_LIMIT` (BACKLOG #5972).
    ``ingress_guards.doc_ref_marker_refusal`` refuses such a body before the ACK whatever its
    first header, because the delivery re-attach looks for each form with a scan of the payload on
    every attempt and refuses a payload past the same limit. Reads the parsed header fields only,
    at most one form past the limit, and scans no text."""
    return _bounded_later_header_forms(message) is None


def may_hold_doc_ref(text: str) -> bool:
    """Whether a delivery payload may carry a live document handle the re-attach must resolve
    (BACKLOG #5099). The delivery path's cheap gate ahead of a parse.

    True when the marker is in the raw text. Also true for an HL7 payload whose leading MSH, FHS
    or BHS header names a character of the marker in its fields 1 and 2: there an engine handle
    written into ``OBX-5.5`` is escaped, so the raw text never holds the marker, and a substring
    test alone let the handle reach the wire unresolved. ``Message.set`` escapes by the delimiters
    the parser read from that first line (BACKLOG #5972), but a payload may wrap a message, or a
    batch, written under its own header's delimiters, so every later MSH, BHS or FHS line is
    checked as well; the re-attach judges a marker escaped by one of them as a copy, refusing it
    where the payload holds a handle or a document or the marker names a content address. A handle hidden by
    any other escape cannot be the engine's, which escapes only the delimiters, so it is the
    sender's text and resolves nothing unless the gate opens for another reason, where the
    re-attach parses it and resolves it only to an attachment the message holds. False otherwise."""
    if DOC_REF_MARKER in text:
        return True
    lead = _whitespace_end(text, 0, len(text))
    if text[lead : lead + 3] not in HEADER_IDS:
        return False
    if _header_names_marker_char(text, lead):
        return True
    for seg_id in HEADER_IDS:
        at = text.find(seg_id, lead + 1)
        while at != -1:
            if text[at - 1] in _SEGMENT_BREAKS and _header_names_marker_char(text, at):
                return True
            at = text.find(seg_id, at + 1)
    return False


def _header_names_marker_char(text: str, start: int) -> bool:
    """Whether the MSH, FHS or BHS segment at ``start`` names a character of the marker as a
    separator or the escape character, read as the parser reads them (its defaults fill a short
    MSH-2, which only opens the gate wider). The read stops at the end of that line, as the
    parser's does, so no separator is taken from the next line."""
    line = text[start : start + _SEPARATOR_HEAD]
    line = line.split("\r", 1)[0].split("\n", 1)[0]
    if len(line) < 4:
        return False
    return not _DOC_REF_MARKER_CHARS.isdisjoint(_extract_separators(line))


def make_doc_ref(sha256: str, content_type: str) -> str:
    """Build a live document handle ``mfdoc:v1:ref:<sha256>:<content-type>`` (#149, ADR 0105) for a
    detached, content-addressed document. ``sha256`` is the content address (the SHA-256 hex of the
    VERBATIM document bytes — the store's ``attachment`` id, or a #94 external-BLOB key), validated to be
    64 lowercase-hex chars. ``content_type`` is sanitized of the structural characters (``:`` and HL7
    delimiters) that would re-split the field or corrupt the handle, mirroring
    :func:`make_document_tombstone`, so an arbitrary declared content-type can't break the round-trip.
    Recover the parts with :func:`parse_doc_ref`."""
    h = (sha256 or "").strip().lower()
    if not _HEX64.fullmatch(h):
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
    if not _HEX64.fullmatch(sha256):
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
# A value that holds the escape character anyway is refused rather than yielded (vault BACKLOG #2809).


def _obx_5_5_holds_escape(message: Message, occurrence: int) -> bool:
    """Whether the RAW (still escaped) ``OBX-5.5`` text of that OBX holds the message's escape
    character. ``Message.field`` decodes escapes on a component read, so the raw field is scanned by
    position instead, on the first repetition as that read takes it. Nothing is copied, and clean
    base64 costs one scan for the escape character from the start of component 5."""
    _field_sep, comp_sep, rep_sep, esc, _sub_sep = message._encoding_chars()
    raw = message.field("OBX-5", occurrence=occurrence) or ""
    start = 0
    for _ in range(4):  # past the separators ahead of component 5
        start = raw.find(comp_sep, start)
        if start == -1:
            return False
        start += 1
    if raw.find(rep_sep, 0, start) != -1:
        return False  # the first repetition ends before component 5
    hit = raw.find(esc, start)
    # The escape counts only if no separator closes component 5 before it.
    return (
        hit != -1 and raw.find(comp_sep, start, hit) == -1 and raw.find(rep_sep, start, hit) == -1
    )


def _obx_is_ed(message: Message, occurrence: int) -> bool:
    """Whether that OBX's ``OBX-2`` is ``ED``, the claim that it carries an embedded document."""
    return (message.field("OBX-2", occurrence=occurrence) or "").upper() == "ED"


def _holds_ed_claim(message: Message) -> bool:
    """Whether any OBX of ``message`` has ``OBX-2`` ``ED``, the claim a colliding header's refusers
    judge (BACKLOG #5972). ``OBX-2`` is a whole field, split on the field separator before any
    other, so it reads as written under such a header too, where an OBX-5 component may not."""
    return any(_obx_is_ed(message, occ) for occ in range(1, message.count_segments("OBX") + 1))


def _is_base64_ed(message: Message, occurrence: int) -> bool:
    """Whether that OBX carries an ED value encoded ``Base64`` (``OBX-2`` and ``OBX-5.4``)."""
    if not _obx_is_ed(message, occurrence):
        return False
    encoding = message.field("OBX-5.4", occurrence=occurrence) or ""
    return encoding.strip().lower() == _ED_ENCODING.lower()


def iter_obx_documents(
    message: Message, *, received: str, min_b64_len: int = 0
) -> Iterator[tuple[int, str, str]]:
    """Yield ``(occurrence, verbatim_base64, content_type)`` for every OBX-5 ED **Base64** document in
    ``message`` whose base64 length is at least ``min_b64_len`` (#149, ADR 0105 Phase 1a).

    Mirrors :func:`strip_documents_in_hl7`'s qualifying-embed scan (``OBX-2 == "ED"``, ``OBX-5.4`` is
    ``"Base64"``, ``OBX-5.5`` non-empty and not already a tombstone). It runs once, on the received
    body, never on a skeleton, so a live ``mfdoc:v1:ref:`` handle is refused below rather than
    skipped as already detached (BACKLOG #5099). The
    ``content_type`` is the ED type-of-data component (``OBX-5.2``), the same label the tombstone uses.
    Pure and read-only — the caller does the ``put_attachment`` + ``message.set("OBX-5.5", handle)``.

    ``received`` is the text ``message`` was parsed from, and is required: the marker check below
    reads it, so a caller cannot skip that check by leaving it out (BACKLOG #5099).

    Raises :class:`EscapedDocumentError` when any ED Base64 ``OBX-5.5`` holds the escape character,
    whose value would be decoded rather than verbatim (vault BACKLOG #2809), and
    :class:`InboundDocRefError` when any ``OBX-5.5``, ED or not, already holds a live handle: only
    this detach writes one, so a received one is the sender's (BACKLOG #5099). Under a header whose
    filled default collides, the header's verdicts below come first instead, so such a handle is
    refused by one of them where they apply. Every refusal comes before the first document is
    yielded, so a caller that stores each one as it goes has stored none of them when it comes.

    It raises :class:`InboundDocRefError` too when a document would be detached and the body holds
    the handle marker anywhere else: in a document's value past its start, or anywhere in
    ``received``, raw or as the message's delimiters escape it. Delivery refuses a marker left after
    the splice (:func:`reattach_documents_in_hl7`), so such a body would be ACKed and then
    dead-letter on every outbound. No base64 value holds the marker, since base64 has no ``:``, so
    the refusal turns away no document a conformant sender sends.

    It raises :class:`Base64DelimiterError`, an :class:`InboundDocRefError`, when a document would
    be detached and a delimiter is a character of the base64 alphabet
    (:func:`_delimits_with_base64`): delivery could not set the value back verbatim, so it would
    refuse the handle after the ACK. It raises :class:`NonVerbatimDocumentError` when a
    document's own value holds a character the splice would escape under the body's own
    delimiters: a document is detached only if splicing it back under them reproduces it exactly.
    A Handler that moves ``MSH-1`` or ``MSH-2`` afterwards is caught by the re-attach instead.
    It raises :class:`CollidingDelimitersError`, a :class:`NonVerbatimDocumentError`, when the
    body's short MSH-2 leaves its separators not distinct and an OBX claims a document, its
    ``OBX-2`` ``ED`` (:func:`_holds_ed_claim`): ``Message`` refuses every write to such a body, so
    no document of it could be detached and set back (BACKLOG #5972). The claim is judged, not a
    document the scan found, because under some such headers, ``MSH|~|`` among them, no OBX-5
    component reads as written, so the scan finds none and the body would be ACKed with its
    document in it. So an ED value the detach would not lift out under a readable header is
    refused too, at least one not Base64, empty, a tombstone or under ``min_b64_len``, as every
    OBX under a short MSH-2 was before. Under such a header it raises :class:`InboundDocRefError`
    first, whatever the OBX segments claim, when ``received`` holds the handle marker
    (:func:`marker_under_colliding_delimiters`, the rule both listeners refuse by at any size):
    under ``MSH|~|`` no ``OBX-5.5`` reads, so a sender's handle there is not read as one. Both
    verdicts come before any ``OBX-5`` value is read: a body refused for its header has its
    received text scanned for the marker, up to two substring scans plus one per distinct form a
    later header naming other delimiters gives, at most :data:`_LATER_HEADER_FORMS_LIMIT`, and
    no value read or splice-scanned. A body whose later headers give more, and whose
    first line's forms are not found, is refused without those scans, as
    :class:`HeaderFormsLimitError`, under any header the marker test runs under. A handle hidden behind a hex
    escape, which the engine never writes, is not looked for in the text, so under such a header
    it is refused as a received handle only where no OBX claims a document and its ``OBX-5.5``
    reads; where an OBX claims one, the claim refuses the body.

    Each document's value is held one at a time, as the caller's in-flight budget assumes: each
    check reads a value inside :func:`_scan_obx`, whose frame ends before the next read, and the
    value is read again when it is yielded and dropped after. No check makes a copy of a value:
    the marker and splice checks scan it in place. What each read holds beside the value is the
    copy of its field that the read splits, dropped when the read returns. Holding every value
    until the scan ends would make the peak the sum of the documents."""
    if message._delimiters_collide():
        # Judged before any OBX-5 value is read, so a body refused here has no value read or
        # splice-scanned: no document of it can be detached, since Message refuses every write
        # to it. The marker comes first, so a received handle is refused as one wherever it
        # sits, in an OBX-5.5 such a header hides included, where the per-OBX read finds none.
        verdict = _body_marker_verdict(message, received)
        if verdict == "over-limit":
            raise HeaderFormsLimitError(_TOO_MANY_HEADER_FORMS)
        if verdict == "held":
            raise InboundDocRefError(
                "the body holds the document handle marker under a header that fills a delimiter "
                "it does not name with one it already uses, where an OBX-5.5 handle may not read "
                "as one and no document can be detached; refusing the body"
            )
        # A detachable document is an ED claim, so the claim alone is judged.
        if _holds_ed_claim(message):
            raise CollidingDelimitersError(
                "an OBX claims a document under a header that fills a delimiter it does not name "
                "with one it already uses, so the message cannot be written and no document of it "
                "could be detached and set back; refusing the detach"
            )
    obx_count = message.count_segments("OBX")
    occurrences: list[int] = []
    documents: list[int] = []
    value_holds_marker = False
    altered: int | None = None
    for occ in range(1, obx_count + 1):
        is_ed, detachable, holds_marker, alters = _scan_obx(message, occ, min_b64_len)
        if is_ed:
            occurrences.append(occ)
        if detachable:
            documents.append(occ)
            value_holds_marker = value_holds_marker or holds_marker
            if alters and altered is None:
                altered = occ
    if documents and _delimits_with_base64(message._encoding_chars()):
        raise Base64DelimiterError(
            "a delimiter of the body is a base64 character, so a detached document could not be "
            "set back verbatim; refusing the detach"
        )
    for occ in occurrences:
        if _obx_5_5_holds_escape(message, occ):
            raise EscapedDocumentError(
                f"OBX occurrence {occ}: the Base64 document in OBX-5.5 holds an HL7 escape "
                "sequence, which base64 never needs; refusing to detach a value that is not the "
                "sender's verbatim bytes"
            )
    if altered is not None:
        raise NonVerbatimDocumentError(
            f"OBX occurrence {altered}: the document in OBX-5.5 holds a character delivery would "
            "escape when it set the value back, so the partner would not get it verbatim; "
            "refusing the detach"
        )
    body_verdict: MarkerVerdict | None = None
    if documents:
        body_verdict = "held" if value_holds_marker else _body_marker_verdict(message, received)
    if body_verdict == "over-limit":
        raise HeaderFormsLimitError(_TOO_MANY_HEADER_FORMS)
    if body_verdict == "held":
        raise InboundDocRefError(
            "the body holds the document handle marker outside an OBX-5.5 start, and a document "
            "would be detached from it; refusing a body delivery would refuse after the ACK"
        )
    for occ in documents:
        # OBX-5.2 first: its read splits OBX-5 into a copy of the whole field, which would sit
        # beside the value if the value were read first.
        ed_type = message.field("OBX-5.2", occurrence=occ) or _UNKNOWN_CONTENT_TYPE
        data_b64 = message.field("OBX-5.5", occurrence=occ) or ""
        yield occ, data_b64, ed_type
        # Dropped before the next read, so no two documents' values are held here at once.
        del data_b64


def _scan_obx(message: Message, occ: int, min_b64_len: int) -> tuple[bool, bool, bool, bool]:
    """Read one OBX's ``OBX-5.5`` for :func:`iter_obx_documents` and return whether the OBX is ED
    Base64, whether its value is a document the detach lifts out, whether that value holds the
    handle marker, and whether delivery's splice, escaping under the message's own delimiters,
    would alter it. The value lives only in this frame, and is read after the OBX-2 and OBX-5.4
    reads, whose splits copy the field and are dropped first, so the scan holds one value at a
    time; the marker and splice checks scan the value in place and copy none of it. Raises
    :class:`InboundDocRefError` when the value is a live handle (BACKLOG #5099): every OBX is
    read, as the delivery re-attach resolves a handle in any ``OBX-5.5`` first repetition."""
    is_ed = _is_base64_ed(message, occ)
    value = message.field("OBX-5.5", occurrence=occ) or ""
    if is_doc_ref(value):
        raise InboundDocRefError(
            f"OBX occurrence {occ}: OBX-5.5 already holds a document handle, which only the "
            "engine writes; refusing a received value that would name a stored attachment"
        )
    if not is_ed:
        return False, False, False, False
    # Not a tombstone: one resolves nothing, so it rides as text.
    detachable = bool(value) and not is_document_tombstone(value) and len(value) >= min_b64_len
    # Kept beside the whole-body check: unlike that one, it does not rest on ``received`` being
    # the text the message was parsed from. It costs one pass over the value.
    holds_marker = detachable and DOC_REF_MARKER in value
    alters = detachable and _splice_alters(value, message._encoding_chars())
    del value
    return True, detachable, holds_marker, alters


def _splice_alters(value: str, separators: tuple[str, str, str, str, str]) -> bool:
    """Whether delivery's splice would not set ``value`` back verbatim under ``separators``, the
    ``(field, component, repetition, escape, subcomponent)`` tuple ``Message._encoding_chars``
    returns: ``Message.set`` applies ``Message._escape_leaf`` to a component value (BACKLOG
    #5099). Answered by :func:`escape_leaf_alters`, which builds no escaped copy and is linear in
    the value: the detach runs this on a sender's value before the ACK, and the escape itself was
    measured slower than linear on a hostile one."""
    field_sep, comp_sep, rep_sep, esc, sub_sep = separators
    # escape_leaf_alters takes the order escape_leaf does, as Message._escape_leaf passes it.
    return escape_leaf_alters(value, (field_sep, comp_sep, rep_sep, sub_sep, esc))


def _received_holds_marker(message: Message, received: str) -> bool:
    """Whether ``received`` holds the handle marker anywhere, raw or escaped by the message's
    delimiters: where a detach would leave it for delivery's after-the-splice guard to find
    (BACKLOG #5099). Reads the text the caller already holds, and copies no document."""
    return _holds_marker(received, message._encoding_chars())


def _body_marker_verdict(message: Message, received: str) -> MarkerVerdict | None:
    """Whether ``received`` holds the handle marker raw, as the message's first line escapes it
    (:func:`_received_holds_marker`), or as a later header naming other delimiters escapes it:
    the one marker test the detach and the colliding-header listener refusal share (BACKLOG
    #5099, #5972), as a :data:`MarkerVerdict`. The later headers' forms are each looked for once,
    as :func:`_later_header_markers` looks, while they number at most
    :data:`_LATER_HEADER_FORMS_LIMIT`; past it the verdict is
    ``"over-limit"`` without those scans (fail closed), so the test costs at most that many scans
    plus two, linear in the body however many headers it has, and reads the header fields once."""
    if _received_holds_marker(message, received):
        return "held"
    forms = _bounded_later_header_forms(message)
    if forms is None:
        return "over-limit"
    return "held" if any(form in received for form in forms) else None


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
    on_unwritable: Callable[[], object] | None = None,
) -> tuple[str, int, int]:
    """Strip embedded documents from a stored ``raw`` body in place, returning
    ``(new_raw, documents_stripped, bytes_reclaimed)`` (#47, ADR 0042).

    Two carriage forms are handled, codec-driven (never raw string-slicing):

    * a **whole-body ``mfb64:v1:`` carriage value** (ADR 0028) → the whole body becomes a tombstone;
    * an **HL7 message carrying OBX-5 ED embeds** → each qualifying OBX-5 value is tombstoned via the
      parsed :class:`Message` model and the message is re-encoded (so it re-parses cleanly).

    Anything else is returned unchanged with ``(raw, 0, 0)``, so the caller can skip a no-op
    write and the pass is idempotent. At least: plain HL7 with no ED; a body whose first eight
    characters do not hold ``MSH``, such as an FHS- or BHS-led batch, whatever segments follow;
    JSON/XML/text; an already-stripped tombstone.

    ``min_bytes`` skips a document whose decoded size is below the threshold (small embeds aren't worth
    evicting; ``0`` = strip every embed). ``content_type`` (the connection's declared format) labels a
    bare-mfb64 tombstone; an OBX-5 ED tombstone is labelled from the segment's own ED type component.
    ``bytes_reclaimed`` is the *base64* length removed (the stored, on-disk cost), not the decoded
    size.

    ``on_unwritable`` is called, with nothing, once for an HL7 body returned unchanged because its
    short MSH-2 fills a delimiter with one it already uses, so no write to it can be read back
    (BACKLOG #5972), when one of its OBX segments has ``OBX-2`` ``ED``: the document it claims
    outlives its strip window. The claim is all it judges, since under some such headers no OBX-5
    component reads as written, so it is called too for an ED value the strip would not strip
    under a readable header, such as one under ``min_bytes``, not Base64, or empty."""
    pruned_at = time.time() if pruned_at is None else pruned_at
    if is_document_tombstone(raw):
        return raw, 0, 0  # already stripped — idempotent
    if is_marked(raw):
        return _strip_whole_body_mfb64(raw, pruned_at, min_bytes, content_type)
    if "OBX" in raw and "MSH" in raw[:8]:
        # Only attempt the HL7/OBX path on something that looks like an HL7 message (starts with MSH).
        # A non-HL7 body that merely contains the substring "OBX" is left untouched by the parse guard
        # below (a parse failure / no OBX-5 ED → returned unchanged).
        return _strip_obx_ed(raw, pruned_at, min_bytes, on_unwritable)
    return raw, 0, 0


def _strip_whole_body_mfb64(
    raw: str, pruned_at: float, min_bytes: int, content_type: str | None
) -> tuple[str, int, int]:
    """Strip a whole-body ``mfb64:v1:`` carriage value (ADR 0028) to a tombstone."""
    b64 = raw[len(MARKER) :]
    try:
        size = _b64decoded_size(b64)
    except BinaryCarriageError:
        # A corrupt carriage value: leave it for the operator to see rather than guess its size.
        return raw, 0, 0
    if size < min_bytes:
        return raw, 0, 0
    tombstone = make_document_tombstone(size, content_type or _UNKNOWN_CONTENT_TYPE, pruned_at)
    return tombstone, 1, len(raw) - len(tombstone)


def strip_documents_in_hl7(
    message: Message, *, pruned_at: float | None = None, min_bytes: int = 0
) -> tuple[int, int]:
    """Strip every qualifying OBX-5 ED embedded document from a parsed :class:`Message` **in place**,
    returning ``(documents_stripped, bytes_reclaimed)``. The message is mutated through its own API
    (reads the message's delimiters, escapes the tombstone as a leaf value) so a re-encode round-trips and
    re-parses. Used by :func:`strip_documents` and directly testable against a parsed message."""
    pruned_at = time.time() if pruned_at is None else pruned_at
    stripped = 0
    reclaimed = 0
    count = message.count_segments("OBX")
    for occ in range(1, count + 1):
        if not _is_base64_ed(message, occ):
            continue  # not Base64-encoded ED — leave it
        data_b64 = message.field("OBX-5.5", occurrence=occ) or ""
        if not data_b64 or is_document_tombstone(data_b64):
            continue  # empty or already-stripped — idempotent
        try:
            size = _b64decoded_size(data_b64)
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


def _strip_obx_ed(
    raw: str, pruned_at: float, min_bytes: int, on_unwritable: Callable[[], object] | None
) -> tuple[str, int, int]:
    """Parse ``raw`` as HL7, strip its OBX-5 ED embeds, and re-encode. Returns the original unchanged on
    a parse failure, on a header ``Message`` refuses every write to (a short MSH-2 whose separators
    repeat, BACKLOG #5972; calling ``on_unwritable`` first where an OBX claims a document), or when
    nothing was stripped (so the caller skips the write)."""
    # Local import keeps the one-way dependency (message.py imports binary.py, never the reverse) — the
    # cycle is broken by importing inside the function, not at module top.
    from messagefoundry.parsing.message import Message

    try:
        message = Message.parse(raw)
    except Exception:
        # A malformed body that merely looked like HL7 — never crash a retention pass on it.
        return raw, 0, 0
    if message._delimiters_collide():
        # No write to it can be read back, so no document of it can be tombstoned, and under
        # some such headers, MSH|~| among them, no OBX-5 component even reads as written. An
        # OBX whose OBX-2 is ED claims a document: OBX-2 is a whole field, which these headers
        # do not disturb. That document outlives its strip window, so it is reported, not
        # silent; the caller holds the row id and logs it, so this pure codec logs nothing.
        if on_unwritable is not None and _holds_ed_claim(message):
            on_unwritable()
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


def _copy_names_address(text: str, marker: str) -> bool:
    """Whether some occurrence of ``marker``, the handle marker as the payload's delimiters escape
    it, is immediately followed in ``text`` by a content address, 64 hex characters in either
    case, as :func:`parse_doc_ref` reads one: a handle copy, not a bare marker. Overlapping
    occurrences each count, and nothing need follow the address."""
    # No regex is built from the marker: a pattern read at run time is one the static ReDoS scan
    # cannot check. The per-hit test is the literal _HEX64_ANYCASE, matched in place without a copy.
    start = text.find(marker)
    while start != -1:
        if _HEX64_ANYCASE.match(text, start + len(marker)):
            return True
        start = text.find(marker, start + 1)
    return False


def _later_header_forms(message: Message) -> Iterator[str]:
    """Each distinct form of the handle marker, as a header line after the first escapes it under
    its own fields 1 and 2, that differs from the raw marker and from the first line's form, in
    the order the headers give them. Reads the parsed fields only, never a slice of the raw text,
    and scans no text: the caller decides which forms to look for."""
    checked = {DOC_REF_MARKER, escape_leaf(DOC_REF_MARKER, message._m["seps"])}
    seen_separators: set[tuple[str, str, str, str, str]] = set()
    segments = message._m["segments"]
    # One pass over the parsed segments: a header line is split eagerly, so its fields 1 and 2
    # are read in place, with no per-header occurrence scan.
    for index in range(1, len(segments)):
        segment = segments[index]
        if segment["id"] not in HEADER_IDS:
            continue
        separators = _extract_separators(header_line_head(segment))
        # A header naming no character of the marker escapes none of it, so its form is the raw
        # marker, already checked; and a delimiter set already read gives the same form. Both
        # are skipped before the escape, which builds a table per distinct delimiter set.
        if separators in seen_separators or _DOC_REF_MARKER_CHARS.isdisjoint(separators):
            continue
        seen_separators.add(separators)
        escaped = escape_leaf(DOC_REF_MARKER, separators)
        if escaped in checked:
            continue
        checked.add(escaped)
        yield escaped


def _bounded_later_header_forms(message: Message) -> list[str] | None:
    """:func:`_later_header_forms` while they number at most :data:`_LATER_HEADER_FORMS_LIMIT`,
    or ``None`` once one more is given, read no further (BACKLOG #5972)."""
    forms = list(islice(_later_header_forms(message), _LATER_HEADER_FORMS_LIMIT + 1))
    return None if len(forms) > _LATER_HEADER_FORMS_LIMIT else forms


def _later_header_markers(message: Message, text: str) -> set[str]:
    """The handle marker as a header line after the first escapes it under its own fields 1 and
    2, for each such header whose form differs from the first line's and is held in ``text``.
    The message reads every line under the first line's delimiters (BACKLOG #5972), so a handle
    a Handler wrote under an inner MSH's own, then wrapped in an envelope of others, would not be
    read as one and would reach the wire unresolved. Each distinct form is scanned for once, so
    a batch of many headers naming the same delimiters costs one scan of the text, not one per
    header.

    The forms are bounded at :data:`_LATER_HEADER_FORMS_LIMIT`, so this costs at most that many
    substring scans of ``text``, and reads at most one form past it. Past the limit it raises
    :class:`UnreattachableDocumentError` without those scans (fail closed), and the row
    dead-letters as its payload's own refusal. The checks before the ACK refuse a body past the
    same limit (:func:`later_header_forms_over_limit`), so a payload whose header lines are its
    received body's is not refused here; a payload a Handler built, or gave other header lines,
    can be."""
    forms = _bounded_later_header_forms(message)
    if forms is None:
        raise UnreattachableDocumentError(_TOO_MANY_HEADER_FORMS_TO_REATTACH)
    return {form for form in forms if form in text}


def doc_ref_addresses_in_hl7(text: str) -> frozenset[str]:
    """The content addresses named by the well-formed document handles in an HL7 body's
    ``OBX-5.5`` values, read as :func:`reattach_documents_in_hl7` reads them: the places delivery
    splices (BACKLOG #5099). A handle anywhere else, or a bare content address, is not one, since
    delivery never resolves it. Empty for a body that does not parse as HL7, and for one whose
    header fills a delimiter it does not name with one it already uses: the re-attach refuses
    every handle in it (BACKLOG #5972), so none names a document its message can deliver, and a
    child carrying one is not linked to it."""
    # Local import, as reattach_documents_in_hl7 does: message.py imports this module.
    from messagefoundry.parsing.message import Message
    from messagefoundry.parsing.peek import HL7PeekError

    try:
        message = Message.parse(text)
    except HL7PeekError:
        return frozenset()
    if message._delimiters_collide():
        # The re-attach's own refusal of any handle under such a header (_COLLIDING_HANDLE),
        # judged from the header alone, before any OBX-5 is read.
        return frozenset()
    found: set[str] = set()
    for occ in range(1, message.count_segments("OBX") + 1):
        value = message.field("OBX-5.5", occurrence=occ) or ""
        if is_doc_ref(value):
            try:
                found.add(parse_doc_ref(value)[0])
            except DocRefError:
                continue  # malformed: delivery refuses it, and it names nothing to hold
    return frozenset(found)


async def reattach_documents_in_hl7(
    text: str, reader: Callable[[str], Awaitable[str | None]], *, bound: Collection[str]
) -> str:
    """Re-materialize every detached document handle in an HL7 body — the delivery-side inverse of the
    ingress detach (#149, ADR 0105 Phase 1b, Approach B — VERBATIM).

    Scans each ``OBX-5.5``; for every value that is a live ``mfdoc:v1:ref:`` handle (:func:`is_doc_ref`)
    it parses the content address (:func:`parse_doc_ref`), ``await``\\ s ``reader(sha256)`` for the stored
    VERBATIM base64 string, and splices it back into ``OBX-5.5`` **byte-for-byte** (no decode/encode — the
    exact bytes the partner sent; the base64 alphabet carries no HL7 delimiter, so the message's own
    escaping is a no-op on it, under any delimiters the rule in :func:`_delimits_with_base64`
    lets through). Returns the fully re-materialized HL7 text.

    ``reader`` is an INJECTED ``async`` callable (``sha256 -> verbatim base64``) so this function stays
    PURE and unit-testable: the caller (``pipeline/``) supplies the async store ``read_attachment`` read
    (run off the event loop like every store read). **Fail-loud** (owner invariant): if a value LOOKS
    like a handle but ``reader`` raises **or** returns ``None`` (the attachment is missing / GC'd), a
    :class:`DocRefError` propagates — the raw ``mfdoc:v1:ref:`` text is **never** emitted (delivering it
    into a partner's ``OBX-5.5`` would be silent corruption). A malformed handle fails loud as an
    :class:`UnreattachableDocumentError`. A body with **no** handle is returned unchanged unless
    refused, mirroring :func:`strip_documents`, so a below-threshold / no-detach delivery is
    untouched. The
    payload-caused shapes :class:`UnreattachableDocumentError` names raise it; every other
    ``ValueError`` propagates as it is, a stored document holding a CR or LF included.

    ``bound`` is the content addresses the payload's own message holds, which the caller reads from
    the store's ``message_attachment`` linkage (BACKLOG #5099). A handle naming any other address is
    refused before ``reader`` runs, so a value the sender wrote cannot name another message's
    document. The handle marker, raw or as this payload's delimiters escape it, anywhere the
    splice does not reach is refused too where ``bound`` is not empty, the copy names a content
    address, or a delimiter is a base64 character and so may have escaped one, so a handle a
    Handler copied elsewhere is never emitted. A handle to splice under such a delimiter is
    refused before ``reader`` runs, since the splice would escape that character inside the
    document (:func:`_delimits_with_base64`). A stored value the splice would escape any other
    way, such as a subcomponent separator in a value that is not base64, is refused after its
    read and before it is set, so no altered document is sent; one holding a control character
    raises a plain ``ValueError``, as a stored CR or LF does."""
    # Local imports. message.py imports binary.py, never the reverse, so the cycle is broken here,
    # exactly as _strip_obx_ed does. asyncio stays out of the module scope: a sandbox worker refuses an
    # import of it once its guard is up (DEFAULT_FORBIDDEN_MODULES), this module has to stay importable
    # there, and only the engine calls this function.
    import asyncio

    from messagefoundry.parsing.message import Message
    from messagefoundry.parsing.peek import HL7PeekError

    # The parse, each splice and the re-encode run in a thread (vault BACKLOG #2757): the splice and
    # the encode scale with the document, and this runs on every delivery attempt. Measured 2026-10-06
    # on SQLite with the AES-GCM cipher, the longest event-loop stall fell from 0.5-0.8 s to 0.3-0.4 s
    # at a 64 MiB document and stayed about 0.1 s at 15 MiB: the splice's escape pass over the whole
    # value is one string operation, which holds the GIL in any thread. Only `reader` runs on the
    # loop, where the store read belongs. Only one thread touches `message` at a time.
    def _handles() -> tuple[
        Message, list[tuple[int, str]], tuple[str, ...], tuple[str, str, str, str, str]
    ]:
        refused: str | None = None
        try:
            message = Message.parse(text)
        except HL7PeekError as exc:
            if exc.parser_fault:
                raise  # a fault in the parser, not the payload: the internal-error policy judges it
            refused = "the payload does not parse as HL7"
        if refused is not None:
            # Raised after the handler, so the parse error, which may quote the payload, is on no
            # chain.
            raise UnreattachableDocumentError(refused)
        found: list[tuple[int, str]] = []
        for occ in range(1, message.count_segments("OBX") + 1):
            value = message.field("OBX-5.5", occurrence=occ) or ""
            if is_doc_ref(value):
                try:
                    found.append((occ, parse_doc_ref(value)[0]))
                except DocRefError:
                    # The payload's own text, refused the same way on every attempt (BACKLOG
                    # #5099), and before any read. Raised after the handler, so the error, which
                    # quotes the value, is on no chain.
                    refused = f"OBX-5.5 occurrence {occ} holds a malformed document handle"
                if refused is not None:
                    raise UnreattachableDocumentError(refused)
        separators = message._encoding_chars()
        # Under a base64 delimiter the splice below would escape it inside the stored document,
        # so a handle to splice is refused before any read (_delimits_with_base64).
        base64_delimited = _delimits_with_base64(separators)
        if found and base64_delimited:
            raise UnreattachableDocumentError(_BASE64_DELIMITED_HANDLE)
        if found and message._delimiters_collide():
            # Message refuses every write to such a payload, the splice included (BACKLOG #5972).
            raise UnreattachableDocumentError(_COLLIDING_HANDLE)
        # Judged as a copy is below: a bare marker under an inner header's delimiters, in a
        # message that holds nothing and names no content address, is carried as text.
        later = _later_header_markers(message, text)
        if later and (found or bound or any(_copy_names_address(text, m) for m in later)):
            raise UnreattachableDocumentError(_MIXED_HEADER_HANDLE)
        markers = _marker_forms(separators)
        # Under the same delimiters a copied content address is escaped too, so the address after
        # a marker cannot be read: every marker counts as a copy.
        if (
            not found
            and any(m in text for m in markers)
            and (bound or base64_delimited or any(_copy_names_address(text, m) for m in markers))
        ):
            # No handle to splice, so the text is what would be sent: a marker in it is a copy.
            # Refused where the message holds a document, and also where the copy names a content
            # address, or may name one its delimiters escaped: a child that inherited none,
            # because its only handle sits outside OBX-5.5, would otherwise send the engine's
            # handle with no document. A bare marker in a message that holds nothing names no
            # document, so it is carried as text where no delimiter is a base64 character.
            raise UnreattachableDocumentError(_UNSPLICED_HANDLE)
        return message, found, markers, separators

    message, handles, markers, separators = await asyncio.to_thread(_handles)

    def _splice(occ: int, verbatim: str) -> None:
        # The detach checks a value under the delimiters it arrived with; MSH-1 or MSH-2
        # rewritten below the Message API since, which refuses such a write (BACKLOG #5972),
        # reaches this instead. Message.set would escape a character the value holds,
        # so the partner would not get the sender's document.
        if _splice_alters(verbatim, separators):
            # Scanned only on this refusal path. The detach refuses a control character under any
            # delimiters, so a stored one is store corruption or an engine bug, as a stored CR or
            # LF is below: the outbound's internal-error policy judges it.
            if any(ch in verbatim for ch in _HEX_ESCAPED_CONTROLS):
                raise ValueError(
                    f"the stored document for OBX-5.5 occurrence {occ} holds a control "
                    "character, so it cannot be set back verbatim"
                )
            # A delimiter the value holds: the same row fails the same way on every attempt, so
            # it is the payload's permanent refusal (BACKLOG #5099).
            raise UnreattachableDocumentError(
                f"the stored document for OBX-5.5 occurrence {occ} holds a character the splice "
                "would escape, so it would not be sent verbatim"
            )
        message.set("OBX-5.5", verbatim, occurrence=occ)

    for occ, sha256 in handles:
        if sha256 not in bound:
            raise UnreattachableDocumentError(
                f"the document handle in OBX-5.5 occurrence {occ} names an attachment its message "
                "does not hold"
            )
    if not handles:
        # No handle in any OBX-5.5 — return the ORIGINAL text unchanged (byte-identical). The caller's
        # gate may open on a header alone, or on a bare marker outside OBX-5.5 in a message that
        # holds no document under delimiters with no base64 character (_handles refuses the
        # rest); that names no document, so it is carried through verbatim.
        return text
    for occ, sha256 in handles:
        verbatim = await reader(sha256)
        if not verbatim:
            # The reader gave back None or "" for this handle, and the detach never stores an empty
            # value, so neither is the document. A store read does not return "" for a header whose
            # chunks are gone: it raises KeyError after the last chunk, unless that header's
            # total_bytes is 0. Fail loud rather than deliver the raw handle text, or an empty
            # OBX-5.5, into the partner's message (silent corruption).
            raise DocRefError(
                f"attachment {sha256!r} not found for re-attach (missing / GC'd); refusing to "
                "deliver an un-hydrated document handle"
            )
        if "\r" in verbatim or "\n" in verbatim:
            # Message.set refuses a CR or LF in a field value. No payload can leave one in the store:
            # the ingress detach refuses an escaped OBX-5.5, and a raw LF ends the segment before the
            # read. So a stored CR or LF is store corruption or an engine bug: a plain ValueError for
            # the outbound's internal-error policy to judge (STOP stops the lane), never the
            # payload's permanent refusal (vault BACKLOG #2809). Checked here rather than caught from
            # set, so the text names the OBX occurrence and no byte of the value.
            raise ValueError(
                f"the stored document for OBX-5.5 occurrence {occ} holds a CR or LF, so it cannot "
                "be set back"
            )
        await asyncio.to_thread(_splice, occ, verbatim)

    def _encode() -> str:
        spliced = message.encode()
        # Every handle has now been replaced by base64, which holds no ':' and no escape
        # character, so any marker left, raw or escaped, is a copy the splice did not reach, or a
        # sender's text the ingress detach refused to store (BACKLOG #5099). Read
        # from the spliced text, not counted beforehand: a handle the parser reads through a hex
        # escape is not the marker in the raw text, so a count could be offset by one copy.
        if any(m in spliced for m in markers):
            raise UnreattachableDocumentError(_UNSPLICED_HANDLE)
        return spliced

    return await asyncio.to_thread(_encode)
