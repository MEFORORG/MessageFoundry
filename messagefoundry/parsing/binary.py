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

__all__ = [
    "MARKER",
    "BinaryCarriageError",
    "encode",
    "decode",
    "is_marked",
    "embed_obx_document",
    "extract_obx_document",
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
