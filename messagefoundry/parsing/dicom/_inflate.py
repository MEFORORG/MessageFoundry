# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Bounded-inflate guard for **Deflated Explicit VR Little Endian** DICOM (ASVS 5.2.3).

A DICOM object whose transfer syntax is ``1.2.840.10008.1.2.1.99`` (Deflated Explicit VR LE, DICOM
PS3.5 A.5) carries its Data Set as a **raw DEFLATE stream** (RFC 1951 — no zlib/gzip wrapper). ``pydicom``
inflates that whole stream into memory with an **unbounded** ``zlib.decompress`` *before* it parses (it
cannot seek inside a deflate stream, so ``stop_before_pixels``/``specific_tags`` do not help). A tiny
compressed "bomb" (a few KiB that inflates to hundreds of MiB) therefore exhausts memory the moment
``dcmread`` touches it. This module pre-checks the inflate **in bounded memory** and rejects an over-cap
object *before* any ``dcmread``.

Pure and stdlib-only (``zlib`` + byte slicing) — **no ``pydicom``**, so the guard runs (and unit-tests)
without the ``[dicom]`` extra, and there is no reliance on any private ``pydicom`` API. It imports
nothing from ``messagefoundry.config`` / ``pipeline`` / ``store`` / ``transports`` (the codec's purity).
``zlib`` is stdlib and **not** a crypto-gate import.

Two entry points:

* :func:`bounded_inflate_or_error` — the core: bound the inflate of a **raw deflate stream** (the shape
  the SCP holds in ``event.request.DataSet`` for a negotiated deflated context).
* :func:`guard_part10_deflate` — for a full **Part-10 file** (preamble + ``DICM`` + uncompressed file-meta
  + deflated Data Set, the shape the codec peek/dataset and the SCU hold): locate the deflate stream after
  the file-meta and bound it. A no-op unless the file-meta declares the deflated transfer syntax.

Both raise :class:`~messagefoundry.parsing.dicom.errors.DicomBombError` (a ``DicomError``) only for a
**confirmed over-cap deflated** object; a non-deflated / non-Part-10 / structurally-odd / corrupt-deflate
input is a silent no-op so the normal ``dcmread`` parse/dead-letter path still runs.
"""

from __future__ import annotations

import zlib

from messagefoundry.parsing.dicom.errors import DicomBombError

__all__ = [
    "DEFLATED_EXPLICIT_VR_LE",
    "DEFAULT_MAX_INFLATED_BYTES",
    "bounded_inflate_or_error",
    "guard_part10_deflate",
]

#: Transfer Syntax UID for Deflated Explicit VR Little Endian (DICOM PS3.5 A.5) — the only standard
#: transfer syntax that DEFLATE-compresses the Data Set, so the only one this guard acts on.
DEFLATED_EXPLICIT_VR_LE = "1.2.840.10008.1.2.1.99"

#: Default max **uncompressed** size the deflate stream may reach before it is rejected as a bomb —
#: matches :data:`messagefoundry.parsing.peek.DEFAULT_MAX_MESSAGE_BYTES` (16 MiB, the MLLP/file ingress
#: cap). A module constant; the guard functions take a ``max_bytes`` override (the DIMSE SCP/SCU pass
#: their own ``max_object_bytes`` so the inflate bound matches the object-size policy they already
#: enforce).
DEFAULT_MAX_INFLATED_BYTES = 16 * 1024 * 1024

# DICOM Part-10 fixed layout: a 128-byte preamble then the 4-byte ``DICM`` magic, then the File Meta
# Information group (0002), which is ALWAYS Explicit VR Little Endian and NEVER deflated. Its first
# element is (0002,0000) FileMetaInformationGroupLength (VR ``UL``, 4-byte value) giving the byte length
# of the rest of the group — so the deflated Data Set begins at a computable offset.
_PREAMBLE_LEN = 128
_MAGIC = b"DICM"
_GROUP_LENGTH_TAG = b"\x02\x00\x00\x00"  # (0002,0000), little-endian group+element
_TRANSFER_SYNTAX_TAG = b"\x02\x00\x10\x00"  # (0002,0010), little-endian group+element
# Explicit-VR value representations encoded with a 2-byte reserved field + 4-byte length (the rest use a
# 2-byte length); needed only to step over any long-form element preceding the transfer-syntax element.
_LONG_FORM_VRS = frozenset(
    {b"OB", b"OW", b"OF", b"SQ", b"UT", b"UN", b"UC", b"UR", b"OD", b"OL", b"OV"}
)
# The working window: never materialise more than this much decompressed output at once. The inflate is
# cancelled the instant the running total crosses ``max_bytes``, so peak memory is ~this + the shrinking
# compressed remainder, regardless of the declared/actual inflated size.
_INFLATE_CHUNK = 65536


def bounded_inflate_or_error(compressed: bytes, *, max_bytes: int) -> None:
    """Inflate a **raw DEFLATE** stream (RFC 1951, DICOM Deflated Explicit VR LE) in bounded memory,
    **discarding** the output, and raise :class:`DicomBombError` if the cumulative uncompressed size
    would exceed ``max_bytes``. Streams the decompression in :data:`_INFLATE_CHUNK`-bounded chunks so a
    small compressed bomb with a huge inflated size never materialises in memory.

    A silent no-op when ``compressed`` is empty or is not a valid deflate stream (``zlib.error``) — those
    are not bombs; the normal ``dcmread`` path then produces the real parse error / dead-letters."""
    if not compressed:
        return
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)  # negative wbits ⇒ raw deflate, no header
    total = 0
    pending = compressed
    try:
        while pending:
            out = decompressor.decompress(pending, _INFLATE_CHUNK)
            total += len(out)
            if total > max_bytes:
                raise DicomBombError(
                    "deflated DICOM object exceeds the maximum uncompressed size "
                    f"({max_bytes} bytes); refusing to decode (possible decompression bomb)"
                )
            pending = decompressor.unconsumed_tail
        tail = decompressor.flush()
        total += len(tail)
        if total > max_bytes:
            raise DicomBombError(
                "deflated DICOM object exceeds the maximum uncompressed size "
                f"({max_bytes} bytes); refusing to decode (possible decompression bomb)"
            )
    except zlib.error:
        # Not a valid deflate stream — not a bomb. Let dcmread surface the real parse error.
        return


def guard_part10_deflate(data: bytes, *, max_bytes: int = DEFAULT_MAX_INFLATED_BYTES) -> None:
    """Bound the inflate of a full **Part-10 file** whose file-meta declares Deflated Explicit VR LE,
    **before** any ``dcmread``. Locates the deflated Data Set (the bytes after the uncompressed file-meta
    group) and delegates to :func:`bounded_inflate_or_error`.

    A no-op for a non-Part-10 body, a non-deflated transfer syntax, or a file-meta that cannot be read —
    those flow on to the normal ``dcmread`` parse/dead-letter path unchanged. Raises
    :class:`DicomBombError` only for a confirmed over-cap deflated object."""
    stream = _deflated_data_set(data)
    if stream is None:
        return
    bounded_inflate_or_error(stream, max_bytes=max_bytes)


def _deflated_data_set(data: bytes) -> bytes | None:
    """The raw deflated Data Set bytes when ``data`` is a Part-10 object whose transfer syntax is
    Deflated Explicit VR LE, else ``None``. Reads only the small, uncompressed file-meta group (never the
    Data Set) via a minimal, defensive Explicit-VR walk — any structural surprise returns ``None`` so the
    normal parse path handles it."""
    if len(data) < _PREAMBLE_LEN + len(_MAGIC) + 12:
        return None
    if data[_PREAMBLE_LEN : _PREAMBLE_LEN + len(_MAGIC)] != _MAGIC:
        return None
    pos = _PREAMBLE_LEN + len(_MAGIC)  # start of (0002,0000) FileMetaInformationGroupLength
    if data[pos : pos + 4] != _GROUP_LENGTH_TAG:
        return None
    group_length = int.from_bytes(data[pos + 8 : pos + 12], "little")
    meta_start = pos + 12
    meta_end = meta_start + group_length
    if meta_end > len(data):
        meta_end = len(data)  # tolerate a truncated meta; the empty/short tail simply won't inflate
    if _transfer_syntax(data, meta_start, meta_end) != DEFLATED_EXPLICIT_VR_LE:
        return None
    return data[meta_end:]


def _transfer_syntax(data: bytes, start: int, end: int) -> str | None:
    """Value of (0002,0010) TransferSyntaxUID within the Explicit-VR file-meta window ``data[start:end]``,
    or ``None`` if not found. Steps over any preceding element (short- or long-form VR)."""
    p = start
    while p + 8 <= end:
        tag = data[p : p + 4]
        vr = data[p + 4 : p + 6]
        if vr in _LONG_FORM_VRS:
            if p + 12 > end:
                break
            length = int.from_bytes(data[p + 8 : p + 12], "little")
            value_start = p + 12
        else:
            length = int.from_bytes(data[p + 6 : p + 8], "little")
            value_start = p + 8
        value_end = value_start + length
        if tag == _TRANSFER_SYNTAX_TAG:
            return data[value_start:value_end].rstrip(b"\x00 ").decode("ascii", "ignore")
        p = value_end
    return None
