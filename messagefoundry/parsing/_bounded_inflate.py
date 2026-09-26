# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One bounded-inflate loop, shared by the compression codec and the DICOM deflate guard (BACKLOG #1977).

Two callers drive a :func:`zlib.decompressobj` against a byte ceiling:
:func:`messagefoundry.parsing.compression.deflate_decompress` (zlib-wrapped, keeps the output) and
:func:`messagefoundry.parsing.dicom._inflate.bounded_inflate_or_error` (raw DEFLATE, discards it).
They used to carry two copies of this loop, so a fix could reach one and not the other. The end-of-
stream hang (BACKLOG #1964) was fixed in one copy first for exactly that reason.

The loop keeps these guarantees for both callers:

* It stops at the end of the stream. After the end, zlib keeps trailing input in ``unconsumed_tail``
  and never uses it, so a loop that watches only the pending input spins forever.
* It feeds the input one :data:`CHUNK` window at a time. ``unconsumed_tail`` is a copy of the input
  not yet used, so handing zlib the whole remainder copies it every round, which is quadratic. The
  loop slices the input as given. A ``bytes`` input copies each window once, which leaves no export
  on a caller's ``bytearray`` behind a raised error; that is what the codec passes. A ``memoryview``
  input slices without copying; that is what the DICOM guard passes.
* The ceiling fires as soon as the output passes it. With ``exact_ceiling=True`` the loop asks zlib
  for at most one byte past the ceiling, so a bomb stops having produced at most
  ``max_output_bytes + 1`` bytes. With ``exact_ceiling=False`` it asks for a whole window each round,
  so the count may pass the ceiling by up to one window before it fires. The DICOM guard needs that
  one; see its docstring.

What follows the end of the stream is the caller's rule, :data:`TrailingRule`:

* ``"refuse"`` raises :class:`InflateTrailingData`. A zlib stream has no multi-member form and no
  padding convention, so the codec has no tail to accept, and returning the first stream would drop
  the rest of the input without a word.
* ``"stop"`` returns at the end of the stream and leaves the rest to the caller. The DICOM guard needs
  it, because pydicom and pynetdicom pad an odd-length deflated Data Set with one NUL, and
  ``dcmread``'s one-shot inflate also stops at the end of the first stream. The DICOM guard ignores
  the rest. :func:`messagefoundry.parsing.compression.deflate_decompress_with_tail` hands it back
  (BACKLOG #1978).

Either way, :attr:`InflateResult.end` says where the stream ended in the input, so the rest is
``data[end:]``.

Any other rule is a ``ValueError`` before a byte is read, so a mistyped rule cannot fall through to
the permissive one.

The caller builds the decompressor, so the caller picks the ``wbits`` (zlib-wrapped, raw, or gzip)
and keeps its own error types. A ``zlib.error`` from a bad stream propagates unchanged: the codec
turns it into ``CompressionError`` and the DICOM guard stands aside for ``dcmread``. Error messages
here carry no decompressed content, which may be PHI.

Stdlib only, no engine imports, like the rest of ``parsing/``.
"""

from __future__ import annotations

from collections.abc import Buffer
from dataclasses import dataclass
from typing import Literal, Protocol, get_args

__all__ = [
    "CHUNK",
    "InflateCeilingExceeded",
    "InflateResult",
    "InflateTrailingData",
    "TrailingRule",
    "bounded_inflate",
]

#: The input window and the largest output request, 64 KiB.
CHUNK = 1 << 16

#: What to do with bytes after the end of the stream. See the module docstring.
TrailingRule = Literal["refuse", "stop"]


class _Decompressor(Protocol):
    """The part of a :func:`zlib.decompressobj` this loop uses, so a test double can stand in."""

    def decompress(self, data: Buffer, max_length: int = ..., /) -> bytes: ...

    def flush(self) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def unconsumed_tail(self) -> bytes: ...

    @property
    def unused_data(self) -> bytes: ...


class InflateCeilingExceeded(Exception):
    """The stream inflates past the caller's ceiling (a possible decompression bomb).

    ``ceiling`` is the ``max_output_bytes`` that was passed. It is never ``None`` here, because
    without a ceiling there is nothing to exceed."""

    def __init__(self, ceiling: int) -> None:
        super().__init__(f"inflated output passes the {ceiling}-byte ceiling")
        self.ceiling = ceiling


class InflateTrailingData(Exception):
    """Bytes follow the end of the stream, under the ``"refuse"`` rule."""


@dataclass(frozen=True, slots=True)
class InflateResult:
    """What one bounded inflate produced.

    ``output`` is empty when the caller asked to discard it. ``produced`` counts every byte inflated
    either way. ``eof`` is false when the input ran out before the stream ended, which is a truncated
    stream; each caller decides whether that is an error. ``end`` is the index in the input just past
    the stream's last byte, so ``data[end:]`` is what follows the stream. When the input ran out first
    it is ``len(data)``."""

    output: bytes
    produced: int
    eof: bool
    end: int


def bounded_inflate(
    data: bytes | bytearray | memoryview,
    decompressor: _Decompressor,
    *,
    max_output_bytes: int | None,
    trailing: TrailingRule,
    keep_output: bool,
    exact_ceiling: bool,
) -> InflateResult:
    """Inflate ``data`` through ``decompressor`` in bounded memory.

    ``max_output_bytes`` of ``None`` means no ceiling. Raises :class:`InflateCeilingExceeded` once the
    output passes the ceiling, :class:`InflateTrailingData` for bytes after the end of the stream under
    ``trailing="refuse"``, and lets ``zlib.error`` through for a corrupt stream. The ceiling is checked
    before the trailing rule, so an over-ceiling stream with junk after it is refused as over the
    ceiling. Raises :class:`ValueError` for a ``trailing`` rule it does not know."""
    if trailing not in get_args(TrailingRule):
        raise ValueError(f"unknown trailing-data rule {trailing!r}")
    out = bytearray()
    produced = 0

    def take(piece: bytes) -> None:
        nonlocal produced
        produced += len(piece)
        if keep_output:
            out.extend(piece)
        if max_output_bytes is not None and produced > max_output_bytes:
            raise InflateCeilingExceeded(max_output_bytes)

    for offset in range(0, len(data), CHUNK):
        pending = data[offset : offset + CHUNK]
        window_end = offset + len(pending)
        while pending and not decompressor.eof:
            request = CHUNK
            if exact_ceiling and max_output_bytes is not None:
                # At least one byte: a negative ceiling must still refuse on the first output rather
                # than ask zlib for a length of zero, which means no limit at all.
                request = min(CHUNK, max(max_output_bytes - produced + 1, 1))
            take(decompressor.decompress(pending, request))
            pending = decompressor.unconsumed_tail
        if decompressor.eof:
            # At the end of the stream zlib moves the rest of the input it was given into
            # unused_data, and that input is this window's remainder. unconsumed_tail then holds
            # either a copy of it or nothing, so it cannot say where the stream ended.
            end = window_end - len(decompressor.unused_data)
            if trailing == "refuse" and end < len(data):
                raise InflateTrailingData
            return InflateResult(bytes(out), produced, eof=True, end=end)
    # The input ran out first. zlib may still hold output for input it has already taken.
    take(decompressor.flush())
    return InflateResult(bytes(out), produced, eof=decompressor.eof, end=len(data))
