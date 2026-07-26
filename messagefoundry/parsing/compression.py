# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Compression codec (ADR 0123) — gzip / zlib-deflate / zip, bytes in → bytes out.

A partner file feed frequently delivers **gzipped/zipped** archives or requires **compressed** outbound
drops. This module is the primitive: a Handler calls it on demand against a
:class:`~messagefoundry.parsing.message.RawMessage`/:class:`~messagefoundry.parsing.message.Message`
body, and the File connector uses the single-stream ``gzip`` pair for its ``compress=``/``decompress=``
option (:mod:`messagefoundry.transports.file`).

It is **pure** — stdlib only (:mod:`gzip`, :mod:`zlib`, :mod:`zipfile`, :mod:`io`), **no engine
imports** — so it sits under the ``parsing/`` carve-out (a client may import it, mirroring
:mod:`messagefoundry.parsing.binary` / :mod:`messagefoundry.parsing.x12`). Compression is **orthogonal**
to the ADR 0028 base64 *carriage* codec: carriage makes bytes NUL-safe over the str/TEXT store;
compression shrinks them. They compose but never share a marker.

Two invariants shape the surface:

* **Re-run purity** ([CLAUDE.md](../../CLAUDE.md) §2). At-least-once relies on a transform re-deriving
  identical output, so :func:`gzip_compress` fixes ``mtime=0`` in the header (stock ``gzip.compress``
  embeds a *wall-clock* mtime → different bytes every second → a silent purity break) and
  :func:`zip_compress` fixes each entry's ZIP date. Compression output is a pure function of its input.

* **Decompression-bomb DoS** ([CLAUDE.md](../../CLAUDE.md) §9). Every decompress accepts an optional
  ``max_output_bytes`` ceiling, enforced **incrementally** (bounded reads) so a bomb is refused after
  producing *at most* the ceiling — never after fully expanding in memory. Every corrupt / truncated /
  over-ceiling / bad-argument failure raises exactly one type, :class:`CompressionError` (a
  ``ValueError``), whose message names the codec and the byte ceiling only — **never any decompressed
  content** (it is PHI).
"""

from __future__ import annotations

import gzip
import io
import zipfile
import zlib
from collections.abc import Mapping

__all__ = [
    "CompressionError",
    "gzip_compress",
    "gzip_decompress",
    "deflate_compress",
    "deflate_decompress",
    "zip_compress",
    "zip_decompress",
]


class CompressionError(ValueError):
    """A compression / decompression operation failed: a corrupt or truncated stream, a
    decompressed size beyond the ceiling (a possible decompression bomb), or an invalid argument.

    Subclasses :class:`ValueError` (not :class:`OSError`) so a connector's ``except (TimeoutError,
    OSError)`` does not silently swallow it — it surfaces as the deliberate content error it is. The
    message names the **codec and the byte ceiling only**, never any (PHI) decompressed content."""


# Read/decompress in bounded chunks so a bomb is refused incrementally, never fully expanded.
_CHUNK = 1 << 16  # 64 KiB
# zlib window-bits selectors: 15 = zlib-wrapped DEFLATE ("deflate"); 31 = 16+15 = gzip.
_ZLIB_WBITS = 15


def _check_level(level: int) -> int:
    if not isinstance(level, int) or not (0 <= level <= 9):
        raise CompressionError(f"compression level must be an int in 0..9, got {level!r}")
    return level


def _check_ceiling(max_output_bytes: int | None) -> int | None:
    if max_output_bytes is not None and (
        not isinstance(max_output_bytes, int) or max_output_bytes < 0
    ):
        raise CompressionError(
            f"max_output_bytes must be a non-negative int or None, got {max_output_bytes!r}"
        )
    return max_output_bytes


def gzip_compress(data: bytes, *, level: int = 6) -> bytes:
    """Compress ``data`` to a single-member gzip stream, **deterministically**.

    ``mtime=0`` fixes the header so the output is a pure function of ``(data, level)`` — a Handler that
    gzips stays re-run-stable ([CLAUDE.md](../../CLAUDE.md) §2). ``level`` is 0..9 (default 6)."""
    _check_level(level)
    return gzip.compress(data, compresslevel=level, mtime=0)


def gzip_decompress(data: bytes, *, max_output_bytes: int | None = None) -> bytes:
    """Decompress a gzip stream, refusing a **decompression bomb** at ``max_output_bytes``.

    Enforced incrementally via :meth:`gzip.GzipFile.read`, which only inflates enough to satisfy each
    read, so a bomb is stopped after producing at most the ceiling (never fully expanded). Multi-member
    gzip is handled by :class:`gzip.GzipFile`. A corrupt / truncated stream or an over-ceiling size
    raises :class:`CompressionError`."""
    _check_ceiling(max_output_bytes)
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as gz:
            if max_output_bytes is None:
                return gz.read()
            # Read one byte past the ceiling: if we get it, the stream exceeds the cap. GzipFile.read(n)
            # only decompresses enough to satisfy n, so the bomb is never fully expanded in memory.
            out = gz.read(max_output_bytes + 1)
            if len(out) > max_output_bytes:
                raise CompressionError(
                    f"gzip stream decompresses beyond the {max_output_bytes}-byte ceiling "
                    "(possible decompression bomb)"
                )
            return out
    except (OSError, EOFError, zlib.error) as exc:
        # EOFError = truncated; OSError/BadGzipFile = corrupt header/trailer; zlib.error = bad DEFLATE.
        raise CompressionError(f"corrupt or truncated gzip stream: {exc}") from exc


def deflate_compress(data: bytes, *, level: int = 6) -> bytes:
    """Compress ``data`` to a zlib-wrapped DEFLATE stream (the "deflate" of HTTP/PDF).

    Deterministic (zlib embeds no timestamp), so a Handler that deflates stays re-run-stable."""
    _check_level(level)
    return zlib.compress(data, level)


def deflate_decompress(data: bytes, *, max_output_bytes: int | None = None) -> bytes:
    """Decompress a zlib-wrapped DEFLATE stream, refusing a bomb at ``max_output_bytes``.

    Enforced incrementally with a :func:`zlib.decompressobj` ``max_length`` loop. A corrupt / truncated
    stream or an over-ceiling size raises :class:`CompressionError`."""
    _check_ceiling(max_output_bytes)
    return _bounded_inflate(data, _ZLIB_WBITS, max_output_bytes, label="deflate")


def _bounded_inflate(data: bytes, wbits: int, max_output_bytes: int | None, *, label: str) -> bytes:
    d = zlib.decompressobj(wbits=wbits)
    out = bytearray()
    pending = data
    try:
        while pending:
            piece = d.decompress(pending, _CHUNK)
            # unconsumed_tail is the *compressed* input held back because the output hit _CHUNK — feed
            # it again next loop. When it is empty, all input was consumed and all output produced.
            pending = d.unconsumed_tail
            out += piece
            if max_output_bytes is not None and len(out) > max_output_bytes:
                raise CompressionError(
                    f"{label} stream decompresses beyond the {max_output_bytes}-byte ceiling "
                    "(possible decompression bomb)"
                )
        out += d.flush()
    except zlib.error as exc:
        raise CompressionError(f"corrupt or truncated {label} stream: {exc}") from exc
    if not d.eof:
        raise CompressionError(f"truncated {label} stream (input ended mid-stream)")
    return bytes(out)


def zip_compress(entries: Mapping[str, bytes], *, level: int | None = None) -> bytes:
    """Build a ZIP archive from ``{name: bytes}``, **deterministically** (fixed entry dates).

    Multi-entry, so it is the Handler-composed sibling of the connector's single-stream gzip. ``level``
    (0..9, or ``None`` for the zlib default) is the DEFLATE level. Each entry's ZIP timestamp is fixed
    to a constant so the archive is a pure function of its inputs (re-run purity, [CLAUDE.md](../../CLAUDE.md)
    §2)."""
    if level is not None:
        _check_level(level)
    buf = io.BytesIO()
    with zipfile.ZipFile(
        buf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=level
    ) as zf:
        for name, payload in entries.items():
            # A fixed (1980-01-01) date_time keeps the archive deterministic across runs.
            info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, payload)
    return buf.getvalue()


def zip_decompress(
    data: bytes, *, max_output_bytes: int | None = None, max_entries: int = 1024
) -> dict[str, bytes]:
    """Extract every member of a ZIP archive to ``{name: bytes}``, refusing a bomb.

    ``max_entries`` caps the member count (a many-entry archive is a bomb axis too). ``max_output_bytes``
    caps the **total** decompressed size across all members, enforced with per-member bounded reads so a
    lying central-directory size cannot force full expansion. A corrupt archive, too many members, or an
    over-ceiling total raises :class:`CompressionError`."""
    _check_ceiling(max_output_bytes)
    if not isinstance(max_entries, int) or max_entries < 0:
        raise CompressionError(f"max_entries must be a non-negative int, got {max_entries!r}")
    result: dict[str, bytes] = {}
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data), mode="r") as zf:
            names = zf.namelist()
            if len(names) > max_entries:
                raise CompressionError(
                    f"zip archive has {len(names)} members, over the {max_entries}-member cap"
                )
            for info in zf.infolist():
                if info.is_dir():
                    continue
                with zf.open(info, "r") as member:
                    chunks = bytearray()
                    while True:
                        block = member.read(_CHUNK)
                        if not block:
                            break
                        chunks += block
                        total += len(block)
                        if max_output_bytes is not None and total > max_output_bytes:
                            raise CompressionError(
                                f"zip archive decompresses beyond the {max_output_bytes}-byte ceiling "
                                "(possible decompression bomb)"
                            )
                result[info.filename] = bytes(chunks)
    except (zipfile.BadZipFile, OSError, EOFError, zlib.error) as exc:
        raise CompressionError(f"corrupt or truncated zip archive: {exc}") from exc
    return result
