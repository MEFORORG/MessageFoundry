# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Compression codec (ADR 0123) — gzip / zlib-deflate / zip, bytes in → bytes out.

A partner file feed frequently delivers **gzipped/zipped** archives or requires **compressed** outbound
drops. This module is the primitive: a Handler calls it on demand against a
:class:`~messagefoundry.parsing.message.RawMessage`/:class:`~messagefoundry.parsing.message.Message`
body, and the File connector uses the single-stream ``gzip`` pair for its ``compress=``/``decompress=``
option (:mod:`messagefoundry.transports.file`).

It is **pure** — stdlib (:mod:`gzip`, :mod:`zlib`, :mod:`zipfile`, :mod:`io`) plus one sibling under
``parsing/`` (:mod:`messagefoundry.parsing.sniff`, for the archive-member admission checks), **no engine
imports** — so it sits under the ``parsing/`` carve-out (a client may import it, mirroring
:mod:`messagefoundry.parsing.binary` / :mod:`messagefoundry.parsing.x12`). The sibling import is
deliberate rather than a copied magic-byte table: the extension-keyed check and the declared-type check
must not be able to drift apart.

Compression is **orthogonal**
to the ADR 0028 base64 *carriage* codec: carriage makes bytes NUL-safe over the str/TEXT store;
compression shrinks them. They compose but never share a marker.

Two invariants shape the surface:

* **Re-run purity** ([CLAUDE.md](../../CLAUDE.md) §2). At-least-once relies on a transform re-deriving
  identical output, so :func:`gzip_compress` fixes ``mtime=0`` in the header (stock ``gzip.compress``
  embeds a *wall-clock* mtime → different bytes every second → a silent purity break) and
  :func:`zip_compress` fixes each entry's ZIP date. Compression output is a pure function of its input.

* **Decompression-bomb DoS** ([CLAUDE.md](../../CLAUDE.md) §9). Every decompress **requires** a
  ``max_output_bytes`` ceiling — it is keyword-only with **no default**, so a caller who has not
  thought about the bound cannot silently get an unbounded one. Passing ``None`` still means "no
  ceiling" and stays available to a caller who has bounded the input upstream, but it becomes a
  deliberate, greppable act rather than the default. The ceiling is enforced **incrementally**
  (bounded reads) so a bomb is refused after producing *at most* the ceiling — never after fully
  expanding in memory. Every corrupt / truncated / over-ceiling / bad-argument failure raises exactly
  one type, :class:`CompressionError` (a ``ValueError``), whose message names the codec and the byte
  ceiling only — **never any decompressed content** (it is PHI).

  Why a required keyword rather than a safer default (BACKLOG #1237): a default is a value the author
  never had to think about. A parameter with **no default** is a gate that refuses when the
  precondition is absent, which is a different construct from a stricter default and the reason this
  is not merely ``= 64 * 1024 * 1024``. The in-tree precedent is
  :func:`messagefoundry.parsing.dicom._inflate.bounded_inflate_or_error`, which takes its bound the
  same way. ``max_entries`` on :func:`zip_decompress` keeps its default because it already ships ON.
"""

from __future__ import annotations

import gzip
import io
import zipfile
import zlib
from collections.abc import Mapping

from messagefoundry.parsing.sniff import (
    archive_member_content_reason,
    archive_member_name_reason,
)

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


def gzip_decompress(data: bytes, *, max_output_bytes: int | None) -> bytes:
    """Decompress a gzip stream, refusing a **decompression bomb** at ``max_output_bytes``.

    ``max_output_bytes`` is **required** (BACKLOG #1237) — pass an explicit ``None`` to mean "no
    ceiling". See the module docstring for why it has no default.

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
                raise _over_ceiling("gzip", max_output_bytes)
            return out
    except (OSError, EOFError, zlib.error) as exc:
        # EOFError = truncated; OSError/BadGzipFile = corrupt header/trailer; zlib.error = bad DEFLATE.
        raise CompressionError(f"corrupt or truncated gzip stream: {exc}") from exc


def deflate_compress(data: bytes, *, level: int = 6) -> bytes:
    """Compress ``data`` to a zlib-wrapped DEFLATE stream (the "deflate" of HTTP/PDF).

    Deterministic (zlib embeds no timestamp), so a Handler that deflates stays re-run-stable."""
    _check_level(level)
    return zlib.compress(data, level)


def deflate_decompress(data: bytes, *, max_output_bytes: int | None) -> bytes:
    """Decompress a zlib-wrapped DEFLATE stream, refusing a bomb at ``max_output_bytes``.

    ``max_output_bytes`` is **required** (BACKLOG #1237) — pass an explicit ``None`` to mean "no
    ceiling". See the module docstring for why it has no default.

    Enforced incrementally with a :func:`zlib.decompressobj` ``max_length`` loop. It stops at the end
    of the stream, and its time is linear in the input plus the output. A corrupt or truncated
    stream, an over-ceiling size, or any bytes after the end of the stream raise
    :class:`CompressionError` (BACKLOG #1964). Stdlib :func:`zlib.decompress` ignores such bytes. This
    refuses them, so no part of the input is dropped without a word."""
    _check_ceiling(max_output_bytes)
    return _bounded_inflate(data, max_output_bytes, label="deflate")


def _over_ceiling(label: str, max_output_bytes: int) -> CompressionError:
    return CompressionError(
        f"{label} stream decompresses beyond the {max_output_bytes}-byte ceiling "
        "(possible decompression bomb)"
    )


def _bounded_inflate(data: bytes, max_output_bytes: int | None, *, label: str) -> bytes:
    # zlib-wrapped only. The tail rule below is wrong for gzip, which has members and NUL padding.
    d = zlib.decompressobj(wbits=_ZLIB_WBITS)
    out = bytearray()
    try:
        # Feed the input one window at a time. unconsumed_tail is a copy of the input not yet used,
        # so handing zlib the whole remainder copies it on every round, which is quadratic in the
        # compressed size (BACKLOG #1964). Slicing copies each window once, and unlike a memoryview
        # it leaves no export on a caller's bytearray behind a raised error.
        for offset in range(0, len(data), _CHUNK):
            pending = data[offset : offset + _CHUNK]
            # Stop at the end of the stream too. After it, zlib can keep trailing input in
            # unconsumed_tail and never use it, so a loop that watches only pending spins forever
            # without growing the output, and the ceiling never fires (BACKLOG #1964).
            while pending and not d.eof:
                # Ask for at most one byte past the ceiling, so a bomb stops at the ceiling itself.
                room = _CHUNK if max_output_bytes is None else max_output_bytes - len(out) + 1
                out += d.decompress(pending, min(_CHUNK, room))
                if max_output_bytes is not None and len(out) > max_output_bytes:
                    raise _over_ceiling(label, max_output_bytes)
                pending = d.unconsumed_tail
            if d.eof:
                if pending or d.unused_data or offset + _CHUNK < len(data):
                    # Refused rather than ignored: returning the first stream would drop the rest
                    # of the input without a word, which is accept-and-drop. A zlib stream has no
                    # multi-member form and no padding convention, so there is no tail to accept.
                    raise CompressionError(f"trailing data after the end of the {label} stream")
                return bytes(out)
        # The input ran out first. zlib may still hold output for input it has already taken.
        out += d.flush()
    except zlib.error as exc:
        raise CompressionError(f"corrupt or truncated {label} stream: {exc}") from exc
    if max_output_bytes is not None and len(out) > max_output_bytes:
        raise _over_ceiling(label, max_output_bytes)
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


def _member_codec_errors() -> tuple[type[Exception], ...]:
    # zipfile reads LZMA and Zstandard members through modules a Python build may omit, and neither
    # module's error is an OSError, so each is named when its module is present.
    errors: list[type[Exception]] = []
    try:
        import lzma

        errors.append(lzma.LZMAError)
    except ImportError:
        pass
    try:
        from compression import zstd

        errors.append(zstd.ZstdError)
    except ImportError:
        pass
    return tuple(errors)


# What a corrupt archive or member raises. ValueError covers a member name flagged UTF-8 that is not
# (UnicodeDecodeError) and a corrupt offset that makes zipfile seek to a negative position.
# CompressionError is a ValueError too, so zip_decompress re-raises it in an arm AHEAD of this one;
# without that arm the refusals its loop raises would be caught here and relabelled.
_ZIP_CORRUPT_ERRORS: tuple[type[Exception], ...] = (
    zipfile.BadZipFile,
    OSError,
    EOFError,
    zlib.error,
    ValueError,
    *_member_codec_errors(),
)


def zip_decompress(
    data: bytes, *, max_output_bytes: int | None, max_entries: int = 1024
) -> dict[str, bytes]:
    """Extract every member of a ZIP archive to ``{name: bytes}``, refusing a bomb.

    ``max_output_bytes`` is **required** (BACKLOG #1237) — pass an explicit ``None`` to mean "no
    ceiling". See the module docstring for why it has no default. ``max_entries`` keeps its default
    because it already ships ON, and is checked against the central directory before any member is
    extracted.

    ``max_entries`` caps the member count (a many-entry archive is a bomb axis too). ``max_output_bytes``
    caps the **total** decompressed size across all members, enforced with per-member bounded reads so a
    lying central-directory size cannot force full expansion. A corrupt archive, too many members, an
    over-ceiling total, or a member that uses a zip feature ``zipfile`` cannot read (encryption, a
    compression method, a format version) raises :class:`CompressionError`, which names a member by
    its position and never by its filename. Duplicate file member names also refuse the whole
    archive, since the returned mapping cannot preserve repeated names.

    Each member is also **admitted or refused** (ASVS 5.2.2 / 5.3.2, BACKLOG #1128) — its name must be a
    safe relative path and its bytes must correspond to the type its own extension names. Both checks are
    unconditional and take no parameter: an archive member names its own type, so nothing here depends on
    operator policy. See :mod:`messagefoundry.parsing.sniff` for what each one refuses and why refusal,
    not sanitization, is the treatment. A refused member raises :class:`CompressionError` for the WHOLE
    archive rather than being skipped — silently dropping one member of a feed is the accept-and-drop this
    project forbids ([CLAUDE.md](../../CLAUDE.md) §12), and the raise routes the message to the caller's
    error / dead-letter path."""
    _check_ceiling(max_output_bytes)
    if not isinstance(max_entries, int) or max_entries < 0:
        raise CompressionError(f"max_entries must be a non-negative int, got {max_entries!r}")
    result: dict[str, bytes] = {}
    total = 0
    position = 0
    failure: str | None = None
    try:
        with zipfile.ZipFile(io.BytesIO(data), mode="r") as zf:
            names = zf.namelist()
            if len(names) > max_entries:
                raise CompressionError(
                    f"zip archive has {len(names)} members, over the {max_entries}-member cap"
                )
            file_names = [info.filename for info in zf.infolist() if not info.is_dir()]
            if len(set(file_names)) != len(file_names):
                raise CompressionError("zip archive contains duplicate member names")
            for position, info in enumerate(zf.infolist(), start=1):
                if info.is_dir():
                    continue
                # Name first, BEFORE a single byte is read: a traversal name is refused for what it is,
                # not for what it expands to, and refusing early spends nothing on a hostile archive.
                name_reason = archive_member_name_reason(info.filename)
                if name_reason is not None:
                    raise CompressionError(f"zip archive member {position} refused: {name_reason}")
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
                body = bytes(chunks)
                content_reason = archive_member_content_reason(info.filename, body)
                if content_reason is not None:
                    raise CompressionError(
                        f"zip archive member {position} refused: {content_reason}"
                    )
                result[info.filename] = body
    except CompressionError:
        raise  # a refusal from the loop is already the verdict; the ValueError arm must not relabel it
    except _ZIP_CORRUPT_ERRORS as exc:
        # The class name is a diagnostic that carries no member name; the message may carry one.
        failure = f"is corrupt or truncated ({type(exc).__name__})"
    except RuntimeError:
        # NotImplementedError is a RuntimeError. zipfile raises RuntimeError for a member flagged as
        # encrypted and NotImplementedError for a compression method, a flag or a format version it
        # lacks (BACKLOG #1598).
        failure = (
            "uses a zip feature this reader does not support "
            "(encryption, a compression method, or a format version)"
        )
    # zipfile's messages embed the archive-chosen member filename, which can be PHI: the encrypted
    # RuntimeError carries the ZipInfo repr, and BadZipFile says "Bad CRC-32 for file '<name>'". So
    # the typed error names the member position only, and it is raised OUTSIDE the handler, with no
    # chain: `from None` clears __cause__ but leaves __context__, where a chain-walking handler
    # would still find the filename (BACKLOG #1598).
    if failure is not None:
        where = f"zip archive member {position}" if position else "zip archive"
        raise CompressionError(f"{where} {failure}")
    return result
