# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Compression codec (ADR 0123) — gzip / zlib-deflate / zip, bytes in → bytes out.

A partner file feed frequently delivers **gzipped/zipped** archives or requires **compressed** outbound
drops. This module is the primitive: a Handler calls it on demand against a
:class:`~messagefoundry.parsing.message.RawMessage`/:class:`~messagefoundry.parsing.message.Message`
body, and the File connector uses the single-stream ``gzip`` pair for its ``compress=``/``decompress=``
option (:mod:`messagefoundry.transports.file`).

It is **pure** — stdlib (:mod:`gzip`, :mod:`zlib`, :mod:`zipfile`, :mod:`io`) plus two siblings under
``parsing/`` (:mod:`messagefoundry.parsing.sniff`, for the archive-member admission checks, and
:mod:`messagefoundry.parsing._bounded_inflate`, the inflate loop it shares with the DICOM deflate
guard), **no engine imports** — so it sits under the ``parsing/`` carve-out (a client may import it,
mirroring :mod:`messagefoundry.parsing.binary` / :mod:`messagefoundry.parsing.x12`). Both sibling
imports are deliberate rather than copies: the extension-keyed check and the declared-type check must
not be able to drift apart, and neither may two copies of one inflate loop (BACKLOG #1977).

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

from messagefoundry.parsing._bounded_inflate import (
    CHUNK,
    InflateCeilingExceeded,
    InflateResult,
    InflateTrailingData,
    TrailingRule,
    bounded_inflate,
)
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
    "deflate_decompress_with_tail",
    "zip_compress",
    "zip_decompress",
]


class CompressionError(ValueError):
    """A compression / decompression operation failed: a corrupt or truncated stream, a
    decompressed size beyond the ceiling (a possible decompression bomb), or an invalid argument.

    Subclasses :class:`ValueError` (not :class:`OSError`) so a connector's ``except (TimeoutError,
    OSError)`` does not silently swallow it — it surfaces as the deliberate content error it is. The
    message names the **codec and the byte ceiling only**, never any (PHI) decompressed content."""


# Read/decompress in bounded chunks so a bomb is refused incrementally, never fully expanded. The
# same 64 KiB window the shared inflate loop feeds, so a stream sized in windows means one thing.
_CHUNK = CHUNK
# zlib window-bits selectors: 15 = zlib-wrapped DEFLATE ("deflate"); 31 = 16+15 = gzip.
_ZLIB_WBITS = 15
# The ZIP end-of-central-directory record (APPNOTE 4.3.16): a fixed 22-byte record whose last two
# bytes declare the length of the archive comment that follows it. The comment ends the archive.
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_SIZE = 22


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
    refuses them, so no part of the input is dropped without a word. When other data follows the
    stream by design, use :func:`deflate_decompress_with_tail`, which hands it back."""
    # Refused rather than ignored: returning the first stream would drop the rest of the input
    # without a word, which is accept-and-drop (BACKLOG #1964).
    return _inflate_zlib(data, max_output_bytes, trailing="refuse").output


def deflate_decompress_with_tail(
    data: bytes, *, max_output_bytes: int | None
) -> tuple[bytes, bytes]:
    """Decompress the zlib-wrapped DEFLATE stream that starts ``data``, and return what follows it.

    Returns ``(body, tail)``. ``body`` is the inflated stream. ``tail`` is every input byte after the
    end of the stream, and is ``b""`` when nothing follows. This is for a stream with other data after
    it, such as a PDF ``FlateDecode`` stream and its end-of-line, or several streams back to back.
    Stripping that data first is not safe: only the inflater knows where the stream ends. A stream's
    last byte is a checksum byte, which can itself be a CR or LF, so stripping line ends truncates
    that stream (BACKLOG #1978).

    ``max_output_bytes`` is **required** (BACKLOG #1237) and bounds this one stream. The ceiling, the
    linear-time loop and the errors are :func:`deflate_decompress`'s: a corrupt or truncated stream
    or an over-ceiling size raises :class:`CompressionError`. The tail is returned unread, so the
    caller decides what it may hold. A caller that walks several streams calls this once per stream,
    and owns the bound on how many it takes. Each call copies the tail, so that walk costs time in
    proportion to the number of streams times the input size."""
    result = _inflate_zlib(data, max_output_bytes, trailing="stop")
    return result.output, bytes(data[result.end :])


def _inflate_zlib(
    data: bytes, max_output_bytes: int | None, *, trailing: TrailingRule
) -> InflateResult:
    """The codec's rules over the shared loop (BACKLOG #1977): its one error type, and a truncated
    stream is an error. ``trailing`` is the only thing the two public callers set differently. Wrong
    for gzip, which has members and NUL padding, so this is zlib-wrapped only."""
    _check_ceiling(max_output_bytes)
    try:
        result = bounded_inflate(
            data,
            zlib.decompressobj(wbits=_ZLIB_WBITS),
            max_output_bytes=max_output_bytes,
            trailing=trailing,
            keep_output=True,
            exact_ceiling=True,
        )
    except InflateCeilingExceeded as exc:
        raise _over_ceiling("deflate", exc.ceiling) from None
    except InflateTrailingData:
        raise CompressionError("trailing data after the end of the deflate stream") from None
    except zlib.error as exc:
        raise CompressionError(f"corrupt or truncated deflate stream: {exc}") from exc
    if not result.eof:
        raise CompressionError("truncated deflate stream (input ended mid-stream)")
    return result


def _over_ceiling(label: str, max_output_bytes: int) -> CompressionError:
    return CompressionError(
        f"{label} stream decompresses beyond the {max_output_bytes}-byte ceiling "
        "(possible decompression bomb)"
    )


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
# (UnicodeDecodeError). A corrupt offset that would make zipfile seek to a negative position is a
# ValueError too, though _zip_layout_reason refuses that archive before any member is opened.
# A zip64 member offset at or above 2**63 makes that seek raise OverflowError, which is not a
# ValueError (BACKLOG #1598).
# CompressionError is a ValueError too, so zip_decompress re-raises it in an arm AHEAD of this one;
# without that arm the refusals its loop raises would be caught here and relabelled.
_ZIP_CORRUPT_ERRORS: tuple[type[Exception], ...] = (
    zipfile.BadZipFile,
    OSError,
    EOFError,
    zlib.error,
    ValueError,
    OverflowError,
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
    archive, since the returned mapping cannot preserve repeated names. So do two members that share
    one local header, the overlapped-entries zip-bomb shape (BACKLOG #1598).

    Each member is also **admitted or refused** (ASVS 5.2.2 / 5.3.2, BACKLOG #1128) — its name must be a
    safe relative path and its bytes must correspond to the type its own extension names. Both checks are
    unconditional and take no parameter: an archive member names its own type, so nothing here depends on
    operator policy. See :mod:`messagefoundry.parsing.sniff` for what each one refuses and why refusal,
    not sanitization, is the treatment. A refused member raises :class:`CompressionError` for the WHOLE
    archive rather than being skipped — silently dropping one member of a feed is the accept-and-drop this
    project forbids ([CLAUDE.md](../../CLAUDE.md) §12), and the raise routes the message to the caller's
    error / dead-letter path.

    Bytes before or after the archive are refused too (BACKLOG #1976). The archive ends at its
    end-of-central-directory record plus the comment that record declares, and starts at its first
    member. Stdlib :mod:`zipfile` finds that record by scanning back from the end of the input, and
    treats anything before the archive as prepended data it skips. So it opens an archive with a short
    tail after it, or with bytes, even a whole second archive, in front of it, and never reads them.
    That is the same accept-and-drop :func:`deflate_decompress` refuses, so this refuses it the same
    way. A tail too long for that scan, with no archive at its end, fails in :mod:`zipfile` as corrupt.
    A comment shorter than its record declares is refused as truncated. Bytes hidden between two
    members are not checked."""
    _check_ceiling(max_output_bytes)
    if not isinstance(max_entries, int) or max_entries < 0:
        raise CompressionError(f"max_entries must be a non-negative int, got {max_entries!r}")
    result: dict[str, bytes] = {}
    total = 0
    position = 0
    failure: str | None = None
    try:
        with zipfile.ZipFile(io.BytesIO(data), mode="r") as zf:
            # Before any member is read, like the member-count cap: a refused archive costs nothing.
            layout_reason = _zip_layout_reason(data, zf)
            if layout_reason is not None:
                raise CompressionError(layout_reason)
            overlap_reason = _zip_overlap_reason(zf)
            if overlap_reason is not None:
                raise CompressionError(overlap_reason)
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
    except RecursionError:
        # A RuntimeError too, so it needs its own arm AHEAD of the next one. Nothing in the archive
        # recurses; the caller's stack was already near the limit, so say that rather than blame the
        # archive for a feature it may not use.
        failure = "could not be read (the interpreter recursion limit was reached)"
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


def _zip_overlap_reason(zf: zipfile.ZipFile) -> str | None:
    """Why two central-directory entries of ``zf`` share one local header, or ``None`` when none do.
    The reason names members by position only.

    The format gives each entry its own local header, and no writer this project knows of shares
    one. Entries that share one are overlapped: each name expands the same stored bytes, which is
    the zip-bomb shape. The names can still differ through the Unicode path extra field, so the
    duplicate-name check does not catch it. A placeholder offset that several entries repeat without
    its zip64 field is refused here too, as overlapped rather than as corrupt. This check
    also closes a PHI leak (BACKLOG #1598). :mod:`zipfile` does not refuse this shape; it warns
    ``Overlapped entries: '<name>'`` and reads on, and that warning prints the archive-chosen member
    name to stderr, which the service log captures. It warns only when an entry's local header is
    where its successor's is, and a header at the central directory's own offset fails its signature
    check first. So no archive this check admits can raise that warning.

    The refusal is by construction rather than by a ``warnings.catch_warnings`` filter: that filter
    edits process-global state, and transforms run on worker threads.

    Every offset counts, including one past the central directory's start. The central directory
    holds archive-chosen bytes, so a forged local header can sit inside it, and two entries pointing
    there would reach the warning if this check skipped them."""
    first_at: dict[int, int] = {}
    for position, info in enumerate(zf.infolist(), start=1):
        earlier = first_at.setdefault(info.header_offset, position)
        if earlier != position:
            return (
                f"zip archive member {position} refused: it shares member {earlier}'s local "
                "header (overlapped entries, a zip-bomb shape)"
            )
    return None


def _zip_layout_reason(data: bytes, zf: zipfile.ZipFile) -> str | None:
    """Why ``data`` holds bytes outside the archive :mod:`zipfile` opened, or ``None`` when it holds
    none. The reason names no content.

    **After the archive.** ``zf.comment`` is the comment :mod:`zipfile` read, after the LAST
    end-record signature in the input. A clean archive therefore ends with that record, whose declared
    comment length is ``len(comment)``, followed by the comment. With a tail, the bytes where the
    record would have to start are not a record: a record there would be a later signature, and
    :mod:`zipfile` would have used it. With a comment shorter than it declares, :mod:`zipfile` still
    reads the short comment, so the record sits where it should and only its declared length
    disagrees.

    **Before the archive.** :mod:`zipfile` adds the length of any prepended data to every member's
    ``header_offset``, so a clean archive has a member at offset 0. An archive with no members is only
    its end record, so that record starts the input."""
    comment = zf.comment
    start = len(data) - _ZIP_EOCD_SIZE - len(comment)
    record = data[start : start + _ZIP_EOCD_SIZE] if start >= 0 else b""
    if record[:4] != _ZIP_EOCD_SIGNATURE:
        return "trailing data after the end of the zip archive"
    if int.from_bytes(record[-2:], "little") != len(comment):
        return "truncated zip archive comment (input ended before the archive did)"
    members = zf.infolist()
    first = min(info.header_offset for info in members) if members else start
    if first != 0:
        return "data before the start of the zip archive"
    return None
