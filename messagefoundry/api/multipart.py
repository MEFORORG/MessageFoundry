# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Minimal stdlib ``multipart/form-data`` parser for the uploaded-logs endpoint (ADR 0134).

**No `python-multipart`.** The engine deliberately carries no multipart dependency — the console
already hand-parses urlencoded bodies with stdlib (``routes/core.py`` no-multipart stance). A single
file upload is a trivial `multipart/form-data` body, so it is hand-parsed here with the stdlib: the
boundary is read from the ``Content-Type``, the body is split on the boundary delimiter, and each
part's ``Content-Disposition`` gives its field name + (for a file) filename. A **hard size cap** is
enforced on each file part before it is retained.

Scope: exactly what an upload form needs — one file part + optional small text fields. It is not a
general RFC-2388 implementation (no nested multipart/mixed, no transfer-encoding decode); those are out
of scope for an operator file upload and are not accepted.
"""

from __future__ import annotations

import asyncio
import functools
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

# The leading ``(?<!\w)`` is a **ReDoS guard**, not a semantic filter (CodeQL py/polynomial-redos).
# Without it, ``(\w+)="…"`` is quadratic on a hostile Content-Disposition line: the scan restarts at
# every offset inside a word run, and at each one ``\w+`` walks the rest of the run before failing —
# O(n^2) on a header of n word characters. That header block is attacker-supplied and bounded only by
# ``[store].max_upload_bytes`` (25 MiB default), and a single scan would wedge the whole engine for
# days. Running the parse in a worker thread (BACKLOG #5522) does not change that: one ``re`` scan is
# a single C call that holds the GIL throughout, so the event loop stalls with it. The lookbehind is
# O(1) and fails every offset *inside* a run immediately, leaving one ``\w+`` walk per run — O(n)
# overall.
#
# It removes no match: ``=`` is not a word character, so ``\w+`` starting anywhere inside a run can
# only ever succeed at that run's end — i.e. an interior offset matches iff the run's first offset
# does, and the leftmost scan always reaches the first offset earlier. Equivalence is pinned by
# ``tests/test_multipart.py::test_disposition_param_regex_matches_legacy_semantics``.
_DISPOSITION_PARAM = re.compile(r'(?<!\w)(\w+)="([^"]*)"')

#: Cap on one part's header block. RFC 2388 part headers are ``Content-Disposition`` plus at most a
#: ``Content-Type``/``Content-Transfer-Encoding``, so 16 KiB is orders of magnitude more than any real
#: client sends. Without it the block is bounded only by the request body cap — ``[store]
#: .max_upload_bytes``, 25 MiB by default and up to 512 MiB — because that cap is applied to a part's
#: *content*, only after its header has already been parsed. The scan is linear (see the guard above),
#: but it ran synchronously on the asyncio event loop that also drives every listener and worker, and
#: linear is not free at that size: a single request would block the engine for ~0.35 s at 25 MiB and
#: ~7 s at the ceiling (the worker thread since BACKLOG #5522 does not help a single scan; see the
#: guard above). Bounding the header keeps the cost microseconds and, incidentally, gives the ReDoS
#: analysis a length-bounded source instead of an attacker-sized one.
_MAX_PART_HEADER_BYTES = 16 * 1024

#: Cap on the number of parts in one body. Both upload surfaces send one file part, and the console
#: form carries no other field, so 16 is generous. Without it the part count is bounded only by the
#: body cap: a 25 MiB body of empty parts is about 2.9 million segments, each one split, copied and
#: header-parsed. Measured 2026-11-10 on a dev box, that took about 2 s with a peak near 150 MiB, about
#: six times the body. The split is bounded, so an over-cap body never builds the long list.
_MAX_PARTS = 16

#: Cap on one non-file field's bytes. ``max_file_bytes`` bounds only file parts, so a text field was
#: bounded by the body cap alone and was decoded into a ``str`` of up to the whole body. No upload
#: surface reads a text field today, so this only has to admit a short form value.
_MAX_FIELD_BYTES = 16 * 1024

#: The upload parse's own executor (BACKLOG #5522). Not the loop's default executor: router and
#: transform work runs there, and each parse holds several transient copies of its body. Two workers
#: bound the threads, and those copies, that concurrent uploads can take in this process. Later
#: parses queue here. A semaphore around ``asyncio.to_thread`` would not hold that bound, because a
#: cancelled request (the request deadline) releases its slot while its thread keeps parsing. The
#: bodies themselves are read before the parse and are not bounded by this.
_PARSE_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="mefor-upload-parse")


class MultipartError(ValueError):
    """The body is not a well-formed single-file ``multipart/form-data`` request."""


class MultipartTooLargeError(MultipartError):
    """A file part exceeds the caller's byte cap, or a text field exceeds ``_MAX_FIELD_BYTES``."""


@dataclass(frozen=True)
class FilePart:
    """One uploaded file part: the form field ``name``, the client ``filename``, and the raw bytes."""

    name: str
    filename: str
    data: bytes


@dataclass(frozen=True)
class MultipartForm:
    """The parsed parts of a ``multipart/form-data`` body: file parts + simple text fields."""

    files: list[FilePart] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)


def parse_boundary(content_type: str | None) -> bytes | None:
    """Extract the boundary token (as bytes) from a ``multipart/form-data`` Content-Type, or ``None``."""
    ct = content_type or ""
    if "multipart/form-data" not in ct.lower():
        return None
    for param in ct.split(";"):
        param = param.strip()
        if param.lower().startswith("boundary="):
            value = param[len("boundary=") :].strip()
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            # RFC 2046 boundaries are ASCII; latin-1 round-trips any byte a client might send.
            return value.encode("latin-1") if value else None
    return None


def _disposition(head: bytes) -> tuple[str | None, str | None]:
    """Parse a part's header block for its Content-Disposition ``name`` + ``filename`` (or ``None``)."""
    text = head.decode("latin-1", "replace")
    name: str | None = None
    filename: str | None = None
    for line in text.split("\r\n"):
        if line.lower().startswith("content-disposition:"):
            for match in _DISPOSITION_PARAM.finditer(line):
                key, value = match.group(1).lower(), match.group(2)
                if key == "name":
                    name = value
                elif key == "filename":
                    filename = value
    return name, filename


def parse_multipart_form(
    content_type: str | None, body: bytes, *, max_file_bytes: int
) -> MultipartForm:
    """Parse a ``multipart/form-data`` body into file parts + text fields.

    Raises :class:`MultipartError` if the Content-Type is not multipart, the body is malformed, or it
    holds more than ``_MAX_PARTS`` parts, and :class:`MultipartTooLargeError` if a file part exceeds
    ``max_file_bytes`` or a text field exceeds ``_MAX_FIELD_BYTES``. The boundary is trusted not to
    appear inside a part body (the RFC-2046 invariant every multipart parser relies on).

    The function is synchronous and walks the whole body, so an async caller goes through
    :func:`parse_upload_off_loop`."""
    boundary = parse_boundary(content_type)
    if boundary is None:
        raise MultipartError("Content-Type is not multipart/form-data with a boundary")
    delim = b"--" + boundary
    # segments[0] is the (usually empty) preamble, and the closing "--boundary--" terminator is the
    # first later segment that starts with b"--"; anything after it is the ignorable epilogue. The
    # split is bounded so a body of many parts never builds a long list: _MAX_PARTS + 1 splits leave
    # room for the preamble, _MAX_PARTS parts and the terminator. When no terminator turns up within
    # them, the body holds more parts than the cap (or is unterminated past it). Refuse before any
    # part is parsed rather than parse the first _MAX_PARTS: a body this shape is never a real form.
    segments = body.split(delim, _MAX_PARTS + 1)
    end = next((i for i in range(1, len(segments)) if segments[i][:2] == b"--"), len(segments))
    if end - 1 > _MAX_PARTS:
        raise MultipartError(f"multipart body has more parts than the limit of {_MAX_PARTS}")
    form = MultipartForm()
    for segment in segments[1:end]:
        # After each delimiter comes CRLF, then the part's header block.
        segment = segment[2:] if segment[:2] == b"\r\n" else segment.lstrip(b"\r\n")
        head, sep, content = segment.partition(b"\r\n\r\n")
        if not sep:
            continue  # no header/body separator — skip a malformed part rather than 500
        if len(head) > _MAX_PART_HEADER_BYTES:
            # Refuse rather than skip: a header this size is never a real client, and skipping would
            # surface as the confusing "no file part" error instead of naming the actual problem.
            raise MultipartError(
                f"multipart part header block is {len(head)} bytes; the limit is "
                f"{_MAX_PART_HEADER_BYTES}"
            )
        if content.endswith(b"\r\n"):
            content = content[:-2]  # trailing CRLF before the next delimiter
        name, filename = _disposition(head)
        if filename is not None:
            if len(content) > max_file_bytes:
                raise MultipartTooLargeError(
                    f"uploaded file part is {len(content)} bytes; the limit is {max_file_bytes}"
                )
            form.files.append(FilePart(name=name or "file", filename=filename, data=content))
        elif name is not None:
            if len(content) > _MAX_FIELD_BYTES:
                # The hint names the likeliest cause: a log sent as a plain field (no filename), as
                # ``curl -F 'file=<log.hl7'`` does, rather than as a file part.
                raise MultipartTooLargeError(
                    f"multipart text field is {len(content)} bytes; the limit is "
                    f"{_MAX_FIELD_BYTES}. Send a file as a file part with a plain filename "
                    f'parameter (filename="...")'
                )
            form.fields[name] = content.decode("utf-8", "replace")
    return form


def parse_single_file_upload(
    content_type: str | None, body: bytes, *, max_file_bytes: int
) -> FilePart:
    """Parse a body expected to carry exactly one file part; return it. Raises :class:`MultipartError`
    if no file part is present."""
    form = parse_multipart_form(content_type, body, max_file_bytes=max_file_bytes)
    if not form.files:
        raise MultipartError("no file part in the multipart/form-data body")
    return form.files[0]


async def parse_upload_off_loop(
    content_type: str | None, body: bytes, *, max_file_bytes: int
) -> FilePart:
    """:func:`parse_single_file_upload` on :data:`_PARSE_EXECUTOR`, for an async caller. It raises
    what that function raises. The per-part work leaves the event loop; each whole-body ``split``,
    slice and ``partition`` is still one C call that holds the GIL while it runs."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _PARSE_EXECUTOR,
        functools.partial(
            parse_single_file_upload, content_type, body, max_file_bytes=max_file_bytes
        ),
    )
