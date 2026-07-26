# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

import re
from dataclasses import dataclass, field

_DISPOSITION_PARAM = re.compile(r'(\w+)="([^"]*)"')


class MultipartError(ValueError):
    """The body is not a well-formed single-file ``multipart/form-data`` request."""


class MultipartTooLargeError(MultipartError):
    """A file part exceeds the caller's byte cap."""


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

    Raises :class:`MultipartError` if the Content-Type is not multipart or the body is malformed, and
    :class:`MultipartTooLargeError` if a file part exceeds ``max_file_bytes``. The boundary is trusted
    not to appear inside a part body (the RFC-2046 invariant every multipart parser relies on)."""
    boundary = parse_boundary(content_type)
    if boundary is None:
        raise MultipartError("Content-Type is not multipart/form-data with a boundary")
    delim = b"--" + boundary
    segments = body.split(delim)
    # segments[0] is the (usually empty) preamble; the terminator segment starts with b"--".
    form = MultipartForm()
    for segment in segments[1:]:
        if segment[:2] == b"--":  # the closing "--boundary--" terminator
            break
        # After each delimiter comes CRLF, then the part's header block.
        segment = segment[2:] if segment[:2] == b"\r\n" else segment.lstrip(b"\r\n")
        head, sep, content = segment.partition(b"\r\n\r\n")
        if not sep:
            continue  # no header/body separator — skip a malformed part rather than 500
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
