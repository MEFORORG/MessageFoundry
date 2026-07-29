# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Stdlib multipart/form-data parser for uploaded logs (ADR 0134) — no python-multipart."""

from __future__ import annotations

import re
import time

import pytest

from messagefoundry.api.multipart import (
    _DISPOSITION_PARAM,
    _MAX_PART_HEADER_BYTES,
    MultipartError,
    MultipartTooLargeError,
    parse_boundary,
    parse_multipart_form,
    parse_single_file_upload,
)

_B = "----WebKitFormBoundaryABC123"


def _body(parts: list[bytes]) -> bytes:
    delim = f"--{_B}".encode()
    out = b""
    for p in parts:
        out += delim + b"\r\n" + p + b"\r\n"
    out += delim + b"--\r\n"
    return out


def test_parse_boundary() -> None:
    assert parse_boundary(f"multipart/form-data; boundary={_B}") == _B.encode()
    assert parse_boundary('multipart/form-data; boundary="quoted-bnd"') == b"quoted-bnd"
    assert parse_boundary("application/json") is None
    assert parse_boundary(None) is None


def test_single_file_upload_extracts_bytes() -> None:
    hl7 = b"MSH|^~\\&|A|B|C|D|202601010000||ADT^A01|X1|P|2.5\rPID|1||MRN\r"
    part = (
        b'Content-Disposition: form-data; name="file"; filename="acme.hl7"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" + hl7
    )
    body = _body([part])
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", body, max_file_bytes=1024
    )
    assert file.filename == "acme.hl7"
    assert file.name == "file"
    assert file.data == hl7  # exact bytes preserved (CR delimiters intact)


def test_file_plus_text_field() -> None:
    part_file = b'Content-Disposition: form-data; name="file"; filename="x.hl7"\r\n\r\nMSH|body'
    part_field = b'Content-Disposition: form-data; name="content_type"\r\n\r\nhl7v2'
    form = parse_multipart_form(
        f"multipart/form-data; boundary={_B}", _body([part_file, part_field]), max_file_bytes=1024
    )
    assert len(form.files) == 1
    assert form.files[0].data == b"MSH|body"
    assert form.fields["content_type"] == "hl7v2"


def test_too_large_rejected() -> None:
    part = b'Content-Disposition: form-data; name="file"; filename="big"\r\n\r\n' + b"x" * 100
    with pytest.raises(MultipartTooLargeError):
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}", _body([part]), max_file_bytes=10
        )


def test_non_multipart_rejected() -> None:
    with pytest.raises(MultipartError):
        parse_single_file_upload("application/json", b"{}", max_file_bytes=1024)


def test_no_file_part_rejected() -> None:
    part = b'Content-Disposition: form-data; name="just_a_field"\r\n\r\nvalue'
    with pytest.raises(MultipartError):
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}", _body([part]), max_file_bytes=1024
        )


# --- ReDoS guard on the Content-Disposition parameter regex (CodeQL py/polynomial-redos) ---------

#: The pre-guard pattern. Kept here so the equivalence test proves the ``(?<!\w)`` guard is a pure
#: performance change; if the production regex ever drifts, this test is what catches the semantic gap.
_LEGACY_DISPOSITION_PARAM = re.compile(r'(\w+)="([^"]*)"')


@pytest.mark.parametrize(
    "line",
    [
        'Content-Disposition: form-data; name="file"; filename="acme.hl7"',
        'Content-Disposition:form-data;name="a";filename="b.txt"',
        'Content-Disposition: form-data; filename="a;b=c.txt"; name="f"',
        'Content-Disposition: form-data; name=""',
        'Content-Disposition: form-data; foo*name="x"',
        'Content-Disposition: form-data; name="x" name="y"',
        'Content-Disposition: form-data; 9name="d"; _n="e"',
        'Content-Disposition: form-data; name = "spaced"',
        'name="a"filename="b"',
        "Content-Disposition: form-data",
    ],
)
def test_disposition_param_regex_matches_legacy_semantics(line: str) -> None:
    """The ``(?<!\\w)`` ReDoS guard must not change which parameters are extracted."""
    assert _DISPOSITION_PARAM.findall(line) == _LEGACY_DISPOSITION_PARAM.findall(line)


def test_hostile_disposition_header_parses_in_linear_time() -> None:
    """A Content-Disposition line of many word chars and no ``="`` must not blow up quadratically.

    The header block is attacker-supplied and ``parse_single_file_upload`` runs synchronously on the
    asyncio event loop, so a quadratic scan here is a whole-engine denial of service, not a slow
    request. ``_MAX_PART_HEADER_BYTES`` now bounds the input as well, but the two controls are
    independent on purpose: the cap is a size policy someone could reasonably raise, while this asserts
    the scan itself stays linear at any size. Assert the growth ratio rather than a wall-clock budget so
    the test is not flaky on a loaded CI runner: quadratic scaling multiplies by ~16 when the input
    quadruples; linear scaling stays near ~4.
    """

    def elapsed(n: int, reps: int = 3) -> float:
        """Best-of-``reps``: a scheduling hiccup can only inflate a sample, never deflate one, so the
        MINIMUM is the noise-free estimate — one slow slice on a loaded runner cannot fake a red."""
        line = "content-disposition: " + "a" * n
        best = float("inf")
        for _ in range(reps):
            start = time.perf_counter()
            _DISPOSITION_PARAM.findall(line)
            best = min(best, time.perf_counter() - start)
        return best

    base_n = 20_000
    elapsed(base_n)  # warm the regex cache / JIT-free interpreter paths
    small = max(elapsed(base_n), 1e-6)
    large = elapsed(base_n * 4)
    assert large / small < 8.0, f"scaling looks super-linear: {small=} {large=}"


def test_oversized_part_header_is_refused_not_parsed() -> None:
    """A part header block past ``_MAX_PART_HEADER_BYTES`` is rejected before ``_disposition`` runs.

    The per-part ``max_file_bytes`` cap applies to a part's *content*, and only AFTER its header has
    been parsed — so without this bound the header scan's input is the whole request body (25 MiB by
    default, 512 MiB at the ceiling) on the asyncio event loop. A real client never approaches it: a
    Content-Disposition plus a Content-Type is a couple hundred bytes.
    """
    fat = b"X" * (_MAX_PART_HEADER_BYTES + 1)
    part = (
        b'Content-Disposition: form-data; name="file"; filename="a.hl7"\r\nX-Pad: '
        + fat
        + b"\r\n\r\nbody"
    )
    with pytest.raises(MultipartError, match="header block"):
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}", _body([part]), max_file_bytes=10_000_000
        )


def test_realistic_part_header_is_well_under_the_cap() -> None:
    """Non-vacuity for the cap: an ordinary upload's header must be nowhere near the limit, so the
    bound can never start rejecting legitimate traffic."""
    head = b'Content-Disposition: form-data; name="file"; filename="acme.hl7"\r\nContent-Type: application/octet-stream'
    assert len(head) * 50 < _MAX_PART_HEADER_BYTES
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}",
        _body([head + b"\r\n\r\nMSH|body"]),
        max_file_bytes=1024,
    )
    assert file.filename == "acme.hl7"
