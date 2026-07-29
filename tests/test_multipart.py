# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Stdlib multipart/form-data parser for uploaded logs (ADR 0134) — no python-multipart."""

from __future__ import annotations

import re
import time

import pytest

from messagefoundry.api.multipart import (
    _DISPOSITION_PARAM,
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

    The header block is attacker-supplied and bounded only by ``[store].max_upload_bytes`` (25 MiB
    default), and ``parse_single_file_upload`` runs synchronously on the asyncio event loop — so a
    quadratic scan here is a whole-engine denial of service, not a slow request. Assert the growth
    ratio rather than a wall-clock budget so the test is not flaky on a loaded CI runner: quadratic
    scaling multiplies by ~16 when the input quadruples; linear scaling stays near ~4.
    """

    def elapsed(n: int) -> float:
        line = "content-disposition: " + "a" * n
        start = time.perf_counter()
        _DISPOSITION_PARAM.findall(line)
        return time.perf_counter() - start

    base_n = 20_000
    elapsed(base_n)  # warm the regex cache / JIT-free interpreter paths
    small = max(elapsed(base_n), 1e-6)
    large = elapsed(base_n * 4)
    assert large / small < 8.0, f"scaling looks super-linear: {small=} {large=}"
