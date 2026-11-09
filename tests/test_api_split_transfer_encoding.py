# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The request body limit refuses any ``Transfer-Encoding`` and any ``Content-Length`` that is not
one plain decimal number (BACKLOG #5345).

``_body_refusal`` once matched ``chunked`` in the first ``Transfer-Encoding`` line only. llhttp frames
``Transfer-Encoding: gzip`` followed by a second ``Transfer-Encoding: chunked`` line as chunked, so
the limit saw ``gzip``: with no Content-Length it admitted the chunked body at any size, and with a
Content-Length it skipped the ambiguous-framing 400. It also parsed the length with ``int()``, which
takes ``+2``, ``-5`` and ``0_2``, and read only the first of several Content-Length lines.

The scopes here are hand-built, because no HTTP client sends these shapes; the wire half is
``tests/test_api_request_framing_wire.py``. Every request goes to ``POST /auth/login``, a public
route that reads a body. The admitted control sends a one-byte body that is not JSON, and the route
answering 422 for it shows the body got past the limit and was read.
"""

from __future__ import annotations

import pytest

from messagefoundry.api.app import create_app
from tests.test_api_security_header_floor import _drive_raw

#: The route's own answer to a body it read and could not decode as JSON.
_ADMITTED = 422


@pytest.mark.parametrize(
    ("request_headers", "expected_status"),
    [
        # Transfer-Encoding is refused by presence: 411 alone, 400 beside a Content-Length.
        pytest.param(
            (("transfer-encoding", "gzip"), ("transfer-encoding", "chunked")),
            411,
            id="split gzip then chunked, no Content-Length",
        ),
        pytest.param(
            (
                ("content-length", "1"),
                ("transfer-encoding", "gzip"),
                ("transfer-encoding", "chunked"),
            ),
            400,
            id="split gzip then chunked, with a Content-Length",
        ),
        pytest.param(
            (("transfer-encoding", ""), ("transfer-encoding", "CHUNKED")),
            411,
            id="split empty then upper-case chunked, no Content-Length",
        ),
        pytest.param(
            (("transfer-encoding", "chunked"),), 411, id="single chunked, no Content-Length"
        ),
        pytest.param(
            (("content-length", "1"), ("transfer-encoding", "chunked")),
            400,
            id="single chunked, with a Content-Length",
        ),
        pytest.param(
            (("transfer-encoding", "gzip"), ("transfer-encoding", "identity")),
            411,
            id="split gzip then identity, no Content-Length",
        ),
        pytest.param(
            (
                ("content-length", "1"),
                ("transfer-encoding", "gzip"),
                ("transfer-encoding", "identity"),
            ),
            400,
            id="split gzip then identity, with a Content-Length",
        ),
        pytest.param((("transfer-encoding", ""),), 411, id="empty, no Content-Length"),
        pytest.param(
            (("content-length", "1"), ("transfer-encoding", "")),
            400,
            id="empty, with a Content-Length",
        ),
        # Content-Length must be one line holding only ASCII digits.
        pytest.param(
            (("content-length", "1"), ("content-length", "1")),
            400,
            id="Content-Length repeated, same value",
        ),
        pytest.param(
            (("content-length", "1"), ("content-length", "2")),
            400,
            id="Content-Length repeated, different values",
        ),
        pytest.param((("content-length", "1, 1"),), 400, id="Content-Length as a list"),
        pytest.param((("content-length", "-5"),), 400, id="Content-Length -5"),
        pytest.param((("content-length", "+1"),), 400, id="Content-Length +1"),
        pytest.param((("content-length", "0_1"),), 400, id="Content-Length 0_1"),
        pytest.param((("content-length", "1 0"),), 400, id="Content-Length with an inner space"),
        pytest.param((("content-length", ""),), 400, id="Content-Length empty"),
        # Controls: the cap, and what the limit admits.
        pytest.param((("content-length", "9" * 5000),), 413, id="Content-Length past int digits"),
        pytest.param((("content-length", "1"),), _ADMITTED, id="plain Content-Length"),
        pytest.param(
            (("content-length", " \t0001\t "),),
            _ADMITTED,
            id="plain Content-Length, leading zeros and surrounding whitespace",
        ),
    ],
)
async def test_the_body_limit_admits_only_one_plain_content_length(
    request_headers: tuple[tuple[str, str], ...], expected_status: int
) -> None:
    status, _ = await _drive_raw(
        create_app(allow_no_auth=True),
        method="POST",
        path="/auth/login",
        headers=(("content-type", "application/json"), *request_headers),
        body=b"{",
    )
    assert status == expected_status
