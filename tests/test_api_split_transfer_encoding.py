# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The request body limit reads every ``Transfer-Encoding`` line, not only the first (BACKLOG #5345).

llhttp frames ``Transfer-Encoding: gzip`` followed by a second ``Transfer-Encoding: chunked`` line as
chunked. ``_body_refusal`` once read the header with ``Headers.get``, which returns the first line
only, so it saw ``gzip``: with no Content-Length it admitted the chunked body at any size, and with a
Content-Length it skipped the ambiguous-framing 400. The scopes here are hand-built, because no HTTP
client sends a split Transfer-Encoding; the wire half is the split shapes in
``tests/test_api_request_framing_wire.py``.

``POST /health`` has no route, so a request the limit admits is answered 405 by the router.
"""

from __future__ import annotations

import pytest

from messagefoundry.api.app import create_app
from tests.test_api_security_header_floor import _drive_raw

_ADMITTED = 405


@pytest.mark.parametrize(
    ("request_headers", "expected_status"),
    [
        pytest.param(
            (("transfer-encoding", "gzip"), ("transfer-encoding", "chunked")),
            411,
            id="split gzip then chunked, no Content-Length",
        ),
        pytest.param(
            (
                ("content-length", "2"),
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
        # Controls: what the fix leaves as it was. The two non-chunked ones pin today's admission,
        # which #5345's original finding (a body with no length and no chunked coding) may change.
        pytest.param(
            (("transfer-encoding", "chunked"),), 411, id="single chunked, no Content-Length"
        ),
        pytest.param(
            (("content-length", "2"), ("transfer-encoding", "chunked")),
            400,
            id="single chunked, with a Content-Length",
        ),
        pytest.param(
            (("transfer-encoding", "gzip"), ("transfer-encoding", "identity")),
            _ADMITTED,
            id="split gzip then identity, no Content-Length",
        ),
        pytest.param(
            (
                ("content-length", "2"),
                ("transfer-encoding", "gzip"),
                ("transfer-encoding", "identity"),
            ),
            _ADMITTED,
            id="split gzip then identity, with a Content-Length",
        ),
    ],
)
async def test_the_body_limit_reads_every_transfer_encoding_line(
    request_headers: tuple[tuple[str, str], ...], expected_status: int
) -> None:
    status, _ = await _drive_raw(
        create_app(allow_no_auth=True), method="POST", path="/health", headers=request_headers
    )
    assert status == expected_status
