# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared stand-ins for the malformed-reply tests of the HTTP callers (BACKLOG #2113).

NOT a test module (the leading underscore keeps pytest from collecting it).
"""

from __future__ import annotations

import http.client
import urllib.request

import pytest

from messagefoundry.transports.bounded_read import EgressReplyError

# The text is planted so a leak into an error message would show. Neither class is an OSError or a
# URLError, which is why each caller needs an arm that names HTTPException.
MALFORMED_REPLIES = [
    pytest.param(http.client.BadStatusLine("SYNTHETICPLANTED"), id="bad-status-line"),
    pytest.param(http.client.LineTooLong("SYNTHETICPLANTED"), id="line-too-long"),
]


class RefusedAndMalformed(EgressReplyError, http.client.HTTPException):
    """Stands in for a reply refusal that is also an HTTPException, the shape the bare-CR refusal
    of BACKLOG #2052 takes."""


class RaisingOpener:
    """An opener whose every ``open`` raises the one exception it was given."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> object:
        raise self._exc
