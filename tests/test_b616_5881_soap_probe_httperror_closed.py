# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5881: the SOAP test-connection probe closes the ``HTTPError`` response it catches.

The bearer half of the row was fixed by BACKLOG #5526 (the probe mints as ``_post`` does; pinned in
``tests/test_soap_credential_pairs.py``). Here: an ``HTTPError`` owns the open response, and the
probe reads only its status, so both arms (credential failure and reachable) close it. The
credential arm is the one that leaked: its ``DeliveryError`` chains the ``HTTPError`` as
``__cause__``, so the open response lived as long as the error did. The reachable arm is pinned
too, so a refactor that keeps a reference there cannot reopen the leak.
"""

from __future__ import annotations

import io
import urllib.error
import urllib.request
from email.message import Message

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Soap
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.soap import SoapDestination

URL = "https://api.example.com/svc"


class _RaisingOpener:
    def __init__(self, code: int) -> None:
        self.code = code
        self.body = io.BytesIO(b"synthetic fault body")

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> object:
        raise urllib.error.HTTPError(req.full_url, self.code, "synthetic", Message(), self.body)


def _dest() -> SoapDestination:
    d = build_destination(
        Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=Soap(url=URL).settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, SoapDestination)
    return d


@pytest.mark.parametrize("code", [401, 403])
def test_a_credential_failure_closes_the_http_error(code: int) -> None:
    d = _dest()
    opener = _RaisingOpener(code)
    d._opener = opener  # type: ignore[assignment]
    with pytest.raises(DeliveryError, match="check credentials") as ei:
        d._probe()
    # The DeliveryError chains the HTTPError, so whoever holds the error (the API reply path, a
    # log record) keeps it alive; reference-counting cannot close it for the probe.
    assert isinstance(ei.value.__cause__, urllib.error.HTTPError)
    assert opener.body.closed


@pytest.mark.parametrize("code", [404, 405, 500])
def test_a_reachable_status_closes_the_http_error(code: int) -> None:
    d = _dest()
    opener = _RaisingOpener(code)
    d._opener = opener  # type: ignore[assignment]
    d._probe()  # the host answered: reachable
    assert opener.body.closed
