# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SOAP sink: the shared loopback HTTP sink (``_http.py``), registered for the ``soap`` kind."""

from __future__ import annotations

from harness.endpoints import Endpoints
from harness.sinks import LOOPBACK, Sink
from harness.sinks._http import HttpSink

KIND = "soap"


class SoapSink(HttpSink):
    kind = KIND


def build(endpoints: Endpoints, key: str) -> Sink:
    return SoapSink(LOOPBACK, endpoints.port(key))
