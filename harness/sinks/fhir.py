# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""FHIR sink: the shared loopback HTTP sink (``_http.py``), registered for the ``fhir`` kind."""

from __future__ import annotations

from harness.endpoints import Endpoints
from harness.sinks import LOOPBACK, Sink
from harness.sinks._http import HttpSink

KIND = "fhir"


class FHIRSink(HttpSink):
    kind = KIND


def build(endpoints: Endpoints, key: str) -> Sink:
    return FHIRSink(LOOPBACK, endpoints.port(key))
