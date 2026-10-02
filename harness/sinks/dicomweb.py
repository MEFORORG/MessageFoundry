# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DICOMweb STOW-RS sink: the shared loopback HTTP sink (``_http.py``), registered for the
``dicomweb`` kind. It records the ``multipart/related`` body as sent; a scenario unpacks it."""

from __future__ import annotations

from harness.endpoints import Endpoints
from harness.sinks import LOOPBACK, Sink
from harness.sinks._http import HttpSink

KIND = "dicomweb"


class DICOMwebSink(HttpSink):
    kind = KIND


def build(endpoints: Endpoints, key: str) -> Sink:
    return DICOMwebSink(LOOPBACK, endpoints.port(key))
