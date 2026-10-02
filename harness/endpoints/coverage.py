# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Endpoints of ``harness/config/coverage.py``: the MLLP and File coverage graph."""

from __future__ import annotations

from harness.endpoints import HOST, PATH, PORT, Endpoint

ENDPOINTS = (
    Endpoint(
        "host",
        HOST,
        "127.0.0.1",
        "the host drivers and engine outbounds dial (a sink always binds loopback)",
    ),
    Endpoint("mllp_in", PORT, "2575", "IB_Coverage_MLLP: the tolerant MLLP inbound"),
    Endpoint(
        "mllp_echo", PORT, "2576", "OB_Coverage_Echo: the MLLP outbound's peer (the harness sink)"
    ),
    Endpoint("mllp_strict", PORT, "2577", "IB_Coverage_Strict: the strict-validation MLLP inbound"),
    Endpoint(
        "file_in", PATH, "./harness_io/in", "FILE-IN_Coverage: the directory the engine polls"
    ),
    Endpoint(
        "file_out", PATH, "./harness_io/out", "FILE-OUT_Coverage: the directory the engine writes"
    ),
)
