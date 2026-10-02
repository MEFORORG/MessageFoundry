# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Endpoints of ``harness/config/hostile.py``: the hostile-content pass-through graph."""

from __future__ import annotations

from harness.endpoints import PATH, PORT, Endpoint

ENDPOINTS = (
    Endpoint("hostile_mllp_in", PORT, "2628", "IB_Hostile_MLLP: the hostile-content MLLP inbound"),
    Endpoint(
        "hostile_mllp_echo",
        PORT,
        "2629",
        "OB_Hostile_Echo: the pass-through MLLP outbound's peer (the harness sink)",
    ),
    Endpoint(
        "hostile_file_in",
        PATH,
        "./harness_io/hostile_in",
        "FILE-IN_Hostile: the directory the hostile-content File inbound polls",
    ),
    Endpoint(
        "hostile_file_out",
        PATH,
        "./harness_io/hostile_out",
        "FILE-OUT_Hostile: the directory the pass-through File outbound writes, named {MSH-10}.hl7",
    ),
)
