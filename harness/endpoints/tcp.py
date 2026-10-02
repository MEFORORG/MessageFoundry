# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Endpoints of the raw-TCP half of ``harness/config/tcp_x12.py`` (vault BACKLOG #2674)."""

from __future__ import annotations

from harness.endpoints import PORT, Endpoint

ENDPOINTS = (
    Endpoint("tcp_in", PORT, "2580", "IB_Harness_TCP: the STX/ETX-framed raw-TCP inbound"),
    Endpoint(
        "tcp_out", PORT, "2581", "OB_Harness_TCP: the raw-TCP outbound's peer (the harness sink)"
    ),
)
