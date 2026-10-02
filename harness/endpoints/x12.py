# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Endpoints of the X12 half of ``harness/config/tcp_x12.py`` (vault BACKLOG #2674)."""

from __future__ import annotations

from harness.endpoints import PORT, Endpoint

ENDPOINTS = (
    Endpoint("x12_in", PORT, "2582", "IB_Harness_X12: the ISA/IEA-framed X12 inbound"),
    Endpoint("x12_out", PORT, "2583", "OB_Harness_X12: the X12 outbound's peer (the harness sink)"),
)
