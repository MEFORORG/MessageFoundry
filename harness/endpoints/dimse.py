# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Endpoints of ``harness/config/dimse.py``: the DICOM DIMSE C-STORE graph."""

from __future__ import annotations

from harness.endpoints import PORT, Endpoint

ENDPOINTS = (
    Endpoint("dimse_in", PORT, "2650", "IB_Harness_DIMSE: the engine's C-STORE SCP inbound"),
    Endpoint(
        "dimse_out",
        PORT,
        "2651",
        "OB_Harness_DIMSE: the C-STORE SCU outbound's peer (the harness DIMSE sink)",
    ),
)
