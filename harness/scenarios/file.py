# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""File scenarios against ``harness/config/coverage.py``: drop into the polled directory, and
observe the archive the File outbound writes."""

from __future__ import annotations

from harness.scenarios._core import Scenario

SCENARIOS = (
    Scenario(
        "file_roundtrip",
        "ADT^A05 dropped into file_in -> PROCESSED, and archived to file_out",
        "ADT",
        "A05",
        3,
        "processed",
        driver="file",
        inbound="file_in",
        sink="file",
        sink_endpoint="file_out",
    ),
)
