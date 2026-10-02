# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""MLLP scenarios against ``harness/config/coverage.py``: the five disposition paths, plus the
MLLP outbound's delivered copy observed at a harness sink."""

from __future__ import annotations

from harness.scenarios._core import Scenario

SCENARIOS = (
    Scenario("processed", "ADT^A05 archived to a file -> PROCESSED", "ADT", "A05", 5, "processed"),
    Scenario("filtered", "ADT^A02 dropped by the handler -> FILTERED", "ADT", "A02", 5, "filtered"),
    Scenario("unrouted", "ORU routed nowhere -> UNROUTED", "ORU", "R01", 5, "unrouted"),
    Scenario("error", "ADT^A03 handler raises -> ERROR", "ADT", "A03", 5, "error"),
    Scenario(
        "dead_letter",
        "ADT^A01 echo to a downed listener -> dead-lettered (run with nothing on mllp_echo)",
        "ADT",
        "A01",
        2,
        "dead_letter",
        dead_letter_destination="OB_Coverage_Echo",
    ),
    Scenario(
        "mllp_echo_delivered",
        "ADT^A04 fan-out: the MLLP echo copy arrives at a harness sink on mllp_echo",
        "ADT",
        "A04",
        3,
        "processed",
        sink="mllp",
        sink_endpoint="mllp_echo",
    ),
)
