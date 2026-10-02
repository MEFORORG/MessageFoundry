# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Endpoints of ``harness/config/internal.py``: the TIMER, PassThrough and Loopback graph.

The three inbound kinds here have no socket of their own, so every port below belongs to an MLLP
entry inbound that feeds them or to a harness sink an outbound delivers to.

The connection names and the timer's marker the scenarios use live here too. The graph may not
import the harness (it is engine input), so it spells the same values as literals, and
``tests/test_harness_internal.py`` fails if the two drift apart.
"""

from __future__ import annotations

from typing import Final

from harness.endpoints import PATH, PORT, Endpoint

ENDPOINTS = (
    Endpoint(
        "internal_timer_out",
        PATH,
        "./harness_io/internal_timer_out",
        "OB_Internal_Timer_File: where the timer's emitted messages are archived",
    ),
    Endpoint("internal_pt_in", PORT, "2610", "IB_Internal_PT_Entry: MLLP entry to the PassThrough"),
    Endpoint(
        "internal_pt_sink", PORT, "2611", "OB_Internal_PT_Sink: the PassThrough leg's harness sink"
    ),
    Endpoint("internal_lb_in", PORT, "2612", "IB_Internal_LB_Entry: MLLP entry to the Loopback"),
    Endpoint(
        "internal_lb_query",
        PORT,
        "2613",
        "OB_Internal_LB_Query: the capturing outbound's peer; its ACK is re-ingressed",
    ),
    Endpoint(
        "internal_lb_reply",
        PORT,
        "2614",
        "OB_Internal_LB_Reply: where the Loopback inbound forwards the captured ACK",
    ),
)

#: The timer inbound, and the control id (MSH-10) its fixed body carries. Every fire emits the same
#: body, so a scenario tells this run's messages from an earlier run's by time, not by this id.
TIMER_INBOUND: Final = "IB_Internal_Timer"
TIMER_CONTROL_ID: Final = "HARNESS-INTERNAL-TIMER"

PT_ENTRY_INBOUND: Final = "IB_Internal_PT_Entry"
PT_INBOUND: Final = "PT_Internal_Relay"

LB_ENTRY_INBOUND: Final = "IB_Internal_LB_Entry"
LB_INBOUND: Final = "LB_Internal_Reply"
LB_QUERY_OUTBOUND: Final = "OB_Internal_LB_Query"
