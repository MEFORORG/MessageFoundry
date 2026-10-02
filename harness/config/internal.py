# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Internal-inbound graph: the three inbound kinds that need no external peer of their own.

Loaded with the rest of ``harness/config`` (``serve --config harness/config``). Three independent
paths, none of which routes another family's messages:

| Path        | Shape                                                                          |
|-------------|--------------------------------------------------------------------------------|
| TIMER       | IB_Internal_Timer fires a fixed synthetic ADT^A08 every 2 s -> File archive    |
| PassThrough | MLLP 2610 -> handler Sends INTO PT_Internal_Relay -> its own router -> MLLP 2611 |
| Loopback    | MLLP 2612 -> OB_Internal_LB_Query (MLLP 2613, ``reingress_to``) -> the peer's    |
|             | ACK is re-ingressed on LB_Internal_Reply -> its own router -> MLLP 2614         |

Ports and the directory are read with the engine's own ``env()``: the key is ``harness_`` plus the
endpoint key in ``harness/endpoints/internal.py``, and each default is the SAME literal as that
endpoint's default (``tests/test_harness_scenarios.py`` holds them equal), so
``MEFOR_VALUE_HARNESS_<KEY>`` moves both ends together. This module imports
nothing from ``harness``: it is engine input, and an engine running from its own wheel cannot
import the harness. The connection names and the timer marker are therefore literals here too, and
``tests/test_harness_internal.py`` checks them against the names the scenarios use.

The timer runs for as long as the engine does, so a served harness archives one small file every
two seconds under ``./harness_io/internal_timer_out``. The PassThrough and Loopback paths move
only when something is injected. All data is synthetic.
"""

from typing import Any

from messagefoundry import (
    MLLP,
    File,
    Loopback,
    PassThrough,
    Send,
    Timer,
    env,
    handler,
    inbound,
    outbound,
    router,
)
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.wiring import ConnectionSpec

_HOST = env("harness_host", default="127.0.0.1")

# Fast retry, so a scenario that withholds a peer dead-letters in seconds rather than holding the
# engine busy for the rest of a test run.
_FAST_RETRY = RetryPolicy(
    max_attempts=2, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=1.0
)


def _port(key: str, default: int) -> Any:
    return env(f"harness_{key}", default=default, cast=int)


def _mllp_out(key: str, default: int, **settings: Any) -> ConnectionSpec:
    return MLLP(
        host=_HOST,
        port=_port(key, default),
        connect_timeout=2.0,
        timeout_seconds=3.0,
        **settings,
    )


# --- TIMER -------------------------------------------------------------------------------------
# A fixed synthetic body; MSH-10 is the marker a scenario matches on (TIMER_CONTROL_ID in
# harness/endpoints/internal.py). Segments end in \r, as HL7 requires.
_TIMER_BODY = (
    "MSH|^~\\&|HARNESS|TIMER|HARNESS|ARCHIVE|20260101000000||ADT^A08^ADT_A01|"
    "HARNESS-INTERNAL-TIMER|P|2.5.1\r"
    "EVN|A08|20260101000000\r"
    "PID|1||TIMER0001^^^HARNESS^MR||SYNTHETIC^TIMER\r"
)

inbound(
    "IB_Internal_Timer",
    Timer(body=_TIMER_BODY, interval_seconds=2.0),
    router="internal_timer_router",
)
outbound(
    "OB_Internal_Timer_File",
    File(
        directory=env("harness_internal_timer_out", default="./harness_io/internal_timer_out"),
        filename="{MSH-10}.hl7",
    ),
)


@router("internal_timer_router")
def route_timer(msg):  # type: ignore[no-untyped-def]
    return ["internal_timer_handler"]


@handler("internal_timer_handler")
def archive_timer(msg):  # type: ignore[no-untyped-def]
    return Send("OB_Internal_Timer_File", msg)


# --- PassThrough -------------------------------------------------------------------------------
inbound(
    "IB_Internal_PT_Entry",
    MLLP(port=_port("internal_pt_in", 2610)),
    router="internal_pt_entry_router",
)
# No socket: fed only by the Send-into-PT handoff below, then routed by its own router.
inbound("PT_Internal_Relay", PassThrough(), router="internal_pt_relay_router")
outbound("OB_Internal_PT_Sink", _mllp_out("internal_pt_sink", 2611), retry=_FAST_RETRY)


@router("internal_pt_entry_router")
def route_pt_entry(msg):  # type: ignore[no-untyped-def]
    return ["internal_pt_entry_handler"]


@handler("internal_pt_entry_handler")
def into_passthrough(msg):  # type: ignore[no-untyped-def]
    return Send("PT_Internal_Relay", msg)  # named like an outbound -> re-ingressed there


@router("internal_pt_relay_router")
def route_pt_relay(msg):  # type: ignore[no-untyped-def]
    return ["internal_pt_relay_handler"]


@handler("internal_pt_relay_handler")
def pt_to_sink(msg):  # type: ignore[no-untyped-def]
    return Send("OB_Internal_PT_Sink", msg)


# --- Loopback ----------------------------------------------------------------------------------
inbound(
    "IB_Internal_LB_Entry",
    MLLP(port=_port("internal_lb_in", 2612)),
    router="internal_lb_entry_router",
)
# No socket: fed only by the capturing outbound's reply (``reingress_to``), then routed here.
inbound("LB_Internal_Reply", Loopback(), router="internal_lb_reply_router")
outbound(
    "OB_Internal_LB_Query",
    _mllp_out("internal_lb_query", 2613, reingress_to="LB_Internal_Reply"),
    retry=_FAST_RETRY,
)
outbound("OB_Internal_LB_Reply", _mllp_out("internal_lb_reply", 2614), retry=_FAST_RETRY)


@router("internal_lb_entry_router")
def route_lb_entry(msg):  # type: ignore[no-untyped-def]
    return ["internal_lb_entry_handler"]


@handler("internal_lb_entry_handler")
def to_query(msg):  # type: ignore[no-untyped-def]
    return Send("OB_Internal_LB_Query", msg)


@router("internal_lb_reply_router")
def route_lb_reply(msg):  # type: ignore[no-untyped-def]
    return ["internal_lb_reply_handler"]


@handler("internal_lb_reply_handler")
def reply_to_sink(msg):  # type: ignore[no-untyped-def]
    return Send("OB_Internal_LB_Reply", msg)
