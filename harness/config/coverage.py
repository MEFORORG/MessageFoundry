# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Full-coverage example graph — the config the test harness drives to exercise *every* engine
behavior from one place. Serve it on its own (it binds MLLP 2575, like ``samples/config/adt.py``,
so don't load both)::

    python -m messagefoundry serve --config harness/config --db ./messagefoundry.db

Then point the harness at it: Send → 127.0.0.1:2575, Receive listening on 2576, Monitor → the
engine API. Every disposition and delivery path is reachable by choosing the message you send:

| Send this                       | Router/Handler decision                  | Disposition (Monitor) |
|---------------------------------|------------------------------------------|-----------------------|
| ADT^A01 / A04 / A08             | fan-out → MLLP echo **and** file archive | PROCESSED (2 sends)   |
| any other ADT trigger           | single send → file archive               | PROCESSED (1 send)    |
| ADT^A02                         | handler returns None                     | FILTERED              |
| ADT^A03                         | handler raises                           | ERROR (AE NAK)        |
| any non-ADT type (ORU/ORM/…)    | router returns []                        | UNROUTED              |
| anything malformed / wrong ver. | to IB_Coverage_Strict (port 2577)        | ERROR (AE NAK)        |

The fan-out path also demonstrates **independent outbound draining** and **dead-lettering**:
``OB_Coverage_Echo`` delivers to the harness Receive tab (127.0.0.1:2576). If that listener is
down or replies AE/AR, those deliveries retry on a fast policy and dead-letter, while the file
archive for the same message still succeeds — visible in the Monitor's Live + Dead Letters tabs,
and replayable from there. The File round-trip is covered by ``FILE-IN_Coverage`` (drop a file in
``./harness_io/in``) → archive in ``./harness_io/out``.

All data is synthetic; never point a real PHI feed at a sample config.
"""

from messagefoundry import MLLP, File, Send, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy

# Inbounds: tolerant MLLP (the harness Send default), a strict-validation MLLP, and a file poller —
# all share one router so the disposition map above holds no matter how a message arrives.
inbound("IB_Coverage_MLLP", MLLP(port=2575), router="coverage_router")
inbound(
    "IB_Coverage_Strict",
    MLLP(port=2577),
    router="coverage_router",
    strict=True,
    hl7_version="2.5.1",
)
inbound(
    "FILE-IN_Coverage",
    File(directory="./harness_io/in", pattern="*.hl7", poll_seconds=0.5),
    router="coverage_router",
)

# Outbounds: an MLLP echo to the harness Receive tab (fast retry so failures dead-letter quickly),
# and a file archive that always succeeds (so fan-out shows one sibling draining while the other
# fails).
outbound(
    "OB_Coverage_Echo",
    MLLP(host="127.0.0.1", port=2576, connect_timeout=3.0, timeout_seconds=5.0),
    retry=RetryPolicy(
        max_attempts=3, backoff_seconds=1.0, backoff_multiplier=2.0, max_backoff_seconds=5.0
    ),
)
outbound("FILE-OUT_Coverage", File(directory="./harness_io/out", filename="{MSH-10}.hl7"))


@router("coverage_router")
def route(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.1"] != "ADT":
        return []  # non-ADT is routed nowhere (logged UNROUTED) — never silently dropped
    return ["coverage_handler"]


@handler("coverage_handler")
def handle(msg):  # type: ignore[no-untyped-def]
    trigger = msg["MSH-9.2"]
    if trigger == "A03":
        raise RuntimeError("simulated handler failure (A03) — routed to the error path")  # ERROR
    if trigger == "A02":
        return None  # admit-cancelled in this example is dropped (logged FILTERED)
    if trigger in ("A01", "A04", "A08"):
        msg["MSH-6"] = "HARNESS"  # a transform so the delivered copy differs from the raw receipt
        return [Send("OB_Coverage_Echo", msg), Send("FILE-OUT_Coverage", msg)]  # fan-out
    return Send("FILE-OUT_Coverage", msg)  # everything else: archive only
