# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Replay-idempotency property test (PIPE-14, Phase 1).

The at-least-once contract (ADR 0001 / ADR 0009 / CLAUDE.md §2) requires Routers/Handlers to be
**pure** so a crash re-run re-derives byte-identical output. This is enforced by prose only today; ADR
0001 itself flagged that purity "should [be] a checked expectation, not just a convention." This module
is the shippable Phase-1 guard: :class:`~messagefoundry.pipeline.dryrun.RouteOutcome` is a frozen
dataclass, so ``==`` between two runs of the same message is a full replay-equality check. A pure
router/transform run twice yields an equal outcome; an impure one (module-global mutation, wall-clock
read, randomness) diverges — proving the harness has teeth.

**Critical:** ``ingest_time`` is pinned. ``current_ingest_time()`` is the sanctioned re-run-stable
"now" (the persisted enqueue time, not a live clock), so a Handler that reads it is PURE. If the harness
did not pin ``ingest_time`` (e.g. the offline ``dry_run`` path injects ``time.time()`` per call) that
legitimately-pure Handler would falsely read as impure — see
:func:`test_unpinned_ingest_time_falsely_diverges_through_dry_run`.
"""

from __future__ import annotations

import time
import uuid

from messagefoundry.config.ingest_time import current_ingest_time
from messagefoundry.config.models import ConnectorType, Validation
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import RouteOutcome, dry_run, route_message

ADT_A01 = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)

# A pinned, re-run-stable epoch value — the engine supplies the persisted row `created_at` here; the
# harness must pin it so a `current_ingest_time()`-using Handler stays deterministic across a re-run.
_PINNED_TS = 1_700_000_000.0


def _registry(route, handlers):  # type: ignore[no-untyped-def]
    """Inline registry builder mirroring ``tests/test_dryrun.py::_registry`` (one MLLP in → one FILE out)."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
            router="r",
            validation=Validation(strict=False, hl7_version="2.5.1"),
        )
    )
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", route)
    for name, fn in handlers.items():
        reg.add_handler(name, fn)
    return reg


def assert_replay_stable(reg: Registry, raw: str = ADT_A01) -> RouteOutcome:
    """Route ``raw`` twice with a PINNED ingest_time; assert the two RouteOutcomes are byte-identical."""
    ic = reg.inbound["in"]
    a = route_message(reg, ic, raw, ingest_time=_PINNED_TS)
    b = route_message(reg, ic, raw, ingest_time=_PINNED_TS)
    assert a == b  # frozen-dataclass value equality == full replay-equality
    return a


def assert_replay_diverges(reg: Registry, raw: str = ADT_A01) -> tuple[RouteOutcome, RouteOutcome]:
    """Route ``raw`` twice with a PINNED ingest_time; assert the outcomes DIFFER (the harness has teeth)."""
    ic = reg.inbound["in"]
    a = route_message(reg, ic, raw, ingest_time=_PINNED_TS)
    b = route_message(reg, ic, raw, ingest_time=_PINNED_TS)
    assert a != b
    return a, b


# --- pure paths: replay-stable -----------------------------------------------


def _pure_handler(msg: Message) -> Send:
    msg["MSH-3"] = "FOUNDRY"  # constant transform — message in → same message out, every run
    return Send("out", msg)


def test_pure_handler_replay_is_byte_identical() -> None:
    reg = _registry(lambda m: ["h"], {"h": _pure_handler})
    outcome = assert_replay_stable(reg)
    assert outcome.handlers == ["h"]
    assert (
        "FOUNDRY" in outcome.deliveries[0].payload
    )  # it actually delivered (not a vacuous equality)


def _ingest_time_handler(msg: Message) -> Send:
    # current_ingest_time() is the sanctioned re-run-stable "now"; with a pinned ts it is PURE.
    msg["MSH-3"] = str(current_ingest_time())
    return Send("out", msg)


def test_pinned_ingest_time_handler_is_not_falsely_impure() -> None:
    # The load-bearing case: a Handler reading current_ingest_time() under a pinned ts must NOT read as
    # impure. If the harness failed to pin ingest_time this would false-positive a legitimately pure feed.
    reg = _registry(lambda m: ["h"], {"h": _ingest_time_handler})
    outcome = assert_replay_stable(reg)
    assert "1700000000.0" in outcome.deliveries[0].payload  # the pinned value reached the wire


# --- impure paths: replay diverges (the detector has teeth) -------------------

_ACCUMULATOR: list[int] = []


def _accumulating_handler(msg: Message) -> Send:
    _ACCUMULATOR.append(1)  # module-global mutation — output depends on prior runs
    msg["MSH-3"] = str(len(_ACCUMULATOR))
    return Send("out", msg)


def test_module_global_accumulator_diverges() -> None:
    _ACCUMULATOR.clear()
    reg = _registry(lambda m: ["h"], {"h": _accumulating_handler})
    a, b = assert_replay_diverges(reg)
    assert a.deliveries[0].payload != b.deliveries[0].payload  # "1" then "2"


def _wall_clock_handler(msg: Message) -> Send:
    msg["MSH-3"] = str(time.time())  # a LIVE clock read — forbidden; breaks re-run stability
    return Send("out", msg)


def test_wall_clock_read_diverges() -> None:
    reg = _registry(lambda m: ["h"], {"h": _wall_clock_handler})
    assert_replay_diverges(reg)


def _random_handler(msg: Message) -> Send:
    msg["MSH-3"] = uuid.uuid4().hex  # randomness — forbidden; different every run
    return Send("out", msg)


def test_random_uuid_diverges() -> None:
    reg = _registry(lambda m: ["h"], {"h": _random_handler})
    assert_replay_diverges(reg)


_ROUTER_CALLS: list[int] = []


def _impure_router(msg: Message) -> list[str]:
    _ROUTER_CALLS.append(1)  # impurity in the ROUTER half, not just the transform half
    return ["h"] if len(_ROUTER_CALLS) % 2 == 1 else []


def test_impure_router_diverges() -> None:
    _ROUTER_CALLS.clear()
    reg = _registry(_impure_router, {"h": _pure_handler})
    a, b = assert_replay_diverges(reg)
    assert a.handlers != b.handlers  # ["h"] on run 1, [] on run 2 — routing decision itself drifted


# --- why the harness MUST pin ingest_time ------------------------------------


def test_unpinned_ingest_time_falsely_diverges_through_dry_run() -> None:
    # dry_run injects a LIVE time.time() as ingest_time per call, so the SAME pure current_ingest_time()
    # Handler produces different bytes across two dry_run calls. A naive replay check on the dry_run entry
    # point would false-positive a legitimately-pure feed — exactly why route_message-level pinning matters.
    reg = _registry(lambda m: ["h"], {"h": _ingest_time_handler})
    a = dry_run(reg, ADT_A01)
    b = dry_run(reg, ADT_A01)
    assert a != b
