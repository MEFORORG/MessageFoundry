# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1736 -- pin ``txn/msg = 3 + 2H + 2N`` through the **RegistryRunner**, and pin what ``N`` is.

Two gates already sit under this model and neither closes it:

* ``tests/test_txn_per_message_cost_model.py`` composes the model from per-method commit counts driven
  against a recording connection. It never runs the runner.
* ``tests/test_live_cost_counters.py`` drives a real ``MessageStore`` end to end and asserts the total
  at ``(1,1)``, ``(8,8)`` and ``(20,4)``. It calls the store's staged-queue methods **directly**, in the
  order the runner would -- so it pins the STORE, not the code that orders those calls.

What was missing is the runner-level weld: the pipeline that decides *how many* routed rows and
outbound rows one received message produces. A change there -- an extra handoff, a second claim, a
bookkeeping commit on the hot path -- moves the number the ADR 0051 / 0069 / 0107 capacity arguments
rest on, and today it would move it silently. MessageFoundry has zero deployments, so nothing is
mis-sized right now; this is test quality and documentation accuracy, and the cost of getting it wrong
is that a future throughput claim would be built on an unchecked number.

**``N`` counts OUTBOUND ROWS, not distinct destinations.** That reading is settled by execution here
(``test_n_counts_outbound_rows_not_distinct_destinations``): one handler emitting two ``Send``s to the
**same** outbound costs 9 transactions, byte-identical to two ``Send``s addressed to two different
outbounds -- because each row is claimed once and resolved once, and neither commit is shared. The
canonical prose definition lives on ``QueueStore.committed_txns`` in ``messagefoundry/store/base.py``;
every other site links there rather than restating it (CLAUDE.md SDS-3.5).

**The claim term is per-SWEEP under the default pooled claimer, which is where the deviation lives.**
Measured on a live started runner, one handler and one destination, SQLite:

===================  =====  ==  ==  ==  ==
claim_mode           1 msg  2   3   5   11
===================  =====  ==  ==  ==  ==
``per_lane``         7      14  21  35  77
``pooled`` (default) 7      14  21  36  79
===================  =====  ==  ==  ==  ==

``per_lane`` claims one row per commit, so it realises ``1 + H + N`` claim commits exactly. ``pooled``
commits once per productive ``claim_fifo_heads`` sweep instead, and a sweep is not a row: it can take
several rows in one commit, and it can commit having taken none (a contended head another claimer
already resolved). The excess is therefore real, small, and **timing-dependent** -- attributed by stack
sampling to ``claim_fifo_heads`` alone, with all four write-path commits landing at exactly
``2 + H + N``. It is not a store defect and not an ``N``-reading question. Nothing here asserts a
pooled multi-message total, because a test asserting a number nobody can explain is a trap for the next
reader; the live gate below pins ``per_lane``, where the model is exact.

``connection_events`` (default ``True``) costs **zero** commits on a healthy steady-state lane: its
three emit sites are a source connect/disconnect/reject, ``connection_lost`` and ``connection_restored``,
none of which fires while a lane is simply delivering. The live gate runs both ways to pin that.

Do **not** read any of this as a reduction target -- ADR 0107 closed transaction reduction as a measured
dead end. These gates pin the number and say what it counts.

Synthetic HL7 only (fabricated MRN and name) -- no PHI.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage
from messagefoundry.transports.base import DeliveryResponse, DestinationConnector

pytestmark = pytest.mark.asyncio

# A conformant synthetic ADT^A01 -- untrusted *data*, never interpreted (CLAUDE.md section 8).
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||900001||DOE^JANE\r"


def expected_txns(handlers: int, outbound_rows: int) -> int:
    """The ADR 0051 model. ``outbound_rows`` is the ``N`` term -- rows, not distinct destinations."""
    return 3 + 2 * handlers + 2 * outbound_rows


class _Sink(DestinationConnector):
    """A one-way outbound that records what it was handed. ``send`` returns ``None``, so the delivery
    worker takes the plain ``mark_done`` branch -- the shape ADR 0051 models."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:
        self.sent.append(payload)
        return None


def _registry(tmp_path: Path, *, handlers: dict[str, Any], outbounds: list[str]) -> Registry:
    """One FILE inbound ``IB`` to router ``r`` to ``handlers`` to the named FILE outbounds.

    FILE (not MLLP) so nothing binds a port; the worker-body gates never start a listener at all."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    for name in outbounds:
        reg.add_outbound(
            OutboundConnection(
                name,
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(tmp_path / "out" / name), "filename": "{MSH-10}.hl7"},
                ),
            )
        )
    reg.add_router("r", lambda m: sorted(handlers))
    for hname, fn in handlers.items():
        reg.add_handler(hname, fn)
    reg.validate()
    return reg


async def _drive(
    store: MessageStore, runner: RegistryRunner, outbounds: list[str]
) -> list[tuple[str, int]]:
    """Push ONE message through the runner's three per-item worker bodies and return the commit ledger.

    ``_process_ingress_item`` / ``_process_routed_item`` / ``_process_delivery_item`` are the per-item
    bodies of the router, transform and delivery workers, extracted verbatim so the per_lane loop and
    the pooled dispatcher share them (ADR 0066). Claiming here rather than letting a dispatcher sweep
    keeps the claim term at exactly one commit per row -- deterministic, and the ``per_lane`` accounting
    the module docstring pins. Returns ``[(step, cumulative_commits_since_baseline), ...]``.
    """
    base = store.committed_txns
    ledger: list[tuple[str, int]] = []

    def mark(step: str) -> None:
        ledger.append((step, store.committed_txns - base))

    await store.enqueue_ingress(channel_id="IB", raw=ADT, control_id="MSG1", message_type="ADT^A01")
    mark("enqueue_ingress")

    ingress = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert ingress is not None
    mark("claim ingress")
    await runner._process_ingress_item("IB", ingress)
    mark("route_handoff")

    routed_seen = 0
    while True:
        routed = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
        if routed is None:
            break
        routed_seen += 1
        mark(f"claim routed {routed_seen}")
        await runner._process_routed_item("IB", routed)
        mark(f"transform_handoff {routed_seen}")

    outbound_seen = 0
    for name in outbounds:
        while True:
            out = await store.claim_next_fifo(name)
            if out is None:
                break
            outbound_seen += 1
            mark(f"claim outbound {outbound_seen}")
            await runner._process_delivery_item(name, out)
            mark(f"mark_done {outbound_seen}")

    return ledger


async def _run_shape(
    tmp_path: Path, *, handlers: dict[str, Any], outbounds: list[str], db: str
) -> list[tuple[str, int]]:
    store = await MessageStore.open(tmp_path / db)
    try:
        reg = _registry(tmp_path, handlers=handlers, outbounds=outbounds)
        runner = RegistryRunner(reg, store)
        for name in outbounds:
            runner._destinations[name] = _Sink()
        return await _drive(store, runner, outbounds)
    finally:
        await store.close()


# --- the base shape, step by step ------------------------------------------------------------------


async def test_runner_pins_the_base_shape_at_seven_commits(tmp_path: Path) -> None:
    """``(H, N) = (1, 1)`` costs exactly 7 commits through the runner, and each of the seven is named.

    The per-step ledger is the point. A bare ``== 7`` tells the next reader that something moved; this
    tells them WHICH step grew, which is the difference between a five-minute fix and a bisect.
    """
    ledger = await _run_shape(
        tmp_path,
        handlers={"h": lambda m: Send("OB0", str(m))},
        outbounds=["OB0"],
        db="base.db",
    )

    assert ledger == [
        ("enqueue_ingress", 1),
        ("claim ingress", 2),
        ("route_handoff", 3),
        ("claim routed 1", 4),
        ("transform_handoff 1", 5),
        ("claim outbound 1", 6),
        ("mark_done 1", 7),
    ]
    assert ledger[-1][1] == expected_txns(1, 1) == 7


# --- N counts outbound ROWS ------------------------------------------------------------------------


async def test_n_counts_outbound_rows_not_distinct_destinations(tmp_path: Path) -> None:
    """The settled reading of ``N``, decided by execution rather than by prose.

    One handler emitting two ``Send``s to the SAME outbound costs the same 9 transactions as two
    ``Send``s addressed to two DIFFERENT outbounds. Each ``Send`` materialises its own outbound row;
    each row is claimed in its own transaction and resolved in its own transaction, and a shared
    destination shares neither. The rival reading -- ``N`` = distinct destination connections -- would
    score the same-destination case at ``N = 1`` and predict 7, so the two readings are separated by
    this gate and only one survives.
    """
    same = await _run_shape(
        tmp_path,
        handlers={"h": lambda m: [Send("OB0", str(m) + "A"), Send("OB0", str(m) + "B")]},
        outbounds=["OB0"],
        db="same.db",
    )
    different = await _run_shape(
        tmp_path,
        handlers={"h": lambda m: [Send("OB0", str(m) + "A"), Send("OB1", str(m) + "B")]},
        outbounds=["OB0", "OB1"],
        db="diff.db",
    )

    assert same[-1][1] == different[-1][1] == expected_txns(1, 2) == 9
    # ...and the rival "N = distinct destinations" reading is excluded, not merely unasserted.
    assert same[-1][1] != expected_txns(1, 1)

    # Non-vacuity: both really did emit two outbound rows, so the 9 is a fan-out and not a repeat.
    assert [step for step, _ in same].count("mark_done 2") == 1
    assert [step for step, _ in different].count("mark_done 2") == 1


# --- the model across shapes -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("handlers", "outbound_rows", "expected"),
    [
        (1, 1, 7),  # the simple feed. ADR 0051 quotes exactly this.
        (2, 2, 11),  # two handlers, one Send each.
        (4, 2, 15),  # four selected, two deliver -- the hub shape in miniature.
        (6, 3, 21),  # a wider fan-in on both terms.
    ],
)
async def test_runner_matches_the_model_at_every_shape(
    tmp_path: Path, handlers: int, outbound_rows: int, expected: int
) -> None:
    """``3 + 2H + 2N`` holds through the runner for every shape, not just the one ADR 0051 quotes.

    The first ``outbound_rows`` handlers each emit one ``Send``; the rest filter (return ``None``), so
    they still cost their 2 transactions -- the ADR 0084 asymmetry -- while contributing no outbound row.

    That construction gives one outbound row per DELIVERING handler, so it can only express
    ``H >= N``. The ``H < N`` shapes -- one handler emitting several ``Send``s -- are exactly the ones
    that settle what ``N`` counts, and they are driven explicitly by
    ``test_n_counts_outbound_rows_not_distinct_destinations``. The assert below is a guard, not a
    formality: a later shape added here with ``N > H`` would silently build a DIFFERENT graph than the
    one its expected number describes and still pass, which is the fabricated-result class this
    repository keeps re-finding.
    """
    assert handlers >= outbound_rows, "this builder emits one Send per handler; use the N > H gate"
    hs: dict[str, Any] = {}
    for i in range(handlers):
        hs[f"h{i}"] = (
            (lambda dest: lambda m: Send(dest, f"{m}{dest}"))(f"OB{i}")
            if i < outbound_rows
            else (lambda m: None)
        )
    outbounds = [f"OB{i}" for i in range(max(handlers, outbound_rows))]

    ledger = await _run_shape(
        tmp_path, handlers=hs, outbounds=outbounds, db=f"shape_{handlers}_{outbound_rows}.db"
    )

    assert ledger[-1][1] == expected_txns(handlers, outbound_rows) == expected


# --- the live, started engine ----------------------------------------------------------------------


@pytest.mark.parametrize("connection_events", [True, False])
async def test_live_per_lane_engine_pins_seven_commits_for_one_message(
    tmp_path: Path, connection_events: bool
) -> None:
    """The end-to-end weld: a STARTED runner, its own workers, a real FILE source and FILE destination.

    Nothing is driven by hand -- a file lands in the inbound directory and the engine's own listener,
    router worker, transform worker and delivery worker carry it. ``claim_mode='per_lane'`` because
    that mode claims one row per commit, so the model is exact; the default pooled claimer's per-sweep
    claim commit is timing-dependent and the module docstring records its measured spread rather than
    asserting one.

    Run both ways on ``connection_events``: capture is on by default and costs nothing on a healthy
    lane, so a future change that starts writing a connection event per delivered message shows up here
    as a split between the two parameters instead of as a quiet extra commit.
    """
    inbox = tmp_path / "in"
    outbox = tmp_path / "out" / "OB0"
    inbox.mkdir(parents=True)
    outbox.mkdir(parents=True)

    store = await MessageStore.open(tmp_path / "live.db")
    reg = _registry(tmp_path, handlers={"h": lambda m: Send("OB0", str(m))}, outbounds=["OB0"])
    runner = RegistryRunner(reg, store, claim_mode="per_lane", connection_events=connection_events)
    await runner.start()
    try:
        # start() awaits its own setup, so every startup commit is already counted here. Measured: an
        # idle started runner commits NOTHING over six seconds, so a slow box delays this gate rather
        # than inflating it.
        base = store.committed_txns

        (inbox / "m0.hl7").write_text(ADT, encoding="utf-8")
        for _ in range(600):  # generous: this must not flake under fleet contention
            await asyncio.sleep(0.05)
            if list(outbox.glob("*.hl7")):
                break
        assert list(outbox.glob("*.hl7")), "the message never reached the outbound directory"
        await asyncio.sleep(0.3)  # let mark_done's commit land after the file write

        assert store.committed_txns - base == expected_txns(1, 1) == 7
    finally:
        await runner.stop()
        await store.close()
