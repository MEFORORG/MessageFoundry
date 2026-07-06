# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0071 (B5) §6.1 crossing-count control — a LIVING Windows gate.

Turns the ADR's A0/A1 driver-constant crossing-count control (§6.1: "with the driver held
constant, fusion drops crossings/msg ~4 -> 2 (>=40% fewer) with commits/msg identical") into a
gate that runs on the existing Windows `test` legs, so the thread-hop-fusion mechanism cannot
silently regress.

The mechanism is NOT re-implemented here. This test loads the committed micro-bench
(``docs/benchmarks/results/2026-07-04-adr0071-b5-executor-marshaling/b5_microbench.py``) as its
single source of arm logic and drives its own ``run_arm`` for arms A0 (unfused) and A1 (fused) at
a scaled-down config, on a pinned ``ProactorEventLoop`` instrumented with the micro-bench's own
``Counters`` + ``instrument_loop``. Loading-over-subprocess was chosen because it lets the gate
assert on the numeric result dict directly (no fragile stdout parsing) while still reusing the
exact arm coroutines.

Only the STABLE quantities are asserted:
  * commits/msg == 2.000 EXACTLY (the covert-transaction-fusion identity guard), and
  * A0 -> A1 crossings/msg drop >= 40% (the ADR §6.1 gate).
Absolute crossings are checked with tolerance BANDS (not exact floats) because the measured
window subtracts the co-tenant validate stream's completions, which introduces a bounded
boundary skew of a few crossings. Throughput is NOT asserted: on SQLite it is sign-unstable
across runs (ADR §8) and asserting it would flake.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sqlite3
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="ProactorEventLoop marshaling wall is Windows-specific",
)

# Scaled down from the full script (WARMUP=1500, MEASURED=6000) so the two arms finish in a few
# seconds on the Windows CI box, while still running enough messages that the crossings/msg ratio
# is stable (crossings are deterministic per hop; the only noise is the bounded validate-stream
# subtraction skew, which is ~1/MEASURED of a crossing).
_GATE_WARMUP = "300"
_GATE_MEASURED = "1500"


def _load_microbench() -> ModuleType:
    """Import the committed micro-bench as the single source of the arm logic.

    The module reads its config from ``B5_*`` env vars at import time, so they are set first.
    """
    path = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "benchmarks"
        / "results"
        / "2026-07-04-adr0071-b5-executor-marshaling"
        / "b5_microbench.py"
    )
    assert path.is_file(), f"committed micro-bench not found at {path}"

    os.environ["B5_WARMUP"] = _GATE_WARMUP
    os.environ["B5_MEASURED"] = _GATE_MEASURED
    os.environ["B5_C"] = "1"
    os.environ["B5_TRIALS"] = "1"

    spec = importlib.util.spec_from_file_location("b5_microbench_gate", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def _run_arm(mod: ModuleType, loop: asyncio.AbstractEventLoop, arm: str, db: Path) -> dict:
    """Drive one micro-bench arm on the instrumented loop with a fresh DB + executor.

    A fresh ``ThreadPoolExecutor`` per arm is mandatory: the micro-bench caches a thread-local
    sqlite connection per worker, so reusing an executor across arms would bind the second arm to
    the first arm's DB path.
    """
    mod._init_db(str(db))
    # Seed the messages rows the handoff UPDATE touches (mirrors the script's setup).
    total = mod.WARMUP + mod.MEASURED
    seed = sqlite3.connect(str(db))
    seed.executemany(
        "INSERT INTO messages (id, status) VALUES (?, 'RECEIVED')",
        [(i,) for i in range(1, total + 1)],
    )
    seed.commit()
    seed.close()

    ex = ThreadPoolExecutor(max_workers=mod.POOL, thread_name_prefix="fused-gate")
    vs = mod.ValidateStream(loop)
    vs.start()
    try:
        # A0/A1 use the sync driver only, so no aiosqlite connection is needed (aconn=None).
        return await mod.run_arm(arm, 1, str(db), ex, None, vs)
    finally:
        await vs.stop()
        ex.shutdown(wait=True)


async def _drive(mod: ModuleType, loop: asyncio.AbstractEventLoop, tmp_path: Path) -> dict:
    ctr = mod.Counters()
    loop._b5_ctr = ctr  # run_arm reads the loop-level crossing counter off this attribute
    mod.instrument_loop(loop, ctr)
    results = {}
    for arm in ("A0", "A1"):
        results[arm] = await _run_arm(mod, loop, arm, tmp_path / f"b5_{arm}.db")
    return results


def test_a0_a1_crossing_count_gate(tmp_path: Path) -> None:
    mod = _load_microbench()

    # Pin the Proactor loop (the wall is Proactor-specific). Save/restore the policy so this gate
    # cannot perturb sibling tests; suppress the 3.14 deprecation notice on the policy shims.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        prev_policy = asyncio.get_event_loop_policy()
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    try:
        loop = asyncio.new_event_loop()
        try:
            if not isinstance(loop, asyncio.ProactorEventLoop):
                pytest.skip(f"expected a ProactorEventLoop, got {type(loop).__name__}")
            results = loop.run_until_complete(_drive(mod, loop, tmp_path))
        finally:
            loop.close()
    finally:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            asyncio.set_event_loop_policy(prev_policy)

    a0 = results["A0"]
    a1 = results["A1"]

    # (i) Identity guard — durable work is byte-identical across arms: EXACTLY 2 commits/msg.
    assert a0["identity_exact"] is True, a0
    assert a1["identity_exact"] is True, a1
    assert a0["commits_per_msg"] == 2.0
    assert a1["commits_per_msg"] == 2.0

    # (ii) Absolute crossings — tolerance BANDS around the expected 4.00 (A0) and 2.00 (A1); the
    # bands absorb the bounded validate-subtraction skew without letting a real regression pass.
    a0_cross = a0["cross_per_msg"]
    a1_cross = a1["cross_per_msg"]
    assert 3.0 <= a0_cross <= 5.0, f"A0 crossings/msg out of band: {a0_cross}"
    assert 1.0 <= a1_cross <= 3.0, f"A1 crossings/msg out of band: {a1_cross}"

    # (iii) The ADR §6.1 gate: fusion drops crossings/msg by >= 40% with the driver held constant.
    drop = (a0_cross - a1_cross) / a0_cross
    assert drop >= 0.40, (
        f"A0->A1 crossings/msg drop {drop:.3f} < 0.40 (A0={a0_cross}, A1={a1_cross})"
    )
