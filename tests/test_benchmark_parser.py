# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Parser throughput / free-threaded scaling benchmark harness (ADR 0054 AC-6, PARSE-15).

ADR 0054 makes the low-allocation built-ins HL7 parser the *free-threading keystone*: its acceptance
criterion AC-6 is **~14× single-thread** over python-hl7 and **≥6× multi-core scaling** on a
free-threaded (cp314t) build. The authoritative scaling numbers are a **measurement**, not a unit
gate — they are produced by the ADR 0053 spike harness on the free-threaded bench box and *recorded*
(measured-not-gated), because a hard timing/scaling assertion is inherently flaky and, on a stock
GIL-enabled cp314 build, the ≥6× multi-core claim is not even measurable (the GIL serializes the
threads).

What this module contributes on *any* build:

* a small, deterministic **benchmark harness** — :func:`bench_single_thread` /
  :func:`bench_multi_thread` over a synthetic HL7 batch, returning msg/s and the parsed routing so a
  caller can compute a scaling ratio;
* a **correctness smoke** proving the harness parses a synthetic batch correctly, that the built-ins
  and python-hl7 backends agree, and — the property that makes the multi-thread path trustworthy —
  that parsing the batch across a thread pool yields **identical, deterministic** results to the
  single-thread pass (pure parse, no shared state);
* a very conservative, non-flaky **floor guard** that catches a catastrophic single-thread throughput
  regression (orders of magnitude, not micro-noise);
* the AC-6 **scaling measurement** itself as a reported-not-gated test: it runs only on a
  free-threaded build and, even there, **records** the ratio rather than asserting ≥6× (the plan's
  disposition), so the number is captured off a real node without turning a bench figure into a unit
  gate.

The scaling *gate* — asserting ≥6× multi-core / ~14× single-thread — remains the operator-owned bench
run on the cp314t box; this file is its reproducible-in-CI smoke + a home for the recorded number.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import pytest

import messagefoundry.parsing._backend as _backend
from messagefoundry.generators import _core, all_types  # noqa: F401 — registers the generators
from messagefoundry.parsing import normalize
from messagefoundry.parsing.peek import Peek

# The benchmark's unit of work: a small PHI-free routing tuple (named fields + the segment id list).
Routing = tuple[str | None, str | None, str | None, str | None, tuple[str, ...]]

# A synthetic, PHI-free batch spanning several message types/triggers so the benchmark exercises
# realistic segment/field/repetition shapes rather than one hot MSH. Kept modest so the smoke stays
# fast; a real bench multiplies it (see ``_repeat``).
_SYNTH_PLAN: list[tuple[str, str, int]] = [
    ("ADT", "A01", 1),
    ("ADT", "A02", 1),
    ("ADT", "A03", 1),
    ("ADT", "A04", 1),
    ("ADT", "A08", 1),
    ("ORU", "R01", 1),
    ("ORU", "R01", 2),
    ("ORM", "O01", 1),
]


def _synthetic_batch() -> list[str]:
    """A deterministic, normalized synthetic HL7 batch (built-ins-safe, PHI-free)."""
    out: list[str] = []
    for code, trigger, index in _SYNTH_PLAN:
        if code not in _core.message_codes():
            continue
        if trigger not in _core.triggers_for(code):
            continue
        out.append(normalize(_core.generate_message(code, trigger, index)))
    return out


def _repeat(batch: list[str], target: int) -> list[str]:
    """Grow ``batch`` to at least ``target`` messages by cycling it (stable, deterministic)."""
    if not batch:
        return batch
    out: list[str] = []
    while len(out) < target:
        out.extend(batch)
    return out[:target]


def _routing_of(raw: str) -> Routing:
    """Parse one message and return a small, PHI-free routing tuple (the benchmark's unit of work)."""
    peek = Peek.parse(raw)
    return (
        peek.message_type,
        peek.trigger_event,
        peek.control_id,
        peek.version,
        tuple(peek.segments()),
    )


def _parse_all_serial(batch: list[str]) -> list[Routing]:
    return [_routing_of(raw) for raw in batch]


def _parse_all_threaded(batch: list[str], workers: int) -> list[Routing]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(_routing_of, batch))


# ---------------------------------------------------------------------------
# Benchmark harness — returns (msg_per_s, results) so a caller can time + verify
# ---------------------------------------------------------------------------


def _timed(fn: Callable[[], list[Routing]], n: int) -> tuple[float, list[Routing]]:
    start = time.perf_counter()
    results = fn()
    elapsed = time.perf_counter() - start
    rate = n / elapsed if elapsed > 0 else float("inf")
    return rate, results


def bench_single_thread(batch: list[str]) -> tuple[float, list[Routing]]:
    """Single-thread throughput (msg/s) + parsed routing for the batch."""
    return _timed(lambda: _parse_all_serial(batch), len(batch))


def bench_multi_thread(batch: list[str], workers: int) -> tuple[float, list[Routing]]:
    """Multi-thread throughput (msg/s) + parsed routing for the batch across ``workers`` threads."""
    return _timed(lambda: _parse_all_threaded(batch, workers), len(batch))


def _is_freethreaded() -> bool:
    getter = getattr(sys, "_is_gil_enabled", None)
    if getter is None:
        return False
    try:
        return not getter()
    except Exception:  # noqa: BLE001 — be conservative if the probe misbehaves
        return False


# ---------------------------------------------------------------------------
# Correctness smoke — the harness parses correctly + is deterministic across threads
# ---------------------------------------------------------------------------


def test_synthetic_batch_is_populated() -> None:
    batch = _synthetic_batch()
    assert len(batch) >= 5, f"synthetic bench batch unexpectedly small: {len(batch)}"
    # every entry is a normalized HL7 message (starts with MSH, CR-delimited)
    for raw in batch:
        assert raw.startswith("MSH")
        assert "\r" in raw


def test_single_thread_parses_batch() -> None:
    batch = _synthetic_batch()
    rate, results = bench_single_thread(batch)
    assert len(results) == len(batch)
    # every message yielded a message_type and a non-trivial segment list
    for message_type, _trigger, _cid, _ver, segments in results:
        assert message_type is not None
        assert isinstance(segments, tuple) and len(segments) >= 2
    assert rate > 0.0


def test_multi_thread_matches_single_thread_deterministic() -> None:
    """The property that makes the AC-6 multi-core path valid: parse is pure, so a thread pool must
    yield byte-identical routing in the same order as the serial pass (no shared mutable state,
    order preserved by ``pool.map``). This holds on GIL and free-threaded builds alike; only the
    *speed* differs.
    """
    batch = _repeat(_synthetic_batch(), 256)
    _, serial = bench_single_thread(batch)
    _, threaded = bench_multi_thread(batch, workers=4)
    assert threaded == serial


def test_both_backends_agree_on_batch() -> None:
    """Built-ins (default) and python-hl7 backends produce identical routing for the batch — the
    benchmark is measuring the same work either way (ties PARSE-15 to the ADR 0054 parity guarantee).
    """
    batch = _synthetic_batch()
    with _backend.backend(builtin=True):
        builtins_out = _parse_all_serial(batch)
    with _backend.backend(builtin=False):
        pyhl7_out = _parse_all_serial(batch)
    assert builtins_out == pyhl7_out


def test_single_thread_throughput_floor() -> None:
    """Non-flaky catastrophic-regression guard. This is NOT the AC-6 ~14× gate (that is a measured
    number vs a python-hl7 baseline on the bench box); it is a floor so far below any real machine's
    parse rate that only an orders-of-magnitude regression (e.g. accidental O(n^2) or per-parse I/O)
    trips it. Micro-throughput lives in the bench measurement, not here.
    """
    batch = _repeat(_synthetic_batch(), 512)
    rate, _ = bench_single_thread(batch)
    # A stock cp314 build parses well into the tens-of-thousands msg/s; 200/s is a ~100x margin.
    assert rate > 200.0, f"single-thread parse throughput floor breached: {rate:.1f} msg/s"


# ---------------------------------------------------------------------------
# AC-6 scaling — reported-not-gated (measured on cp314t; disposition per FEATURE-COVERAGE-PLAN P5)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _is_freethreaded(),
    reason=(
        "AC-6 ≥6× multi-core scaling is measurable only on a free-threaded (cp314t) build; on a "
        "GIL build the threads serialize. Gate stays operator-owned on the bench box (ADR 0054/0053)."
    ),
)
def test_freethread_scaling_measure(capsys: pytest.CaptureFixture[str]) -> None:
    """Reported-not-gated AC-6 measurement (PARSE-15 disposition).

    On a free-threaded build this RECORDS the single→multi-thread scaling ratio rather than asserting
    ≥6×: the authoritative pass/fail is the ADR 0053 spike harness on the bench rig. We assert only
    that scaling is *present* (ratio > 1.0) — a genuine free-threaded build must parse faster on N
    threads than on one — and print the number so a CI/bench log captures it.
    """
    workers = min(8, (getattr(__import__("os"), "cpu_count", lambda: 1)() or 1))
    batch = _repeat(_synthetic_batch(), 4096)
    single_rate, single = bench_single_thread(batch)
    multi_rate, multi = bench_multi_thread(batch, workers=workers)
    assert multi == single  # correctness holds under load
    ratio = multi_rate / single_rate if single_rate > 0 else float("inf")
    with capsys.disabled():
        print(
            f"\n[PARSE-15 AC-6 measure] workers={workers} "
            f"single={single_rate:,.0f} msg/s multi={multi_rate:,.0f} msg/s "
            f"scaling={ratio:.2f}x (gate ≥6x is operator-owned on the cp314t bench box)"
        )
    # Present, not gated: a real free-threaded build scales past 1x; the ≥6x bar is recorded, not here.
    assert ratio > 1.0
