# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A CPU-time stopwatch for the cost arms whose margin a loaded runner can eat (BACKLOG #2958).

Shared here rather than imported as a private name from one test module. ``tests/test_redaction.py``
built it; ``tests/test_logging.py``'s log read-back arm (BACKLOG #1547) uses it too.
:func:`interleaved_thread_cpu` is the thread-clock sampler ``tests/test_logging.py``'s traceback
arm reads (BACKLOG #3456); ``tests/test_redaction.py``'s ``_thread_cpu_sample`` is its block-shaped
sibling, still private to that module."""

from __future__ import annotations

import random
import time
from collections.abc import Callable

#: The least CPU time one :func:`cpu_seconds` sample spends. **A floor, because the clock is coarse:**
#: ``time.process_time`` reports a resolution of 100 ns on Windows but moves in 15.625 ms ticks,
#: measured 2026-10-13. One call of a 5 ms arm reads 0 or 15.6 ms, so a sample repeats the call
#: until this much CPU time has passed and divides by the count. That caps the tick's error at
#: about 8% of the sample.
CPU_SAMPLE_FLOOR_SECONDS = 0.2


def cpu_seconds(work: Callable[[], object], reps: int = 3) -> float:
    """Best-of-``reps`` CPU seconds per call of ``work``, each sample at least
    :data:`CPU_SAMPLE_FLOOR_SECONDS` long.

    **CPU time rather than wall time, for the arms whose margin a loaded runner can eat (BACKLOG
    #2958).** A busy host delays a process without charging it the delay, so the clock this reads
    stops while the runner is away. **It counts every thread in the process, not only this one**, so
    a thread an earlier test left running is charged here too. It does not stop everything: a shared
    core still slows each instruction through the cache, which is why the arms read a RATIO between
    two sizes timed back to back, under one load, rather than a fixed number of seconds. A wall-clock ratio was built and
    withdrawn in PR 2000, red 12 times in 25 on a shared Linux core; this is not that instrument.

    The MINIMUM over samples, the statistic load inflates least. The coarse tick can read a sample up
    to one tick LOW as well as high, and the floor is what caps that error at about 8%."""
    best = float("inf")
    for _ in range(reps):
        calls = 0
        start = time.process_time()
        while True:
            work()
            calls += 1
            spent = time.process_time() - start
            if spent >= CPU_SAMPLE_FLOOR_SECONDS:
                break
        best = min(best, spent / calls)
    return best


def interleaved_thread_cpu(
    arms: dict[str, Callable[[], object]],
    *,
    floor: float = CPU_SAMPLE_FLOOR_SECONDS,
    min_calls: int = 1,
    once: frozenset[str] = frozenset(),
    max_passes: int = 100_000,
) -> dict[str, float]:
    """CPU seconds per call of each arm on the CALLING thread, with the arms' calls interleaved.

    Each pass calls every arm still pending once, in an order drawn from an unseeded generator (the
    rule ``tests/_growth.py`` gives, BACKLOG #3721), and charges each call the thread clock's move
    across it. An arm is pending until it has spent ``floor`` and had ``min_calls`` calls, however
    long one call is, so one load-skewed call cannot set an arm on its own. An arm named in ``once``
    is called once, in the first pass, for an arm whose one call is many ticks long. Past
    ``max_passes`` passes it raises rather than spin, for an arm that accrues no thread CPU, because
    it blocks or hands its work to another thread.

    **Interleaved call by call rather than one block per arm**, so a stretch of load lifts every
    arm alike instead of landing on one arm's block (BACKLOG #3456: in blocks, beside 64 copying
    processes, a filter read 0.73 to 1.31 times a render it costs about one of).

    The thread clock rather than :func:`cpu_seconds`'s process clock, because a thread an earlier
    test left running would otherwise be billed to whichever arm it overlapped; so every arm must
    run synchronously on the calling thread. On Windows it moves in 15.625 ms ticks; a call's charge
    is off by up to one, in either direction, and those errors average across an arm's calls."""
    if floor <= 0 or min_calls < 1 or max_passes < 1:
        raise ValueError(
            f"floor {floor}, min_calls {min_calls} and max_passes {max_passes} must all be positive"
        )
    spent = dict.fromkeys(arms, 0.0)
    calls = dict.fromkeys(arms, 0)

    def pending(name: str) -> bool:
        if name in once:
            return calls[name] == 0
        return spent[name] < floor or calls[name] < min_calls

    order = random.Random()
    passes = 0
    while due := [name for name in arms if pending(name)]:
        passes += 1
        if passes > max_passes:
            raise RuntimeError(
                f"{due} still under {floor} CPU s after {max_passes} passes: an arm that does its "
                "work off the calling thread reads as free here"
            )
        for name in order.sample(due, k=len(due)):
            start = time.thread_time()
            arms[name]()
            spent[name] += time.thread_time() - start
            calls[name] += 1
    return {name: spent[name] / calls[name] for name in arms}
