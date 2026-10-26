# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A CPU-time stopwatch for the cost arms whose margin a loaded runner can eat (BACKLOG #2958).

Shared here rather than imported as a private name from one test module. ``tests/test_redaction.py``
built it; ``tests/test_logging.py``'s log read-back arm (BACKLOG #1547) uses it too."""

from __future__ import annotations

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
