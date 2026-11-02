# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shared growth reading for the timing tests that tell linear scaling from super-linear.

Moved here from ``tests/test_log_redaction_secret_domain.py`` unchanged (BACKLOG #3452), so a
timing test elsewhere imports it without importing that module. Its self-test,
``test_the_growth_reading_samples_both_lengths_alike``, stays in that file.
"""

from __future__ import annotations

import math
import random
import time
from collections.abc import Callable

#: The least wall-clock time a growth reading samples for, whatever ``rounds`` says. A cheap subject
#: finishes five rounds in about 2 ms, a window short enough to sit inside one bad stretch of a shared
#: core. :func:`_growth_between` says what that cost.
_GROWTH_MIN_SECONDS = 0.05


def _growth_between(call: Callable[[str], object], short: str, long: str, *, rounds: int) -> float:
    """Per-call time on ``long`` over per-call time on ``short``, each the minimum over the samples.

    THE RATIO'S ARGUMENT IS THAT LOAD CANCELS, AND TWO MINIMA TAKEN APART DID NOT CANCEL IT. Three
    properties here each close one way they failed. Measured 2026-10-06 on 4 cores, with
    ``scrub_credentials`` linear at a flat 33 to 36 ns per character from 1 KB to 128 KB, and a
    spinner pinned to the measuring core as the co-tenant.

    1. EQUAL WINDOWS. Each short sample repeats the call until it does the same work as one long
       sample. A co-tenant taking the core every 0.3 ms interrupts every 0.5 ms long sample, while a
       0.07 ms short one often fits between, so a minimum cleans the short endpoint only. Under that
       co-tenant the old form, five short minima then five long, read a median of 15.5x for 8x, and
       2 of 500 trials were over 24x, the 25.1x a hosted ubuntu leg failed on. Alternating without
       repeats still read 14.9x. Equal windows read 7.7x, the unloaded median.
    2. NO FIXED RHYTHM. A loop whose round, stall included, matches the co-tenant's period puts the
       stall in the same place every round. With a 0.4 ms-on, 0.3 ms-off spinner, the gate-reject
       subject read over 24x in 18 of 3000 trials, each with all five long samples about 4.7x slow
       and every short one clean. So which endpoint goes first is drawn per round, from an unseeded
       generator: a seeded one replays the same opening every run, and a co-tenant that lines up
       with it once lines up every time.
    3. A FLOOR ON SAMPLING TIME, :data:`_GROWTH_MIN_SECONDS`. A drawn order still puts every long
       sample in the stall with probability 1 in 2**rounds per trial, and five rounds is a 2 ms
       window, so cheap subjects take as many rounds as the floor allows.

    A super-linear subject still shows: its short block is then SHORTER than its long sample, so
    what bias remains raises the ratio, which is the direction its control needs."""
    span = max(1, round(len(long) / len(short)))
    order = random.Random()
    best_short = best_long = math.inf

    def time_short() -> float:
        start = time.perf_counter()
        for _ in range(span):
            call(short)
        return (time.perf_counter() - start) / span

    def time_long() -> float:
        start = time.perf_counter()
        call(long)
        return time.perf_counter() - start

    began = time.perf_counter()
    done = 0
    while done < rounds or time.perf_counter() - began < _GROWTH_MIN_SECONDS:
        if order.random() < 0.5:
            best_short = min(best_short, time_short())
            best_long = min(best_long, time_long())
        else:
            best_long = min(best_long, time_long())
            best_short = min(best_short, time_short())
        done += 1
    return best_long / best_short
