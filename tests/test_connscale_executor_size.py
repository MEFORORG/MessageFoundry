# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connscale executor shim sizes its pool the way CPython 3.14 sizes asyncio's default executor
(BACKLOG #3132, step 7).

The shim exists to measure the REAL default-pool wall, so its size must be CPython's. Since Python
3.13 ``ThreadPoolExecutor`` reads ``os.process_cpu_count()``, which honours a CPU affinity mask, and
not ``os.cpu_count()``, which counts every CPU in the machine. On a box whose engine is pinned to a
subset of CPUs the two differ, and the shim used to install the larger pool.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from messagefoundry.pipeline import connscale_shim


def _cpython_default_size() -> int:
    executor = ThreadPoolExecutor()
    try:
        # CPython's own computation, read from the executor it builds. No thread starts until a
        # submit, so constructing one is cheap.
        return int(executor._max_workers)  # noqa: SLF001
    finally:
        executor.shutdown(wait=False)


@pytest.mark.parametrize(("machine", "process"), [(64, 4), (8, 2), (1, 1), (128, 64)])
def test_the_shim_sizes_like_cpython_when_affinity_narrows_the_cpus(
    monkeypatch: pytest.MonkeyPatch, machine: int, process: int
) -> None:
    monkeypatch.setattr(os, "cpu_count", lambda: machine)
    monkeypatch.setattr(os, "process_cpu_count", lambda: process)
    assert connscale_shim.default_executor_max_workers() == _cpython_default_size()
    assert connscale_shim.default_executor_max_workers() == min(32, process + 4)


def test_an_unknown_cpu_count_falls_back_to_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "process_cpu_count", lambda: None)
    assert connscale_shim.default_executor_max_workers() == 5 == _cpython_default_size()
