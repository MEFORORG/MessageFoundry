# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Process-tree helpers for the tests that prove a spawned tree does not outlive its owner.

Shared by ``test_engine_node_process_tree``, ``test_durability_hook_push_bound`` and the connscale
smoke's leak check, so a fix to how a census reads a process reaches all three. Every read here
tolerates the process vanishing mid-walk: in a leak test that is the outcome being waited for.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable

import psutil

POLL = 0.2


def wait_until(predicate: Callable[[], bool], budget: float) -> bool:
    """Poll ``predicate`` until it holds or ``budget`` seconds pass; return whether it held."""
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(POLL)
    return predicate()


def tree_of(pid: int) -> list[psutil.Process]:
    """``pid`` and every descendant, or ``[]`` when ``pid`` is already gone."""
    try:
        root = psutil.Process(pid)
        return [root, *root.children(recursive=True)]
    except psutil.NoSuchProcess:
        return []


def cmdline_of(proc: psutil.Process) -> str | None:
    """``proc``'s command line joined by spaces, or ``None`` when it cannot be read."""
    try:
        return " ".join(proc.cmdline())
    except psutil.Error:
        return None


def alive(procs: Iterable[psutil.Process]) -> list[psutil.Process]:
    """The ones still running. ``is_running`` also checks the creation time, so a reused PID never
    reads as a survivor."""
    return [p for p in procs if p.is_running()]


def kill_all(procs: Iterable[psutil.Process]) -> None:
    """Kill each, ignoring one already gone. ``TerminateProcess`` on Windows, which also ends a
    suspended process without resuming it."""
    for proc in procs:
        try:
            proc.kill()
        except psutil.Error:
            continue


def describe(procs: Iterable[psutil.Process]) -> str:
    """One line per process, for a failure message."""
    return "\n".join(f"{p.pid} {cmdline_of(p)}" for p in procs)
