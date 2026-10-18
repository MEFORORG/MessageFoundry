# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An engine a harness node spawned must not outlive the process that spawned it.

Measured 2026-10-17 on a developer box: 54 ``messagefoundry serve --config harness/config/connscale``
processes from 9 agent worktrees, up to 16.5 hours old, each a venv launcher whose parent pytest
worker was dead, plus the live interpreter under it. The owner died before ``EngineNode.stop`` ran,
so no ``finally`` could help. ``EngineNode._spawn`` now starts the engine suspended in a
kill-on-close job (``messagefoundry.proctree``); this file pins that.

**THE OWNER IS A REAL SEPARATE PROCESS, KILLED THE WAY PYTEST DIED.** A test that stops a node in
its own process measures ``stop()``, not the leak. So a child process plays pytest: it spawns a node
tree, reports the root PID, and is then terminated with no chance to clean up.

**THE INSTRUMENT IS ARMED BY A CONTROL THAT MUST LEAK.** "No process survived" is also what a tree
that never started, or a census that cannot see it, looks like. The control runs the same owner with
the job left out and asserts the tree SURVIVES its owner -- the 2026-10-17 shape -- before the real
case may claim a pass. Every test here kills what it spawned on the way out, so the control leaks
nothing past the test.

**THE TREE IS THREE DEEP ON PURPOSE.** The node's root (the venv launcher where there is one) starts
an interpreter, which starts a grandchild. The grandchild is what proves the job reaches processes
the engine itself starts, not just the PID the node holds. Killing the launcher alone already takes
the interpreter, measured the same day: the launcher holds it in a kill-on-close job of its own.

Windows only: the job object is the mechanism, and POSIX has none.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import IO

import psutil
import pytest

from harness.load.failover import EngineNode
from tests._proc_tree import alive, describe, kill_all, tree_of, wait_until

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="the kill-on-close job object is Windows-only"
)

#: Long enough that nothing in the tree exits on its own inside a test, short enough that a tree
#: that escaped every cleanup still goes by itself.
SLEEP_SECONDS = 120
#: The grandchild marks its command line with this, so the census finds the deepest process.
GRANDCHILD_MARK = "mefor-proctree-grandchild"
#: Starting an owner imports the harness, which takes seconds on a loaded box.
OWNER_WAIT = 45.0
TREE_WAIT = 20.0
GONE_WAIT = 10.0
#: How long the control watches for a death that must NOT come. Kill-on-close fires as the owner's
#: handles are torn down, which is done by the time its exit is observed.
SURVIVE_WATCH = 1.0

#: The node's stand-in for ``serve``: start a grandchild, then sleep.
_TREE_ROOT_SRC = textwrap.dedent(
    f"""
    import subprocess, sys, time
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep({SLEEP_SECONDS})",
                      "{GRANDCHILD_MARK}"])
    time.sleep({SLEEP_SECONDS})
    """
)


class TreeNode(EngineNode):
    """An ``EngineNode`` whose subprocess is a cheap three-deep tree instead of ``serve``."""

    async def _exec(self, *argv: str) -> asyncio.subprocess.Process:
        return await super()._exec(sys.executable, "-c", _TREE_ROOT_SRC)


#: Plays pytest: spawns a node tree through the REAL ``EngineNode._spawn``, reports the root PID,
#: then waits to be killed. ``argv[1] == "nojob"`` resumes the engine without a job: the control.
_OWNER_SRC = textwrap.dedent(
    """
    import asyncio, os, sys
    from pathlib import Path

    import psutil

    from harness.load import failover
    from tests.test_engine_node_process_tree import SLEEP_SECONDS, TreeNode

    if sys.argv[1] == "nojob":
        def resume_without_job(pid, *, who):
            psutil.Process(pid).resume()
            return None
        failover.resume_into_job = resume_without_job

    async def main():
        node = TreeNode("owner", 1, env=dict(os.environ), config_dir="unused", cwd=Path.cwd())
        await node._spawn()
        print(node.pid, flush=True)
        await asyncio.sleep(SLEEP_SECONDS)

    asyncio.run(main())
    """
)


def _full_tree(root_pid: int) -> list[psutil.Process]:
    """``root_pid``'s tree once the grandchild has appeared. Fails the test if it never does,
    because a tree with no grandchild cannot show the job reaching one."""
    found: list[psutil.Process] = []

    def full() -> bool:
        nonlocal found
        found = tree_of(root_pid)
        return any(_is_grandchild(p) for p in found)

    assert wait_until(full, TREE_WAIT), (
        f"could not arm: the node tree under PID {root_pid} never grew its grandchild within "
        f"{TREE_WAIT}s, so nothing here can show the tree being reaped"
    )
    return found


def _is_grandchild(proc: psutil.Process) -> bool:
    """The mark as a WHOLE argument. A substring match would also fire on the tree root, whose
    ``-c`` source spells the mark out -- measured: it armed before the grandchild existed."""
    try:
        return GRANDCHILD_MARK in proc.cmdline()
    except psutil.Error:
        return False


def _gone_within(procs: list[psutil.Process], budget: float) -> list[psutil.Process]:
    """Wait up to ``budget`` for every one of ``procs`` to exit; return those still running."""
    wait_until(lambda: not alive(procs), budget)
    return alive(procs)


@pytest.fixture
def spawned() -> Iterator[list[psutil.Process]]:
    """Every process a test registers here is killed on the way out, pass or fail."""
    procs: list[psutil.Process] = []
    yield procs
    kill_all(procs)


def _read_line(stream: IO[str] | None, budget: float) -> str:
    """One line from ``stream`` within ``budget``, or ``""``: a pipe read cannot time out itself."""
    assert stream is not None
    got: list[str] = []
    reader = threading.Thread(target=lambda: got.append(stream.readline()), daemon=True)
    reader.start()
    reader.join(budget)
    return got[0] if got else ""


def _own_tree(
    mode: str, spawned: list[psutil.Process]
) -> tuple[subprocess.Popen[str], list[psutil.Process], list[psutil.Process]]:
    """Start an owner in ``mode``; return it, its own process chain, and the node tree it spawned.
    The chain is the owner launcher (where there is one) and the interpreter holding the job."""
    owner = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", _OWNER_SRC, mode],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        stdout=subprocess.PIPE,
        text=True,
    )
    spawned.append(psutil.Process(owner.pid))
    line = _read_line(owner.stdout, OWNER_WAIT)
    assert line.strip().isdigit(), f"the owner never reported a node PID (got {line!r})"
    tree = _full_tree(int(line))
    in_tree = {p.pid for p in tree}
    chain = [p for p in tree_of(owner.pid) if p.pid not in in_tree]
    spawned.extend([*tree, *chain])
    return owner, chain, tree


def _hard_kill(owner: subprocess.Popen[str], chain: list[psutil.Process]) -> None:
    """Terminate the owner as pytest died: no handler, no ``finally``, no ``atexit``."""
    kill_all(chain)
    owner.wait(timeout=GONE_WAIT)


def test_the_CONTROL_a_tree_with_no_job_SURVIVES_its_owner(spawned: list[psutil.Process]) -> None:
    owner, chain, tree = _own_tree("nojob", spawned)
    _hard_kill(owner, chain)
    time.sleep(SURVIVE_WATCH)
    assert alive(tree), (
        "THE CONTROL DID NOT LEAK. With no job, the node tree should outlive its killed owner, "
        "which is the 2026-10-17 leak; it did not, so a pass of the real test below would not "
        "show the job doing anything."
    )


def test_a_node_tree_DIES_WITH_its_hard_killed_owner(spawned: list[psutil.Process]) -> None:
    owner, chain, tree = _own_tree("job", spawned)
    _hard_kill(owner, chain)
    survivors = _gone_within(tree, GONE_WAIT)
    assert not survivors, (
        f"THE NODE TREE OUTLIVED ITS OWNER. {len(survivors)} process(es) still running "
        f"{GONE_WAIT}s after the owner was terminated -- the 2026-10-17 leak of 54 connscale "
        "engines:\n" + describe(survivors)
    )


@pytest.mark.parametrize("how", ["stop", "kill"])
async def test_stop_and_kill_take_the_WHOLE_tree(
    how: str, spawned: list[psutil.Process], tmp_path: Path
) -> None:
    node = TreeNode("in-process", 1, env=dict(os.environ), config_dir="unused", cwd=tmp_path)
    try:
        await node._spawn()
        assert node.pid is not None
        tree = await asyncio.to_thread(_full_tree, node.pid)
        spawned.extend(tree)
        if how == "kill":
            node.kill()
        await node.stop()
        survivors = await asyncio.to_thread(_gone_within, tree, GONE_WAIT)
        assert not survivors, (
            f"EngineNode.{how}() left {len(survivors)} process(es) of its tree running:\n"
            + describe(survivors)
        )
    finally:
        await node.stop()
