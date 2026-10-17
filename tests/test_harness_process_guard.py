# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A headless harness run's children die with it on Windows, ``os._exit`` included.

Each case starts an OWNER process that runs ``harness.__main__.main`` with one mode's runner
replaced: the replacement starts a SLEEPER, checks it is running, prints its pid and calls
``os._exit``, which runs no ``finally`` block, as a killed coordinator would. Run as the process
entry point (``main()``) the sleeper must be gone. Run in-process (``main([...])``, what a test
does) or as the GUI, the harness holds no job, and the same sleeper must outlive its owner: those
are the must-leak controls that show this test can see a leak.
"""

from __future__ import annotations

import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from harness import __main__ as harness_main
from tests.test_process_guard import _kill, _sleeper_alive

_ROOT = Path(__file__).resolve().parents[1]

# argv: the mode ("shardcert", "load" or "gui"), "entry" or "inprocess", then the sleeper's marker.
# Prints "<job held 0|1> <sleeper pid>". Exits 4 if the sleeper is not running before os._exit, so a
# sleeper that never ran cannot pass the guarded case.
_OWNER = """\
import os, subprocess, sys, time
import harness.__main__ as hm
mode, call, marker = sys.argv[1:4]

def owner(*_args):
    python = getattr(sys, "_base_executable", sys.executable)
    sleeper = subprocess.Popen(
        [python, "-c", "import time; time.sleep(120)", marker],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)
    if sleeper.poll() is not None:
        os._exit(4)
    print(int(hm._children_job is not None), sleeper.pid, flush=True)
    os._exit(0)

argv = {"shardcert": ["shardcert"], "load": ["--load", "x"], "gui": []}[mode]
hm._run_shardcert = owner
hm._run_load = owner
hm._launch_gui = owner
if call == "entry":
    sys.argv = ["harness", *argv]
    hm.main()
else:
    hm.main(argv)
sys.exit(5)
"""


def _run_owner(mode: str, call: str, marker: str) -> tuple[bool, int]:
    owner = subprocess.run(
        [sys.executable, "-c", _OWNER, mode, call, marker],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert owner.returncode == 0, (owner.returncode, owner.stderr)
    held, pid = owner.stdout.split()
    return held == "1", int(pid)


def test_an_in_process_call_holds_no_job() -> None:
    """``main([...])`` is a library call, so it must not nest a job in the caller (on Linux the
    whole helper is a no-op, so this holds there too)."""
    harness_main._hold_children_job(["shardcert"])
    assert harness_main._children_job is None


windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows job objects")


@windows_only
@pytest.mark.parametrize(
    ("mode", "call"), [("shardcert", "inprocess"), ("load", "inprocess"), ("gui", "entry")]
)
def test_without_the_job_the_sleeper_outlives_its_owner(mode: str, call: str) -> None:
    """The must-leak controls. If one fails, the guarded cases below prove nothing."""
    marker = f"mefor-harness-guard-control-{uuid.uuid4().hex}"
    held, pid = _run_owner(mode, call, marker)
    try:
        assert not held
        time.sleep(0.5)
        assert _sleeper_alive(pid, marker), (
            "the unguarded owner's sleeper died; the control is blind"
        )
    finally:
        _kill(pid, marker)


@windows_only
@pytest.mark.parametrize("mode", ["shardcert", "load"])
def test_a_headless_run_s_sleeper_dies_with_it(mode: str) -> None:
    """A positional subcommand (``shardcert``) and a flag mode (``--load``), each run as the entry
    point."""
    marker = f"mefor-harness-guard-real-{uuid.uuid4().hex}"
    held, pid = _run_owner(mode, "entry", marker)
    try:
        assert held, "the harness entry point set up no job"
        deadline = time.monotonic() + 10.0
        while _sleeper_alive(pid, marker) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not _sleeper_alive(pid, marker), "the headless harness's sleeper outlived it"
    finally:
        _kill(pid, marker)
