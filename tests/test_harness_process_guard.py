# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A headless harness run's children die with it on Windows, ``os._exit`` included.

Each case starts an OWNER process that runs ``harness.__main__.main`` with one mode's runner
replaced: the replacement starts a SLEEPER, checks it is running, and calls ``os._exit``, which runs
no ``finally`` block, as a killed coordinator would. Run as the process entry point (``main()``) the
sleeper must be gone. Run in-process (``main([...])``, what a test does) or as the GUI, the harness
holds no job, and the same sleeper must outlive its owner: those are the must-leak controls that
show this test can see a leak.

The sleeper starts through ``sys.executable``, as the real start sites do (``_spawn_proc``,
``build_remote_argv``, ``EngineNode``). In a venv that is the launcher, which runs the interpreter as
a child of its own, so every process carrying the sleeper's marker is checked, not one pid.
"""

from __future__ import annotations

import subprocess
import sys
import time
import uuid
from pathlib import Path

import psutil
import pytest

from harness import __main__ as harness_main

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows job objects")

# The directory the owner imports `harness` from: the one this suite imported it from.
_ROOT = Path(harness_main.__file__).resolve().parents[1]

# argv: the mode ("shardcert", "load" or "gui"), "entry" or "inprocess", then the sleeper's marker.
# Prints whether the harness holds a job ("1" or "0"). Exits 4 if the sleeper is not running before
# os._exit, so a sleeper that never ran cannot pass the guarded case.
_OWNER = """\
import os, subprocess, sys, time
import harness.__main__ as hm
mode, call, marker = sys.argv[1:4]

def owner(*_args):
    sleeper = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)", marker],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)
    if sleeper.poll() is not None:
        os._exit(4)
    print(int(hm._children_job is not None), flush=True)
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


def _marked(marker: str) -> list[psutil.Process]:
    """Every live process whose command line carries ``marker``: the sleeper, and in a venv the
    interpreter its launcher started."""
    return [p for p in psutil.process_iter(["cmdline"]) if marker in (p.info["cmdline"] or ())]


def _kill_marked(marker: str) -> None:
    for proc in _marked(marker):
        try:  # noqa: SIM105 - it may die between the scan and the kill, which is what was wanted
            proc.kill()
        except psutil.NoSuchProcess:
            pass


def _run_owner(mode: str, call: str, marker: str) -> bool:
    """Run one owner; return whether the harness held a job when its runner ran."""
    owner = subprocess.run(
        [sys.executable, "-c", _OWNER, mode, call, marker],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert owner.returncode == 0, (owner.returncode, owner.stderr)
    return owner.stdout.strip() == "1"


@pytest.mark.parametrize(
    ("mode", "call"), [("shardcert", "inprocess"), ("load", "inprocess"), ("gui", "entry")]
)
def test_without_the_job_the_sleeper_outlives_its_owner(mode: str, call: str) -> None:
    """The must-leak controls. If one fails, the guarded cases below prove nothing."""
    marker = f"mefor-harness-guard-control-{uuid.uuid4().hex}"
    try:
        assert not _run_owner(mode, call, marker)
        time.sleep(0.5)
        assert _marked(marker), "the unguarded owner's sleeper died; the control is blind"
    finally:
        _kill_marked(marker)


@pytest.mark.parametrize("mode", ["shardcert", "load"])
def test_a_headless_run_s_sleeper_dies_with_it(mode: str) -> None:
    """A positional subcommand (``shardcert``) and a flag mode (``--load``), each run as the entry
    point."""
    marker = f"mefor-harness-guard-real-{uuid.uuid4().hex}"
    try:
        assert _run_owner(mode, "entry", marker), "the harness entry point set up no job"
        deadline = time.monotonic() + 10.0
        while _marked(marker) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not _marked(marker), "a process of the headless harness's sleeper outlived it"
    finally:
        _kill_marked(marker)
