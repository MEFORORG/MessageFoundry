# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Windows process guard in ``tests/_process_guard.py`` ends a pytest process's children when
that process dies by ``os._exit``, the way pytest-timeout ends a hung worker.

Each case starts an OWNER process that starts a SLEEPER and then calls ``os._exit``. Without the
guard the sleeper must outlive its owner: that is the leak, and the control that shows this test
can see one. With the guard, the same owner's sleeper must be gone.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
import time
import uuid
from pathlib import Path

import psutil
import pytest

from messagefoundry import proctree
from tests import _process_guard as process_guard

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows job objects")

_ROOT = Path(__file__).resolve().parents[1]

# The owner. argv: install the guard ("1") or not ("0"), then the sleeper's marker. Prints the
# sleeper's pid, then exits the way pytest-timeout's thread method ends a worker: no teardown. It
# first checks the sleeper is running, so a sleeper that never ran cannot pass the guarded case.
_OWNER = """\
import os, subprocess, sys, time
if sys.argv[1] == "1":
    from tests import _process_guard
    if _process_guard.install() is None:
        sys.exit(3)
python = getattr(sys, "_base_executable", sys.executable)
sleeper = subprocess.Popen(
    [python, "-c", "import time; time.sleep(120)", sys.argv[2]],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
time.sleep(0.5)
if sleeper.poll() is not None:
    sys.exit(4)
print(sleeper.pid, flush=True)
os._exit(0)
"""


def _sleeper_alive(pid: int, marker: str) -> bool:
    """Whether ``pid`` is still the sleeper. The marker in its command line tells it from a process
    that reused the pid. AccessDenied is left to raise: the sleeper is this account's own process,
    so an unreadable one must not read as gone."""
    try:
        return marker in psutil.Process(pid).cmdline()
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return False


def _run_owner(*, guard: bool, marker: str) -> int:
    owner = subprocess.run(
        [sys.executable, "-c", _OWNER, "1" if guard else "0", marker],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert owner.returncode == 0, owner.stderr
    return int(owner.stdout.strip())


def _kill(pid: int, marker: str) -> None:
    try:  # noqa: SIM105 - it may die between the check and the kill, which is what was wanted
        if _sleeper_alive(pid, marker):
            psutil.Process(pid).kill()
    except psutil.NoSuchProcess:
        pass


def test_this_worker_is_guarded() -> None:
    """conftest's pytest_configure ran in this process, controller or xdist worker alike, and the
    job it holds ends its processes when it closes."""
    if sys.platform != "win32":  # pytestmark skips first; this tells mypy's linux leg
        pytest.skip("Windows job objects")
    job = process_guard.job()
    assert job is not None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel32.QueryInformationJobObject
    query.restype = ctypes.c_int
    query.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    info = proctree._JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    assert query(
        ctypes.c_void_p(job),
        proctree._JobObjectExtendedLimitInformation,
        ctypes.byref(info),
        ctypes.sizeof(info),
        None,
    ), ctypes.get_last_error()
    assert info.BasicLimitInformation.LimitFlags & proctree._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE


def test_install_is_idempotent() -> None:
    """A second call keeps the first job rather than nesting a new one."""
    before = process_guard.job()
    assert before is not None
    assert process_guard.install() == before
    assert process_guard.job() == before


def test_without_the_guard_the_sleeper_outlives_its_owner() -> None:
    """The must-leak control. If this fails, the case below proves nothing."""
    marker = f"mefor-guard-control-{uuid.uuid4().hex}"
    pid = _run_owner(guard=False, marker=marker)
    try:
        time.sleep(1.0)
        assert _sleeper_alive(pid, marker), (
            "the unguarded owner's sleeper died; the control is blind"
        )
    finally:
        _kill(pid, marker)


def test_with_the_guard_the_sleeper_dies_with_its_owner() -> None:
    marker = f"mefor-guard-real-{uuid.uuid4().hex}"
    pid = _run_owner(guard=True, marker=marker)
    try:
        deadline = time.monotonic() + 10.0
        while _sleeper_alive(pid, marker) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not _sleeper_alive(pid, marker), "the guarded owner's sleeper outlived it"
    finally:
        _kill(pid, marker)


def test_a_breakaway_request_is_refused() -> None:
    """The cost the guard's docstring names: the job does not allow breakaway, so a test that asks
    for it fails loudly rather than leaking."""
    if sys.platform != "win32":  # pytestmark skips first; this tells mypy's linux leg
        pytest.skip("Windows job objects")
    with pytest.raises(PermissionError):
        subprocess.run(
            [sys.executable, "-c", "pass"],
            creationflags=subprocess.CREATE_BREAKAWAY_FROM_JOB,
            check=False,
            timeout=60,
        )
