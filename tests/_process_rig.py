# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Start child processes, hold them until each has opened its store, then release them together.

Shared by the suites that race two engine processes over one store: the repeat-request race
(``tests/_approval_repeat_two_process.py``, vault BACKLOG #3236) and the SQL Server audit applock
(``tests/test_sqlserver_audit_applock.py``, BACKLOG #1605). They had two copies of this rig (vault
BACKLOG #3193 N5). A rig inside one interpreter would be serialized by the store's in-process lock
and prove nothing, so each child is its own OS process.

The contract with a child: it prints ``READY`` on stdout once its store is open, then waits for
the go file :attr:`ProcessRig.go` names, and exits 0 when its run is done. Store open is far
slower than one write, so without the barrier a fast child can finish before its peer connects.

Every wait is bounded, so a hung child fails here with its stderr rather than being cut off by
pytest-timeout with nothing to read. Each child's stderr goes to a file, never a pipe: a pipe
nobody reads fills and blocks the child, and the wait for ``READY`` would then never end.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path
from types import TracebackType

_REPO_ROOT = Path(__file__).resolve().parents[1]

#: The line a child prints once its store is open.
READY = "READY"


class ProcessRig:
    """Children run from the repository root, released together through one go file.

    Use it as a context manager, so a child still running when the test fails is killed."""

    def __init__(self, signal_dir: Path, tag: str) -> None:
        self._signal_dir = signal_dir
        self._tag = tag
        #: The file the children wait for. Pass it in their argv.
        self.go = signal_dir / f"go-{tag}"
        self._procs: list[subprocess.Popen[str]] = []
        self._errs: list[Path] = []

    def __enter__(self) -> ProcessRig:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        for proc in self._procs:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    def start(self, argvs: list[list[str]], *, ready_timeout: float) -> None:
        """Start one child per argv, with this process's environment, and return once every one
        has printed ``READY``. A child that fails first, or hangs, fails the call with its
        stderr."""
        for n, argv in enumerate(argvs):
            err_path = self._signal_dir / f"err-{self._tag}-{n}.txt"
            self._errs.append(err_path)
            with err_path.open("w", encoding="utf-8") as err_file:
                self._procs.append(
                    subprocess.Popen(
                        argv,
                        cwd=_REPO_ROOT,
                        stdout=subprocess.PIPE,
                        stderr=err_file,
                        text=True,
                    )
                )
        # One deadline for all of them, so the wait stays within ``ready_timeout`` however many.
        deadline = time.monotonic() + ready_timeout
        for proc, err_path in zip(self._procs, self._errs, strict=True):
            ready, killed = _readline_within(proc, max(0.0, deadline - time.monotonic()))
            if ready.strip() != READY:
                # Said in words: a kill's exit code can match a crash's (1 on Windows).
                try:
                    code: int | None = proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    code = None
                raise AssertionError(
                    f"a child never opened its store: {ready!r}, "
                    f"{'killed after hanging' if killed else 'exited'} with code {code}; "
                    f"its stderr:\n{_tail(err_path)}"
                )

    def release(self, content: str) -> None:
        """Write the go file, whole and renamed into place, so no child reads half of it."""
        staged = self.go.with_suffix(".tmp")
        staged.write_text(content, encoding="utf-8")
        os.replace(staged, self.go)

    def finish(self, timeout: float) -> list[str]:
        """Each child's stdout once it exits, in start order. A child that exits non-zero fails
        the call with its stderr; one still running ``timeout`` seconds after this is called
        raises :class:`subprocess.TimeoutExpired`, and leaving the ``with`` block kills it."""
        deadline = time.monotonic() + timeout
        outs = [
            proc.communicate(timeout=max(0.0, deadline - time.monotonic()))[0]
            for proc in self._procs
        ]
        for proc, err_path in zip(self._procs, self._errs, strict=True):
            assert proc.returncode == 0, f"a child exited {proc.returncode}: {_tail(err_path)}"
        return outs


def _readline_within(proc: subprocess.Popen[str], timeout: float) -> tuple[str, bool]:
    """The child's next stdout line, or ``""`` when none comes within ``timeout`` seconds, and
    whether the child was killed for it. A child that dies first closes stdout, so the read ends;
    one that hangs is killed, which ends it too."""
    stdout = proc.stdout
    assert stdout is not None
    line: list[str] = []
    reader = threading.Thread(target=lambda: line.append(stdout.readline()), daemon=True)
    reader.start()
    reader.join(timeout)
    killed = reader.is_alive()
    if killed:
        proc.kill()
        reader.join(5.0)
    return (line[0] if line else ""), killed


def _tail(path: Path) -> str:
    """The end of a child's stderr file, for a failure message."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-4000:]
    except OSError as exc:
        return f"(stderr unreadable: {exc})"
