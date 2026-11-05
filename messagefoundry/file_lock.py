# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An exclusive OS lock on an open file, the one statement of it (BACKLOG #2279 item 9).

The generated TLS pair (``api/tls.py``), the config edit lock (``config/atomic_edit.py``), the log
spool (``log_spool.py``) and the DR staging directory (``pipeline/dr_backup.py``) each wrote the
same ``msvcrt.locking`` / ``fcntl.flock`` pair. They now call this one. A caller that reads a
failure differently, such as the spool treating any ``OSError`` as "not ours", wraps it.

A leaf module: it imports nothing from the engine, so any package may use it.

**An OS lock, not a lock FILE.** The kernel releases it when its holder dies, so a SIGKILL or a
power loss cannot leave a lock that blocks every later start.

**One byte at offset 0.** ``msvcrt.locking`` locks from the current file position, so both calls
seek to 0 first, and holder and releaser name the same range.

**``flock`` on POSIX, not ``lockf``.** A ``lockf`` lock belongs to the process, so two handles in
one process would not exclude each other. ``msvcrt.locking`` on Windows is per handle already. So
both forms conflict between separate opens of the file, within one process as across processes.
"""

from __future__ import annotations

import errno
import os
import sys


def lock_exclusive(fd: int, *, wait: bool = False) -> bool:
    """Take an exclusive OS lock on ``fd``. ``True`` when held.

    With ``wait`` False, one attempt: ``False`` means another handle holds the lock. With ``wait``
    True it blocks, on Windows for the CRT's bounded ``LK_LOCK`` retry, and contention that
    outlasts that raises. Any other failure raises ``OSError`` in both modes."""
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_LOCK if wait else msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            # Measured on Windows: a held range refuses with EACCES. EDEADLOCK is the CRT's other
            # documented contention code. Anything else is a real fault and propagates.
            if wait or exc.errno not in (errno.EACCES, errno.EDEADLOCK):
                raise
            return False
        return True
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        if wait:
            raise
        return False
    return True


def unlock(fd: int) -> None:
    """Drop the lock :func:`lock_exclusive` took on ``fd``. Raises ``OSError`` on failure; closing
    the handle drops the lock anyway, so a caller about to close may suppress it."""
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)
