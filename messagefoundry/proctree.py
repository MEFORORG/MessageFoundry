# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Kill a child process together with every process it started.

Killing a child kills that one process. Anything it started lives on as an orphan. Two callers need
the whole tree gone: the sandbox worker (:mod:`messagefoundry.pipeline.sandbox`), whose grandchild
could hold its response pipe, and the DR takeover hook (:mod:`messagefoundry.pipeline.dr`), whose shell's
children could still be taking the address after the activation was recorded as aborted (vault
BACKLOG #2622).

* **Windows.** The child is put in a job object with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``, and
  :func:`terminate_job` ends every process in it. A process joins a job only when it is created, so
  the child must be in the job before it starts anything. The sandbox worker waits for its boot
  frame, so assigning it just after the start is safe. A shell does not wait, so the takeover hook starts
  suspended (:data:`ADOPT_CREATIONFLAGS`) and :func:`resume_into_job` assigns it before it runs.
* **POSIX.** The child starts as the leader of its own process group (:data:`ADOPT_NEW_SESSION`),
  and :func:`kill_process_group` sends that group ``SIGKILL``.

**A process can still escape**, so this is process hygiene and not a trust control. At least
these escape: on POSIX a descendant that leaves the group (``setsid``, and ``sudo`` in its default
``use_pty`` mode) or that the engine's account may not signal; on Windows, work a child hands to
another process outside its tree (a WMI provider, Task Scheduler, a service). Any failure to set up
the job, or to signal the group, degrades to a single-process kill, logged.

Standard library only (``ctypes``), so ``pipeline/`` modules may import it.
"""

from __future__ import annotations

import ctypes
import logging
import os
import signal
import sys
from typing import Any, Final

log = logging.getLogger(__name__)

#: ``CreateProcess`` flag: create the process with its first thread suspended.
_CREATE_SUSPENDED: Final = 0x00000004

#: Pass as ``creationflags=`` when starting a child that :func:`resume_into_job` will adopt. Zero
#: off Windows, where ``subprocess`` refuses any other value.
ADOPT_CREATIONFLAGS: Final[int] = _CREATE_SUSPENDED if sys.platform == "win32" else 0

#: Pass as ``start_new_session=`` when starting such a child. It makes the child the leader of its
#: own process group on POSIX, which :func:`kill_process_group` needs. Windows ignores it.
ADOPT_NEW_SESSION: Final[bool] = sys.platform != "win32"

#: ``SetInformationJobObject`` info class + the ``LimitFlags`` bit for a job that terminates its whole
#: process tree when the job is closed/terminated (``JOBOBJECTINFOCLASS`` / ``winnt.h``).
_JobObjectExtendedLimitInformation: Final = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final = 0x2000

#: ``OpenProcess`` rights: assigning to a job needs the first two, resuming needs the third.
_PROCESS_TERMINATE: Final = 0x0001
_PROCESS_SET_QUOTA: Final = 0x0100
_PROCESS_SUSPEND_RESUME: Final = 0x0800


# The three Win32 structs below are plain ctypes layout classes (no Windows-only ctypes types), so
# they define cleanly on every platform and are only ever *used* under a ``sys.platform == "win32"``
# guard. Field names/types mirror ``winnt.h`` exactly — the layout must match for the API to read it.
class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    )


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = (
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    )


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


def _close_handle(kernel32: Any, handle: int) -> None:
    """Close a Win32 handle, swallowing a failure (nothing to do about it, and it must not raise
    from a kill path)."""
    try:  # noqa: SIM105
        kernel32.CloseHandle(ctypes.c_void_p(handle))
    except OSError:
        pass


def _set_job_limit(set_info: Any, job: int, flags: int) -> bool:
    info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = flags
    return bool(
        set_info(
            ctypes.c_void_p(job),
            _JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
    )


def kill_on_close_job(process_handle: int, *, who: str) -> int | None:
    """Assign the process behind ``process_handle`` to a fresh Windows job object whose whole tree
    dies when the job is terminated or its last handle closes; return the job handle (an int) to
    hold open for the process's lifetime.

    Returns ``None`` off Windows or on ANY failure (missing API, a job-setup error), logged under
    ``who``. The caller then degrades to a single-process kill. Mirrors the fail-open ctypes
    pattern in :mod:`messagefoundry.crashdump`."""
    if sys.platform != "win32":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:  # pragma: no cover - kernel32 is always present on win32
        return None
    create = getattr(kernel32, "CreateJobObjectW", None)
    set_info = getattr(kernel32, "SetInformationJobObject", None)
    assign = getattr(kernel32, "AssignProcessToJobObject", None)
    if create is None or set_info is None or assign is None:  # pragma: no cover - defensive
        log.warning(
            "%s: Windows job-object API missing; kill degrades to a single-process kill", who
        )
        return None
    create.restype = ctypes.c_void_p
    create.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    set_info.restype = ctypes.c_int
    set_info.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    assign.restype = ctypes.c_int
    assign.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    handle = create(None, None)
    if not handle:  # pragma: no cover - defensive
        log.warning("%s: CreateJobObject failed; kill degrades to a single-process kill", who)
        return None
    set_ok = _set_job_limit(set_info, int(handle), _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    if not set_ok or not assign(handle, ctypes.c_void_p(process_handle)):
        log.warning("%s: job-object setup failed; kill degrades to a single-process kill", who)
        _close_handle(kernel32, int(handle))
        return None
    return int(handle)


def terminate_job(job: int) -> None:
    """Terminate every process in ``job`` (the child and its whole tree) and close the handle."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type-checker / non-Windows
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:  # pragma: no cover - kernel32 is always present on win32
        return
    terminate = getattr(kernel32, "TerminateJobObject", None)
    if terminate is not None:
        terminate.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        terminate.restype = ctypes.c_int
        try:  # noqa: SIM105
            terminate(ctypes.c_void_p(job), 1)
        except OSError:  # pragma: no cover - defensive
            pass
    _close_handle(kernel32, job)


def release_job(job: int) -> None:
    """Close ``job`` and leave alive whatever is still in it.

    For a child that finished on its own. Closing a kill-on-close job's last handle would kill what
    the child left running, which a caller that only wanted the tree gone on a timeout did not ask
    for. So the limit is cleared first. If that fails the handle is kept open, which leaks one
    handle rather than killing a process the caller meant to keep."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type-checker / non-Windows
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:  # pragma: no cover - kernel32 is always present on win32
        return
    set_info = getattr(kernel32, "SetInformationJobObject", None)
    if set_info is None:  # pragma: no cover - defensive
        return
    set_info.restype = ctypes.c_int
    set_info.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    if _set_job_limit(set_info, job, 0):
        _close_handle(kernel32, job)
    else:  # pragma: no cover - defensive
        log.warning("could not clear a job's kill-on-close limit; keeping its handle open")


def resume_into_job(pid: int, *, who: str) -> int | None:
    """Put the suspended child ``pid`` in a kill-on-close job, then let it run. Returns the job
    handle, or ``None`` off Windows or when the job could not be set up (the child still runs).

    The child must have been started with :data:`ADOPT_CREATIONFLAGS`, and its caller must still
    hold the handle ``subprocess`` opened, so ``pid`` cannot name a different process. The process
    is opened again by ``pid`` rather than through that handle, which asyncio keeps private. A
    process's default access list grants these rights to the account that created it. Raises
    :class:`OSError` when the child cannot be resumed: it would otherwise never run, so the caller
    kills it."""
    if sys.platform != "win32":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    open_process = kernel32.OpenProcess
    open_process.restype = ctypes.c_void_p
    open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    # NtResumeProcess resumes every thread of the process. It is the call Windows' own tools use
    # for this. The documented alternative walks a thread snapshot to find the one thread.
    resume = ntdll.NtResumeProcess
    resume.restype = ctypes.c_long
    resume.argtypes = [ctypes.c_void_p]
    rights = _PROCESS_TERMINATE | _PROCESS_SET_QUOTA | _PROCESS_SUSPEND_RESUME
    handle = open_process(rights, 0, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error(), f"{who}: could not open the started process")
    job: int | None = None
    try:
        job = kill_on_close_job(int(handle), who=who)
        status = resume(ctypes.c_void_p(handle))
        if status < 0:  # NT_SUCCESS is status >= 0; print it the way Windows writes an NTSTATUS
            raise OSError(
                f"{who}: could not resume the started process (status {status & 0xFFFFFFFF:#010x})"
            )
        return job
    except BaseException:
        # The child never ran, so ending the job ends only it. Without this the handle would leak.
        if job is not None:
            terminate_job(job)
        raise
    finally:
        _close_handle(kernel32, int(handle))


def kill_process_group(pid: int, *, started_as_leader: bool = False) -> bool:
    """``SIGKILL`` the process group that ``pid`` leads, on POSIX. Returns whether the signal was
    sent.

    Returns ``False``, signalling nothing, on Windows, when ``pid`` leads no group of its own, when
    its group cannot be read, or when the signal fails. The caller then kills the one process.

    The leadership check reads ``pid``'s group, so it needs ``pid`` to still be a live process.
    ``started_as_leader=True`` is for a caller that started ``pid`` with
    :data:`ADOPT_NEW_SESSION` itself and so knows the group is ``pid``'s. It skips the check, so it
    still reaches the group's other members after the leader has exited and been reaped. Either way
    this never signals the caller's own group (the engine's, or pytest's)."""
    if sys.platform == "win32":
        return False
    if started_as_leader:
        if pid == os.getpgrp():
            return False
        pgid = pid
    else:
        try:
            pgid = os.getpgid(pid)
        except OSError:
            return False
        if pgid != pid:
            return False
    try:
        os.killpg(pgid, signal.SIGKILL)
    except OSError as exc:
        log.warning(
            "could not signal process group %d (%s); kill degrades to a single-process kill",
            pgid,
            exc.strerror or type(exc).__name__,
        )
        return False
    return True
