# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse a script injected into the engine through the interpreter's remote debugging (vault
BACKLOG #2700).

**What this is about.** Python 3.14 (PEP 768) lets another process ask a running interpreter to
execute a script file: ``sys.remote_exec(pid, path)``. The caller needs the right to write the
target's memory, which a process running as the same account has on a default Windows or Linux
host. The interface is on unless the interpreter was started with ``-X disable-remote-debug`` or
``PYTHON_DISABLE_REMOTE_DEBUG=1``. The engine's children are started with the option
(``messagefoundry/childenv.py``). The engine itself is started through a console-script launcher,
which cannot pass an interpreter option, so ``serve`` and ``supervise`` would start with it on.

**What this does.** Before it runs an injected script, the target interpreter raises the audit
event ``cpython.remote_debugger_script``, and it does not run the script when an audit hook raises.
:func:`install_remote_debug_guard` adds a hook that raises on that event and on nothing else.
:func:`remote_debug_posture` reports the interpreter setting and whether the hook answers.
``tests/test_remote_debug_guard.py`` injects into a real child both ways, because the behaviour is
the interpreter's and could change under this module.

**What this is not.** The hook closes the interpreter's own injection interface. It does not close
the capability underneath it: a process that can write this process's memory can run code in it
some other way, and can remove a hook. So an enabled interface with the hook in place is reported
as a residual (:func:`remote_debug_loosening`), and turning the interface off at launch is separate
work. Running untrusted code under a different account is what takes the capability away.

**Why the hook does so little.** The interpreter calls it on the main thread between two bytecodes
of whatever was running, which is the position a signal handler is in. The engine's log handlers
take locks that are not reentrant, and the interrupted code may hold one, so a log call made here
could wait on its own thread forever. The hook therefore only counts, queues the file name on a
``queue.SimpleQueue`` (whose ``put`` is documented as reentrant) and raises. A daemon thread
writes the WARNING, with the script's file name only. The interpreter also reports the hook's
exception itself, through ``sys.unraisablehook``: by default one line on standard error with the
script's full path, and a traceback.

**Cost.** An audit hook runs on every audited operation in the process, not only this event.
Measured on one Windows development machine, CPython 3.14.6: about 60 to 90 ns for each audited
operation. How many audited operations the engine performs for each message is not measured. Where
the interface is already disabled the event cannot fire, so no hook is installed and nothing is
paid.

No engine state. It imports the standard library and ``messagefoundry.controlchars``, which
imports nothing, so any package may import it.
"""

from __future__ import annotations

import logging
import os
import queue
import sys
import threading
from dataclasses import dataclass
from typing import Final

from messagefoundry.controlchars import scrub_log_argument

__all__ = [
    "REMOTE_SCRIPT_EVENT",
    "RemoteDebugPosture",
    "RemoteScriptRefused",
    "install_remote_debug_guard",
    "remote_debug_loosening",
    "remote_debug_posture",
]

#: The audit event the target interpreter raises before it runs an injected script. Its one
#: argument is the script's path.
REMOTE_SCRIPT_EVENT: Final = "cpython.remote_debugger_script"

#: Raised by :func:`_guard_answers` to ask whether the hook is in the interpreter's hook list.
#: The interpreter has no call that lists audit hooks, and it drops a new hook without an error
#: when one already installed objects, so asking is the only way to know.
_PROBE_EVENT: Final = "messagefoundry.remotedebug.probe"

#: The injecting process chooses the script's name, so the logged copy is bounded.
_FILE_NAME_LIMIT: Final = 120

#: Refusals waiting for the reporter thread. Past this the refusal is still counted and still
#: refused; only its log line is dropped, so a caller that repeats cannot grow the queue.
_REPORT_BACKLOG: Final = 64

_log = logging.getLogger(__name__)
_install_lock = threading.Lock()
_reports: queue.SimpleQueue[str] = queue.SimpleQueue()
_refused = 0


class RemoteScriptRefused(RuntimeError):
    """Raised inside the audit hook, which is what makes the interpreter drop the script."""


@dataclass(frozen=True, slots=True)
class RemoteDebugPosture:
    """What :func:`remote_debug_posture` read from this process."""

    #: ``sys.is_remote_debug_enabled()``: whether the interpreter accepts an injected script.
    interpreter_enabled: bool
    #: Whether this module's hook answered a probe just now. Measured, never remembered.
    guard_installed: bool
    #: Scripts the hook has refused since this process started.
    refused_scripts: int = 0


def _file_name(args: tuple[object, ...]) -> str:
    path = args[0] if args and isinstance(args[0], str) else ""
    return os.path.basename(path)[:_FILE_NAME_LIMIT]


def _guard(event: str, args: tuple[object, ...]) -> None:
    """The audit hook. See the module docstring for why it neither logs nor takes a lock."""
    if event == REMOTE_SCRIPT_EVENT:
        global _refused
        _refused += 1
        if _reports.qsize() < _REPORT_BACKLOG:
            _reports.put(_file_name(args))
        raise RemoteScriptRefused("remote debugging scripts are refused in the engine process")
    if event == _PROBE_EVENT and args and isinstance(args[0], list):
        args[0].append(True)


def _report(name: str) -> None:
    # Scrubbed here as well as by the handlers: the injecting process chooses the name, it may
    # hold a line break, and a handler with no filter chain would write it as it came.
    _log.warning(
        "refused a script that another process injected through the interpreter's remote "
        "debugging (audit event %s, script file name %s). Nothing in it ran.",
        REMOTE_SCRIPT_EVENT,
        scrub_log_argument(name),
    )


def _report_refusals() -> None:
    """Write one WARNING for each refused script, off the thread the hook interrupted."""
    while True:
        _report(_reports.get())


def _start_reporter() -> None:
    threading.Thread(target=_report_refusals, name="mefor-remote-debug-report", daemon=True).start()


def _guard_answers() -> bool:
    answer: list[bool] = []
    sys.audit(_PROBE_EVENT, answer)
    return bool(answer)


def install_remote_debug_guard() -> None:
    """Add the hook to this process, once, when the interpreter accepts injected scripts.

    Call it as early in the process as possible: a script injected before the call runs. A second
    call finds the hook answering and adds nothing, and an audit hook cannot be removed.

    Nothing is added where ``sys.is_remote_debug_enabled()`` is False, which is every child started
    through :func:`messagefoundry.childenv.python_child_argv`. The event cannot fire there.

    The hook may still be missing afterwards: the interpreter drops a new hook without an error
    when one already installed raises on ``sys.addaudithook``. :func:`remote_debug_posture` reports
    which it is. Nothing in the engine installs another hook.
    """
    if not sys.is_remote_debug_enabled():
        return
    with _install_lock:
        if _guard_answers():
            return
        sys.addaudithook(_guard)
        _start_reporter()


def remote_debug_posture() -> RemoteDebugPosture:
    """The reading for THIS process. It says nothing about any other process."""
    return RemoteDebugPosture(
        interpreter_enabled=sys.is_remote_debug_enabled(),
        guard_installed=_guard_answers(),
        refused_scripts=_refused,
    )


def remote_debug_loosening(posture: RemoteDebugPosture) -> tuple[str, str] | None:
    """The ``(name, plain-language risk)`` entry for ``posture``, or None where the interface is off.

    One place for the wording, so ``security_loosenings()`` and the ``supervise`` start-up line
    cannot say different things. Two names, because the two states ask for different actions."""
    if not posture.interpreter_enabled:
        return None
    if not posture.guard_installed:
        return (
            "remote_debug_unguarded",
            "the interpreter's remote debugging (PEP 768) is enabled in this process and the "
            "engine's refusal hook is NOT installed. A process running as the same account "
            "could run Python inside this one with sys.remote_exec, with everything it holds "
            "(the store key, connection secrets, messages in flight). `serve` and `supervise` "
            "install the hook at start. Start the interpreter with -X disable-remote-debug to "
            "turn the interface off",
        )
    refused = (
        f" It has refused {posture.refused_scripts} since this process started."
        if posture.refused_scripts
        else ""
    )
    return (
        "remote_debug_enabled",
        "the interpreter's remote debugging (PEP 768) is enabled in this process. The engine "
        "refuses a script injected through it, so this is a residual and not an open path."
        f"{refused} A process that can write into this process's address space can still run "
        "code in it by other means. Start the interpreter with -X disable-remote-debug to turn "
        "the interface off",
    )
