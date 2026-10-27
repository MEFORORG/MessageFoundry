# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse a script injected into the engine through the interpreter's remote debugging (vault
BACKLOG #2700, #2742).

**What this is about.** Python 3.14 (PEP 768) lets another process ask a running interpreter to
execute a script file: ``sys.remote_exec(pid, path)``. The caller needs the right to write the
target's memory. On Windows a process running as the same account, at the same integrity level,
has it. On Linux it depends on the kernel's ptrace policy: where Yama ``ptrace_scope`` is 1, as
Ubuntu ships it, only a parent process or one with ``CAP_SYS_PTRACE`` has it. The interface is
on unless the interpreter was started with ``-X disable-remote-debug`` or
``PYTHON_DISABLE_REMOTE_DEBUG=1``. The engine's children are started with the option
(``messagefoundry/childenv.py``), and so is the engine by both shipped service launches. A start
through the console-script launcher cannot pass an interpreter option, so it has the interface on
unless ``PYTHON_DISABLE_REMOTE_DEBUG=1`` is set.

**What this does.** Before it runs an injected script, the target interpreter raises the audit
event ``cpython.remote_debugger_script``, and it does not run the script when an audit hook raises.
:func:`install_remote_debug_guard` adds a hook that raises on that event and on nothing else.
:func:`remote_debug_posture` reports the interpreter setting and whether the hook answers.
``tests/test_remote_debug_guard.py`` injects into a real child both ways, because the behaviour is
the interpreter's and could change under this module.

**What this is not.** The hook closes the interpreter's own injection interface, from the moment
it is installed. At least two things stay open. A script injected earlier in start-up runs: the
process has to import this module and reach the install call first, and a caller that can restart
the engine can aim for that window. The command line makes the call when
``messagefoundry/__main__.py`` is imported, ahead of that module's other imports and for every
command. What is left is at least the interpreter's own start-up, the package's ``__init__``,
loading that module, and this module's imports, which are most of the part the engine controls.
And the capability underneath is untouched: a process that can write this process's
memory can run code in it some other way, and can remove a hook. So an enabled interface with the
hook in place is reported as a residual (:func:`remote_debug_loosening`). Under ``enforce``,
``serve`` and ``supervise`` refuse to start with the interface on unless
:data:`REMOTE_DEBUG_ACCEPTANCE` accepts it (:func:`remote_debug_refusal`); the shipped service
launches turn it off with ``-X disable-remote-debug``.
``docs/SECURITY-LOOSENING.md`` carries the operator's account of what stays open.

**Why the hook does so little.** The interpreter calls it on the main thread between two bytecodes
of whatever was running, which is the position a signal handler is in. The engine's log handlers
take locks that are not reentrant, and the interrupted code may hold one, so a log call made here
could wait on its own thread forever. The hook therefore only counts, queues the file name on a
``queue.SimpleQueue`` (whose ``put`` is documented as reentrant) and raises. A daemon thread
writes the WARNING, with the script's file name only, spelled in ASCII (:func:`_ascii`).

**The interpreter's own report of the refusal is dropped.** The interpreter hands the hook's
exception to ``sys.unraisablehook``, which by default writes four lines to standard error for
each attempt: the script's full path as the injecting process spelled it, and a traceback. That
output has no bound and no scrubbing, so :func:`install_remote_debug_guard` wraps the hook to
drop that one report and pass every other one on. Code that replaces ``sys.unraisablehook``
afterwards brings the interpreter's lines back.

**Cost.** An audit hook runs on every audited operation in the process, not only this event.
Where the interface is already disabled the event cannot fire, so no hook is installed and nothing
is paid.

The cost for each message was measured once, on one machine (vault BACKLOG #2742). It is a
reading, not a contract and not a bound. It was taken on 2026-10-12, on Windows 11 (10.0.26300)
with CPython 3.14.6, at engine ``main`` ``cb2dca6be6``. The processor was an Intel64 Family 6
Model 198 with 20 logical CPUs, and other work was running on the machine. An audit hook cannot
be removed, so each reading came from a child process of its own.

- *Count.* One child ran a ``RegistryRunner`` on a SQLite store with one feed: MLLP inbound,
  router, handler, MLLP outbound, cleartext, with logging at INFO. It added an audit hook that
  only counts events by name. Another process sent synthetic ADT messages, on one connection
  for each batch, and ACKed each delivery. After 200 warm-up messages, 5 idle seconds raised no event. Then 500
  messages raised 502 events: 501 ``socket.__new__`` and one thread start. 2,000 more raised
  2,001, all ``socket.__new__``. That is about one audited operation for each message. It fits
  the MLLP outbound's default of a new connection for each message, though no event was traced
  to that code. Each batch arrived on a new sender connection, which may be its one extra socket.
- *Time.* Four more children, two for each arm, timed ``sys.audit`` for an event this hook does
  not match. Each ran 9 rounds of 2,000,000 calls, so each arm has 18. With no audit hook the median was 36 ns a call (30 to 52).
  With this hook, installed as the command line installs it, it was 110 ns (91 to 133). The
  medians differ by 74 ns. An earlier reading, taken when the hook was written, was 60 to 90 ns.

So on that feed, on Windows, the hook cost about 74 ns for each message. That figure is the two
readings multiplied, not a timed message. The count belongs to that operating system as well as
that feed: asyncio connects another way on Linux, and may raise more events there for the same
message. Not measured: at least Linux, a File connection, a TLS hop, a peer given by name, a
persistent MLLP outbound and a DEBUG log level. Start-up and API requests were not measured
either.

No engine state. It imports the standard library and ``messagefoundry.controlchars``, which
imports only the standard library, so any package may import it.
"""

from __future__ import annotations

import contextlib
import logging
import os
import queue
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from messagefoundry.controlchars import scrub_log_argument

__all__ = [
    "REMOTE_DEBUG_ACCEPTANCE",
    "REMOTE_DEBUG_ACCEPTANCE_LOOSENING",
    "REMOTE_SCRIPT_EVENT",
    "RemoteDebugPosture",
    "RemoteScriptRefused",
    "install_remote_debug_guard",
    "remote_debug_loosening",
    "remote_debug_posture",
    "remote_debug_refusal",
]

#: The named acceptance that lifts :func:`remote_debug_refusal` under ``enforce`` (owner ruling
#: 2026-10-16, vault BACKLOG #2700). One spelling, for the refusal and the docs.
REMOTE_DEBUG_ACCEPTANCE: Final = "[security].allow_remote_debugging"

#: The loosening entry for that acceptance, while it is set: one wording for
#: ``security_loosenings()`` and the ``supervise`` start-up line.
REMOTE_DEBUG_ACCEPTANCE_LOOSENING: Final = (
    "allow_remote_debugging",
    "serve and supervise may start under enforcement = enforce with the interpreter's remote "
    "debugging (PEP 768) enabled in their process -- the start-up refusal is acknowledged away "
    "wherever it would fire. Whether the interface is on in this process is the "
    "remote_debug_enabled or remote_debug_unguarded entry",
)

#: The audit event the target interpreter raises before it runs an injected script. Its one
#: argument is the script's path.
REMOTE_SCRIPT_EVENT: Final = "cpython.remote_debugger_script"

#: Raised by :func:`_probe` to ask whether the hook is in the interpreter's hook list.
#: The interpreter has no call that lists audit hooks, and it drops a new hook without an error
#: when one already installed objects, so asking is the only way to know.
_PROBE_EVENT: Final = "messagefoundry.remotedebug.probe"

#: The injecting process chooses the script's name, so the logged copy is bounded: the hook keeps
#: this many characters of it. :func:`_ascii` then spells each one in up to ten characters, and
#: the spelling is logged whole, so it can be read back.
_FILE_NAME_LIMIT: Final = 120

#: Refusals waiting for the reporter thread. Past this the refusal is still counted and still
#: refused; only its log line is dropped, so a caller that repeats cannot grow the queue.
_REPORT_BACKLOG: Final = 64

_log = logging.getLogger(__name__)
_install_lock = threading.Lock()
_reports: queue.SimpleQueue[str] = queue.SimpleQueue()
_refused = 0
_reporter_started = False


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


def _ascii(name: str) -> str:
    """``name`` in printable ASCII: the standard ``unicode_escape`` spelling, which escapes every
    character outside ASCII, every control character and the backslash itself.

    The injecting process chooses the name, and a log sink encodes what it is given. Measured on
    the three sinks ``configure_logging`` builds (vault BACKLOG #2742): a lone surrogate fails the
    write on the ``[logging].file`` sink and on the syslog forwarder, which both encode UTF-8, so
    the refusal line reaches neither. Standard output keeps the line only where ``main()`` has
    set the stream to replace what it cannot encode, and it then shows ``?`` for the character.
    An ASCII line is written whole by all three, whatever each one's encoding.

    The spelling can be read back with the same codec. The backslash is escaped too, so a file
    named with the six characters of an escape is not logged the same as the character that
    escape stands for.

    This covers this module's one line. A lone surrogate in any other log line failed the same two
    sinks the same way until vault BACKLOG #2815; the handlers' log escape now writes it as the
    text ``\\\\udcff`` (vault BACKLOG #3012), unlike this function's ``\\udcff``. A printable
    character a sink cannot encode is not in that escape's alphabet, so this function is still
    what keeps such a name on a strict standard output.
    """
    return name.encode("unicode_escape").decode("ascii")


def _report(name: str) -> None:
    # Scrubbed here as well as by the handlers: the injecting process chooses the name, it may
    # hold a line break, and a handler with no filter chain would write it as it came. `_ascii`
    # has escaped the line break already; the scrub stays as the step CodeQL's log-injection
    # query recognises.
    _log.warning(
        "refused a script that another process injected through the interpreter's remote "
        "debugging (audit event %s, script file name %s). Nothing in it ran.",
        REMOTE_SCRIPT_EVENT,
        scrub_log_argument(_ascii(name)),
    )


def _report_refusals() -> None:
    """Write one WARNING for each refused script, off the thread the hook interrupted."""
    while True:
        name = _reports.get()
        # never-raise: this is the only reporter, and nothing restarts it. If the log call itself
        # fails there is no log to say so in. The refusal is already counted, and the posture
        # reading carries the count.
        with contextlib.suppress(Exception):
            _report(name)


def _start_reporter() -> None:
    threading.Thread(target=_report_refusals, name="mefor-remote-debug-report", daemon=True).start()


def _ensure_reporter() -> None:
    """Start the reporter thread, unless an earlier call did. Called with the install lock held."""
    global _reporter_started
    if _reporter_started:
        return
    # never-raise: the interpreter cannot always start a thread (a thread or process limit). The
    # command line makes the install call at import, where an exception would end every command
    # before it could report anything. The hook is in and refuses either way. Without the
    # reporter a refusal is counted and not logged, and the next install call tries again.
    with contextlib.suppress(RuntimeError):
        _start_reporter()
        _reporter_started = True


def _without_own_refusals(
    previous: Callable[[sys.UnraisableHookArgs], object],
) -> Callable[[sys.UnraisableHookArgs], None]:
    """An unraisable hook that drops the interpreter's report of :class:`RemoteScriptRefused` and
    hands everything else to ``previous``. The module docstring says why."""

    def hook(unraisable: sys.UnraisableHookArgs) -> None:
        if isinstance(unraisable.exc_value, RemoteScriptRefused):
            return
        previous(unraisable)

    return hook


def _probe() -> bool | None:
    """Ask the hook whether it is in the interpreter's hook list.

    True: it answered. False: the probe passed every hook and none answered, so it is not in the
    list. None: a hook raised before the probe reached this one, so the list cannot be read (vault
    BACKLOG #3463). The interpreter calls hooks in the order they were added and stops at the
    first that raises, so only an earlier hook can cut the probe off."""
    answer: list[bool] = []
    # never-raise: another audit hook may raise on an event it does not know. That must not stop
    # `serve` at its first statement or fail the posture route.
    try:
        sys.audit(_PROBE_EVENT, answer)
    except Exception:
        return True if answer else None
    return bool(answer)


def _guard_answers() -> bool:
    """Whether the hook answered. A probe another hook cut off reads as not installed."""
    return _probe() is True


def install_remote_debug_guard() -> None:
    """Add the hook to this process when the interpreter accepts injected scripts and the hook
    does not answer a probe. Behind a hook that cuts the probe off, every call adds a copy.

    Call it as early in the process as possible: a script injected before the call runs. A later
    call adds nothing once the hook answers, and an audit hook cannot be removed. Each call starts
    the reporter thread if no earlier call managed to.

    A hook that another hook refused, and a reporter thread the interpreter could not start, do
    not raise here. The command line makes this call at import, ahead of everything that could
    report a failure, so a hook that did not go in is left for :func:`remote_debug_posture` to
    report.

    Nothing is added where ``sys.is_remote_debug_enabled()`` is False, which is every child started
    through :func:`messagefoundry.childenv.python_child_argv`. The event cannot fire there.

    The probe after the add reads one of three ways (vault BACKLOG #3463), and the install acts on
    what each one proves:

    - It answered: the hook is in. Later calls find it answering and add nothing.
    - It passed every hook unanswered (False): the hook is not in the list, for example because
      an audit hook added earlier raised on ``sys.addaudithook`` and the interpreter dropped the
      new hook without an error. The quiet wrapper this call put on ``sys.unraisablehook`` comes
      off, this call starts no reporter, and the next call tries again. Nothing can stack, because
      the hook is not in the list. A wrapper and a reporter an earlier cut-off call left stay.
    - An earlier hook raised on the probe event and cut it off (None). The hook may be in behind
      it, refusing, or that hook may also have refused the add. The quiet wrapper and the reporter
      stay, so a refusal is logged and its full path is kept off standard error. The posture reads
      the hook as missing.

    Any call whose first probe does not read True adds the hook, whatever an earlier call read.
    That keeps the retry for an earlier hook that cuts the probe off and refused the add at
    import, but no longer refuses it by the time ``serve`` or ``supervise`` makes its own call.
    The cost is a copy that may stack where the first add did go in behind a cut-off probe: one
    per call made while the probe stays cut off, and nothing else bounds them. ``serve`` and
    ``supervise`` make at least two calls, at import and then first in ``_serve`` or
    ``_supervise``; other subcommands make the import's call. Under
    ``python -m``, a later import of the command-line module runs the import-time call again, as
    ``api/tls.py`` does when it writes a key. A stacked copy changes no count: the first copy
    raises on ``cpython.remote_debugger_script``, and the interpreter stops at the first hook
    that raises, so a later copy never sees the event. Each copy does run on every other audited
    event, so the per-event cost the module docstring measures is paid once per copy, and each
    call that adds also wraps ``sys.unraisablehook`` once more.

    Where ``sys.addaudithook`` raised instead of returning, the hook is not in, so the quiet
    wrapper is put back and the next call tries again. Nothing is logged there: the command line
    makes this call before logging is configured, and the posture reports the missing hook.

    One refusal is out of reach in any state. An audit hook added earlier that raises on
    ``cpython.remote_debugger_script`` refuses the script before the interpreter calls this
    module's hook. The script does not run, but this module's count, WARNING and audit row never
    hear of it. The interpreter's report on standard error, with the script's full path, is then
    the only trace of the refusal. It carries the other hook's exception, so the quiet wrapper
    passes it on rather than hide the one record that exists.
    """
    if not sys.is_remote_debug_enabled():
        return
    with _install_lock:
        # A cut-off probe adds too: the docstring says why, and what can stack.
        if not _guard_answers():
            # Quiet first, so no refusal is ever reported with its full path.
            previous = sys.unraisablehook
            quiet = sys.unraisablehook = _without_own_refusals(previous)
            # never-raise: a hook already installed may object to this one. The documented
            # contract is that the interpreter swallows a RuntimeError from it and passes on any
            # other exception. Measured on CPython 3.14.6 it swallows a ValueError too, so this
            # holds the line for an interpreter that does what the documentation says. A
            # BaseException such as KeyboardInterrupt still leaves, with the wrapper put back.
            try:
                sys.addaudithook(_guard)
            except BaseException as exc:
                if sys.unraisablehook is quiet:
                    sys.unraisablehook = previous
                if isinstance(exc, Exception):
                    return
                raise
            if _probe() is False:
                # Dropped: there is nothing to report for, and nothing to quiet.
                if sys.unraisablehook is quiet:
                    sys.unraisablehook = previous
                return
        _ensure_reporter()


def remote_debug_posture() -> RemoteDebugPosture:
    """The reading for THIS process. It says nothing about any other process."""
    return RemoteDebugPosture(
        interpreter_enabled=sys.is_remote_debug_enabled(),
        guard_installed=_guard_answers(),
        refused_scripts=_refused,
    )


def remote_debug_refusal(posture: RemoteDebugPosture) -> str | None:
    """Why ``serve`` and ``supervise`` refuse to start under ``enforce``, or None where the
    interface is off (owner ruling 2026-10-16, vault BACKLOG #2700).

    It reads only ``interpreter_enabled``, the same reading the posture reports. The hook does not
    lift it: the hook closes the interface from the moment it is installed, not before, and not
    against a process that can write this one's memory. The caller decides whether
    :data:`REMOTE_DEBUG_ACCEPTANCE` lifts it."""
    if not posture.interpreter_enabled:
        return None
    return (
        "the interpreter's remote debugging (PEP 768) is enabled in this process, so a process "
        "the operating system lets attach to it could run Python inside the engine. Start the "
        "interpreter as `python -P -X disable-remote-debug -m messagefoundry ...`, where -P keeps "
        "the working directory off the import path; the shipped service launches use -I, which "
        "implies it. A console-script start such as `messagefoundry serve` "
        "cannot pass the option, and takes PYTHON_DISABLE_REMOTE_DEBUG=1 instead, which -I and "
        "-E ignore. To "
        f"accept the interface on, set {REMOTE_DEBUG_ACCEPTANCE} = true, which is reported as a "
        "loosening. See docs/SECURITY-LOOSENING.md"
    )


def remote_debug_loosening(posture: RemoteDebugPosture) -> tuple[str, str] | None:
    """The ``(name, plain-language risk)`` entry for ``posture``, or None where the interface is off.

    One place for the wording, so ``security_loosenings()`` and the ``supervise`` start-up line
    cannot say different things. Two names, because the two states ask for different actions."""
    if not posture.interpreter_enabled:
        return None
    if not posture.guard_installed:
        # A count here says the hook was in at some point, which a hook that never went in cannot
        # produce. It does not say the hook is in now: a process that can write this one's memory
        # can remove it. So the entry still says to read it as missing.
        seen = (
            f" The hook has refused {posture.refused_scripts} since this process started. That "
            "says it was in at some point, not that it still is."
            if posture.refused_scripts
            else ""
        )
        return (
            "remote_debug_unguarded",
            "the interpreter's remote debugging (PEP 768) is enabled in this process and the "
            "engine's refusal hook did NOT answer. Either it is NOT installed (nothing installed "
            "it, or an audit hook added earlier refused it), or an audit hook added earlier stops "
            "it from answering. Read it as not installed: a process the operating system lets "
            "attach to this one, which on Windows includes one running as the same account, "
            "could run Python inside it with sys.remote_exec, with everything it holds (the store "
            f"key, connection secrets, messages in flight).{seen} The `messagefoundry` command "
            "line installs the hook as it starts. Look for what else in the process adds an "
            "audit hook. Start the interpreter with -X disable-remote-debug to turn the "
            "interface off",
        )
    refused = (
        f" It has refused {posture.refused_scripts} since this process started."
        if posture.refused_scripts
        else ""
    )
    return (
        "remote_debug_enabled",
        "the interpreter's remote debugging (PEP 768) is enabled in this process. The engine "
        "refuses a script injected through it once its hook is installed, so this is a "
        f"residual and not an open path.{refused} A script injected earlier in start-up still "
        "runs, and a process that can write into this process's address space can still run "
        "code in it by other means. Start the interpreter with -X disable-remote-debug to turn "
        "the interface off",
    )
