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
:func:`install_remote_debug_guard` adds a hook that raises on that event. It raises on one other:
any ``sys.addaudithook`` made on the installing thread while that install adds its own copy.
:func:`remote_debug_posture` reports the interpreter setting and whether the hook answers.
``tests/test_remote_debug_guard.py`` injects into a real child both ways, because the behaviour is
the interpreter's and could change under this module.

**What this is not.** The hook closes the interpreter's own injection interface, from the moment
it is installed. At least two things stay open. A script injected earlier in start-up runs: the
process has to import this module and reach the install call first, and a caller that can restart
the engine can aim for that window. The command line makes the call when
``messagefoundry/__main__.py`` is imported, ahead of that module's other imports and for every
command. What is left is at least the interpreter's own start-up, the package's ``__init__``,
loading that module, and this module's imports ("Start-up cost" below has the reading).
:func:`messagefoundry.api.create_app` makes the same call, for an application that builds the API
without the command line.
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
  The hook has since gained a third test for each event, the one that refuses a second copy
  (vault BACKLOG #3673). It was not timed again in the engine. A stand-in for the hook, timed on
  the same machine on 2026-10-28 in child processes, took about 3 ns more for each event with
  it than without it.

So on that feed, on Windows, the hook cost about 74 ns for each message. That figure is the two
readings multiplied, not a timed message. The count belongs to that operating system as well as
that feed: asyncio connects another way on Linux, and may raise more events there for the same
message. Not measured: at least Linux, a File connection, a TLS hop, a peer given by name, a
persistent MLLP outbound and a DEBUG log level. Start-up and API requests were not measured
either.

**Start-up cost.** Every millisecond spent importing this module is time in which an injected
script still runs, so it imports neither ``logging`` nor ``dataclasses``. In CPython 3.14
``logging`` pulls in ``traceback``, which pulls in ``dataclasses`` and ``inspect``. The reporter
thread imports ``logging`` when it first writes. Measured once on one machine (vault BACKLOG
#3673), on 2026-10-27, on Windows 11 (10.0.26300) with CPython 3.14.6 and other work running:

- *Spawn to hook.* A parent read the clock, started a child, and the child printed the clock
  right after its install call. The median of 21 runs was 64 ms before the cut, and of 41 runs
  43 ms after it. A child that only printed the clock took 22 ms both times.
- *Import time.* ``python -X importtime -c "import messagefoundry.remotedebug"``, six runs each.
  This module's cumulative time went from 41 to 45 ms to 19 to 21 ms. About 9 ms of each is
  the package's ``__init__``, almost all of it ``typing``.

It is a reading, not a bound, and it was not taken on Linux.

No engine state. It imports the standard library and ``messagefoundry.controlchars``, which
imports only the standard library, so any package may import it.
"""

from __future__ import annotations

# No `logging` and no `dataclasses` here: see "Start-up cost" in the module docstring.
import contextlib
import os
import queue
import sys
import threading
from collections.abc import Callable
from typing import Final, NamedTuple

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
#: the spelling is logged whole, so it can be read back. A text line can then reach about 1,400
#: characters, and the forwarder's JSON line about 1,600 bytes. A collector that cuts at the
#: 1,024 bytes RFC 3164 allows cuts into the name. On a text line the refusal and the event name
#: come first and survive; a JSON line is left unterminated, and a parser may drop all of it.
#: Kept as a known limit, since a cut after escaping would let the injecting process choose how
#: little of the name survives (vault BACKLOG #3673, finding 1).
_FILE_NAME_LIMIT: Final = 120

#: Refusals waiting for the reporter thread. Past this the refusal is still counted and still
#: refused; only its log line is dropped, so a caller that repeats cannot grow the queue.
_REPORT_BACKLOG: Final = 64

#: The audit event ``sys.addaudithook`` raises to the hooks already in, before it adds a new one.
#: The interpreter drops the new hook, without an error, when one of them raises an Exception.
_ADD_HOOK_EVENT: Final = "sys.addaudithook"

_install_lock = threading.Lock()
_reports: queue.SimpleQueue[str] = queue.SimpleQueue()
_refused = 0
_reporter_started = False
#: The thread an install is adding the hook on, while that add runs, so a copy already in can
#: refuse it (vault BACKLOG #3673, the Lander's finding 2). None at every other moment.
_adding_on: int | None = None
#: What ``_quiet`` holds before any install wraps. A private object, never None: a process may set
#: ``sys.unraisablehook`` to None, and a None here would then read as a wrapper already in place.
_NOT_WRAPPED: Final = object()
#: The quiet wrapper an install left on ``sys.unraisablehook``. A later install does not wrap
#: again while it is still the hook in place.
_quiet: object = _NOT_WRAPPED


class RemoteScriptRefused(RuntimeError):
    """Raised inside the audit hook, which is what makes the interpreter drop the script."""


class _SecondCopyRefused(RuntimeError):
    """Raised by a copy of the hook already in, on the add of another copy. The interpreter
    swallows it and drops the new copy."""


class RemoteDebugPosture(NamedTuple):
    """What :func:`remote_debug_posture` read from this process. A named tuple rather than a
    dataclass, for the start-up cost the module docstring measures."""

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
    # A copy already in refuses the next one, whatever the probe could read. The event names no
    # hook, so this refuses every add on the installing thread while the install adds. The thread
    # check keeps an unrelated hook added by another thread meanwhile from being refused. The None test
    # comes first because it is the cheapest, and the marker is None outside an install.
    if _adding_on is not None and event == _ADD_HOOK_EVENT and _adding_on == threading.get_ident():
        raise _SecondCopyRefused("the remote-debugging hook is already in this process")


def _ascii(name: str) -> str:
    """``name`` in printable ASCII, spelled by the standard ``unicode_escape`` codec. It escapes
    every character outside ASCII, every control character and the backslash itself.

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
    # query recognises. Imported here, on the reporter thread, to keep it out of start-up.
    import logging

    logging.getLogger(__name__).warning(
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


def _after_fork_in_child() -> None:
    """Give a forked child its own reporter (vault BACKLOG #3673, defect 2).

    The child keeps the hook, the flag and the queue, but not the reporter thread: fork copies
    only the thread that called it. Without this a refusal in the child is counted and never
    logged, because the inherited flag stops every later call from starting a reporter. The lock
    is new because a thread that no longer exists may have held it at the fork. The queue is new
    because the parent's reporter logs what was queued before the fork. The count starts again
    because it is this process's, and the child's refusal watch would otherwise report the
    parent's refusals as its own.

    The child keeps the hook list and ``sys.unraisablehook`` too, so the copy and the quiet
    wrapper it inherited still stop a later install from adding another (vault BACKLOG #3673, the
    Lander's finding 2). Only the marker of an add in progress is cleared: the thread that set it
    does not exist in the child."""
    global _adding_on, _install_lock, _refused, _reports, _reporter_started
    _install_lock = threading.Lock()
    _adding_on = None
    _reports = queue.SimpleQueue()
    _refused = 0
    if _reporter_started:
        _reporter_started = False
        with _install_lock:
            _ensure_reporter()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


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
    does not answer a probe. Repeated calls add no second copy and no second quiet wrapper,
    whatever the probe reads (vault BACKLOG #3673, the Lander's finding 2).

    Call it as early in the process as possible: a script injected before the call runs. A later
    call adds nothing once the hook answers, and an audit hook cannot be removed. Each call starts
    the reporter thread if no earlier call managed to.

    A hook that another hook refused, and a reporter thread the interpreter could not start, do
    not raise here. The command line makes this call at import, ahead of everything that could
    report a failure. So a hook that did not go in is left for :func:`remote_debug_posture` to
    report.

    Nothing is added where ``sys.is_remote_debug_enabled()`` is False, which is every child started
    through :func:`messagefoundry.childenv.python_child_argv`. The event cannot fire there.

    The probe after the add reads one of three ways (vault BACKLOG #3463), and the install acts on
    what each one proves:

    - It answered: the hook is in. Later calls find it answering and add nothing.
    - It passed every hook unanswered (False): the hook is not in the list, for example because
      an audit hook added earlier raised on ``sys.addaudithook`` and the interpreter dropped the
      new hook without an error. The quiet wrapper this call put on ``sys.unraisablehook`` comes
      off, this call starts no reporter, and the next call tries again. A wrapper and a reporter
      an earlier cut-off call left stay.
    - An earlier hook raised on the probe event and cut it off (None). The hook may be in behind
      it, refusing, or that hook may also have refused the add. The quiet wrapper and the reporter
      stay, so a refusal is logged and its full path is kept off standard error. The posture reads
      the hook as missing.

    Any call whose first probe does not read True tries the add, whatever an earlier call read.
    That keeps the retry for an earlier hook that cuts the probe off and refused the add at
    import, but no longer refuses it by the time ``serve`` or ``supervise`` makes its own call.
    The retry cannot stack a copy. Before it adds a hook, the interpreter raises
    ``sys.addaudithook`` to every hook already in. It drops the new hook when any of them raises.
    A copy already in raises there while this call's add runs, on this call's thread only. So the
    add goes in only where no copy saw that event. Either none is in, or a hook ahead of it raised
    and dropped the add anyway. The event names no hook, so a wrapper around
    ``sys.addaudithook`` that adds a hook of its own inside this call's add is refused as well.

    The bound holds for one module object. A process that removes this module from
    ``sys.modules`` and imports it again gets a second set of state. A copy from the first import
    never refuses an add the second one makes.

    The quiet wrapper goes on only where the hook in place is not the one an earlier call left.
    So calls made while the probe stays cut off add no wrapper either. Code that replaces
    ``sys.unraisablehook`` after an install gets one more wrapper from the next call, not one per
    call.

    Where ``sys.addaudithook`` raised instead of returning, the hook is not in. The wrapper this
    call put on comes off, one an earlier call left stays, and the next call tries again. Nothing is logged there: the command line
    makes this call before logging is configured, and the posture reports the missing hook.

    One refusal is out of reach in any state. An audit hook added earlier that raises on
    ``cpython.remote_debugger_script`` refuses the script before the interpreter calls this
    module's hook. The script does not run, but this module's count, WARNING and audit row never
    hear of it. The interpreter's report on standard error, with the script's full path, is then
    the only trace of the refusal. It carries the other hook's exception, so the quiet wrapper
    passes it on rather than hide the one record that exists.
    """
    global _adding_on, _quiet
    if not sys.is_remote_debug_enabled():
        return
    with _install_lock:
        # A cut-off probe tries the add too; a copy already in refuses it. The docstring says why.
        if not _guard_answers():
            # Quiet first, so no refusal is ever reported with its full path. Only once: a wrapper
            # an earlier call left in place is still the one.
            previous = sys.unraisablehook
            if previous is not _quiet:
                _quiet = sys.unraisablehook = _without_own_refusals(previous)
            # never-raise: a hook already installed may object to this one. The documented
            # contract is that the interpreter swallows a RuntimeError from it and passes on any
            # other exception. Measured on CPython 3.14.6, it swallows a ValueError and an
            # Exception subclass of its own too. So this catch matters only on an interpreter that
            # does what the documentation says. A BaseException such as KeyboardInterrupt still
            # leaves, with the wrapper put back. The marker is set inside the try, so an exception
            # that lands right after it is set still meets the finally that clears it.
            try:
                _adding_on = threading.get_ident()
                sys.addaudithook(_guard)
            except BaseException as exc:
                # A wrapper an earlier call left is `previous` too, so this leaves it in place.
                if sys.unraisablehook is _quiet:
                    sys.unraisablehook = previous
                if isinstance(exc, Exception):
                    return
                raise
            finally:
                _adding_on = None
            if _probe() is False:
                # Dropped: there is nothing to report for, and nothing to quiet.
                if sys.unraisablehook is _quiet:
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
            "line installs the hook as it starts, and so does building the API app. Look for "
            "what else in the process adds an "
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
