# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared pytest fixtures.

Holds teardown-window logging guards. A background-component logger (the asyncio loop, the aiosqlite
worker, the engine/store/pipeline, the tee relay, uvicorn) can emit a record AFTER pytest has begun
tearing per-test capture down, raising 'I/O operation on closed file' inside logging.Handler.emit. The
fixtures below drop such a late emit at its source and make any straggler fail fast-and-silent.

The related mid-test asyncio<->aiosqlite cross-loop concern is handled in pyproject.toml — not here —
by running tests AND their async fixtures on one shared session loop (asyncio_default_test_loop_scope +
asyncio_default_fixture_loop_scope = "session"), which removes the per-test event-loop churn.
"""

from __future__ import annotations

import atexit
import logging
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.config.settings import INSECURE_CONFIG_SOURCE_ESCAPE_ENV

# ---------------------------------------------------------------------------------------------------
# Per-PROCESS test slot.
#
# A few tests reach machine-GLOBAL resources, so two pytest runs at once trample each other. That used to
# be an edge case; now that every session works in its own worktree, concurrent runs are the NORMAL case.
# Both of these were reproduced, not theorised:
#
#   * tests/test_multishard_smoke.py::_free_window scanned for a free port window from a FIXED floor of
#     20000. Probing alone is a TOCTOU race -- each process probes, each sees the window free, each takes
#     it. Measured: three concurrent processes ALL chose base=20000, and FOUR concurrent runs of that
#     suite produced THREE failures with WinError 10048 (address already in use). With this slot, the
#     same four runs all pass.
#   * tests/test_console_shards.py used a QSettings org of "MEFOR-Test", whose comment claimed it was
#     "in-memory" and touched "no disk". It is not: it writes %APPDATA%\MEFOR-Test\ShardTest.ini, and the
#     fixture .clear()s it -- so a sibling run's settings vanish mid-test.
#
# The colliding actor is the pytest PROCESS, not the worktree (two runs in one checkout collide just as
# hard, and you running the suite while an agent runs it is routine), so the slot is keyed on the process.
# Claiming is an exclusive-create: atomic, and free of the read-modify-write race a shared counter file
# would reintroduce.
#
# It never fails a run. If every slot is taken it falls back to the shared defaults -- the old behaviour,
# no worse.
# ---------------------------------------------------------------------------------------------------

_MAX_SLOTS = 32
_PORTS_PER_SLOT = 1000


def _pid_alive(pid: int) -> bool:
    if sys.platform != "win32":  # pragma: no cover - the CI Linux legs
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    out = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True, check=False
    ).stdout
    return str(pid) in out


def _slot_root() -> Path | None:
    """Machine-global, shared by every worktree of this repo -- the same scope as the collisions."""
    common = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if not common:
        return None
    root = Path(common) / "mefor-coord" / "test-slots"
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return root


def _claim_test_slot() -> int:
    root = _slot_root()
    if root is None:
        return 0
    # Two passes: the first claims, the second retries slots the first pass reaped from dead owners.
    for _ in (0, 1):
        for n in range(_MAX_SLOTS):
            lock = root / f"{n}.lock"
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:  # a crashed run must not hold a slot forever
                    owner = int(lock.read_text().strip() or "0")
                    if owner and not _pid_alive(owner):
                        lock.unlink(missing_ok=True)
                except (OSError, ValueError):
                    pass
                continue
            except OSError:
                return 0
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            atexit.register(lock.unlink, missing_ok=True)
            return n
    return 0  # saturated: fall back to the shared defaults rather than failing the run


_SLOT = _claim_test_slot()
os.environ.setdefault("MEFOR_TEST_SLOT", str(_SLOT))
os.environ.setdefault("MEFOR_TEST_PORT_BASE", str(20000 + _PORTS_PER_SLOT * _SLOT))
os.environ.setdefault("MEFOR_TEST_QSETTINGS_ORG", f"MEFOR-Test-{_SLOT}")


@pytest.fixture(scope="session", autouse=True)
def _allow_insecure_config_source_in_tests() -> Iterator[None]:
    """The suite loads sample/harness configs from the repo checkout, which is intentionally
    user-writable — and on the Windows CI runner the default workspace ACL grants ``BUILTIN\\Users``
    write, so the SEC-003 config-source trust guard would fail-closed on every config load. Set the
    documented dev/test escape (``MEFOR_ALLOW_INSECURE_CONFIG_SOURCE``) so the guard downgrades its
    production refusal to a warning here. Scoped to win32 only: POSIX checkouts aren't group/world-
    writable, so the POSIX refusal tests must keep seeing the escape OFF. The guard's own Windows
    refusal test pins the escape back OFF to assert the fail-closed path. Never set in production."""
    if sys.platform != "win32":
        yield
        return
    prev = os.environ.get(INSECURE_CONFIG_SOURCE_ESCAPE_ENV)
    os.environ[INSECURE_CONFIG_SOURCE_ESCAPE_ENV] = "1"
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, None)
        else:
            os.environ[INSECURE_CONFIG_SOURCE_ESCAPE_ENV] = prev


# Minimal source-logger set: every background-component child reaches one of these by propagation, so
# quiescing these five drops a late teardown-window emit at its source. Chosen from the suite's actual
# late emitters:
#   - "asyncio": the loop itself. asyncio routes loop-teardown faults ("Task was destroyed but it is
#     pending", unhandled callback exceptions via loop.call_exception_handler) through
#     logging.getLogger("asyncio") FROM THE LOOP THREAD during the exact teardown window #17 lives in —
#     the most on-mechanism late emitter, and reachable by NO other parent below (it does not propagate
#     through them).
#   - "aiosqlite": fixed name in aiosqlite/core.py — THE lost-wakeup emitter (worker-thread emits).
#   - "messagefoundry": engine/store/pipeline/transports all use getLogger(__name__); this parent
#     covers every child (incl. messagefoundry.audit) by propagation.
#   - "tee.relay": fixed name in tee/relay.py — the relay behind the historically-flaky test_tee_relay.
#   - "uvicorn": covers uvicorn / uvicorn.error / uvicorn.access (the server-side emits).
# Deliberately excluded (evidence-backed, not oversight): starlette registers no dedicated app logger;
# the harness monitor uses print()/Qt, not stdlib logging; python-hl7's loggers are getLogger(__file__)-
# named (absolute paths, unreachable via getLogger("hl7")) and are a synchronous parse-path concern
# already silenced to CRITICAL by logging_setup.silence_phi_prone_dependency_loggers — none is a
# teardown-window background emitter.
_QUIESCE_TARGETS: tuple[str, ...] = (
    "asyncio",
    "aiosqlite",
    "messagefoundry",
    "tee.relay",
    "uvicorn",
)

# A sentinel level safely above CRITICAL so any late record is below the bar and dropped at the source.
_ABOVE_CRITICAL = logging.CRITICAL + 10


class _Baseline:
    """Snapshot of one target logger's natural (caplog-capturing) configuration.

    Captured once per session BEFORE any quiescing, so setup can restore each test body to the exact
    state caplog-asserting tests expect (e.g. messagefoundry.audit.propagate is True;
    uvicorn.error.handlers == []). We record the raw ``logger.level`` int (NOTSET is ``0``) so restore
    re-applies NOTSET vs an explicit level faithfully.
    """

    __slots__ = ("level", "propagate")

    def __init__(self, logger: logging.Logger) -> None:
        self.level: int = logger.level
        self.propagate: bool = logger.propagate


@pytest.fixture(scope="session", autouse=True)
def _quiesce_baseline() -> Iterator[dict[str, _Baseline]]:
    """Snapshot each target logger's natural config ONCE, before any per-test quiescing runs.

    Session-scoped so the baseline is the loggers' real configured state — not a state already
    perturbed by an earlier test's teardown quiesce. The per-test finalizer restores to this baseline
    at setup (pre-yield) so every test body captures exactly as it would without #17 in play.

    On session teardown it restores the baseline once more, so the final test's teardown-quiesce does
    not leave the targets mutated at process exit (state symmetry; harmless either way as the pytest
    process exits immediately and production loads a fresh interpreter).
    """
    baseline = {name: _Baseline(logging.getLogger(name)) for name in _QUIESCE_TARGETS}
    yield baseline
    _restore_baseline(baseline)


# A sentinel handler so a quiesced logger always has a terminal sink during teardown even if it does
# not propagate — a record that somehow clears the level still lands in a NullHandler (never a closing
# capture stream). We tag instances so setup can remove exactly the ones we added, leaving any
# application-installed handlers alone.
class _QuiesceNullHandler(logging.NullHandler):
    pass


@pytest.fixture(autouse=True)
def _quiesce_background_loggers_at_teardown(
    _quiesce_baseline: dict[str, _Baseline],
) -> Iterator[None]:
    """PRIMARY guard for the teardown-LOGGING race: quiesce background-component loggers in the per-test
    TEARDOWN window. (The mid-test cross-loop concern is handled by the shared session loop in pyproject.)

    This function-scoped autouse fixture is the version-robust hook point (GROUND A): its post-yield
    body runs inside ``LoggingPlugin``'s teardown ``catching_logs`` window — i.e. WHILE pytest's
    capture handlers are attached and BEFORE the capture streams finish closing — without depending on
    fragile relative hookwrapper ordering. It pairs setup-restore with teardown-quiesce atomically, so
    quiescing is ALWAYS undone before the next test body.

    SETUP (pre-yield): restore each target logger to its session baseline — propagate, level, and
    removal of any sentinel NullHandler we added. This guarantees the upcoming test body (and its
    ``caplog.at_level(...)`` assertions) captures normally, because the record must still propagate to
    the root capture handler during the body.

    TEARDOWN (post-yield): quiesce each target — propagate=False, level above CRITICAL, and a sentinel
    NullHandler if absent. A late emit from a background thread is then dropped at the SOURCE logger and
    never reaches a root capture handler on a closing stream, closing the dangerous
    teardown -> next-setup gap that #17 lives in. We do NOT touch pytest's own root handlers (GROUND A
    notes detaching is optional and secondary; several test_logging.py tests assert exact root-handler
    composition), so source-logger quiescing alone carries the fix.
    """
    # SETUP: restore the caplog-capturing baseline before the test body runs.
    _restore_baseline(_quiesce_baseline)
    try:
        yield
    finally:
        # TEARDOWN: drop late emits at the source for the rest of the teardown/next-setup window.
        _quiesce_targets()


def _restore_baseline(baseline: dict[str, _Baseline]) -> None:
    """Return every target logger to its natural, caplog-capturing baseline (pre-yield)."""
    for name, snap in baseline.items():
        logger = logging.getLogger(name)
        logger.propagate = snap.propagate
        logger.setLevel(snap.level)
        # Drop only the sentinel handlers we added during a prior teardown; leave app handlers intact.
        for handler in [h for h in logger.handlers if isinstance(h, _QuiesceNullHandler)]:
            logger.removeHandler(handler)


def _quiesce_targets() -> None:
    """Drop late emits at the source logger during the teardown window (post-yield)."""
    for name in _QUIESCE_TARGETS:
        logger = logging.getLogger(name)
        logger.propagate = False
        logger.setLevel(_ABOVE_CRITICAL)
        if not any(isinstance(h, _QuiesceNullHandler) for h in logger.handlers):
            logger.addHandler(_QuiesceNullHandler())


@pytest.fixture(scope="session", autouse=True)
def _tolerate_logging_on_closed_capture_streams() -> Iterator[None]:
    """SECONDARY backstop for the #17 teardown race — fast-and-silent, not the primary fix.

    Even with source-logger quiescing in place (the primary fix above), a record can in principle reach
    a closed capture stream during the brief teardown window. ``logging.Handler.emit`` then raises
    ``ValueError: I/O operation on closed file`` and routes it to ``Handler.handleError``, which — while
    ``logging.raiseExceptions`` is the default ``True`` — writes a traceback to ``sys.stderr``.
    Background threads can make that error-handling path flood output and wedge the event-loop thread
    *inside the synchronous* ``emit`` (it holds the handler lock) until the per-test ``--timeout`` fires.

    Setting ``logging.raiseExceptions = False`` makes ``handleError`` a no-op, so any straggler fails
    fast and silently instead of flooding / deadlocking. It is the stdlib's documented production-mode
    switch, scoped to the test session only (production keeps the default). This was shipped on its own
    first and did NOT clear the hang (flaked again on PR #396) — hence it is retained only as a
    secondary backstop beneath the teardown-ordering finalizer; the ``pytest-timeout`` watchdog (#375)
    remains the final guard.
    """
    prior_raise = logging.raiseExceptions
    logging.raiseExceptions = False
    try:
        yield
    finally:
        logging.raiseExceptions = prior_raise
