# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared pytest fixtures.

Holds the secondary teardown-logging guards for BACKLOG #17. The #17 ROOT cause — a mid-test
asyncio<->aiosqlite cross-loop lost wakeup from per-test event-loop churn — is fixed in pyproject.toml
by running tests AND their async fixtures on one shared session loop (asyncio_default_test_loop_scope +
asyncio_default_fixture_loop_scope = "session"); these fixtures address a distinct manifestation only.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Iterator

import pytest

# --------------------------------------------------------------------------------------------------
# BACKLOG #17 — the py3.11 pytest hang. SCOPE OF THIS FILE (after CI falsified the simple fixes,
# 2026-06-19; full history in docs/BACKLOG.md §17):
#
# The CORE py3.11 hang is a MID-TEST asyncio<->aiosqlite CROSS-LOOP lost wakeup: under pytest's
# per-test event-loop churn, a completed aiosqlite query's result is delivered to a different loop than
# the one awaiting it, so a coroutine awaiting a DB op hangs in `run_until_complete -> _run_once ->
# selector.select()` (proven by two CI thread dumps on PR #409 — the aiosqlite worker idle in
# `tx.get()`, the loop idle in the selector). It does NOT reproduce on py3.13, and the production store
# soak (one long-lived loop, no pytest) is clean, so it is a TEST-HARNESS fault, not a product bug.
# That core hang is ADDRESSED in pyproject.toml, not here: the suite runs on ONE shared session loop
# (asyncio_default_test_loop_scope + asyncio_default_fixture_loop_scope = "session"), so tests and their
# async fixtures share a loop and the per-test churn that delivered an aiosqlite result cross-loop is
# gone. (Earlier in-conftest attempts — a teardown-ordering finalizer and a bounded-selector loop
# self-wake — were each CI-falsified: the self-wake's clamp was active in the dump yet it still hung,
# confirming cross-loop delivery, not a recoverable lost selector wake. Removing the *churn* closes it.)
#
# DO NOT add a per-test `loop_scope="function"` exemption (e.g. via pytest_collection_modifyitems for
# test_api_reload::test_reload_endpoint_applies_config). Under the shared session loop that test passes
# on its own; forcing it back onto a fresh function loop while its fixtures stay on the session loop
# REINTRODUCES the cross-loop split — which only *looks* fine on py3.13 (it tolerates cross-loop
# aiosqlite) and would hang again on py3.11. The whole point is one loop for tests and fixtures alike.
#
# What the fixtures below DO fix is a DISTINCT, real manifestation: a late log emit into a CLOSING
# capture stream at teardown. A background-component logger (the asyncio loop, the aiosqlite worker, the
# engine/store/pipeline, the tee relay, uvicorn) can emit a record AFTER pytest has begun tearing
# per-test capture down; it propagates to a StreamHandler over capture-swapped sys.stdout/stderr (a
# per-item temp file closed at the item boundary), and 'ValueError: I/O operation on closed file' is
# raised INSIDE the synchronous logging.Handler.emit (which holds the per-handler lock) — under py3.11 +
# background threads that can flood/wedge. The PRIMARY guard (_quiesce_background_loggers_at_teardown)
# drops such a late emit at its SOURCE logger during the teardown window so it never reaches the closing
# handler; the SECONDARY backstop (_tolerate_logging_on_closed_capture_streams) makes any straggler fail
# fast-and-silent. Both are scoped to the pytest session only; production logging is untouched. This
# removes the LOGGING vector of #17 (a genuine CI-noise improvement) but is NOT a claim the hang is gone.
#
# RESIDUAL STATUS (Lane X.2, 2026-06-19). The shared session loop + the logging finalizer REDUCED but did
# not provably ELIMINATE the intermittent py3.11 wedge, and it cannot be settled from here: it reproduces
# only on a real py3.11 box (this dev/CI box that runs the suite green is py3.13, which tolerates the
# cross-loop delivery py3.11 deadlocks on). So `test (ubuntu-latest, py3.11)` stays **ADVISORY**, not a
# required gate: the required coverage is py3.13 x {ubuntu, win-2022, win-2025}, and the production-path
# `py311-store-soak` CI job (one long-lived loop, no pytest — clean on py3.11) is the meanwhile regression
# guard. The CI marker that encodes "advisory" lives in `.github/workflows/ci.yml` (`continue-on-error` on
# the py3.11 leg), NOT here, and the leg is re-promoted to required ONLY once it is provably green across
# repeated runs on a real py3.11 env — never flipped blind. The `pytest_collection_modifyitems` lever just
# below is the conftest half of the residual fix: an OFF-BY-DEFAULT, py3.11-only quarantine of the modules
# with hard evidence of wedging, for use when the advisory `continue-on-error` is eventually removed (so a
# known-flaky module can still be deselected on py3.11 without editing the test bodies — scope is conftest
# + CI config only). It is off by default precisely so a real-py3.11-box validation run exercises the full
# suite and proves whether the residual is gone.
# --------------------------------------------------------------------------------------------------

# Modules with HARD evidence (the two PR #409 CI thread dumps; BACKLOG #17 (2)(3)) of wedging the py3.11
# `test` leg on the aiosqlite<->asyncio lost wakeup — the late-emit roamed between these two async,
# store/engine-driven modules. This list is the operator-editable quarantine set: add a file stem here
# only when CI proves another module wedges on py3.11 (do NOT speculatively pad it — over-skipping silently
# erodes py3.11 coverage, and the `continue-on-error` advisory marker already absorbs a roaming wedge).
_PY311_QUARANTINE_MODULES: frozenset[str] = frozenset(
    {
        "test_tee_relay",  # (2) test_capture_corepoint_copy_only — first dump (tee/relay start-banner emit)
        "test_harness_monitor",  # (3) test_monitor_observes_engine — second dump (engine/store late-emit)
    }
)

# Opt-in switch. Unset/anything-but-"1" => this hook is a no-op and the full suite runs (the default
# everywhere, including a real-py3.11 validation run). Set to "1" only on the advisory py3.11 CI leg if
# `continue-on-error` is later dropped and the quarantine is still needed.
_PY311_QUARANTINE_ENV = "MEFOR_PY311_QUARANTINE"


def pytest_report_header(config: pytest.Config) -> list[str] | None:
    """Surface the quarantine state at the top of the run so a green py3.11 leg is never silently partial.

    Reports BEFORE collection (so it lists the static quarantine set, not a post-collection count) and only
    when the lever is actually active — on py3.13 or with the env unset it returns None and adds no noise.
    """
    if sys.version_info < (3, 12) and os.environ.get(_PY311_QUARANTINE_ENV) == "1":
        modules = ", ".join(sorted(_PY311_QUARANTINE_MODULES))
        return [
            f"BACKLOG #17: py3.11 quarantine ACTIVE ({_PY311_QUARANTINE_ENV}=1) — deselecting: {modules}"
        ]
    return None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """OFF-BY-DEFAULT, py3.11-only quarantine lever for BACKLOG #17 (rationale in the top-of-file write-up).

    No-op unless BOTH hold, so it changes nothing on the required py3.13 legs and nothing on a default
    py3.11 run (the validation path): (1) the interpreter is py3.11 (``sys.version_info < (3, 12)``), and
    (2) ``MEFOR_PY311_QUARANTINE=1``. When active it attaches a ``skip`` marker to every collected item
    whose test file stem is in ``_PY311_QUARANTINE_MODULES`` — deselecting the known-wedging modules so the
    advisory leg stays green WITHOUT touching the test bodies (scope = conftest + CI config only). This is
    deliberately NOT a ``loop_scope="function"`` exemption (those reintroduce the cross-loop split — see the
    top-of-file DO-NOT note); a plain skip removes the module from the py3.11 run entirely.
    """
    if sys.version_info >= (3, 12):
        return
    if os.environ.get(_PY311_QUARANTINE_ENV) != "1":
        return
    skip = pytest.mark.skip(
        reason=(
            f"BACKLOG #17 py3.11 aiosqlite<->asyncio lost-wakeup quarantine "
            f"({_PY311_QUARANTINE_ENV}=1; advisory leg only). Unset it to run + validate the residual fix."
        )
    )
    for item in items:
        if item.path.stem in _PY311_QUARANTINE_MODULES:
            item.add_marker(skip)


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
    """PRIMARY guard for the #17 teardown-LOGGING manifestation: quiesce background-component loggers
    in the per-test TEARDOWN window. (This does not fix the core mid-test cross-loop hang — see top.)

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
    ``logging.raiseExceptions`` is the default ``True`` — writes a traceback to ``sys.stderr``. Under
    py3.11 + background threads that error-handling path can flood output and wedge the event-loop
    thread *inside the synchronous* ``emit`` (it holds the handler lock) until the per-test
    ``--timeout`` fires.

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
