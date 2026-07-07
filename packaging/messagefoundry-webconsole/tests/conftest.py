# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared /ui fixtures for the web console's OWN test suite (Option B, ADR 0065).

This package is separately versioned and tested (its own ``[tool.pytest.ini_options]`` in the
adjacent ``pyproject.toml`` — ``asyncio_mode="auto"`` + session loop scopes + timeout addopts), so it
does NOT inherit the engine's ``tests/conftest.py``. The two pieces of that conftest the relocated
/ui tests genuinely depend on are reproduced here:

* the win32 config-source escape (``MEFOR_ALLOW_INSECURE_CONFIG_SOURCE``) — the ASGI serve/reload
  tests load ``samples/config`` from the user-writable checkout, which the SEC-003 trust guard would
  otherwise fail-closed on the Windows CI runner; and
* the teardown-window logging guards (BACKLOG #17) — an ASGI/engine background logger can emit AFTER
  pytest starts closing per-test capture, raising 'I/O operation on closed file' inside
  ``logging.Handler.emit``; these drop such a late emit at its source and make a straggler fail
  fast-and-silent.

The shared ``engine`` fixture (moved out of ``test_webui.py`` so the golden-surface tests can build
an app too) lives here as well. The mid-test asyncio<->aiosqlite cross-loop concern is handled by the
session loop scopes in ``pyproject.toml`` — not here.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

from messagefoundry.config.settings import INSECURE_CONFIG_SOURCE_ESCAPE_ENV
from messagefoundry.pipeline import Engine


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    """A throwaway engine on a per-test store — the workhorse behind every ASGI /ui test and the
    golden-surface app builder (moved from ``test_webui.py`` so it is shared across the suite)."""
    eng = await Engine.create(tmp_path / "webui.db", poll_interval=0.02)
    yield eng
    await eng.stop()


@pytest.fixture(scope="session", autouse=True)
def _allow_insecure_config_source_in_tests() -> Iterator[None]:
    """The suite loads sample/harness configs from the repo checkout, which is intentionally
    user-writable — and on the Windows CI runner the default workspace ACL grants ``BUILTIN\\Users``
    write, so the SEC-003 config-source trust guard would fail-closed on every config load. Set the
    documented dev/test escape (``MEFOR_ALLOW_INSECURE_CONFIG_SOURCE``) so the guard downgrades its
    production refusal to a warning here. Scoped to win32 only: POSIX checkouts aren't group/world-
    writable, so the POSIX refusal keeps seeing the escape OFF. Never set in production."""
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
# quiescing these drops a late teardown-window emit at its source (see the engine conftest for the
# full rationale — "asyncio"/"aiosqlite" are the on-mechanism late emitters, "messagefoundry"/
# "uvicorn" cover the engine + server side by propagation).
_QUIESCE_TARGETS: tuple[str, ...] = (
    "asyncio",
    "aiosqlite",
    "messagefoundry",
    "uvicorn",
)

# A sentinel level safely above CRITICAL so any late record is below the bar and dropped at the source.
_ABOVE_CRITICAL = logging.CRITICAL + 10


class _Baseline:
    """Snapshot of one target logger's natural (caplog-capturing) configuration, captured once per
    session BEFORE any quiescing so setup can restore each test body to the state caplog-asserting
    tests expect. The raw ``logger.level`` int (NOTSET is ``0``) is recorded so restore re-applies
    NOTSET vs an explicit level faithfully."""

    __slots__ = ("level", "propagate")

    def __init__(self, logger: logging.Logger) -> None:
        self.level: int = logger.level
        self.propagate: bool = logger.propagate


@pytest.fixture(scope="session", autouse=True)
def _quiesce_baseline() -> Iterator[dict[str, _Baseline]]:
    """Snapshot each target logger's natural config ONCE, before any per-test quiescing runs."""
    baseline = {name: _Baseline(logging.getLogger(name)) for name in _QUIESCE_TARGETS}
    yield baseline
    _restore_baseline(baseline)


class _QuiesceNullHandler(logging.NullHandler):
    """A sentinel terminal sink so a quiesced logger always has somewhere to land a record during
    teardown even if it does not propagate — tagged so setup removes exactly the ones we added."""


@pytest.fixture(autouse=True)
def _quiesce_background_loggers_at_teardown(
    _quiesce_baseline: dict[str, _Baseline],
) -> Iterator[None]:
    """PRIMARY guard for the teardown-LOGGING race (BACKLOG #17): restore the caplog-capturing
    baseline before the test body (so ``caplog`` assertions capture normally), then quiesce every
    target in the teardown window so a late background emit is dropped at its source and never reaches
    a root capture handler on a closing stream."""
    _restore_baseline(_quiesce_baseline)
    try:
        yield
    finally:
        _quiesce_targets()


def _restore_baseline(baseline: dict[str, _Baseline]) -> None:
    """Return every target logger to its natural, caplog-capturing baseline (pre-yield)."""
    for name, snap in baseline.items():
        logger = logging.getLogger(name)
        logger.propagate = snap.propagate
        logger.setLevel(snap.level)
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
    """SECONDARY backstop for the #17 teardown race: ``logging.raiseExceptions = False`` makes
    ``Handler.handleError`` a no-op, so a straggler that still reaches a closed capture stream fails
    fast-and-silent instead of flooding stderr / wedging the loop thread inside ``emit``. Scoped to
    the test session only (production keeps the stdlib default)."""
    prior_raise = logging.raiseExceptions
    logging.raiseExceptions = False
    try:
        yield
    finally:
        logging.raiseExceptions = prior_raise
