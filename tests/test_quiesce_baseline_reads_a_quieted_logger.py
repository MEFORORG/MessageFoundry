# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine tree's quiesce baseline reads a logger the web console tree quieted as the logger's
natural state (vault BACKLOG #2990 closing step 1; #2987 Part A finding 1).

Each test tree's conftest quiets ``messagefoundry`` at every test's teardown and snapshots a
baseline at its own first test. When a web console test ran first, the engine tree's snapshot held
the quieted state, every later setup put it back, and ``caplog`` lost every engine record. The
review of engine PR 2021 saw it as the revocation guard's ``caplog`` control failing.
``_Baseline`` in ``tests/conftest.py`` now reads a quieted logger as NOTSET and propagating.

Measured 2026-11-05: with that reading disabled, a run of one web console test and then
``test_the_guard_capture_does_not_depend_on_the_root_logger`` fails on that control's ``caplog``
assertion, and with it the run passes, as does the whole web console tree followed by that file.
This pins the reading in process, on the loaded conftest module, rather than in a child pytest,
which took minutes to import both trees on a loaded box. The web console conftest's ``_Baseline``
carries the same reading and is not pinned here."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

_TESTS = Path(__file__).resolve().parent
_ENGINE_CONFTEST = _TESTS / "conftest.py"
_CONSOLE_CONFTEST = (
    _TESTS.parent / "packaging" / "messagefoundry-webconsole" / "tests" / "conftest.py"
)

#: The class name both trees' sentinels share. ``_QuiesceNullHandler.tags`` matches by NAME, so a
#: rename in either conftest would silently stop the reading for the other tree's sentinel.
_SENTINEL = "_QuiesceNullHandler"


@pytest.fixture(scope="module")
def engine_conftest(pytestconfig: pytest.Config) -> ModuleType:
    """The engine tree's conftest as pytest loaded it. Not re-imported: its module body claims a
    test slot, and a bare ``import conftest`` can bind the other tree's file (BACKLOG #1255)."""
    for plugin in pytestconfig.pluginmanager.get_plugins():
        where = getattr(plugin, "__file__", None)
        if isinstance(plugin, ModuleType) and where and Path(where).resolve() == _ENGINE_CONFTEST:
            return plugin
    raise AssertionError(f"{_ENGINE_CONFTEST} is not a loaded plugin")


@pytest.fixture
def logger() -> Iterator[logging.Logger]:
    """A logger of this test's own, so no real target's state is touched."""
    lg = logging.getLogger("mefor_test_2990_quiesce_baseline")
    yield lg
    lg.handlers.clear()
    lg.setLevel(logging.NOTSET)
    lg.propagate = True


#: What the web console conftest's teardown leaves: a sentinel of its own class, of the shared name.
_ConsoleSentinel = type(_SENTINEL, (logging.NullHandler,), {})


def test_both_trees_name_their_sentinel_alike(engine_conftest: ModuleType) -> None:
    assert engine_conftest._QuiesceNullHandler.__name__ == _SENTINEL
    assert f"class {_SENTINEL}(" in _CONSOLE_CONFTEST.read_text(encoding="utf-8")


@pytest.mark.parametrize("left", ["level", "handler", "both"])
def test_a_logger_the_other_tree_quieted_is_read_as_natural(
    engine_conftest: ModuleType, logger: logging.Logger, left: str
) -> None:
    logger.propagate = False
    # The handler-only arm starts from a non-default level, so the level assertion can fail there.
    logger.setLevel(logging.CRITICAL + 10 if left in ("level", "both") else logging.INFO)
    if left in ("handler", "both"):
        logger.addHandler(_ConsoleSentinel())
    baseline = engine_conftest._Baseline(logger)
    assert baseline.level == logging.NOTSET
    assert baseline.propagate is True


def test_a_logger_nobody_quieted_keeps_its_own_state(
    engine_conftest: ModuleType, logger: logging.Logger
) -> None:
    """The CONTROL: the reading keys on the sentinels, so a non-default state with neither is kept."""
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.NullHandler())
    baseline = engine_conftest._Baseline(logger)
    assert baseline.level == logging.INFO
    assert baseline.propagate is False
