# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The conftest guard that fails a module leaving a Qt object in a reference cycle.

A test that left a harness panel in a cycle let the cyclic collector destroy it later on a non-GUI
thread; its armed timers stayed registered and a later file's ``processEvents()`` segfaulted
(``tests/_qt_cycles.py``). These pin that the detector sees such an object, ignores one freed by
reference counting, and reports the shape that crashed.
"""

from __future__ import annotations

import gc
from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("PySide6")

from tests._qt_cycles import collect_qobjects_in_cycles  # noqa: E402


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _no_automatic_collection() -> Iterator[None]:
    """An automatic collection between dropping a cycle and checking for it would free it first and
    flake the positive controls, so they do not lean on the conftest guard to turn it off."""
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def test_a_qobject_in_a_cycle_is_reported_and_freed(qapp: Any) -> None:
    from PySide6.QtCore import QObject

    class _Cyclic(QObject):
        pass

    obj = _Cyclic()
    obj.me = obj  # type: ignore[attr-defined]
    del obj
    assert collect_qobjects_in_cycles() == [
        "test_a_qobject_in_a_cycle_is_reported_and_freed.<locals>._Cyclic"
    ]
    assert collect_qobjects_in_cycles() == []  # the first call freed it


def test_a_qobject_freed_by_refcount_is_not_reported(qapp: Any) -> None:
    from PySide6.QtCore import QObject

    obj = QObject()
    del obj
    assert collect_qobjects_in_cycles() == []


def test_the_panel_shape_that_crashed_a_later_file_is_reported(qapp: Any) -> None:
    """The leak that segfaulted ``tests/test_harness.py`` on CI: a stub ``submit`` on the panel's own
    runner, closing over a list that collects closures over the panel. The panel's tables had armed
    timers, and only the cyclic collector could free it."""
    from harness._console_widgets import MessageDetailPanel

    def leave_it_in_a_cycle() -> None:
        # Returning drops the locals but not the cells the stub closes over; a ``del`` here would
        # empty those cells and break the very cycle under test.
        panel = MessageDetailPanel(object())  # type: ignore[arg-type]
        submitted: list[Any] = []
        panel._runner.submit = lambda fn, **_kw: submitted.append(fn)  # type: ignore[method-assign]
        panel._runner.submit(panel.clear, on_done=print)  # a bound method: the list holds the panel
        panel.stop()

    leave_it_in_a_cycle()
    assert "MessageDetailPanel" in collect_qobjects_in_cycles()
