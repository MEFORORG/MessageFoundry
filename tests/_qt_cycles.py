# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Find Qt objects that only the cyclic garbage collector can free, and free them here.

Why this matters: a Qt object that sits in a Python reference cycle is destroyed whenever the cyclic
collector next runs, on WHICHEVER Python thread happens to trigger it -- an asyncio executor thread, a
socket accept loop, a ``QThreadPool`` worker. Destroyed off the GUI thread, a widget cannot unregister
its still-armed timers (``QBasicTimer::stop`` asks the CURRENT thread's event dispatcher, and that
thread has none), so the timers stay registered with the GUI thread's dispatcher and point at freed
memory. The next ``processEvents()`` anywhere in the process then fires one into the freed object and
the process dies in ``QCoreApplication::notifyInternal2`` under ``QTimerInfoList::activateTimers``.
Under ``pytest --dist loadfile`` that lands in whichever later test file happens to share the worker,
so the crash moves with test ordering and never names the file that leaked.
"""

from __future__ import annotations

import gc


def collect_qobjects_in_cycles() -> list[str]:
    """Run a full collection, return the class names of live Qt objects it found only in cycles, and
    free them. Call on the GUI thread: the collection destroys the objects on the calling thread, so a
    leaked object that was moved to a still-running worker ``QThread`` can still abort here."""
    import shiboken6
    from PySide6.QtCore import QObject

    flags = gc.get_debug()
    already_saved = len(gc.garbage)
    gc.set_debug(flags | gc.DEBUG_SAVEALL)
    try:
        gc.collect()
    finally:
        gc.set_debug(flags)
    try:
        found = sorted(
            {
                type(obj).__qualname__
                for obj in gc.garbage[already_saved:]
                # ``type()`` rather than ``isinstance``: it neither follows a mock's spec through
                # ``__class__`` nor dereferences a dead ``weakref.proxy``. A wrapper whose C++
                # object is already gone (its parent deleted it) frees nothing in Qt.
                if issubclass(type(obj), QObject) and shiboken6.isValid(obj)
            }
        )
    finally:
        del gc.garbage[already_saved:]
        gc.collect()  # now actually free them, on this thread, even if the scan above raised
    return found
