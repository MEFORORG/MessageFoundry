# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Off-thread API calls for the console.

The :class:`~messagefoundry.console.client.EngineClient` is synchronous, and calling it on the Qt main
thread freezes the GUI for the duration of the call. That's fine for sub-millisecond loopback reads, but
a **DB-backed read during a failover** (``/cluster/nodes``, ``/status``) can stall for seconds while the
new primary recovers — long enough to lock up the window. :class:`AsyncRunner` runs a blocking callable on
a worker thread and delivers its result (or exception) back to a **main-thread** slot via a queued signal,
so the handler can safely touch widgets. Background work off the main thread + ``Signal``/``Slot`` back is
the PySide6 rule (CLAUDE.md §10).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal


class _CallSignals(QObject):
    """Per-call signals — emitted from the worker thread, delivered (queued) on the main thread."""

    done = Signal(object)
    failed = Signal(object)


class _Call(QRunnable):
    def __init__(self, fn: Callable[[], Any], signals: _CallSignals) -> None:
        super().__init__()
        self._fn = fn
        self._signals = signals

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001 — deliver ANY failure to the main thread, never crash the pool worker
            self._signals.failed.emit(exc)
        else:
            self._signals.done.emit(result)


class AsyncRunner(QObject):
    """Run blocking callables off the Qt main thread; deliver the result/error to main-thread slots.

    ``submit(fn, on_done=…, on_error=…)`` runs ``fn()`` on a :class:`QThreadPool` worker; when it finishes,
    ``on_done(result)`` (or ``on_error(exc)``) fires **on the main thread** so the handler can touch widgets.
    Call :meth:`stop` on window close: after it, late results are dropped (a slow in-flight call can't update
    a torn-down widget) and it waits, bounded, for workers to finish.

    Delivery is via the per-call signals connected to **this** runner's bound-method slots. Because the
    runner is a QObject with main-thread affinity, the cross-thread emit is an AutoConnection that resolves
    to a *queued* connection — so the callbacks run on the main thread. (Connecting to a bare lambda has no
    receiver context and would run on the worker thread, so don't.)
    """

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._pool = QThreadPool(self)
        self._stopped = False
        # Hold each call's signals object (and its callbacks) alive until its slot has run: a queued signal
        # needs its sender to outlive the emit→deliver gap, and the QRunnable is dropped when run() returns.
        self._calls: dict[
            _CallSignals, tuple[Callable[[Any], None], Callable[[BaseException], None] | None]
        ] = {}

    def submit(
        self,
        fn: Callable[[], Any],
        *,
        on_done: Callable[[Any], None],
        on_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        if self._stopped:
            return
        signals = _CallSignals()
        self._calls[signals] = (on_done, on_error)
        signals.done.connect(self._handle_done)
        signals.failed.connect(self._handle_failed)
        self._pool.start(_Call(fn, signals))

    def _take(self) -> tuple[Callable[[Any], None], Callable[[BaseException], None] | None] | None:
        sender = self.sender()
        if not isinstance(sender, _CallSignals):
            return None
        return self._calls.pop(sender, None)

    def _handle_done(self, result: Any) -> None:
        callbacks = self._take()
        if callbacks is None or self._stopped:
            return  # dropped after stop(), or an unknown sender — don't touch (torn-down) widgets
        callbacks[0](result)

    def _handle_failed(self, error: BaseException) -> None:
        callbacks = self._take()
        if callbacks is None or self._stopped:
            return
        on_error = callbacks[1]
        if on_error is not None:
            on_error(error)

    def stop(self) -> None:
        """Drop late results and wait (bounded) for in-flight workers — call on window/page close."""
        self._stopped = True
        self._pool.waitForDone(2000)
        self._calls.clear()
