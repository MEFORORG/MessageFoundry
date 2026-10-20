# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fire the request deadline from inside the operation it is meant to cut off (vault BACKLOG #3871).

A test that sets ``request_timeout_seconds`` to a fraction of a second races wall time against the
request: the deadline counts from the start of the request, so on a loaded runner the auth
dependencies, the body read or the file save alone could outlast it. The 503 then came before the
route had started the operation, nothing was left running to outlive the request, and the test
failed on a state the code under test never reached.

:func:`capture_deadlines` replaces ``asyncio`` inside the deadline middleware's module only, so the
:class:`DeadlineCapture` it returns keeps each deadline the middleware opens, and gives the app a
deadline long enough never to fire on its own. The operation the test holds awaits
:meth:`DeadlineCapture.cut_off`. That expires the middleware's own ``asyncio.Timeout`` on the loop's
next pass, wherever the request is, so the 503 lands mid-operation and nowhere else, then holds the
operation until :meth:`DeadlineCapture.held` lets it go.

Engine PR 2438, open and not on ``main`` when this was written, carries a simpler copy of the
stand-in in the web console's ``test_ui_dr_outlive.py``: it fires the latest deadline, with none of
the checks below.
"""

from __future__ import annotations

import asyncio
import contextlib
import types
from collections.abc import AsyncIterator, Awaitable
from typing import Any

import httpx
import pytest

from messagefoundry.api import request_timeout
from messagefoundry.api.outlive import OutlivingOperations

__all__ = ["GENEROUS_DEADLINE_SECONDS", "DeadlineCapture", "capture_deadlines", "expect_cut_off"]

#: Long enough that a deadline never fires on its own during a test: :meth:`DeadlineCapture.fire`
#: fires it. Short enough that a test whose operation never fires it still fails on its own
#: assertion inside the per-test timeout, after this, the drain below and its cancel grace.
GENEROUS_DEADLINE_SECONDS = 15.0

#: How long a test waits for the held operation to finish once it is let go.
_DRAIN_SECONDS = 10.0


class DeadlineCapture:
    """Keeps each deadline the middleware opens, so a test can make the real one fire when it
    chooses. :func:`capture_deadlines` builds and installs it."""

    def __init__(self, outliving: OutlivingOperations) -> None:
        self.deadlines: list[asyncio.Timeout] = []
        self.fired = False
        #: Why a fire went wrong. Recorded rather than raised: :meth:`fire` runs on the operation's
        #: task, where the code under test may catch an error and turn it into its own outcome.
        #: :func:`expect_cut_off` reports it on the test's task.
        self.problem: str | None = None
        self._outliving = outliving
        self._released = asyncio.Event()

    def timeout(self, delay: float | None) -> asyncio.Timeout:
        deadline = asyncio.timeout(delay)
        self.deadlines.append(deadline)
        return deadline

    def fire(self) -> None:
        """Expire the one request deadline opened since this capture was installed, now.

        Exactly one, still armed: a test installs the capture just before the request it cuts off,
        so a second deadline means a request the test did not expect, and a disarmed one means the
        response has already started, where firing would cut the body rather than the operation.
        Anything else fires nothing: it is recorded, and the hold is let go so the request ends
        and the test reports it, rather than every await waiting on the next."""
        if len(self.deadlines) != 1:
            self._refuse(f"expected one request deadline, saw {len(self.deadlines)}")
            return
        deadline = self.deadlines[0]
        if deadline.when() is None:
            self._refuse("the request had already started its response")
            return
        try:
            deadline.reschedule(asyncio.get_running_loop().time())
        except RuntimeError as exc:  # it had already expired, or its request had ended
            self._refuse(f"the deadline could not be fired: {exc}")
            return
        self.fired = True

    def _refuse(self, problem: str) -> None:
        self.problem = problem
        self._released.set()

    async def cut_off(self) -> None:
        """Awaited from inside the held operation: fire the deadline, then hold the operation until
        :meth:`held` lets it go, so it cannot end before the 503 is in."""
        self.fire()
        await self._released.wait()

    @contextlib.asynccontextmanager
    async def held(self) -> AsyncIterator[None]:
        """While the block runs, the operation stays held in :meth:`cut_off`. On the way out it is
        let go and waited for, so it never runs on into the fixture's engine stop, and on a clean
        exit it must have finished by itself rather than been cancelled by the drain. Whether it
        succeeded is for the test's own assertions on its outcome rows."""
        try:
            yield
        finally:
            self._released.set()
            cancelled = await self._outliving.drain(timeout=_DRAIN_SECONDS)
        assert cancelled == [], f"never finished once let go: {cancelled}"


def capture_deadlines(monkeypatch: pytest.MonkeyPatch, app: Any) -> DeadlineCapture:
    """Install a :class:`DeadlineCapture` for ``app`` and give it a deadline that never fires on
    its own; both are undone with ``monkeypatch``.

    Call it after the sign-in and any proof, just before the request the test cuts off. The
    middleware's module sees only ``timeout``, which is all it uses, so a new use fails loudly."""
    capture = DeadlineCapture(app.state.outliving_operations)
    monkeypatch.setattr(request_timeout, "asyncio", types.SimpleNamespace(timeout=capture.timeout))
    monkeypatch.setattr(
        app.state, request_timeout.TIMEOUT_STATE_ATTR, GENEROUS_DEADLINE_SECONDS, raising=False
    )
    return capture


async def expect_cut_off(capture: DeadlineCapture, request: Awaitable[httpx.Response]) -> None:
    """Await ``request`` and check the answer is the deadline middleware's own 503, fired by
    ``capture`` from inside the operation: not a route's 503, and not the deadline running out.

    The generous deadline bounds the wait: a deadline the operation never fires answers 503 there,
    and the ``fired`` check fails. A fire that went wrong is reported first, even when the request
    raised because of it."""
    try:
        r = await request
    except Exception as exc:
        if capture.problem is not None:
            raise AssertionError(capture.problem) from exc
        raise
    assert capture.problem is None, capture.problem
    assert r.status_code == 503, r.text
    assert r.json() == {"detail": "the server timed out building a response"}
    assert capture.fired, "the deadline was not fired from inside the operation"
