# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fire the request deadline from inside the operation it is meant to cut off (vault BACKLOG #3871).

A test that sets ``request_timeout_seconds`` to a fraction of a second races wall time against the
request: the deadline counts from the start of the request, so on a loaded runner the auth
dependencies, the body read or the file save alone could outlast it. The 503 then came before the
route had started the operation, nothing was left running to outlive the request, and the test
failed on a state the code under test never reached.

:class:`DeadlineCapture` stands in for ``asyncio`` inside the deadline middleware's module only and
keeps each deadline the middleware opens. A test installs it with :func:`capture_deadlines`, which
also sets a deadline long enough never to fire on its own, and the operation it holds awaits
:meth:`DeadlineCapture.cut_off`. That expires the middleware's own ``asyncio.Timeout`` on the loop's
next pass, wherever the request is, so the 503 lands mid-operation and nowhere else, and then holds
the operation until :meth:`DeadlineCapture.held` lets it go.

The web console's ``test_ui_dr_outlive.py`` gets the same stand-in, as its own copy, in its own
change (engine PR 2438).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable
from typing import Any

import httpx
import pytest

from messagefoundry.api import request_timeout
from messagefoundry.api.outlive import OutlivingOperations

__all__ = ["GENEROUS_DEADLINE_SECONDS", "DeadlineCapture", "capture_deadlines", "expect_cut_off"]

#: Long enough that a deadline never fires on its own during a test: :meth:`DeadlineCapture.fire`
#: fires it.
GENEROUS_DEADLINE_SECONDS = 30.0

#: How long a test waits for the held operation to finish once it is let go.
_DRAIN_SECONDS = 10.0


class DeadlineCapture:
    """Stands in for ``asyncio`` inside :mod:`messagefoundry.api.request_timeout`, and keeps each
    deadline the middleware opens so a test can make the real one fire when it chooses."""

    def __init__(self) -> None:
        self.deadlines: list[asyncio.Timeout] = []
        self.fired = False
        self._released = asyncio.Event()

    def timeout(self, delay: float | None) -> asyncio.Timeout:
        deadline = asyncio.timeout(delay)
        self.deadlines.append(deadline)
        return deadline

    def fire(self) -> None:
        """Expire the one request deadline opened since this capture was installed, now.

        Exactly one: a test installs the capture just before the request it cuts off, so a second
        deadline means a request the test did not expect, and firing the wrong one would prove
        nothing. ``reschedule`` refuses a deadline whose request has already ended."""
        assert len(self.deadlines) == 1, f"expected one request deadline, saw {len(self.deadlines)}"
        self.deadlines[0].reschedule(asyncio.get_running_loop().time())
        self.fired = True

    async def cut_off(self) -> None:
        """Awaited from inside the held operation: fire the deadline, then hold the operation until
        :meth:`held` lets it go, so it cannot end before the 503 is in."""
        self.fire()
        await self._released.wait()

    @contextlib.asynccontextmanager
    async def held(self, outliving: OutlivingOperations) -> AsyncIterator[None]:
        """While the block runs, the operation stays held in :meth:`cut_off`. On the way out it is
        let go and waited for, so it never runs on into the fixture's engine stop, and on a clean
        exit the operation must have finished by itself rather than been cancelled by the drain."""
        try:
            yield
        finally:
            self._released.set()
            cancelled = await outliving.drain(timeout=_DRAIN_SECONDS)
        assert cancelled == [], f"never finished once let go: {cancelled}"

    def __getattr__(self, name: str) -> Any:
        return getattr(asyncio, name)


def capture_deadlines(monkeypatch: pytest.MonkeyPatch, app: Any) -> DeadlineCapture:
    """Install a :class:`DeadlineCapture` and give ``app`` a deadline that never fires on its own.

    Call it after the sign-in and any proof, just before the request the test cuts off."""
    capture = DeadlineCapture()
    monkeypatch.setattr(request_timeout, "asyncio", capture)
    setattr(app.state, request_timeout.TIMEOUT_STATE_ATTR, GENEROUS_DEADLINE_SECONDS)
    return capture


async def expect_cut_off(capture: DeadlineCapture, request: Awaitable[httpx.Response]) -> None:
    """Await ``request`` and check the answer is the deadline middleware's own 503, fired by
    ``capture`` from inside the operation: not a route's 503, and not the deadline running out.

    Bounded, so a deadline that never fires fails here rather than hanging the run."""
    r = await asyncio.wait_for(request, timeout=GENEROUS_DEADLINE_SECONDS + 10)
    assert r.status_code == 503, r.text
    assert r.json() == {"detail": "the server timed out building a response"}
    assert capture.fired, "the deadline was not fired from inside the operation"
