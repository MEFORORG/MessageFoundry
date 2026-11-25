# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5664 remainder: the group committer's ``aclose()`` same-turn race.

A committer task cancelled outside ``aclose()`` is only marked closed by its done-callback, and
asyncio runs a done-callback one loop turn after the task finishes. In that turn ``submit()`` still
enrols, because ``_closed`` is not yet set. If ``aclose()`` runs in the same turn, its
``await task`` raises the task's CancelledError without yielding (the task is already done),
aclose swallows that stale cancel and clears ``_task``, and the done-callback then reads itself as
a stale task's and returns early. The member enrolled in that turn was never committed and never
rejected, so its caller (the ingress ACK gate among them) would park on its future forever.

The test drives the loop turn by turn rather than sleeping: ``asyncio.sleep(0)`` yields exactly one
turn, and an eagerly started task runs synchronously up to its first suspension, which is how a
``submit()`` and an ``aclose()`` land in the same turn here."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import pytest

from messagefoundry.store.store import MessageStore

GC_WINDOW_MS = 5.0


async def _ret(n: int) -> int:
    return n


async def test_member_enrolled_in_the_turn_the_committer_stopped_is_refused_by_aclose(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="messagefoundry.store.store")
    s = await MessageStore.open(tmp_path / "race.db", group_commit_window_ms=GC_WINDOW_MS)
    member: asyncio.Task[object] | None = None
    closer: asyncio.Task[None] | None = None
    try:
        gc = s._group_commit
        assert gc is not None and gc._task is not None
        task = gc._task

        task.cancel()
        await asyncio.sleep(0)  # one turn: the committer dies, its done-callback is queued, not run
        # The window under test: the task is finished, and nothing has marked the committer closed.
        assert task.done()
        assert not gc._closed

        # Same turn: a member enrols (submit runs eagerly up to its await on the future), then the
        # store closes the committer (aclose runs eagerly and, on a done task, never yields).
        member = asyncio.create_task(gc.submit(lambda: _ret(1)), eager_start=True)
        assert not member.done()
        assert len(gc._pending) == 1
        closer = asyncio.create_task(gc.aclose(), eager_start=True)
        assert closer.done()
        closer.result()  # aclose itself raised nothing
        assert gc._pending == []  # refused by aclose itself, not left to a later callback

        # A few turns are ample for any queued callback to run; the member must be resolved.
        for _ in range(5):
            await asyncio.sleep(0)
        assert member.done(), "a member accepted before close was neither committed nor refused"
        with pytest.raises(RuntimeError, match="group committer stopped"):
            member.result()
        # The abnormal stop is still reported, not read as an orderly close.
        assert "stopped outside close; rejecting 1 pending member(s)" in caplog.text
        assert gc._pending == []
        assert gc._closed
        with pytest.raises(RuntimeError, match="closed"):
            await gc.submit(lambda: _ret(2))
    finally:
        # The regression case: release the parked caller (and a closer that yielded) so the run
        # can exit.
        leftovers = [t for t in (member, closer) if t is not None and not t.done()]
        for t in leftovers:
            t.cancel()
        await asyncio.gather(*leftovers, return_exceptions=True)
        await s.close()
