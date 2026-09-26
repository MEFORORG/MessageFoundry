# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``FileSource.stop()`` is bounded when a share call blocks (BACKLOG #1620).

Every share touch runs on a thread that nothing engine-side can interrupt, and a dead SMB/UNC share
holds it for the OS timeout, tens of seconds. ``stop()`` used to await the poll task with no bound,
so a reload issued while the share was down blocked for that long. It now waits a grace, then
cancels the task and logs; a pipeline hand-off is never cut. A batch file's hand-offs can also be
interrupted between messages now, leaving the file in place to be re-read whole.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports import file as file_mod
from messagefoundry.transports.file import FileSource

_MSG = "MSH|^~\\&|SND|FAC|RCV|FAC|20260101120000||ADT^A01|{n}|P|2.5.1\rPID|1||{n}\r"


def _source(inbox: Path) -> FileSource:
    return FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "poll_seconds": 0.05})
    )


async def test_stop_returns_within_the_grace_when_a_share_call_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The listing call stands in for a dead share: it blocks on a thread for up to 10 s.

    Mutation: restore the unbounded ``gather`` in ``stop()``. Red: ``stop()`` does not return
    within 3 s (it waits for the blocked call)."""
    monkeypatch.setattr(file_mod, "_STOP_GRACE_S", 0.2)
    inbox = tmp_path / "in"
    inbox.mkdir()
    source = _source(inbox)
    entered = threading.Event()
    release = threading.Event()

    def blocked_listing() -> list[Path]:
        entered.set()
        release.wait(10)
        return []

    monkeypatch.setattr(source, "_candidates", blocked_listing)

    async def handler(_raw: bytes) -> str | None:
        return None

    await source.start(handler)
    try:
        assert await asyncio.to_thread(entered.wait, 5), "the poll never reached the listing"
        started = time.monotonic()
        with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.file"):
            await asyncio.wait_for(source.stop(), 3)
        elapsed = time.monotonic() - started
    finally:
        release.set()

    assert elapsed < 2, f"stop() took {elapsed:.2f}s against a 0.2s grace"
    assert any("did not stop within" in r.getMessage() for r in caplog.records)


async def test_stop_never_cancels_a_hand_off_in_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hand-off is the durable store commit. A stop that arrives mid-hand-off waits it out, past
    the grace, and the file is then disposed of normally: the grace restarts when the hand-off ends,
    so the archive move after it is not cut at an arbitrary step boundary either.

    Mutation: cancel regardless of ``_handing_off``. Red: the hand-off is cancelled mid-commit."""
    monkeypatch.setattr(file_mod, "_STOP_GRACE_S", 0.25)
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "one.hl7").write_bytes(_MSG.format(n=1).encode("ascii"))
    source = _source(inbox)
    in_handler = asyncio.Event()
    committed: list[bool] = []

    async def slow_commit(_raw: bytes) -> str | None:
        in_handler.set()
        await asyncio.sleep(1.0)  # four graces long
        committed.append(True)
        return None

    await source.start(slow_commit)
    await asyncio.wait_for(in_handler.wait(), 5)
    await asyncio.wait_for(source.stop(), 5)

    assert committed == [True], "the hand-off was cut short"
    assert not (inbox / "one.hl7").exists(), "a completed hand-off is still archived"


async def test_a_stop_between_batch_hand_offs_leaves_the_file_to_be_re_read(
    tmp_path: Path,
) -> None:
    """A batch file of three messages; the stop arrives during the first hand-off. The other two are
    not handed off, and the file stays in the inbox so the next start re-emits all three.

    Mutation: drop the stop check in ``_emit``'s loop. Red: all three are handed off and the file
    is archived."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    batch = inbox / "batch.hl7"
    batch.write_bytes("".join(_MSG.format(n=n) for n in (1, 2, 3)).encode("ascii"))
    source = _source(inbox)
    handed_off: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        handed_off.append(raw)
        source._stop.set()  # the stop signal arrives while this hand-off is in flight
        return None

    source._handler = handler
    await source._scan_once()

    assert len(handed_off) == 1
    assert batch.exists(), "an interrupted batch file must stay in place to be re-read whole"
    assert not source._handing_off
