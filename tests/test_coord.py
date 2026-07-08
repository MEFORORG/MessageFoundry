# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The file-drop coordination primitive (:mod:`harness.load.coord`) — the two-message rendezvous the
WS-C two-box shardcert drive uses. Pure local filesystem; no sockets, no engine, no SQL Server."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from harness.load.coord import (
    DEFAULT_COORD_DIR,
    DRIVE_START,
    SHARDS_READY,
    CoordTimeout,
    FileDropCoord,
    default_coord_dir,
)


def test_post_read_round_trips_payload(tmp_path: Path) -> None:
    coord = FileDropCoord(tmp_path, run_id="r1")
    assert coord.read(SHARDS_READY) is None  # nothing posted yet
    coord.post(SHARDS_READY, {"shards": ["a", "b"], "lanes": 2})
    got = coord.read(SHARDS_READY)
    assert got == {"shards": ["a", "b"], "lanes": 2}


def test_post_is_last_write_wins_and_atomic(tmp_path: Path) -> None:
    coord = FileDropCoord(tmp_path, run_id="r1")
    coord.post(SHARDS_READY, {"v": 1})
    coord.post(SHARDS_READY, {"v": 2})
    assert coord.read(SHARDS_READY) == {"v": 2}
    # No stale temp files linger next to the atomic target.
    assert not list(tmp_path.glob("*.tmp"))


def test_run_id_scopes_messages(tmp_path: Path) -> None:
    a = FileDropCoord(tmp_path, run_id="runA")
    b = a.for_run("runB")
    a.post(DRIVE_START, {"who": "A"})
    assert b.read(DRIVE_START) is None  # different run id → different file
    b.post(DRIVE_START, {"who": "B"})
    assert a.read(DRIVE_START) == {"who": "A"}
    assert b.read(DRIVE_START) == {"who": "B"}


def test_clear_removes_handshake_pair(tmp_path: Path) -> None:
    coord = FileDropCoord(tmp_path, run_id="r1")
    coord.post(SHARDS_READY, {"v": 1})
    coord.post(DRIVE_START, {"v": 2})
    coord.clear()
    assert coord.read(SHARDS_READY) is None
    assert coord.read(DRIVE_START) is None


async def test_await_message_returns_when_posted(tmp_path: Path) -> None:
    coord = FileDropCoord(tmp_path, run_id="r1")

    async def _post_soon() -> None:
        await asyncio.sleep(0.05)
        coord.post(SHARDS_READY, {"ready": True})

    poster = asyncio.create_task(_post_soon())
    payload = await coord.await_message(SHARDS_READY, timeout=5.0, interval=0.02)
    await poster
    assert payload == {"ready": True}


async def test_await_message_times_out(tmp_path: Path) -> None:
    coord = FileDropCoord(tmp_path, run_id="r1")
    with pytest.raises(CoordTimeout):
        await coord.await_message(DRIVE_START, timeout=0.1, interval=0.02)


def test_default_coord_dir_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_COORD_DIR", raising=False)
    assert default_coord_dir() == DEFAULT_COORD_DIR
    monkeypatch.setenv("MEFOR_COORD_DIR", "/tmp/mefor-coord-test")
    assert default_coord_dir() == "/tmp/mefor-coord-test"
