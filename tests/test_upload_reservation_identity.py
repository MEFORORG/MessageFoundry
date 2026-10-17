# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3180: each upload-quota reservation has its own identity, the ledger calls a
cancelled save leaves running are bounded, and they are drained before the store closes.

The ledger used to hold one row per uploader, so a release could not say which slot it paid back,
a reserve whose outcome was unknown could not be reconciled, and one clock kept every slot alive
while the uploader stayed active. ``tests/test_uploads_shard_quota_interleave.py`` covers the
per-reservation reclaim on all three backends. This file covers the save-side halves on SQLite.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import uploads as uploads_mod
from messagefoundry.config.settings import EgressSettings, StoreSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from messagefoundry.uploads import UploadedFileMeta, UploadStore
from tests.test_uploads import _GatedLedger, _hold_after_the_sidecar_lands

_ADT = "MSH|^~\\&|A|B|C|D|202601011200||ADT^A01|MSGID1|P|2.5\rPID|1||MRN123^^^HOSP||DOE^JOHN\r"


@pytest.fixture
async def ledger_db(tmp_path: Path) -> AsyncIterator[MessageStore]:
    db = await MessageStore.open(tmp_path / "engine.db")
    try:
        yield db
    finally:
        await db.close()


def _uploads(tmp_path: Path, ledger: Any, *, max_files: int = 100) -> UploadStore:
    return UploadStore(
        tmp_path / "uploads",
        make_cipher(generate_key()),
        max_bytes=4096,
        max_files_per_user=max_files,
        store=ledger,
    )


async def _settled(store: UploadStore, seconds: float = 10.0) -> bool:
    """Whether the store's stragglers all finish within ``seconds``."""
    for _ in range(int(seconds / 0.02)):
        if not store._stragglers:
            return True
        await asyncio.sleep(0.02)
    return False


class _PassThrough:
    """The real SQLite ledger, call for call. A test subclasses it and overrides the one call it
    changes."""

    def __init__(self, store: MessageStore) -> None:
        self.store = store

    async def reserve_upload_quota(self, *args: Any, **kwargs: Any) -> bool:
        return await self.store.reserve_upload_quota(*args, **kwargs)

    async def release_upload_quota(self, reservation_id: str) -> None:
        await self.store.release_upload_quota(reservation_id)

    async def touch_upload_quota(self, reservation_id: str) -> None:
        await self.store.touch_upload_quota(reservation_id)

    async def upload_quota_in_flight(self, uploader_id: str) -> tuple[int, int]:
        return await self.store.upload_quota_in_flight(uploader_id)


async def test_a_reserve_that_raises_after_its_commit_is_released_by_its_id(
    tmp_path: Path, ledger_db: MessageStore
) -> None:
    """A ledger error still fails the upload closed, and the slot the reserve may have taken is
    paid back by its id first. Red before #3180: the release could only subtract counts, which
    might have been a sibling's, so nothing was paid back and ``(1, 2)`` stayed in flight."""

    class _CommitThenFail(_PassThrough):
        async def reserve_upload_quota(self, *args: Any, **kwargs: Any) -> bool:
            await self.store.reserve_upload_quota(*args, **kwargs)
            raise ConnectionError("lost after the commit")

    store = _uploads(tmp_path, _CommitThenFail(ledger_db))
    with pytest.raises(ConnectionError):
        await store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    assert not store._stragglers, "the release by id was not awaited"
    assert await ledger_db.upload_quota_in_flight("u-op") == (0, 0)
    assert not (tmp_path / "uploads").exists() or not list((tmp_path / "uploads").iterdir())


async def test_a_late_release_is_cancelled_at_its_cap_rather_than_absorbed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The cap must reach the store call itself. A held wrapper that waited on the call absorbed
    the cancellation for ``_LEDGER_CANCEL_WAIT_SECONDS`` and then held the call again under a fresh
    cap (found in code review), so a stalled release outlived its cap several times over. The save
    waits for the release only up to ``_LEDGER_CANCEL_WAIT_SECONDS``, then fails as it would."""
    monkeypatch.setattr(uploads_mod, "_LEDGER_CANCEL_WAIT_SECONDS", 0.05)
    monkeypatch.setattr(uploads_mod, "_LEDGER_STRAGGLER_MAX_SECONDS", 0.2)

    class _ReserveFailsReleaseStalls:
        async def reserve_upload_quota(self, *args: Any, **kwargs: Any) -> bool:
            raise ConnectionError("store unreachable")

        async def release_upload_quota(self, reservation_id: str) -> None:
            await asyncio.Event().wait()

        async def touch_upload_quota(self, reservation_id: str) -> None:
            return None

        async def upload_quota_in_flight(self, uploader_id: str) -> tuple[int, int]:
            return (0, 0)

    store = _uploads(tmp_path, _ReserveFailsReleaseStalls())
    with pytest.raises(ConnectionError):
        await store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert await _settled(store, 2.0), "the late release outlived its cap"
    assert "release for u-op was cancelled before it finished" in caplog.text, caplog.text


async def test_a_ledger_call_left_running_is_cancelled_at_its_cap(
    tmp_path: Path,
    ledger_db: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The Lander's review of #2263: a call a cancelled save left running was never cancelled, so a
    stalled store held every one of them for the life of the process. Past its cap it is cancelled,
    and a reserve that may have taken a slot is paid back by its id."""
    monkeypatch.setattr(uploads_mod, "_LEDGER_CANCEL_WAIT_SECONDS", 0.05)
    monkeypatch.setattr(uploads_mod, "_LEDGER_STRAGGLER_MAX_SECONDS", 0.2)
    ledger = _GatedLedger(ledger_db, hold="reserve")  # the gate is never opened: a stalled call
    store = _uploads(tmp_path, ledger)
    save = asyncio.create_task(
        store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    )
    await asyncio.wait_for(ledger.at_gate.wait(), 10)
    assert await ledger_db.upload_quota_in_flight("u-op") == (1, 2)  # the control: it committed
    save.cancel()
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"),
        pytest.raises(asyncio.CancelledError),
    ):
        await asyncio.wait_for(save, 10)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert await _settled(store), "the stalled ledger call was never cancelled"
    assert "reserve for u-op was cancelled before it finished" in caplog.text, caplog.text
    assert await ledger_db.upload_quota_in_flight("u-op") == (0, 0)


async def test_the_drain_cancels_what_is_left_and_starts_no_release(
    tmp_path: Path,
    ledger_db: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Shutdown drains the stragglers before the store closes. A reserve still stalled at the
    bound is cancelled, and no release starts against a store about to close; its slot goes stale
    instead, and the WARNING says so."""
    monkeypatch.setattr(uploads_mod, "_LEDGER_CANCEL_WAIT_SECONDS", 0.05)
    ledger = _GatedLedger(ledger_db, hold="reserve")
    store = _uploads(tmp_path, ledger)
    save = asyncio.create_task(
        store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    )
    await asyncio.wait_for(ledger.at_gate.wait(), 10)
    save.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(save, 10)
    assert store._stragglers, "the control: the stalled reserve was left running"
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        await store.drain_stragglers(timeout=0.1, grace=5.0)
        await asyncio.sleep(0)  # a done callback runs one loop pass after its task ends
    assert not store._stragglers, "the drain left a ledger call running"
    assert "shutdown: cancelling 1 upload ledger call(s)" in caplog.text, caplog.text
    assert "is not released; it is reclaimed once it goes stale" in caplog.text, caplog.text
    assert await ledger_db.upload_quota_in_flight("u-op") == (1, 2)


async def test_the_drain_returns_at_once_with_nothing_left_running(tmp_path: Path) -> None:
    store = _uploads(tmp_path, None)
    await asyncio.wait_for(store.drain_stragglers(timeout=30.0), 1.0)


async def test_a_cancelled_save_removes_its_pair_before_another_save_scans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Lander's review of #2262: the removal of a cancelled save's landed pair ran after the
    per-process lock was released, so the next save in the process could scan the disk while the
    pair was still on it and be refused at the quota edge. Red before #3180: B was refused with
    one file over a cap of one, from a pair that was then removed."""
    store = _uploads(tmp_path, None, max_files=1)
    landed, finish = _hold_after_the_sidecar_lands(monkeypatch)
    b_scanned = threading.Event()
    real_observed = store._observed_sync
    armed = False

    def _observed(uploader_id: str) -> tuple[int, int]:
        out = real_observed(uploader_id)
        if armed:
            b_scanned.set()
        return out

    real_discard = store._discard_cancelled_sync

    def _slow_discard(file_id: str) -> None:
        # Hold the removal until B has scanned, or long enough that B plainly could not.
        b_scanned.wait(1.0)
        real_discard(file_id)

    monkeypatch.setattr(store, "_observed_sync", _observed)
    monkeypatch.setattr(store, "_discard_cancelled_sync", _slow_discard)
    a = asyncio.create_task(
        store.save(data=_ADT.encode(), filename="a.hl7", uploader="op", uploader_id="u-op")
    )
    try:
        assert await asyncio.to_thread(landed.wait, 10), "A's sidecar never landed"
        armed = True
        b = asyncio.create_task(
            store.save(data=b"second\n", filename="b.txt", uploader="op", uploader_id="u-op")
        )
        await asyncio.sleep(0.05)  # B is queued on the lock
        a.cancel()
    finally:
        finish.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(a, 10)
    assert isinstance(await asyncio.wait_for(b, 10), UploadedFileMeta)
    assert [m.filename for m in await store.list_files()] == ["b.txt"]


async def test_the_managed_teardown_drains_the_upload_stragglers_before_the_engine_stops(
    tmp_path: Path,
) -> None:
    """The drain has to run while the store is open, so before ``engine.stop()`` closes it."""
    from messagefoundry.api import create_managed_app

    app = create_managed_app(
        store_settings=StoreSettings(
            path=str(tmp_path / "managed.db"),
            uploads_dir=str(tmp_path / "uploads"),
            max_upload_bytes=4096,
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    calls: list[str] = []
    real_stop: list[Any] = []
    try:
        async with app.router.lifespan_context(app):
            engine = app.state.engine
            real_stop.append(engine.stop)

            async def _drain(*_args: Any, **_kwargs: Any) -> None:
                calls.append("uploads")

            async def _stop() -> None:
                calls.append("stop")
                await real_stop[0]()

            app.state.upload_store.drain_stragglers = _drain
            engine.stop = _stop
    finally:
        if real_stop and "stop" not in calls:
            await real_stop[0]()
    assert calls == ["uploads", "stop"]


async def test_a_retry_right_after_a_failed_reserve_is_not_refused_for_its_own_orphan(
    tmp_path: Path, ledger_db: MessageStore
) -> None:
    """The release after a reserve that raised is awaited before the error propagates. Red when
    it was only started: an immediate retry in the same process reserved while the first save's
    orphan row was still counted, and was refused at the quota edge as another engine shard's
    upload."""
    calls = {"reserve": 0}

    class _FirstReserveCommitsThenFails(_PassThrough):
        async def reserve_upload_quota(self, *args: Any, **kwargs: Any) -> bool:
            calls["reserve"] += 1
            applied = await self.store.reserve_upload_quota(*args, **kwargs)
            if calls["reserve"] == 1:
                raise ConnectionError("lost after the commit")
            return applied

        async def release_upload_quota(self, reservation_id: str) -> None:
            await asyncio.sleep(0.05)  # a release slower than the retry's reserve
            await self.store.release_upload_quota(reservation_id)

    store = _uploads(tmp_path, _FirstReserveCommitsThenFails(ledger_db), max_files=1)
    with pytest.raises(ConnectionError):
        await store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    meta = await store.save(data=b"y\n", filename="b.txt", uploader="op", uploader_id="u-op")
    assert meta.filename == "b.txt"
    assert await ledger_db.upload_quota_in_flight("u-op") == (0, 0)


async def test_a_reserve_that_finishes_inside_the_drain_still_pays_its_slot_back(
    tmp_path: Path, ledger_db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round two: the drain refused every late release from its first line, so a reserve
    that finished while the drain was still waiting for it kept its slot until it went stale. Only
    what the drain cancels is refused a release now."""
    monkeypatch.setattr(uploads_mod, "_LEDGER_CANCEL_WAIT_SECONDS", 0.05)
    ledger = _GatedLedger(ledger_db, hold="reserve")
    store = _uploads(tmp_path, ledger)
    save = asyncio.create_task(
        store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    )
    await asyncio.wait_for(ledger.at_gate.wait(), 10)
    save.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(save, 10)
    assert await ledger_db.upload_quota_in_flight("u-op") == (1, 2)  # the control
    drain = asyncio.create_task(store.drain_stragglers(timeout=10.0, grace=1.0))
    await asyncio.sleep(0.05)  # the drain is waiting on the stalled reserve
    ledger.gate.set()
    await asyncio.wait_for(drain, 10)
    assert not store._stragglers
    assert await ledger_db.upload_quota_in_flight("u-op") == (0, 0)
    assert not store._drain_cancelled


async def test_a_straggler_that_ends_after_the_drain_returned_starts_no_release(
    tmp_path: Path, ledger_db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review round two: the drain cleared its flag as it returned, so a reserve that outlived the
    grace and ended later started a release against a store being closed. A reserve the drain
    cancelled is now refused its release whenever it ends, and then forgotten."""
    monkeypatch.setattr(uploads_mod, "_LEDGER_CANCEL_WAIT_SECONDS", 0.05)
    at_gate, finish = asyncio.Event(), asyncio.Event()
    released: list[str] = []

    class _ReserveOutlivesItsCancel(_PassThrough):
        async def reserve_upload_quota(self, *args: Any, **kwargs: Any) -> bool:
            applied = await self.store.reserve_upload_quota(*args, **kwargs)
            at_gate.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await finish.wait()  # a driver still unwinding past the drain's grace
                raise
            return applied

        async def release_upload_quota(self, reservation_id: str) -> None:
            released.append(reservation_id)
            await self.store.release_upload_quota(reservation_id)

    store = _uploads(tmp_path, _ReserveOutlivesItsCancel(ledger_db))
    save = asyncio.create_task(
        store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    )
    await asyncio.wait_for(at_gate.wait(), 10)
    save.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(save, 10)
    await store.drain_stragglers(timeout=0.05, grace=0.05)
    assert store._stragglers, "the control: the reserve outlived the grace"
    finish.set()
    assert await _settled(store), "the reserve never ended"
    await asyncio.sleep(0)
    assert released == [], "a release started after the drain returned"
    assert await ledger_db.upload_quota_in_flight("u-op") == (1, 2)
    assert not store._drain_cancelled, "the drain still holds a task that ended"


def test_the_straggler_drain_fits_inside_the_retention_runner_stop() -> None:
    """The managed lifespan runs the two side by side, so the drain adds nothing to NSSM's 15 s
    graceful-stop window only while its two bounds fit inside the runner's (review round two)."""
    assert (
        uploads_mod._STRAGGLER_DRAIN_SECONDS + uploads_mod._STRAGGLER_CANCEL_GRACE_SECONDS
        <= uploads_mod._DEFAULT_STOP_TIMEOUT_SECONDS
    )


async def test_the_managed_teardown_drains_beside_the_retention_runner_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run in turn, the drain's bounds added to the runner's in the shutdown budget. The fake stop
    waits for the drain to begin, so a sequential teardown would time out here."""
    from messagefoundry.api import create_managed_app

    drain_started = asyncio.Event()
    calls: list[str] = []

    async def _stop(self: Any) -> None:
        calls.append("runner")
        await asyncio.wait_for(drain_started.wait(), 5)

    monkeypatch.setattr(uploads_mod.UploadRetentionRunner, "stop", _stop)
    app = create_managed_app(
        store_settings=StoreSettings(
            path=str(tmp_path / "managed.db"),
            uploads_dir=str(tmp_path / "uploads"),
            max_upload_bytes=4096,
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    async with app.router.lifespan_context(app):

        async def _drain(*_args: Any, **_kwargs: Any) -> None:
            drain_started.set()
            calls.append("uploads")

        app.state.upload_store.drain_stragglers = _drain
    assert sorted(calls) == ["runner", "uploads"]


async def test_the_old_per_uploader_ledger_table_is_dropped_at_open(tmp_path: Path) -> None:
    """The ``upload_quota`` table the reservations replaced is dropped, not left beside them."""
    import sqlite3

    db = tmp_path / "legacy.db"
    await (await MessageStore.open(db)).close()
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "CREATE TABLE upload_quota (uploader_id TEXT PRIMARY KEY, inflight_files INTEGER,"
            " inflight_bytes INTEGER, since REAL)"
        )
        conn.commit()
    finally:
        conn.close()
    await (await MessageStore.open(db)).close()
    conn = sqlite3.connect(db)
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()
    assert "upload_reservation" in names
    assert "upload_quota" not in names


async def test_a_reserve_already_done_when_the_drain_cancels_still_pays_its_slot_back(
    tmp_path: Path, ledger_db: MessageStore
) -> None:
    """A reserve that finished in the pass the drain's wait timed out is still in the straggler
    set, because its done callback has not run yet. The drain cannot cancel it, so it must not
    refuse its release either (found in code review). The drain's grace covers that release, so
    it has ended before the drain returns and cannot run into a closing store (review round two)."""
    released: list[str] = []

    class _Recording(_PassThrough):
        async def release_upload_quota(self, reservation_id: str) -> None:
            await asyncio.sleep(0.05)  # slower than one loop pass, so only a wait covers it
            released.append(reservation_id)
            await self.store.release_upload_quota(reservation_id)

    store = _uploads(tmp_path, _Recording(ledger_db))
    reserve: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
    store._leave_running(reserve, what="reserve", uploader_id="u-op", reservation="r-1")
    reserve.set_result(True)  # done, with its callbacks scheduled but not yet run
    await store.drain_stragglers(timeout=0.0, grace=5.0)
    assert released == ["r-1"], "the drain returned before the release it started had ended"
    assert not store._stragglers


async def test_a_release_still_running_at_the_grace_is_cancelled(
    tmp_path: Path, ledger_db: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """A release a callback started during the grace and still running at its end is cancelled,
    so nothing the drain saw outlives it."""

    class _Stalls(_PassThrough):
        async def release_upload_quota(self, reservation_id: str) -> None:
            await asyncio.Event().wait()

    store = _uploads(tmp_path, _Stalls(ledger_db))
    reserve: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
    store._leave_running(reserve, what="reserve", uploader_id="u-op", reservation="r-1")
    reserve.set_result(True)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        await store.drain_stragglers(timeout=0.0, grace=0.1)
        await asyncio.sleep(0)  # the cancelled release ends one loop pass later
        await asyncio.sleep(0)
    assert not store._stragglers
    assert "release for u-op was cancelled before it finished" in caplog.text, caplog.text


async def test_discard_waits_for_the_quota_lock_before_it_removes_the_pair(
    tmp_path: Path,
) -> None:
    """A pair whose upload.create row failed is removed under the per-process lock, so a save in
    this process cannot scan the disk while the pair is still on it (found in code review)."""
    store = _uploads(tmp_path, None)
    meta = await store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    async with store._quota_lock:
        discard = asyncio.create_task(store.discard(meta.file_id))
        await asyncio.sleep(0.05)
        assert [m.file_id for m in await store.list_files()] == [meta.file_id]
    await asyncio.wait_for(discard, 10)
    assert await store.list_files() == []
