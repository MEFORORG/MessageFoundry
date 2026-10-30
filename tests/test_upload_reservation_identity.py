# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3180: each upload-quota reservation has its own identity, the ledger calls a
cancelled save leaves running are bounded, and the shutdown drain waits for them, then cancels
them, before the store closes.

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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import uploads as uploads_mod
from messagefoundry.config.settings import EgressSettings, StoreSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from messagefoundry.uploads import UploadedFileMeta, UploadStore, _Observed
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

    async def release_upload_quota(self, *, uploader_id: str, reservation_id: str) -> None:
        await self.store.release_upload_quota(
            uploader_id=uploader_id, reservation_id=reservation_id
        )

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

        async def release_upload_quota(self, *, uploader_id: str, reservation_id: str) -> None:
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


async def test_the_drain_cancels_a_held_touch_once(tmp_path: Path) -> None:
    """Vault BACKLOG #3740 item 14. A touch the drain cancelled may take a while to unwind, as the
    SQLite writer guard's rollback does, and a second cancel would cut that unwind short. Red
    with the cancel of every task left after the wait: a straggler outlasting the wait put the
    touch in that set, so it was cancelled twice."""
    store = _uploads(tmp_path, None)
    cancels = 0

    async def _touch() -> None:
        nonlocal cancels
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancels += 1
            try:
                await asyncio.sleep(0.3)  # the store's unwind of the cancelled statement
            except asyncio.CancelledError:
                cancels += 1
            raise

    touch = asyncio.ensure_future(_touch())
    store._touches.add(touch)
    touch.add_done_callback(store._touches.discard)
    store._hold(touch)
    stalled = asyncio.ensure_future(asyncio.Event().wait())
    store._hold(stalled)  # outlasts the drain's wait, so the cancel pass runs
    await asyncio.sleep(0)  # the touch starts, so a cancel lands inside it
    await store.drain_stragglers(0.05, grace=0.5)
    await asyncio.gather(touch, stalled, return_exceptions=True)
    assert cancels == 1


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

    def _observed(uploader_id: str) -> _Observed:
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


async def test_a_hung_removal_of_a_cancelled_pair_does_not_hold_the_quota_lock(
    tmp_path: Path,
    ledger_db: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Vault BACKLOG #3740 item 4: the removal of a cancelled save's landed pair waited under
    ``_quota_lock`` with no bound, so one hung unlink queued every upload in the process. Past
    ``_CANCELLED_REMOVAL_WAIT_SECONDS`` the cancelled save drops the lock with the removal still
    running, names the file at ERROR, and the next upload reserves and lands; the pair goes once
    the unlink returns. Red before: B never reached its reserve while A's unlink hung."""
    monkeypatch.setattr(uploads_mod, "_CANCELLED_REMOVAL_WAIT_SECONDS", 0.05)
    reserved: list[str] = []

    class _Recording(_PassThrough):
        async def reserve_upload_quota(self, *args: Any, **kwargs: Any) -> bool:
            reserved.append(args[1])
            return await super().reserve_upload_quota(*args, **kwargs)

    store = _uploads(tmp_path, _Recording(ledger_db))
    landed, finish = _hold_after_the_sidecar_lands(monkeypatch)
    unhang, removed = threading.Event(), threading.Event()
    real_discard = store._discard_cancelled_sync

    def _hung_discard(file_id: str) -> None:
        unhang.wait(30)  # bounded, so a red run cannot hang the suite
        real_discard(file_id)
        removed.set()

    monkeypatch.setattr(store, "_discard_cancelled_sync", _hung_discard)
    caplog.set_level(logging.WARNING, logger="messagefoundry.uploads")
    a = asyncio.create_task(
        store.save(data=_ADT.encode(), filename="a.hl7", uploader="op", uploader_id="u-op")
    )
    try:
        try:
            assert await asyncio.to_thread(landed.wait, 10), "A's sidecar never landed"
            b = asyncio.create_task(
                store.save(data=b"second\n", filename="b.txt", uploader="op", uploader_id="u-op")
            )
            await asyncio.sleep(0.05)  # B is queued on the lock
            assert len(reserved) == 1, "the control: B has not reserved while A holds the lock"
            a.cancel()
        finally:
            finish.set()
        done, _ = await asyncio.wait({a, b}, timeout=5)
        assert b in done, "B waited on the lock for A's hung unlink"
        assert isinstance(b.result(), UploadedFileMeta)
        assert len(reserved) == 2
        assert a in done and a.cancelled()
        assert "has no upload.create audit row; its removal did not finish" in caplog.text
        assert len(await store.list_files()) == 2, "the control: A's pair is still on disk"
    finally:
        unhang.set()
    assert await asyncio.to_thread(removed.wait, 10), "A's removal never finished"
    assert [m.filename for m in await store.list_files()] == ["b.txt"]
    assert await _settled(store), "a ledger call was left running"
    assert await ledger_db.upload_quota_in_flight("u-op") == (0, 0)
    withdrawn = "its removal finished after it was named at ERROR"
    for _ in range(50):  # the done callback runs one loop pass after the thread returns
        if withdrawn in caplog.text:
            break
        await asyncio.sleep(0.02)
    assert withdrawn in caplog.text, caplog.text


async def test_abandoned_removals_run_on_their_own_capped_pool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3740 item 4, the Lander's hold on PR 2645: each removal abandoned at the
    bound kept a default-executor worker, with no cap, so hung unlinks could fill the pool every
    ``asyncio.to_thread`` in the engine shares. Removals now run on their own small pool, so a
    hung one past its cap queues there. Red before: three hung removals ran at once on the
    default executor."""
    monkeypatch.setattr(uploads_mod, "_CANCELLED_REMOVAL_WAIT_SECONDS", 0.05)
    pool = ThreadPoolExecutor(max_workers=1)
    # raising=False, so the unfixed module, which has no such pool, fails on the count below.
    monkeypatch.setattr(uploads_mod, "_removal_executor", lambda: pool, raising=False)
    store = _uploads(tmp_path, None)
    metas = [
        await store.save(data=b"x\n", filename=f"{n}.txt", uploader="op", uploader_id="u-op")
        for n in range(3)
    ]
    unhang, count = threading.Event(), threading.Lock()
    running, peak, finished = 0, 0, 0
    real_discard = store._discard_cancelled_sync

    def _hung_discard(file_id: str) -> bool:
        nonlocal running, peak, finished
        with count:
            running += 1
            peak = max(peak, running)
        try:
            unhang.wait(30)  # bounded, so a red run cannot hang the suite
            return real_discard(file_id)
        finally:
            with count:
                running -= 1
                finished += 1

    monkeypatch.setattr(store, "_discard_cancelled_sync", _hung_discard)
    try:
        for meta in metas:
            await store._remove_cancelled_pair(meta.file_id, "u-op")
        await asyncio.sleep(0.1)  # time for a queued removal to start, were nothing capping it
        assert peak == 1, f"{peak} hung removals ran at once"
    finally:
        unhang.set()
        await asyncio.to_thread(pool.shutdown, True)  # runs the queued removals, then returns
    assert finished == 3
    assert await store.list_files() == []


async def test_the_drain_names_a_removal_still_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Vault BACKLOG #3740 item 4: a removal's bound ERROR is a loop timer, which a closing loop
    drops, so the shutdown drain names a removal still running inside its bound at ERROR. Once
    the removal lands, a WARNING withdraws it."""
    monkeypatch.setattr(uploads_mod, "_CANCELLED_REMOVAL_WAIT_SECONDS", 30.0)
    store = _uploads(tmp_path, None)
    meta = await store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    unhang, removed = threading.Event(), threading.Event()
    real_discard = store._discard_cancelled_sync

    def _hung_discard(file_id: str) -> bool:
        unhang.wait(30)
        try:
            return real_discard(file_id)
        finally:
            removed.set()

    monkeypatch.setattr(store, "_discard_cancelled_sync", _hung_discard)
    caplog.set_level(logging.WARNING, logger="messagefoundry.uploads")
    try:
        task = asyncio.create_task(store._remove_cancelled_pair(meta.file_id, "u-op"))
        await asyncio.sleep(0.05)
        task.cancel()  # the repeat cancellation that ends the cancelled save's wait
        await asyncio.wait_for(task, 5)
        await store.drain_stragglers(timeout=0.0, grace=0.0)
        assert f"upload {meta.file_id} was cancelled after its file landed" in caplog.text
        assert "its removal was still running at shutdown" in caplog.text, caplog.text
        assert not store._pending_removals, "the drain left the removal holding later saves"
    finally:
        unhang.set()
    assert await asyncio.to_thread(removed.wait, 10)
    for _ in range(50):
        if "its removal finished after it was named at ERROR" in caplog.text:
            break
        await asyncio.sleep(0.02)
    assert "its removal finished after it was named at ERROR" in caplog.text, caplog.text
    assert await store.list_files() == []


async def test_a_repeated_cancel_does_not_spin_a_cancelled_save_on_its_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3740 item 4, the Lander's hold on PR 2645: the removal's wait absorbed every
    cancellation in a loop, under ``_quota_lock``, so an anyio scope, which cancels again on every
    loop pass, spun the cancelled save for the whole bound while every other upload queued. The
    cancelled save now stops waiting at the next cancellation, and the next save waits for the
    removal, without spinning, before it scans. Red before: A ran out the whole bound."""
    import anyio

    # Long enough that B is still inside it on a slow runner, so B is waiting, not past it.
    monkeypatch.setattr(uploads_mod, "_CANCELLED_REMOVAL_WAIT_SECONDS", 5.0)
    store = _uploads(tmp_path, None)
    landed, finish = _hold_after_the_sidecar_lands(monkeypatch)
    unhang = threading.Event()
    real_discard = store._discard_cancelled_sync

    def _hung_discard(file_id: str) -> bool:
        unhang.wait(30)  # bounded, so a red run cannot hang the suite
        return real_discard(file_id)

    monkeypatch.setattr(store, "_discard_cancelled_sync", _hung_discard)
    loop = asyncio.get_running_loop()
    ended: list[float] = []

    async def _a() -> None:
        try:
            await store.save(
                data=_ADT.encode(), filename="a.hl7", uploader="op", uploader_id="u-op"
            )
        finally:
            ended.append(loop.time())

    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(_a)
            try:
                assert await asyncio.to_thread(landed.wait, 10), "A's sidecar never landed"
                cancelled_at = loop.time()
                tg.cancel_scope.cancel()
            finally:
                finish.set()
        assert ended[0] - cancelled_at < 2.0, "A waited out the bound under repeated cancels"
        b = asyncio.create_task(
            store.save(data=b"second\n", filename="b.txt", uploader="op", uploader_id="u-op")
        )
        await asyncio.sleep(0.1)
        assert not b.done(), "B went on while A's pair was still being removed"
    finally:
        unhang.set()
    assert isinstance(await asyncio.wait_for(b, 10), UploadedFileMeta)
    assert [m.filename for m in await store.list_files()] == ["b.txt"]


async def test_the_drain_reads_its_default_waits_when_it_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3740 item 12: the drain's default waits were bound when the method was
    defined, so a changed module default never reached a caller that passed none."""
    monkeypatch.setattr(uploads_mod, "_STRAGGLER_DRAIN_SECONDS", 0.05)
    monkeypatch.setattr(uploads_mod, "_STRAGGLER_CANCEL_GRACE_SECONDS", 0.05)
    store = _uploads(tmp_path, None)
    stalled = asyncio.ensure_future(asyncio.Event().wait())
    store._hold(stalled)
    await asyncio.wait_for(store.drain_stragglers(), 1.0)
    assert stalled.cancelled()


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

        async def release_upload_quota(self, *, uploader_id: str, reservation_id: str) -> None:
            await asyncio.sleep(0.05)  # a release slower than the retry's reserve
            await self.store.release_upload_quota(
                uploader_id=uploader_id, reservation_id=reservation_id
            )

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

        async def release_upload_quota(self, *, uploader_id: str, reservation_id: str) -> None:
            released.append(reservation_id)
            await self.store.release_upload_quota(
                uploader_id=uploader_id, reservation_id=reservation_id
            )

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


async def test_the_managed_teardown_hands_the_straggler_drain_a_share_of_its_step_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The drain is one step of the teardown, under its one budget (BACKLOG #3191). Its own two
    waits together fit inside the share of the step's bound it is handed, so it cancels what is
    left before the teardown cuts the step, and neither wait exceeds the drain's own default."""
    from messagefoundry.api import app as app_module
    from messagefoundry.api import create_managed_app

    bounds: list[float] = []
    real_invoke = app_module._invoke

    async def _invoke(run: Any, bound: float) -> object:
        bounds.append(bound)
        return await real_invoke(run, bound)

    monkeypatch.setattr(app_module, "_invoke", _invoke)
    app = create_managed_app(
        store_settings=StoreSettings(
            path=str(tmp_path / "managed.db"),
            uploads_dir=str(tmp_path / "uploads"),
            max_upload_bytes=4096,
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    waits: list[tuple[float, float]] = []
    async with app.router.lifespan_context(app):
        bounds.clear()  # only the teardown's steps

        async def _drain(timeout: float, *, grace: float) -> None:
            waits.append((timeout, grace))
            bounds.append(-1.0)  # marks which step's bound precedes it

        app.state.upload_store.drain_stragglers = _drain
    [(timeout, grace)] = waits
    bound = bounds[bounds.index(-1.0) - 1]
    assert timeout + grace <= bound * app_module._INNER_SHARE + 1e-9
    assert timeout <= uploads_mod._STRAGGLER_DRAIN_SECONDS
    assert grace <= uploads_mod._STRAGGLER_CANCEL_GRACE_SECONDS
    assert grace > 0.0


@pytest.mark.parametrize(
    ("budget", "expected", "defaults"),
    [
        (0.3, (0.2, 0.1), None),
        (10.0, (2.0, 1.0), None),
        (0.0, (0.0, 0.0), None),
        # Vault BACKLOG #3740 item 17: the split moves with the defaults it is derived from. Red
        # before: two thirds was written by hand, so equal defaults still got (2/3, 1/3).
        (1.0, (0.5, 0.5), (1.0, 1.0)),
    ],
)
async def test_drain_stragglers_within_fits_both_waits_inside_the_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    budget: float,
    expected: tuple[float, float],
    defaults: tuple[float, float] | None,
) -> None:
    if defaults is not None:
        monkeypatch.setattr(uploads_mod, "_STRAGGLER_DRAIN_SECONDS", defaults[0])
        monkeypatch.setattr(uploads_mod, "_STRAGGLER_CANCEL_GRACE_SECONDS", defaults[1])
    store = _uploads(tmp_path, None)
    waits: list[tuple[float, float]] = []

    async def _drain(timeout: float, *, grace: float) -> None:
        waits.append((timeout, grace))

    store.drain_stragglers = _drain  # type: ignore[method-assign,assignment]
    await store.drain_stragglers_within(budget)
    [(timeout, grace)] = waits
    assert (timeout, grace) == pytest.approx(expected)
    assert timeout + grace <= budget + 1e-9


async def test_drain_stragglers_within_settles_first_inside_its_wait(tmp_path: Path) -> None:
    """Vault BACKLOG #3740 item 6: ``settle`` gets the wait's share, and the drain's own wait what
    it leaves; the grace is not touched."""
    store = _uploads(tmp_path, None)
    settled: list[float] = []
    waits: list[tuple[float, float]] = []

    async def _settle(timeout: float) -> None:
        settled.append(timeout)
        await asyncio.sleep(0.1)

    async def _drain(timeout: float, *, grace: float) -> None:
        waits.append((timeout, grace))

    store.drain_stragglers = _drain  # type: ignore[method-assign,assignment]
    await store.drain_stragglers_within(0.9, settle=_settle)
    [(timeout, grace)] = waits
    assert settled == [pytest.approx(0.6)]
    assert 0.0 <= timeout <= 0.5 + 0.02
    assert grace == pytest.approx(0.3)


async def test_the_embedded_teardown_drains_the_upload_stragglers(tmp_path: Path) -> None:
    """``create_app(engine=...)`` runs the same drains as the managed lifespan
    (``_app_drain_steps``), the upload store's included, so a caller that stops its engine after
    the app has shut down closes no store under a ledger call the drain waited for or cancelled.
    The drain is bounded, so one that outlives its grace can still meet the closed store."""
    from messagefoundry.api import create_app
    from messagefoundry.pipeline.engine import Engine

    engine = await Engine.create(
        tmp_path / "embedded.db", egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        app = create_app(engine)
        calls: list[str] = []

        class _Uploads:
            async def drain_stragglers_within(self, budget: float, **_kwargs: Any) -> None:
                calls.append("uploads")

        async def _outliving(timeout: float = 0.0, *, grace: float = 0.0) -> list[str]:
            calls.append("outliving")
            return []

        async with app.router.lifespan_context(app):
            app.state.upload_store = _Uploads()
            app.state.outliving_operations.drain = _outliving
        assert calls == ["outliving", "uploads"]
    finally:
        await engine.stop()


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
        async def release_upload_quota(self, *, uploader_id: str, reservation_id: str) -> None:
            await asyncio.sleep(0.05)  # slower than one loop pass, so only a wait covers it
            released.append(reservation_id)
            await self.store.release_upload_quota(
                uploader_id=uploader_id, reservation_id=reservation_id
            )

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
        async def release_upload_quota(self, *, uploader_id: str, reservation_id: str) -> None:
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


async def test_a_discard_cancelled_while_it_waits_for_the_lock_still_removes_the_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Review: a cancellation that reached discard while it waited for ``_quota_lock`` ended it
    there, so a stored file with no upload.create row stayed with no log. The removal now
    outlives the caller's cancel. Past the caller's bound it goes on held, and if the shutdown
    drain cancels it before it finishes, an ERROR names the file_id."""
    monkeypatch.setattr(uploads_mod, "_LEDGER_CANCEL_WAIT_SECONDS", 0.05)
    store = _uploads(tmp_path, None)
    kept = await store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    lost = await store.save(data=b"y\n", filename="b.txt", uploader="op", uploader_id="u-op")
    async with store._quota_lock:
        discard = asyncio.create_task(store.discard(kept.file_id))
        await asyncio.sleep(0.02)  # waiting for the lock
        discard.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(discard, 10)
        assert store._stragglers, "the removal stopped with its caller"
    assert await _settled(store), "the removal never finished"
    assert [m.file_id for m in await store.list_files()] == [lost.file_id]

    # The removal itself cut short, by the shutdown drain while the lock is still held: logged.
    async with store._quota_lock:
        discard = asyncio.create_task(store.discard(lost.file_id))
        await asyncio.sleep(0.02)
        discard.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(discard, 10)
        with caplog.at_level(logging.ERROR, logger="messagefoundry.uploads"):
            await store.drain_stragglers(timeout=0.0, grace=1.0)
    assert (
        f"upload {lost.file_id} has no upload.create audit row and its removal was cancelled"
        in (caplog.text)
    ), caplog.text


async def test_a_discard_whose_removal_is_cancelled_does_not_raise_into_its_caller(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Review: the removal's own cancellation surfaced as a CancelledError from a caller nobody
    cancelled, replacing the error the caller was handling. It is logged by file_id instead."""
    store = _uploads(tmp_path, None)
    meta = await store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    async with store._quota_lock:
        discard = asyncio.create_task(store.discard(meta.file_id))
        await asyncio.sleep(0.02)  # the removal waits for the lock
        with caplog.at_level(logging.ERROR, logger="messagefoundry.uploads"):
            await store.drain_stragglers(timeout=0.0, grace=1.0)
    await asyncio.wait_for(discard, 10)  # returns rather than raising the removal's cancel
    assert f"upload {meta.file_id} has no upload.create audit row" in caplog.text, caplog.text
