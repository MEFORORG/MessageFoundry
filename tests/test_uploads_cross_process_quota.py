# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 2.3.4 — the per-uploader upload quota must hold ACROSS processes, not only within one.

BACKLOG #1112's surviving half. ``UploadStore._quota_lock`` is an ``asyncio.Lock``, so it is
per-event-loop and therefore per-process. Engine sharding is the built, shipped, default scaling
axis, and nothing partitions ``uploads_dir`` per shard, so N shards over one directory hold N
independent locks: each can be between its own scan and its own file landing on disk while the
others scan, and each of those overshoots the budget by one file.

**What the two shipped tests already prove, and what they do NOT.**
``tests/test_uploads.py::test_quota_is_shared_by_stores_over_one_dir_not_per_process`` is
SEQUENTIAL — it proves the sidecar scan is uncached, so a second store SEES the first's files. That
is shared visibility, not exclusion.
``tests/test_uploads.py::test_concurrent_uploads_cannot_double_book_the_quota`` is concurrent but
lives on ONE ``UploadStore`` in ONE event loop, so the per-process lock is sufficient there by
construction. Neither one can fail on the cross-process defect.

**What this rig models, and what it does not.** Two OS threads, each running its OWN event loop,
its OWN ``MessageStore`` connection and its OWN ``UploadStore`` over the ONE shared uploads
directory. For the property under test that is a faithful stand-in for two ``serve --shard``
processes: two independent ``asyncio.Lock`` objects (so the shipped intra-process control provides
exactly zero protection between them) and two independent database connections over one file.

It is NOT a two-process ``serve --shard`` run, and it CANNOT be one on SQLite:
``messagefoundry/pipeline/sharding.py::require_unified_store`` raises on any non-server backend for
more than one distinct shard id, and ``supervise`` calls it before spawning anything. So this rig
exercises the SQLite implementation of the cross-process reservation; the Postgres and SQL Server
implementations of the same one protocol method are the ones a real sharded deployment would run,
and they are not exercised here.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from messagefoundry import uploads as uploads_mod
from messagefoundry.store.base import UPLOAD_RESERVATION_STALE_AFTER
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from messagefoundry.uploads import UploadedFileMeta, UploadQuotaError, UploadStore

#: Long enough that thread-scheduling jitter cannot separate the two scans, short enough to keep the
#: test quick. Only the BROKEN path needs it: with the reservation in place the two shards are
#: ordered by the database, not by this sleep.
_SCAN_OVERLAP_SECONDS = 0.15


def _shard_result(
    *,
    db_path: Path,
    uploads_dir: Path,
    key: str,
    barrier: threading.Barrier,
    filename: str,
    body: bytes,
    bind_store: bool,
) -> object:
    """One shard: its own loop, its own store connection, its own UploadStore. Returns the save's
    result, or the exception it raised (so the caller can classify both shards' outcomes)."""

    async def _run() -> object:
        store = await MessageStore.open(db_path)
        try:
            uploads = UploadStore(
                uploads_dir,
                make_cipher(key),  # one DEK across the fleet — a per-shard key would fake isolation
                max_bytes=4096,
                max_files_per_user=1,
                store=store if bind_store else None,
            )
            real_scan = uploads._scan_metas_sync

            def _slow_scan() -> list[UploadedFileMeta]:
                out = real_scan()
                time.sleep(_SCAN_OVERLAP_SECONDS)  # widen the scan -> write window
                return out

            uploads._scan_metas_sync = _slow_scan  # type: ignore[method-assign]
            barrier.wait(timeout=30)
            return await uploads.save(
                data=body, filename=filename, uploader="alice", uploader_id="u-alice"
            )
        finally:
            await store.close()

    try:
        return asyncio.run(_run())
    except BaseException as exc:  # noqa: BLE001 — the exception IS the result being classified
        return exc


def _race_two_shards(tmp_path: Path, *, bind_store: bool) -> tuple[list[object], list[Path]]:
    """Run two shards concurrently over one uploads dir; return (outcomes, sidecars-on-disk)."""
    db_path = tmp_path / "engine.db"
    uploads_dir = tmp_path / "uploads"
    key = generate_key()
    # Create the schema up front so the two shards never race each other on DDL — the race under
    # test is the quota one, and a "database is locked" here would be a fixture artifact.
    asyncio.run(_open_and_close(db_path))

    barrier = threading.Barrier(2)
    outcomes: dict[str, object] = {}

    def _worker(name: str, filename: str, body: bytes) -> None:
        outcomes[name] = _shard_result(
            db_path=db_path,
            uploads_dir=uploads_dir,
            key=key,
            barrier=barrier,
            filename=filename,
            body=body,
            bind_store=bind_store,
        )

    threads = [
        threading.Thread(target=_worker, args=("a", "from_a.txt", b"from shard a\n")),
        threading.Thread(target=_worker, args=("b", "from_b.txt", b"from shard b\n")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not any(t.is_alive() for t in threads), "a shard thread hung"

    sidecars = sorted(uploads_dir.glob("*.meta")) if uploads_dir.exists() else []
    return [outcomes["a"], outcomes["b"]], sidecars


async def _open_and_close(db_path: Path) -> None:
    store = await MessageStore.open(db_path)
    await store.close()


def test_two_shard_concurrent_uploads_cannot_double_book_the_quota(tmp_path: Path) -> None:
    """The acceptance criterion from BACKLOG #1112: concurrent writers on two shards sharing one
    uploads_dir enforce ONE budget between them, with overshoot zero."""
    outcomes, sidecars = _race_two_shards(tmp_path, bind_store=True)

    won = [o for o in outcomes if isinstance(o, UploadedFileMeta)]
    refused = [o for o in outcomes if isinstance(o, UploadQuotaError)]
    other = [o for o in outcomes if not isinstance(o, UploadedFileMeta | UploadQuotaError)]

    assert not other, f"a shard failed for a reason that is not the quota: {other!r}"
    assert len(won) == 1, (
        "exactly one shard may win a quota of 1; the per-process asyncio.Lock does not span "
        f"processes, so both can pass the check. outcomes={outcomes!r}"
    )
    assert len(refused) == 1, f"the losing shard must be refused on quota. outcomes={outcomes!r}"
    # Which LIMB refused matters. If the loser's scan had simply seen the winner's file already on
    # disk, this test would pass on the shipped code and prove nothing about cross-process exclusion
    # (that is precisely the hole in the sequential shipped test). Pin the reservation's own wording,
    # which is only reachable when the scan left headroom and another shard consumed it.
    assert "another engine shard is mid-upload" in str(refused[0]), (
        "the loser must be refused by the cross-shard reservation, not by a scan that happened to "
        f"see the winner's file: {refused[0]!r}"
    )
    # Print what was matched, not just how many: the sidecar filenames ARE the overshoot.
    assert len(sidecars) == 1, (
        f"overshoot: {len(sidecars)} files landed for a budget of 1 -> {[p.name for p in sidecars]}"
    )


def test_the_reservation_is_released_so_the_next_upload_is_not_locked_out(tmp_path: Path) -> None:
    """A reservation that is not released would permanently consume budget. Positive control that
    the SAME shard can keep uploading up to (and only up to) the cap after a winning save."""

    async def _run() -> None:
        store = await MessageStore.open(tmp_path / "engine.db")
        try:
            uploads = UploadStore(
                tmp_path / "uploads",
                make_cipher(generate_key()),
                max_bytes=4096,
                max_files_per_user=2,
                store=store,
            )
            for i in range(2):
                await uploads.save(
                    data=f"body {i}\n".encode(),
                    filename=f"f{i}.txt",
                    uploader="alice",
                    uploader_id="u-alice",
                )
            assert len(await uploads.list_files()) == 2
            # The cap, not a stuck reservation, is what refuses the third.
            with pytest.raises(UploadQuotaError) as exc:
                await uploads.save(
                    data=b"third\n", filename="f2.txt", uploader="alice", uploader_id="u-alice"
                )
            assert "the limit is 2" in str(exc.value), str(exc.value)
            # And the ledger itself is back at zero in-flight: a reserve with a headroom of exactly
            # one succeeds, which it could not if either completed save had left a slot outstanding.
            assert await store.reserve_upload_quota(
                "u-alice", files=1, size_bytes=1, max_files=1, max_total_bytes=1
            ), "a completed upload left its reservation outstanding"
        finally:
            await store.close()

    asyncio.run(_run())


def test_a_leaked_reservation_is_reclaimed_once_it_goes_stale(tmp_path: Path) -> None:
    """A process killed between reserve and release leaks its reservation. It must not consume the
    uploader's budget forever: a row with no activity for longer than ``stale_after`` is reset on
    the next reserve."""

    async def _run() -> None:
        store = await MessageStore.open(tmp_path / "engine.db")
        try:
            # Simulate the crash: reserve, never release.
            assert await store.reserve_upload_quota(
                "u-alice", files=1, size_bytes=10, max_files=1, max_total_bytes=100
            )
            # A live reservation blocks the next one (this is the control that the leak is real).
            assert not await store.reserve_upload_quota(
                "u-alice", files=1, size_bytes=10, max_files=1, max_total_bytes=100
            )
            # Once stale, the same call succeeds — the leak self-heals.
            assert await store.reserve_upload_quota(
                "u-alice",
                files=1,
                size_bytes=10,
                max_files=1,
                max_total_bytes=100,
                stale_after=0.0,
            )
        finally:
            await store.close()

    asyncio.run(_run())


@asynccontextmanager
async def _a_save_held_mid_write(
    tmp_path: Path,
) -> AsyncIterator[tuple[MessageStore, UploadStore, asyncio.Future[UploadedFileMeta]]]:
    """Shard A: a save over a fresh store, held inside its write with its reservation taken. On
    exit the write is released, the save settles, and its heartbeat is given time to end before
    the store closes, so a test failure never strands a cancel-resistant write thread."""
    store = await MessageStore.open(tmp_path / "engine.db")
    try:
        uploads = UploadStore(
            tmp_path / "uploads",
            make_cipher(generate_key()),
            max_bytes=4096,
            max_files_per_user=1,
            store=store,
        )
        entered, gate = threading.Event(), threading.Event()
        real_encrypt = uploads._encrypt_blob

        def _held(data: bytes, file_id: str) -> str:
            entered.set()
            gate.wait(timeout=30)
            return real_encrypt(data, file_id)

        uploads._encrypt_blob = _held  # type: ignore[method-assign]
        save = asyncio.ensure_future(
            uploads.save(data=b"slow\n", filename="a.txt", uploader="alice", uploader_id="u-alice")
        )
        try:
            assert await asyncio.to_thread(entered.wait, 30), "the save never reached its write"
            yield store, uploads, save
        finally:
            gate.set()
            await asyncio.gather(save, return_exceptions=True)
            if uploads._heartbeats:
                await asyncio.wait(set(uploads._heartbeats), timeout=10)
    finally:
        await store.close()


@pytest.mark.parametrize(("heartbeat", "reclaimed"), [(0.05, False), (3600.0, True)])
def test_a_slow_save_keeps_its_slot_past_the_staleness_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, heartbeat: float, reclaimed: bool
) -> None:
    """BACKLOG #2648. Shard A's save is held mid-write for twice the staleness window, and then a
    sibling shard reserves against a budget of one file. With the heartbeat the sibling sees A's
    slot and is refused. The 3600 s arm is the control: no touch lands in time, the store reclaims
    A's live slot, and the sibling's reserve applies, which is the double-book this closes."""
    monkeypatch.setattr(uploads_mod, "_RESERVATION_HEARTBEAT_SECONDS", heartbeat)

    async def _run() -> bool:
        async with _a_save_held_mid_write(tmp_path) as (store, uploads, save):
            await asyncio.sleep(0.6)
            applied = await store.reserve_upload_quota(
                "u-alice", files=1, size_bytes=5, max_files=1, max_total_bytes=4096, stale_after=0.3
            )
        assert isinstance(save.result(), UploadedFileMeta)
        assert not uploads._heartbeats, "the heartbeat outlived its save"
        return applied

    assert asyncio.run(_run()) is reclaimed


def test_the_heartbeat_stops_at_its_lifetime_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A save whose write never finishes must not pin the row for as long as the process lives.
    Past the cap the heartbeat stops with a WARNING, while the save is still held mid-write."""
    monkeypatch.setattr(uploads_mod, "_RESERVATION_HEARTBEAT_SECONDS", 0.02)
    monkeypatch.setattr(uploads_mod, "_RESERVATION_HEARTBEAT_MAX_SECONDS", 0.1)

    async def _run() -> None:
        async with _a_save_held_mid_write(tmp_path) as (_store, uploads, save):
            for _ in range(500):
                if "no longer refreshed" in caplog.text:
                    break
                await asyncio.sleep(0.02)
            assert "no longer refreshed" in caplog.text, "the heartbeat ran past its cap"
            await asyncio.sleep(0.05)  # the task leaves the set on its done callback
            assert not uploads._heartbeats
            assert not save.done()

    with caplog.at_level("WARNING", logger=uploads_mod._log.name):
        asyncio.run(_run())


def test_a_lagging_clock_never_moves_the_row_backwards(tmp_path: Path) -> None:
    """BACKLOG #2648. ``since`` is stamped from each writer's own clock. A shard whose clock lags
    must not age a row a sibling keeps fresh, or the sibling's next reserve reclaims live slots.
    The row is stamped well ahead, but inside one window, to stand in for the sibling; a reserve,
    a release and a touch from this host must all leave that stamp where it is."""

    async def _run() -> None:
        store = await MessageStore.open(tmp_path / "engine.db")
        try:
            assert await store.reserve_upload_quota(
                "u-alice", files=1, size_bytes=10, max_files=5, max_total_bytes=100
            )
            ahead = time.time() + UPLOAD_RESERVATION_STALE_AFTER * 2 / 3
            await store._db.execute(
                "UPDATE upload_quota SET since = ? WHERE uploader_id = ?", (ahead, "u-alice")
            )
            await store._db.commit()
            assert await store.reserve_upload_quota(
                "u-alice", files=1, size_bytes=10, max_files=5, max_total_bytes=100
            )
            await store.reserve_upload_quota("u-alice", files=-1, size_bytes=-10)
            await store.reserve_upload_quota("u-alice", files=0, size_bytes=0)
            cur = await store._db.execute(
                "SELECT since FROM upload_quota WHERE uploader_id = ?", ("u-alice",)
            )
            row = await cur.fetchone()
            assert row is not None and float(row[0]) == ahead
        finally:
            await store.close()

    asyncio.run(_run())


def test_a_stamp_more_than_a_window_ahead_does_not_pin_a_leaked_slot(tmp_path: Path) -> None:
    """BACKLOG #2648, code review. Never-backwards alone let one write from a host whose clock ran
    far ahead pin the row's clock in the future, so a slot leaked later never went stale. Here the
    leaked slot fills the budget, so without the fix every reserve is refused and the row is never
    written again. A stamp more than a window ahead is not trusted: the reserve reclaims the slot
    and restamps the row with now. A release restamps it too."""

    async def _run() -> None:
        store = await MessageStore.open(tmp_path / "engine.db")
        try:
            assert await store.reserve_upload_quota(
                "u-alice", files=1, size_bytes=10, max_files=1, max_total_bytes=100
            )
            year = time.time() + 365 * 86_400.0
            for writer in ("reserve", "release"):
                await store._db.execute(
                    "UPDATE upload_quota SET since = ? WHERE uploader_id = ?", (year, "u-alice")
                )
                await store._db.commit()
                before = time.time()
                if writer == "reserve":
                    assert await store.reserve_upload_quota(
                        "u-alice", files=1, size_bytes=10, max_files=1, max_total_bytes=100
                    ), "a slot under a future stamp was never reclaimed"
                    assert await store.upload_quota_in_flight("u-alice") == (1, 10)
                else:
                    await store.reserve_upload_quota("u-alice", files=0, size_bytes=0)
                cur = await store._db.execute(
                    "SELECT since FROM upload_quota WHERE uploader_id = ?", ("u-alice",)
                )
                row = await cur.fetchone()
                assert row is not None and before <= float(row[0]) <= time.time(), writer
        finally:
            await store.close()

    asyncio.run(_run())


def test_the_heartbeat_fits_three_times_inside_the_staleness_window() -> None:
    """The heartbeat interval is written out in ``uploads`` to keep that module a leaf. Pin it to
    the store's window, so a change to either cannot leave a live save reclaimable."""
    assert uploads_mod._RESERVATION_HEARTBEAT_SECONDS * 3 <= UPLOAD_RESERVATION_STALE_AFTER


def test_an_unbound_upload_store_still_enforces_the_in_process_budget(tmp_path: Path) -> None:
    """``store=None`` (the store-less embedding/test construction path) must not regress: the
    per-process quota still refuses an over-budget upload. It buys NO cross-process exclusion —
    that is the documented degradation, not a second control."""

    async def _run() -> None:
        uploads = UploadStore(
            tmp_path / "uploads",
            make_cipher(generate_key()),
            max_bytes=4096,
            max_files_per_user=1,
            store=None,
        )
        await uploads.save(
            data=b"only\n", filename="a.txt", uploader="alice", uploader_id="u-alice"
        )
        with pytest.raises(UploadQuotaError):
            await uploads.save(
                data=b"second\n", filename="b.txt", uploader="alice", uploader_id="u-alice"
            )

    asyncio.run(_run())
