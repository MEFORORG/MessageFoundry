# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Where the DR backup and its restore-verify stage plaintext, and what removes it (BACKLOG #1174,
#1721 limb 3), plus the keyring walk that picks the archive's key (BACKLOG #1167).

A backup stages a plaintext tar of the store snapshot, and a verify stages the decrypted archive. On
a SQLite store both now stage in the store's own data directory, never in the OS temp dir, and are
removed on success, on an exception and on cancellation. What a crash or SIGKILL leaves is removed by
the NEXT backup's sweep, which goes by each directory's lock and never by its age, so a live run
beside it survives.

Every test here points the OS temp dir at an empty directory of its own and asserts it stays empty,
so "the plaintext went somewhere else" cannot pass as "the plaintext is gone"."""

from __future__ import annotations

import asyncio
import base64
import hmac
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupError, BackupRunner, run_restore_verify
from messagefoundry.store import MessageStore
from messagefoundry.store.backup_codec import key_fingerprint
from messagefoundry.store.crypto import generate_key, make_cipher

# --- helpers -----------------------------------------------------------------


def _isolate_os_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    iso = tmp_path / "ostemp"
    iso.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(iso))
    return iso


def _everything_under(root: Path) -> list[Path]:
    return sorted(root.rglob("*"))


def _staging_dirs(root: Path) -> list[Path]:
    return sorted(
        p
        for prefix in ("mefor-backup-", "mefor-verify-", "mefor-tar-")
        for p in root.glob(f"{prefix}*")
        if p.is_dir()
    )


async def _keyed_store(data_dir: Path, key_b64: str) -> MessageStore:
    data_dir.mkdir(parents=True, exist_ok=True)
    store = await MessageStore.open(data_dir / "msg.db", cipher=make_cipher(key_b64))
    await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|synthetic-body",
        deliveries=[("d1", "OUT|synthetic-delivery")],
        control_id="CID-1",
        now=1.0,
    )
    return store


def _runner(store: MessageStore, data_dir: Path, dest: Path, key_b64: str) -> BackupRunner:
    return BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(dest)),
        store_settings=StoreSettings(path=str(data_dir / "msg.db"), encryption_key=key_b64),
        config_dir=None,
        instance="dev",
    )


class _SnapshotSpy:
    """Wrap ``store.snapshot_to`` to record where the plaintext snapshot was written."""

    def __init__(self, store: MessageStore) -> None:
        self.dests: list[Path] = []
        self._real = store.snapshot_to

    async def __call__(self, dest_path: str | Path, *, method: str = "vacuum_into") -> None:
        self.dests.append(Path(dest_path))
        await self._real(dest_path, method=method)


# --- location: the data dir, never the OS temp dir -----------------------------


async def test_backup_and_verify_stage_in_the_sqlite_data_dir_and_leave_nothing(
    tmp_path, monkeypatch
) -> None:
    """The snapshot, the tar and the verify's decrypted copy all land in the store's data directory,
    each plaintext file is locked to its owner before its first byte, and nothing is left afterwards.
    Before BACKLOG #1174 all three staged under the OS temp dir with no ACL."""
    iso = _isolate_os_temp(tmp_path, monkeypatch)
    data_dir = tmp_path / "data"
    key = generate_key()
    store = await _keyed_store(data_dir, key)
    spy = _SnapshotSpy(store)
    monkeypatch.setattr(store, "snapshot_to", spy)
    counted: list[Path] = []
    real_count = dr_backup._count_tables

    def count(db_path: Path) -> dict[str, int]:
        counted.append(Path(db_path))
        return real_count(db_path)

    monkeypatch.setattr(dr_backup, "_count_tables", count)
    from messagefoundry.store import store as store_mod

    secured: list[Path] = []
    real_secure = store_mod._secure_file

    def secure(path: Path, **kw: object) -> None:
        secured.append(Path(path))
        real_secure(path, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(store_mod, "_secure_file", secure)

    result = await _runner(store, data_dir, tmp_path / "dest", key).run_once(now=1.0)
    await store.close()

    assert result is not None and result.verify is not None and result.verify.ok
    (snap,) = spy.dests
    assert snap.parent.parent == data_dir.absolute(), snap
    assert snap.parent.name.startswith("mefor-backup-")
    # The verify's extracted copy is the one `_count_tables` read under a `mefor-verify-` dir.
    verify_reads = [p for p in counted if p.parent.name.startswith("mefor-verify-")]
    assert verify_reads and all(p.parent.parent == data_dir.absolute() for p in verify_reads)
    # The build's tar, the verify's tar and the verify's extracted store were each secured.
    secured_names = {(p.parent.name.split("-")[1], p.name) for p in secured}
    assert {
        ("backup", "archive.tar"),
        ("verify", "archive.tar"),
        ("verify", "extracted_store.db"),
    } <= secured_names
    assert _staging_dirs(data_dir) == []
    assert _everything_under(iso) == []


def test_a_server_db_store_stages_under_the_destination_unsecured(tmp_path) -> None:
    """A server-DB store has no data directory, so it stages in `.mefor-staging` under the backup
    destination. The engine applies no ACL there, and docs/PHI.md records that as a gap."""
    dest = tmp_path / "dest"
    root, secure = dr_backup._staging_root_for(
        server_db=True, store_path=str(tmp_path / "ignored.db"), destination=dest
    )
    assert root == dest.absolute() / ".mefor-staging"
    assert secure is False
    # An in-memory SQLite store has no data directory either.
    root, secure = dr_backup._staging_root_for(
        server_db=False, store_path=":memory:", destination=dest
    )
    assert root == dest.absolute() / ".mefor-staging" and secure is False
    # A SQLite store on disk stages beside itself, secured.
    root, secure = dr_backup._staging_root_for(
        server_db=False, store_path=str(tmp_path / "data" / "msg.db"), destination=dest
    )
    assert root == (tmp_path / "data").absolute() and secure is True


async def test_standalone_restore_verify_stages_in_the_data_dir(tmp_path, monkeypatch) -> None:
    """`restore-verify` and the cold-seed activation stage where the backup stages, not in the OS
    temp dir (#1721 limb 3)."""
    data_dir = tmp_path / "data"
    key = generate_key()
    store = await _keyed_store(data_dir, key)
    result = await _runner(store, data_dir, tmp_path / "dest", key).run_once(now=1.0)
    await store.close()
    assert result is not None

    iso = _isolate_os_temp(tmp_path, monkeypatch)
    seen: list[Path] = []
    real_count = dr_backup._count_tables

    def count(db_path: Path) -> dict[str, int]:
        seen.append(Path(db_path))
        return real_count(db_path)

    monkeypatch.setattr(dr_backup, "_count_tables", count)
    res = await run_restore_verify(
        result.archive_path,
        store_settings=StoreSettings(path=str(data_dir / "msg.db"), encryption_key=key),
    )
    assert res.ok, res.reason
    assert seen and all(p.parent.parent == data_dir.absolute() for p in seen)
    assert _staging_dirs(data_dir) == []
    assert _everything_under(iso) == []


# --- cleanup on every failure path ----------------------------------------------


async def test_a_build_that_raises_leaves_no_staging_behind(tmp_path, monkeypatch) -> None:
    """An exception after the plaintext snapshot is staged: the run fails, and the staging directory
    goes with it. Nothing ever reached the OS temp dir."""
    iso = _isolate_os_temp(tmp_path, monkeypatch)
    data_dir = tmp_path / "data"
    key = generate_key()
    store = await _keyed_store(data_dir, key)
    spy = _SnapshotSpy(store)
    monkeypatch.setattr(store, "snapshot_to", spy)

    def boom(*_a: object, **_kw: object) -> None:
        raise OSError("synthetic write failure after the snapshot")

    monkeypatch.setattr(dr_backup, "encrypt_stream", boom)
    with pytest.raises(BackupError):
        await _runner(store, data_dir, tmp_path / "dest", key).run_once(now=1.0)
    await store.close()

    (snap,) = spy.dests
    assert snap.parent.parent == data_dir.absolute()
    assert not snap.parent.exists()
    assert _staging_dirs(data_dir) == []
    assert _everything_under(iso) == []


async def test_a_run_cancelled_during_the_snapshot_leaves_no_staging_behind(
    tmp_path, monkeypatch
) -> None:
    """Cancellation on the loop, the engine-stop path, after the snapshot is on disk."""
    iso = _isolate_os_temp(tmp_path, monkeypatch)
    data_dir = tmp_path / "data"
    key = generate_key()
    store = await _keyed_store(data_dir, key)
    real = store.snapshot_to
    written: list[Path] = []
    parked = asyncio.Event()

    async def snapshot_then_park(dest_path: str | Path, *, method: str = "vacuum_into") -> None:
        await real(dest_path, method=method)
        written.append(Path(dest_path))
        parked.set()
        await asyncio.Event().wait()  # until cancelled

    monkeypatch.setattr(store, "snapshot_to", snapshot_then_park)
    task = asyncio.create_task(_runner(store, data_dir, tmp_path / "dest", key).run_once(now=1.0))
    await asyncio.wait_for(parked.wait(), 30)
    (snap,) = written
    assert snap.is_file() and snap.parent.parent == data_dir.absolute()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await store.close()

    assert not snap.parent.exists()
    assert _staging_dirs(data_dir) == []
    assert _everything_under(iso) == []


async def test_a_run_cancelled_during_the_build_is_cleaned_up_by_its_worker(
    tmp_path, monkeypatch
) -> None:
    """A build cancelled on the loop keeps running on its worker thread. Its staging directory stays
    locked while the worker still uses it, so neither the loop nor a sweep tears it down under the
    worker, and the worker removes it once it lets go."""
    iso = _isolate_os_temp(tmp_path, monkeypatch)
    data_dir = tmp_path / "data"
    key = generate_key()
    store = await _keyed_store(data_dir, key)
    entered = threading.Event()
    release = threading.Event()
    real_build = BackupRunner._build_archive_blocking

    def slow_build(self: BackupRunner, **kw: object) -> tuple[str, dict[str, int], int]:
        entered.set()
        assert release.wait(30), "the test never released the build"
        return real_build(self, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(BackupRunner, "_build_archive_blocking", slow_build)
    task = asyncio.create_task(_runner(store, data_dir, tmp_path / "dest", key).run_once(now=1.0))
    assert await asyncio.to_thread(entered.wait, 30)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The worker still holds the directory, and a sweep proves it live rather than abandoned.
    (live,) = _staging_dirs(data_dir)
    assert await asyncio.to_thread(dr_backup._sweep_abandoned_staging, data_dir.absolute()) == 0
    assert live.is_dir()

    release.set()
    deadline = time.monotonic() + 30
    while live.exists() and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    await store.close()
    assert not live.exists(), "the worker did not remove its staging directory"
    assert _everything_under(iso) == []


# --- the orphan sweep: by lock, never by age, and never at serve start ------------------


def _abandoned(root: Path, prefix: str) -> Path:
    """A staging directory whose run died: made the real way, holding plaintext, then its handle
    closed with nothing removed, which is what a crash or SIGKILL leaves."""
    work = dr_backup._open_staging(root, prefix, secure=False)
    (work.path / "archive.tar").write_bytes(b"synthetic plaintext")
    dr_backup._unlock_and_close(work._fd)
    return work.path


def _aged(path: Path, days: int = 30) -> None:
    old = time.time() - days * 86400
    os.utime(path, (old, old))


def test_the_sweep_removes_only_what_a_lock_proves_abandoned(tmp_path) -> None:
    root = tmp_path / "data"
    dead_backup = _abandoned(root, "mefor-backup-")
    dead_verify = _abandoned(root, "mefor-verify-")
    live = dr_backup._open_staging(root, "mefor-backup-", secure=False)
    (live.path / "store.db").write_bytes(b"synthetic plaintext")
    _aged(live.path)  # old enough for any age rule; it must survive anyway
    no_lock = root / "mefor-backup-nolock"
    no_lock.mkdir()
    (no_lock / "archive.tar").write_bytes(b"synthetic")
    no_marker = root / "mefor-verify-nomarker"
    no_marker.mkdir()
    (no_marker / ".lock").write_bytes(b"")
    unrelated = root / "not-ours"
    unrelated.mkdir()
    try:
        swept = dr_backup._sweep_abandoned_staging(root)
        assert swept == 2
        assert not dead_backup.exists() and not dead_verify.exists()
        assert (live.path / "store.db").read_bytes() == b"synthetic plaintext"
        assert no_lock.is_dir() and no_marker.is_dir() and unrelated.is_dir()
    finally:
        assert live.release() is None
    assert not live.path.exists()


async def test_a_live_runs_staging_survives_a_concurrent_sweep(tmp_path, monkeypatch) -> None:
    """A sibling engine shard sweeping the same data directory while this run is mid-backup: the
    sweep removes the dead run's directory and leaves this one, and this run completes."""
    iso = _isolate_os_temp(tmp_path, monkeypatch)
    data_dir = tmp_path / "data"
    key = generate_key()
    store = await _keyed_store(data_dir, key)
    dead = _abandoned(data_dir.absolute(), "mefor-backup-")
    real = store.snapshot_to
    observed: dict[str, object] = {}

    async def snapshot_then_sibling_sweeps(
        dest_path: str | Path, *, method: str = "vacuum_into"
    ) -> None:
        # This run's own sweep already ran and removed `dead`. Re-create a dead one so the sibling's
        # sweep has something to take, then sweep from another thread, as another engine would.
        observed["dead_gone_before"] = not dead.exists()
        second_dead = _abandoned(data_dir.absolute(), "mefor-verify-")
        await real(dest_path, method=method)
        swept = await asyncio.to_thread(dr_backup._sweep_abandoned_staging, data_dir.absolute())
        observed["swept"] = swept
        observed["second_dead_gone"] = not second_dead.exists()
        observed["own_snapshot_survived"] = Path(dest_path).is_file()

    monkeypatch.setattr(store, "snapshot_to", snapshot_then_sibling_sweeps)
    result = await _runner(store, data_dir, tmp_path / "dest", key).run_once(now=1.0)
    await store.close()

    assert observed == {
        "dead_gone_before": True,
        "swept": 1,
        "second_dead_gone": True,
        "own_snapshot_survived": True,
    }
    assert result is not None and result.verify is not None and result.verify.ok
    assert _staging_dirs(data_dir) == []
    assert _everything_under(iso) == []


async def test_the_sweep_runs_at_the_next_backup_never_at_serve_start(
    tmp_path, monkeypatch
) -> None:
    data_dir = tmp_path / "data"
    key = generate_key()
    store = await _keyed_store(data_dir, key)
    dead = _abandoned(data_dir.absolute(), "mefor-backup-")
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "dest"), schedule_at="02:00"),
        store_settings=StoreSettings(path=str(data_dir / "msg.db"), encryption_key=key),
        config_dir=None,
        instance="dev",
    )
    monkeypatch.setattr(runner, "_backup_due", lambda _now: False)
    runner.start()
    await asyncio.sleep(0.05)
    await runner.stop()
    assert dead.is_dir(), "serve start swept a staging directory"

    await runner.run_once(now=1.0)
    await store.close()
    assert not dead.exists(), "the next backup did not sweep the abandoned directory"


# --- #1167: the keyring walk visits every key ------------------------------------------


@pytest.mark.parametrize("match_at", [0, 1, 2])
def test_key_selection_walks_every_key_with_a_constant_time_compare(monkeypatch, match_at) -> None:
    keys = [base64.b64decode(generate_key()) for _ in range(3)]
    header_key_id = key_fingerprint(keys[match_at])
    fingerprinted: list[bytes] = []
    compared = 0
    real_fp = key_fingerprint
    real_cmp = hmac.compare_digest

    def fp(key: bytes) -> str:
        fingerprinted.append(key)
        return real_fp(key)

    def cmp(a: bytes, b: bytes) -> bool:
        nonlocal compared
        compared += 1
        return real_cmp(a, b)

    monkeypatch.setattr(dr_backup, "key_fingerprint", fp)
    monkeypatch.setattr(hmac, "compare_digest", cmp)
    assert dr_backup._select_decrypt_key(keys, header_key_id) is keys[match_at]
    assert fingerprinted == keys, "the walk stopped before the end of the keyring"
    assert compared == len(keys)


def test_key_selection_keeps_first_match_and_reports_none(monkeypatch) -> None:
    key = base64.b64decode(generate_key())
    twin = bytes(bytearray(key))  # equal bytes, a distinct object
    assert twin == key and twin is not key
    assert dr_backup._select_decrypt_key([key, twin], key_fingerprint(key)) is key
    other = base64.b64decode(generate_key())
    assert dr_backup._select_decrypt_key([other], key_fingerprint(key)) is None
    assert dr_backup._select_decrypt_key([], key_fingerprint(key)) is None
