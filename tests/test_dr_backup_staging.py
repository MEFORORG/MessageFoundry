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
    try:
        task = asyncio.create_task(
            _runner(store, data_dir, tmp_path / "dest", key).run_once(now=1.0)
        )
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
        assert not live.exists(), "the worker did not remove its staging directory"
        assert _everything_under(iso) == []
    finally:
        release.set()
        await store.close()


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
    try:
        runner.start()
        await asyncio.sleep(0.05)
        await runner.stop()
        assert dead.is_dir(), "serve start swept a staging directory"

        await runner.run_once(now=1.0)
        assert not dead.exists(), "the next backup did not sweep the abandoned directory"
    finally:
        await store.close()


def test_a_teardown_that_half_fails_leaves_proof_for_the_next_sweep(tmp_path, monkeypatch) -> None:
    """A refused removal can take the lock file and marker with it (on NTFS the dot-names list first)
    and stop at a file something holds. The teardown puts both back, so the next sweep can still prove
    the directory abandoned rather than skipping it for good."""
    root = tmp_path / "data"
    work = dr_backup._open_staging(root, "mefor-verify-", secure=False)
    (work.path / "extracted_store.db").write_bytes(b"synthetic plaintext")
    real_remove = dr_backup._remove_tree

    def remove_the_dot_names_then_fail(path: Path) -> bool:
        for name in (".lock", ".lock-held"):
            (path / name).unlink(missing_ok=True)
        return False

    monkeypatch.setattr(dr_backup, "_remove_tree", remove_the_dot_names_then_fail)
    monkeypatch.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", (0.0,))
    assert work.release() is None  # emptied in place, so no plaintext is reported
    assert work.path.is_dir()
    assert (work.path / ".lock").exists() and (work.path / ".lock-held").exists()

    monkeypatch.setattr(dr_backup, "_remove_tree", real_remove)
    assert dr_backup._sweep_abandoned_staging(root) == 1
    assert not work.path.exists()


def test_the_fail_safe_never_truncates_a_hard_linked_file(tmp_path) -> None:
    """The sweep runs the truncate fail-safe on directories it did not make this run. A file there with
    a second link shares its bytes with a name outside, so it is reported, never truncated."""
    staging = tmp_path / "mefor-verify-planted"
    staging.mkdir()
    outside = tmp_path / "outside.dat"
    outside.write_bytes(b"not the engine's to empty")
    try:
        os.link(outside, staging / "link.dat")
    except OSError as exc:  # pragma: no cover - a file system without hard links
        pytest.skip(f"hard links unavailable here: {exc}")
    (staging / "own.tar").write_bytes(b"synthetic plaintext")

    unproven = dr_backup._empty_files_in_place(staging)
    assert unproven == ["link.dat (hard-linked, not truncated)"]
    assert outside.read_bytes() == b"not the engine's to empty"
    assert (staging / "own.tar").read_bytes() == b""


async def test_a_config_dir_holding_the_data_dir_does_not_bundle_the_staging(
    tmp_path, monkeypatch
) -> None:
    """With the store inside the config dir, the backup's own staging sits inside it too. Its plaintext
    snapshot and the tar being written must not be tarred into the config bundle."""
    import tarfile

    from messagefoundry.store.backup_codec import decrypt_stream

    _isolate_os_temp(tmp_path, monkeypatch)
    cfg = tmp_path / "cfg"
    key = generate_key()
    store = await _keyed_store(cfg, key)
    (cfg / "connections.toml").write_text("# synthetic\n", encoding="utf-8")
    # An operator's own directory that merely shares a prefix, with no lock file, stays in.
    lookalike = cfg / "codesets" / "mefor-verify-maps"
    lookalike.mkdir(parents=True)
    (lookalike / "map.csv").write_text("a,b\n", encoding="utf-8")
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "dest")),
        store_settings=StoreSettings(path=str(cfg / "msg.db"), encryption_key=key),
        config_dir=cfg,
        instance="dev",
    )
    try:
        result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None
    tar_path = tmp_path / "out.tar"
    with open(result.archive_path, "rb") as src, open(tar_path, "wb") as dst:
        decrypt_stream(src, dst, base64.b64decode(key))
    with tarfile.open(tar_path, "r:") as tar:
        names = tar.getnames()
    assert "config/connections.toml" in names
    staged = [n for n in names if "mefor-backup-" in n or "mefor-verify-" in n]
    assert staged == ["config/codesets/mefor-verify-maps/map.csv"], names


async def test_a_failed_build_names_its_leftover_in_the_audited_error(
    tmp_path, monkeypatch
) -> None:
    """When the build fails AND its teardown leaves plaintext, the error the audit row records names
    the directory first, so the 200-character cut of the failure record cannot drop it."""
    import json

    data_dir = tmp_path / "data"
    key = generate_key()
    store = await _keyed_store(data_dir, key)
    real_teardown = dr_backup._teardown_staging
    leftover = "the plaintext staging directory SYNTHETIC-DIR could not be removed"

    def teardown_fails(path: Path) -> str | None:
        real_teardown(path)
        return leftover

    def boom(*_a: object, **_kw: object) -> None:
        raise OSError("synthetic write failure " + "x" * 300)

    monkeypatch.setattr(dr_backup, "_teardown_staging", teardown_fails)
    monkeypatch.setattr(dr_backup, "encrypt_stream", boom)
    try:
        with pytest.raises(BackupError) as caught:
            await _runner(store, data_dir, tmp_path / "dest", key).run_once(now=1.0)
        rows = [r for r in await store.list_audit(limit=10) if r["action"] == "dr_backup"]
    finally:
        await store.close()
    assert caught.value.kind == "write"
    assert str(caught.value).startswith(leftover)
    (row,) = rows
    assert "SYNTHETIC-DIR" in json.loads(row["detail"])["error"]


async def test_a_staging_leftover_after_a_good_build_is_alerted_and_audited(
    tmp_path, monkeypatch
) -> None:
    """The archive is good and published, so the run succeeds, and the plaintext the teardown could
    not clear is still what an operator hears about: a `cleanup` alert and a field in the audit row."""
    import json

    data_dir = tmp_path / "data"
    key = generate_key()
    store = await _keyed_store(data_dir, key)
    real_teardown = dr_backup._teardown_staging

    def build_teardown_fails(path: Path) -> str | None:
        real_teardown(path)
        if path.name.startswith("mefor-backup-"):
            return f"the plaintext staging directory {path} could not be removed (synthetic)"
        return None

    monkeypatch.setattr(dr_backup, "_teardown_staging", build_teardown_fails)
    alerts: list[tuple[str, str, str | None]] = []

    class _Sink:
        def backup_failed(self, name: str, *, kind: str, detail: str | None = None) -> None:
            alerts.append((name, kind, detail))

        def __getattr__(self, _name: str) -> object:
            return lambda *a, **k: None

    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "dest")),
        store_settings=StoreSettings(path=str(data_dir / "msg.db"), encryption_key=key),
        config_dir=None,
        instance="dev",
        alert_sink=_Sink(),  # type: ignore[arg-type]
    )
    try:
        result = await runner.run_once(now=1.0)
        rows = [r for r in await store.list_audit(limit=10) if r["action"] == "dr_backup"]
    finally:
        await store.close()
    assert result is not None and Path(result.archive_path).is_file()
    assert result.staging_leftover is not None and "synthetic" in result.staging_leftover
    (row,) = rows
    detail = json.loads(row["detail"])
    assert detail["verify"] == "PASS" and "synthetic" in detail["staging_leftover"]
    assert [(n, k) for n, k, _d in alerts] == [("dr_backup", "cleanup")]


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


def test_a_forged_key_id_with_a_lone_surrogate_is_a_non_match(tmp_path) -> None:
    """The header is read before anything authenticates it. A `key_id` holding a lone surrogate must
    come back as no match -- a clean KEY_MISMATCH -- and not as a UnicodeEncodeError."""
    key = base64.b64decode(generate_key())
    assert dr_backup._select_decrypt_key([key], "\ud800") is None
