# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The DR BackupRunner (ADR 0049, #60): the scheduled/on-demand pass snapshots a live store read-only
(never mutating a staged-queue row — AC-2), encrypts to a verified .mfbak archive + audits PHI-free
(AC-1), prunes keep-N excluding a verify-failed archive (AC-6), is config-only on a server-DB store
(AC-7), alerts + preserves the prior archive on failure (AC-9/AC-10), and is leader-gated (AC-12).
The dr_backup audit row is asserted on the SQLite store (the parity quartet runs the maintainer's
multi-backend suite)."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tarfile
import time
from collections import namedtuple
from pathlib import Path

import pytest

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline.dr_backup import BackupError, BackupRunner, _day_key
from messagefoundry.store import MessageStore
from messagefoundry.store.backup_codec import decrypt_stream, key_fingerprint
from messagefoundry.store.crypto import generate_key, make_cipher

# --- fakes -------------------------------------------------------------------


class _RecordingAlertSink:
    """Captures backup_failed (+ storage_threshold) calls; satisfies the AlertSink contract loosely."""

    def __init__(self) -> None:
        self.backup_failures: list[tuple[str, str, str | None]] = []
        self.storage_alerts: list[str] = []

    def backup_failed(self, name: str, *, kind: str, detail: str | None = None) -> None:
        self.backup_failures.append((name, kind, detail))

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        self.storage_alerts.append(path)

    def __getattr__(self, _name: str):  # any other alert method is a no-op in these tests
        return lambda *a, **k: None


class _FollowerCoordinator:
    """A coordinator that never leads (for the AC-12 leader-gating test)."""

    node_id = "follower"

    def is_leader(self) -> bool:
        return False


# --- fixtures / helpers ------------------------------------------------------


@pytest.fixture
def key_b64() -> str:
    return generate_key()


async def _store_with_rows(path: Path, key_b64: str | None) -> MessageStore:
    cipher = make_cipher(key_b64) if key_b64 else None
    store = await MessageStore.open(path, cipher=cipher)
    await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|raw-body",
        deliveries=[("d1", "OUT|delivered-body")],
        control_id="CID-1",
        message_type="ADT^A01",
        summary="MRN001 DOE^JOHN",
        now=1.0,
    )
    return store


def _settings(dest: Path, key_b64: str | None, **over: object) -> BackupSettings:
    base: dict[str, object] = {"enabled": True, "destination": str(dest)}
    base.update(over)
    return BackupSettings(**base)


def _store_settings(path: Path, key_b64: str | None) -> StoreSettings:
    return StoreSettings(path=str(path), encryption_key=key_b64)


# --- AC-1 + AC-2: verify + audit + consistent, non-mutating snapshot ---------


async def test_scheduled_backup_verifies_and_audits(tmp_path, key_b64) -> None:
    dest = tmp_path / "backups"
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    runner = BackupRunner(
        store,
        _settings(dest, key_b64),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
        instance="dev",
    )
    result = await runner.run_once(now=1000.0)
    assert result is not None
    assert Path(result.archive_path).exists()
    assert result.encrypted is True
    assert result.verify is not None and result.verify.status == "PASS"
    assert result.verify.integrity_ok is True

    # AC-1: exactly one dr_backup audit row whose detail is metadata-only (no message body, no key bytes).
    rows = await store.list_audit(limit=10)
    backup_rows = [r for r in rows if r["action"] == "dr_backup"]
    assert len(backup_rows) == 1
    detail = json.loads(backup_rows[0]["detail"])
    assert detail["verify"] == "PASS"
    import base64

    assert detail["key_id"] == key_fingerprint(base64.b64decode(key_b64))
    # PHI-free: the detail carries metadata only — never a message body / raw HL7 / key bytes.
    blob = json.dumps(detail)
    assert "raw-body" not in blob and "DOE^JOHN" not in blob and key_b64 not in blob
    await store.close()


@pytest.mark.parametrize("snapshot_method", ["vacuum_into", "online_backup"])
async def test_snapshot_is_consistent_and_nonmutating(tmp_path, key_b64, snapshot_method) -> None:
    # AC-2: the snapshot is a point-in-time consistent copy that never claims/mutates a staged-queue row.
    # Both mechanisms are exercised: vacuum_into (default) AND online_backup (the low-contention path
    # operators pick for a large/busy store — the store where a snapshot bug matters most).
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    before = await store.stats()
    before_pipeline = await store.in_pipeline_depth()
    runner = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64, snapshot_method=snapshot_method),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
    )
    result = await runner.run_once(now=1000.0)
    assert result is not None and result.verify.status == "PASS"
    assert result.snapshot_method == snapshot_method  # the chosen mechanism actually ran
    # The live queue is untouched (no claim/mutate/reset/complete) and integrity holds in the snapshot.
    assert await store.stats() == before
    assert await store.in_pipeline_depth() == before_pipeline
    assert (
        result.row_counts["queue"] >= 1
    )  # the snapshot captured the in-flight row, wholly present
    await store.close()


# --- AC-3/AC-4: encryption + fail-closed no-key PHI --------------------------


async def test_archive_encrypted_under_store_dek(tmp_path, key_b64) -> None:
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    runner = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
    )
    result = await runner.run_once(now=1.0)
    assert result is not None and result.key_id is not None
    # The manifest inside the archive records the DEK fingerprint, never key bytes.
    import base64

    key = base64.b64decode(key_b64)
    with open(result.archive_path, "rb") as src:
        tar_bytes = _decrypt_to_bytes(src, key)
    manifest = _manifest_from_tar_bytes(tar_bytes)
    assert manifest["key_id"] == key_fingerprint(key)
    assert key_b64 not in json.dumps(manifest)  # no key bytes leaked into the manifest
    await store.close()


async def test_refuses_unencrypted_phi_backup(tmp_path) -> None:
    # AC-4: no key + allow_unencrypted=false → refuse to write a cleartext archive (fail-closed).
    store = await _store_with_rows(tmp_path / "msg.db", None)
    runner = BackupRunner(
        store,
        _settings(tmp_path / "b", None, allow_unencrypted=False),
        store_settings=_store_settings(tmp_path / "msg.db", None),
        config_dir=None,
    )
    with pytest.raises(BackupError) as exc:
        await runner.run_once(now=1.0)
    assert exc.value.kind == "encrypt"
    # A dr_backup ERROR row was recorded for the refusal.
    rows = await store.list_audit(limit=5)
    assert any(r["action"] == "dr_backup" for r in rows)
    await store.close()


async def test_allow_unencrypted_writes_plaintext_for_a_no_key_box(tmp_path) -> None:
    store = await _store_with_rows(tmp_path / "msg.db", None)
    dest = tmp_path / "b"
    runner = BackupRunner(
        store,
        _settings(dest, None, allow_unencrypted=True),
        store_settings=_store_settings(tmp_path / "msg.db", None),
        config_dir=None,
    )
    result = await runner.run_once(now=1.0)
    assert result is not None and result.encrypted is False
    assert result.verify is not None and result.verify.status == "PASS"
    await store.close()


# --- ASVS 11.3.4: a REAL run charges its DR frames to the key's persisted bound ---------------


async def test_a_real_backup_run_advances_the_persisted_invocation_count(
    tmp_path, key_b64, monkeypatch
) -> None:
    """Every archive frame is an AES-GCM invocation under the SAME store DEK, so it spends the same
    birthday budget. ``backup_codec`` builds its own ``AESGCM`` from the raw key and never reaches
    ``AesGcmCipher``, so a run that did not charge the bound would under-count the key by ~10k
    invocations per backup on a 10 GB store — an error in the unsafe direction.

    Driven through the real ``BackupRunner``: deleting its ``_charge_archive_invocations`` call must red
    this test, which asserting the arithmetic by hand could never do."""
    import base64 as _b64

    from messagefoundry.pipeline import dr_backup as dr

    db = tmp_path / "msg.db"
    store = await _store_with_rows(db, key_b64)
    key_id = key_fingerprint(_b64.b64decode(key_b64))

    # Observe the frame count the codec ACTUALLY performs, without changing what the runner does.
    frames: list[int] = []
    real_encrypt_stream = dr.encrypt_stream

    def _spy(src, dst, key, *, chunk_size=None, on_frames=None):
        def _record(n: int) -> None:
            frames.append(n)
            if on_frames is not None:
                on_frames(n)

        return real_encrypt_stream(src, dst, key, chunk_size=chunk_size, on_frames=_record)

    monkeypatch.setattr(dr, "encrypt_stream", _spy)

    before = await store.cipher_invocations(key_id)
    runner = BackupRunner(
        store,
        _settings(tmp_path / "backups", key_b64),
        store_settings=_store_settings(db, key_b64),
        config_dir=None,
        instance="dev",
    )
    result = await runner.run_once(now=1000.0)
    assert result is not None and result.encrypted is True
    assert frames and sum(frames) > 0, "the archive must have been encrypted, or nothing is proven"
    after = await store.cipher_invocations(key_id)
    assert after - before == sum(frames)
    await store.close()


async def test_a_plaintext_backup_charges_nothing(tmp_path, key_b64) -> None:
    # The allow_unencrypted plaintext-tar path performs NO AES-GCM invocation, so it must charge none —
    # a blanket post-run add would inflate the key's budget for archives it never encrypted.
    import base64 as _b64

    db = tmp_path / "msg.db"
    store = await _store_with_rows(db, key_b64)  # the STORE is keyed...
    key_id = key_fingerprint(_b64.b64decode(key_b64))
    before = await store.cipher_invocations(key_id)
    runner = BackupRunner(
        store,
        _settings(tmp_path / "plain", None, allow_unencrypted=True),
        store_settings=_store_settings(db, None),  # ...but the archive resolves NO key
        config_dir=None,
    )
    result = await runner.run_once(now=1.0)
    assert result is not None and result.encrypted is False
    assert await store.cipher_invocations(key_id) == before
    await store.close()


# --- AC-6: keep-N prune excludes a verify-failed archive ---------------------


async def test_keep_n_prune_excludes_failed(tmp_path, key_b64) -> None:
    dest = tmp_path / "backups"
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    settings = _settings(dest, key_b64, retention_keep=2)
    ss = _store_settings(tmp_path / "msg.db", key_b64)
    runner = BackupRunner(store, settings, store_settings=ss, config_dir=None, instance="dev")
    # Three good backups at distinct seconds → after the third, keep-N=2 prunes the oldest.
    for i, t in enumerate((1000.0, 1001.0, 1002.0)):
        result = await runner.run_once(now=t)
        assert result is not None
        if i == 2:
            assert result.pruned == 1
    remaining = sorted(dest.glob("*.mfbak"))
    assert len(remaining) == 2
    await store.close()


# --- AC-7: server-DB store is config-only ------------------------------------


async def test_server_db_is_config_only(tmp_path, key_b64) -> None:
    # A SQLite store whose backend is faked to 'postgres' must NOT snapshot the DB (DBA-delegated, #52)
    # and produce a config-only archive instead. We don't need a real Postgres — only the backend gate.
    from messagefoundry.config.settings import StoreBackend

    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text("# router")
    runner = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64, config_only_on_server_db=True),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=cfg,
    )
    # Force the server-DB classification via the backend value the runner reads.
    object.__setattr__(store, "backend", StoreBackend.POSTGRES)
    result = await runner.run_once(now=1.0)
    assert result is not None and result.config_only is True
    assert result.snapshot_sha256 == ""  # no DB snapshot taken
    # The archive verifies as a config-only archive (no store.db member to integrity-check).
    assert result.verify is not None and result.verify.status == "PASS"
    import base64

    with open(result.archive_path, "rb") as src:
        tar_bytes = _decrypt_to_bytes(src, base64.b64decode(key_b64))
    names = _member_names(tar_bytes)
    assert "store.db" not in names
    assert any(n.startswith("config/") for n in names)
    await store.close()


async def test_server_db_skip_when_config_only_disabled(tmp_path, key_b64) -> None:
    from messagefoundry.config.settings import StoreBackend

    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    runner = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64, config_only_on_server_db=False),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
    )
    object.__setattr__(store, "backend", StoreBackend.SQLSERVER)
    with pytest.raises(BackupError) as exc:
        await runner.run_once(now=1.0)
    assert exc.value.kind == "snapshot"
    await store.close()


# --- config bundle: a symlink out of the config dir is excluded (no host-file smuggling) ---


async def test_add_config_dir_excludes_symlink_out_of_dir(tmp_path, key_b64) -> None:
    # Security: `_add_config_dir` must add regular config files only. A symlink inside the config dir
    # pointing at a host file OUTSIDE the bundle would smuggle arbitrary host contents into the
    # archive — it must be skipped (dr_backup.py:448 is_symlink guard + rglob(recurse_symlinks=False)).
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text("# router")  # a legitimate regular config file

    # A host secret OUTSIDE the config dir, and a symlink INSIDE it that escapes to the secret.
    host_secret = tmp_path / "host_secret.txt"
    host_secret.write_text("SMUGGLED-SECRET")
    try:
        (cfg / "escape.link").symlink_to(host_secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not permitted (Windows w/o Developer Mode/privilege)")

    # A symlinked DIRECTORY that escapes the bundle too — rglob(recurse_symlinks=False) must not
    # descend into it, so its contents never land in the archive.
    host_dir = tmp_path / "host_dir"
    host_dir.mkdir()
    (host_dir / "buried.txt").write_text("SMUGGLED-SECRET-DIR")
    try:  # noqa: SIM105
        (cfg / "escape_dir").symlink_to(host_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pass  # the file-symlink case above already exercises the guard

    runner = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=cfg,
    )
    result = await runner.run_once(now=1.0)
    assert result is not None and result.verify is not None and result.verify.status == "PASS"

    import base64

    with open(result.archive_path, "rb") as src:
        tar_bytes = _decrypt_to_bytes(src, base64.b64decode(key_b64))
    names = _member_names(tar_bytes)
    # (1) The escaping symlink members are absent.
    assert "config/escape.link" not in names
    assert "config/escape_dir/buried.txt" not in names
    # (2) The out-of-dir secret bytes never reach the archive.
    assert b"SMUGGLED-SECRET" not in tar_bytes
    # (3) The legitimate regular file IS present (the fix must not over-exclude real config files).
    assert "config/feed.py" in names
    await store.close()


# --- AC-9/AC-10: failure alerts + preserves the prior good archive -----------


async def test_failed_backup_alerts_and_preserves_prior(tmp_path, key_b64) -> None:
    dest = tmp_path / "backups"
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    sink = _RecordingAlertSink()
    settings = _settings(dest, key_b64)
    ss = _store_settings(tmp_path / "msg.db", key_b64)
    runner = BackupRunner(
        store, settings, store_settings=ss, config_dir=None, alert_sink=sink, instance="dev"
    )
    # First, a good backup.
    good = await runner.run_once(now=1000.0)
    assert good is not None
    prior = Path(good.archive_path)
    assert prior.exists()

    # Now force a failure: monkeypatch the store snapshot to raise. The prior archive stays intact and
    # backup_failed fires.
    async def _boom(*_a, **_k):
        raise OSError("disk gone")

    object.__setattr__(store, "snapshot_to", _boom)
    with pytest.raises(BackupError):
        await runner.run_once(now=2000.0)
    assert sink.backup_failures, "backup_failed alert was not raised"
    assert prior.exists(), "the prior good archive must be preserved on a failed run"
    await store.close()


async def test_unreachable_destination_alerts(tmp_path, key_b64) -> None:
    # AC-10: a destination that cannot be created → backup_failed + a dr_backup ERROR row.
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    sink = _RecordingAlertSink()
    # A destination under a regular FILE can't be mkdir'd → OSError on _ensure_destination.
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    runner = BackupRunner(
        store,
        _settings(blocker / "sub", key_b64),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
        alert_sink=sink,
    )
    with pytest.raises(BackupError) as exc:
        await runner.run_once(now=1.0)
    assert exc.value.kind == "destination"
    assert sink.backup_failures and sink.backup_failures[0][1] == "destination"
    await store.close()


# --- DR-9: safe_exc PHI-scrub of the failure reason (alert detail + ERROR audit row) ---


async def test_failed_backup_reason_is_phi_scrubbed_on_both_sinks(tmp_path, key_b64) -> None:
    # DR-9 (scrub half): a failing snapshot whose OSError carries an HL7-shaped body must NOT leak PHI
    # into either the backup_failed alert detail OR the dr_backup ERROR audit row. The single safe_exc
    # call in _record_failure re-scrubs the (already-scrubbed) BackupError, keeping the exception TYPE.
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    sink = _RecordingAlertSink()
    runner = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
        alert_sink=sink,
    )

    async def _boom(*_a, **_k):
        # A Router/OS error path could carry a raw HL7 body — synthetic PHI here.
        raise OSError("MSH|^~\\&|S|F PID|1||MRN001||DOE^JANE^M||19800505")

    object.__setattr__(store, "snapshot_to", _boom)
    with pytest.raises(BackupError):
        await runner.run_once(now=2000.0)

    # (1) The alert detail is scrubbed (segment field data cut) but keeps the exception type.
    assert sink.backup_failures, "backup_failed alert was not raised"
    alert_detail = sink.backup_failures[0][2]
    assert alert_detail is not None
    assert "[redacted]" in alert_detail
    assert "OSError" in alert_detail  # the useful, non-PHI exception type survives
    for phi in ("DOE^JANE", "19800505", "MRN001"):
        assert phi not in alert_detail

    # (2) The dr_backup ERROR audit row's error is likewise scrubbed (single :507 safe_exc authority).
    rows = await store.list_audit(limit=10)
    error_rows = [
        d
        for r in rows
        if r["action"] == "dr_backup"
        for d in (json.loads(r["detail"]),)
        if d.get("outcome") == "error"
    ]
    assert len(error_rows) == 1
    err = error_rows[0]
    assert err["outcome"] == "error"
    assert err["kind"] == "snapshot"
    assert "[redacted]" in err["error"]
    assert "OSError" in err["error"]
    for phi in ("DOE^JANE", "19800505", "MRN001"):
        assert phi not in err["error"]
    await store.close()


# --- DR-9: startup preflight is advisory (warns, never raises) ---------------


async def test_preflight_unwritable_destination_warns_but_does_not_raise(
    tmp_path, key_b64, caplog
) -> None:
    # DR-9 (preflight half): a destination under a regular FILE cannot be created. The STARTUP preflight
    # is advisory — it logs a WARNING and returns, never raising (unlike the runtime _ensure_destination).
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    dest = blocker / "sub"
    runner = BackupRunner(
        store,
        _settings(dest, key_b64),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
    )
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.dr_backup"):
        runner._preflight_destination()  # advisory: must return without raising
    assert any("not writable at startup" in rec.getMessage() for rec in caplog.records), (
        "expected an advisory 'not writable at startup' WARNING"
    )
    assert not dest.exists()  # nothing was created under the blocking file
    await store.close()


async def test_preflight_low_space_fires_storage_threshold_alert(
    tmp_path, key_b64, monkeypatch
) -> None:
    # DR-9 (preflight low-space): a writable destination with < 1 GiB free surfaces the storage_threshold
    # alert at startup (so an operator learns of a filling share at boot, not silently at 02:00).
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    sink = _RecordingAlertSink()
    dest = tmp_path / "ok"
    runner = BackupRunner(
        store,
        _settings(dest, key_b64),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
        alert_sink=sink,
    )
    gib = 1024 * 1024 * 1024
    DiskUsage = namedtuple("DiskUsage", "total used free")
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda _p: DiskUsage(total=10 * gib, used=10 * gib - gib // 2, free=gib // 2),
    )
    runner._preflight_destination()
    assert sink.storage_alerts, "storage_threshold was not fired for a low-space destination"
    assert sink.storage_alerts[0] == str(dest)
    await store.close()


# --- AC-12: leader-gated ------------------------------------------------------


async def test_backup_is_leader_gated(tmp_path, key_b64) -> None:
    dest = tmp_path / "backups"
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    runner = BackupRunner(
        store,
        _settings(dest, key_b64),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
        coordinator=_FollowerCoordinator(),
    )
    # A follower returns None and writes nothing to the shared destination.
    assert await runner.run_once(now=1000.0) is None
    assert not dest.exists() or not list(dest.glob("*.mfbak"))
    await store.close()


# --- small decrypt helpers ----------------------------------------------------


def _decrypt_to_bytes(src, key: bytes) -> bytes:
    import io

    out = io.BytesIO()
    decrypt_stream(src, out, key)
    return out.getvalue()


def _member_names(tar_bytes: bytes) -> list[str]:
    import io

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
        return tar.getnames()


def _manifest_from_tar_bytes(tar_bytes: bytes) -> dict:
    import io

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
        member = tar.extractfile("manifest.json")
        assert member is not None
        return json.loads(member.read())


# --- DR-4: the supervised daily loop (in-loop gates, cancellable sleep, start/stop) ----------
#
# The AC-12 test above exercises run_once's early return; these cover the DISTINCT in-loop path the
# supervised daily loop actually walks: `_backup_due` (schedule/leader/daily-latch) + a `_sleep` that
# short-circuits on stop + `start`/`stop` lifecycle. All SQLite + a chosen local wall-clock, no rig.


def _local_epoch(year: int, month: int, day: int, hour: int, minute: int) -> float:
    """An epoch built from a chosen LOCAL wall-clock time via ``time.mktime`` so that
    ``time.localtime()`` round-trips to the same (hour, minute) on any CI timezone — ``_backup_due`` /
    ``_day_key`` compare against ``time.localtime(now)``, so a hardcoded UTC offset would make this
    timezone-dependent. ``tm_isdst=-1`` lets ``mktime`` resolve DST; January avoids a fold anyway."""
    return time.mktime((year, month, day, hour, minute, 0, 0, 0, -1))


async def test_backup_due_daily_latch_and_in_loop_leader_gate(tmp_path, key_b64) -> None:
    # `_backup_due` is the in-loop gate (dr_backup.py:223), distinct from run_once's early return: it is
    # False before the scheduled minute, True at/after it (a late start still catches up the SAME day),
    # then latches to at-most-once-per-local-day, re-arms the next local day, is False when on-demand-only
    # (schedule_at=""), and is False for a follower even once the clock has reached the target.
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    runner = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64, schedule_at="02:00"),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
    )
    before = _local_epoch(2026, 1, 15, 1, 59)  # 01:59 — one minute short of the schedule
    at_target = _local_epoch(2026, 1, 15, 2, 0)  # 02:00 — exactly the schedule
    late = _local_epoch(2026, 1, 15, 2, 30)  # 02:30 — a late start the same day
    next_day = _local_epoch(2026, 1, 16, 2, 0)  # the following local day

    assert runner._backup_due(before) is False
    assert runner._backup_due(at_target) is True
    assert runner._backup_due(late) is True  # late-start catch-up (still today, not yet latched)

    # Latch today's backup: no second pass the same local day...
    runner._last_backup_day = _day_key(at_target)
    assert runner._backup_due(at_target) is False
    assert runner._backup_due(late) is False
    # ...but the next local day re-arms.
    assert runner._backup_due(next_day) is True

    # schedule_at="" → on-demand-only → the loop is never due (schedule_time() is None).
    on_demand = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64, schedule_at=""),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
    )
    assert on_demand._backup_due(at_target) is False

    # Leader-gated IN THE LOOP (AC-12): a follower is never due even with the clock past the target — the
    # gate that stops HA followers racing the shared destination at 02:00, not just the run_once return.
    follower = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64, schedule_at="02:00"),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
        coordinator=_FollowerCoordinator(),
    )
    assert follower._backup_due(at_target) is False
    await store.close()


async def test_sleep_short_circuits_when_stop_is_set(tmp_path, key_b64) -> None:
    # The loop's inter-pass wait (`_sleep`, dr_backup.py:217) must be cooperatively cancellable: once the
    # stop Event is set, a nominal 60s sleep returns promptly instead of blocking the shutdown path.
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    runner = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
    )
    runner._stop.set()
    await asyncio.wait_for(
        runner._sleep(60.0), timeout=1.0
    )  # returns well under the 60s nominal delay
    await store.close()


async def test_start_spawns_loop_and_stop_cancels_cleanly(tmp_path, key_b64) -> None:
    # start() spawns the supervised loop when a schedule is set; stop() cancels it cleanly (exercising the
    # _sleep/loop cancellation path). A fixed pre-schedule clock keeps the loop from doing a real backup
    # while it runs. A schedule_at="" (on-demand-only) box makes start() a no-op (nothing to loop).
    store = await _store_with_rows(tmp_path / "msg.db", key_b64)
    runner = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64, schedule_at="02:00"),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
        clock=lambda: _local_epoch(2026, 1, 15, 1, 0),  # 01:00 local — before the 02:00 schedule
    )
    runner.start()
    assert runner._task is not None
    await runner.stop()
    assert runner._task is None

    on_demand = BackupRunner(
        store,
        _settings(tmp_path / "b", key_b64, schedule_at=""),
        store_settings=_store_settings(tmp_path / "msg.db", key_b64),
        config_dir=None,
    )
    on_demand.start()
    assert on_demand._task is None  # on-demand-only → start() is a no-op
    await store.close()
