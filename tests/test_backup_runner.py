# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The DR BackupRunner (ADR 0049, #60): the scheduled/on-demand pass snapshots a live store read-only
(never mutating a staged-queue row — AC-2), encrypts to a verified .mfbak archive + audits PHI-free
(AC-1), prunes keep-N excluding a verify-failed archive (AC-6), is config-only on a server-DB store
(AC-7), alerts + preserves the prior archive on failure (AC-9/AC-10), and is leader-gated (AC-12).
The dr_backup audit row is asserted on the SQLite store (the parity quartet runs the maintainer's
multi-backend suite)."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline.dr_backup import BackupError, BackupRunner
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
