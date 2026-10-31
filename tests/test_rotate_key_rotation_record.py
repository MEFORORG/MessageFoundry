# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3737: what a ``rotate-key`` run that stops short leaves behind.

``reconcile_rotation_meta`` stamped a changed store key at the next ``serve`` start whether or not
``rotate-key`` had finished, so a run's withheld stamp held only until then. The rotation record
closes that: a ``secret_rotation_meta`` row the command opens first and closes last, which the
reconcile honours. At least the tests of that behaviour fail on the code before #3737, because the
stamp is written. A run that skipped an upload rolls the audit chain as it did before, by owner
ruling of 2026-10-30, and the tests of that and of the out-of-band stamp pin what must not change.

The skipped upload is sealed under a key nobody supplies, a cause an operator can fix by removing
it, and it fails the run the way any skip does."""

from __future__ import annotations

import asyncio
import datetime
import logging
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.config.settings import SecretRotationSettings
from messagefoundry.pipeline.secret_rotation import (
    ROTATION_RECORD_ID,
    SecretStamp,
    StoreKeyRotationOverdueError,
    close_rotation_record,
    dek_fingerprint,
    enforce_store_key_expiry,
    open_rotation_record,
    reconcile_rotation_meta,
    secrets_from_settings_and_stamps,
)
from messagefoundry.store.crypto import CipherError, cipher_info, generate_key, make_cipher
from messagefoundry.store.store import MessageStore, SecretRotationMetaRow
from messagefoundry.uploads import UploadStore
from tests.test_cli import _rotate_env

_DEK = "MEFOR_STORE_ENCRYPTION_KEY"
_OLD_DATE = "2025-01-01"
_MSG = "MSH|^~\\&|A|B|C|D|202601010000||ADT^A01|1|P|2.5\rPID|1||1\r"


def _key_id(key: str) -> str:
    key_id = cipher_info(make_cipher(key)).active_key_id
    assert key_id
    return key_id


async def _open(db: Path, key: str, *retired: str) -> MessageStore:
    cipher = make_cipher(key, retired)
    return await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())


async def _seed(db: Path, uploads: Path, key: str) -> None:
    """A store under ``key`` with a message, one sound upload, an audit row (so ``key`` keys the
    chain's first range, and a key keys one range only) and a DEK stamp dated long ago."""
    store = await _open(db, key)
    try:
        await store.record_audit("test.seed", actor="u")
        await store.enqueue_message(channel_id="ch", raw=_MSG, deliveries=[("d", _MSG)])
        await UploadStore(uploads, store.cipher(), max_bytes=1 << 20).save(
            data=_MSG.encode(), filename="a.hl7", uploader="op", uploader_id="u"
        )
        await store.upsert_secret_rotation_meta(
            _DEK,
            fingerprint=dek_fingerprint(_key_id(key)),
            tracked_since=_OLD_DATE,
            last_rotated=_OLD_DATE,
        )
    finally:
        await store.close()


def _plant_unopenable_upload(uploads: Path) -> list[Path]:
    """An upload under a key no run is given. Returns its two files, so a test can remove them."""
    stranger = make_cipher(generate_key(), write_v2=True)
    meta = asyncio.run(
        UploadStore(uploads, stranger, max_bytes=1 << 20).save(
            data=_MSG.encode(), filename="b.hl7", uploader="op", uploader_id="u"
        )
    )
    return [uploads / f"{meta.file_id}.blob", uploads / f"{meta.file_id}.meta"]


def _env(monkeypatch: pytest.MonkeyPatch, active: str, retired: str, uploads: Path) -> None:
    _rotate_env(monkeypatch, active=active, retired=retired, uploads=uploads)


async def _rows(db: Path, key: str, *retired: str) -> dict[str, SecretRotationMetaRow]:
    store = await _open(db, key, *retired)
    try:
        return await store.get_secret_rotation_meta()
    finally:
        await store.close()


async def _serve_reconcile(db: Path, key: str, *retired: str) -> dict[str, SecretRotationMetaRow]:
    """What a ``serve`` start does to the rows, through the real store, returning them after."""
    store = await _open(db, key, *retired)
    try:
        await reconcile_rotation_meta(
            store,
            SecretRotationSettings(),
            dek_key_id=_key_id(key),
            enforcement=SecurityEnforcement.WARN,
            env_values={},
        )
        return await store.get_secret_rotation_meta()
    finally:
        await store.close()


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, str, str]:
    monkeypatch.chdir(tmp_path)
    db, uploads = tmp_path / "rot.db", tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    asyncio.run(_seed(db, uploads, key_a))
    return db, uploads, key_a, key_b


def test_a_serve_start_after_a_partial_run_writes_no_stamp(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The closing condition: the start leaves the DEK row as it was, says so, and the run that
    completes still finds a changed key, stamps it, and closes the record."""
    db, uploads, key_a, key_b = rig
    planted = _plant_unopenable_upload(uploads)
    _env(monkeypatch, key_b, key_a, uploads)
    assert main(["rotate-key", "--db", str(db)]) == 1
    capsys.readouterr()

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.secret_rotation"):
        rows = asyncio.run(_serve_reconcile(db, key_b, key_a))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))
    assert rows[_DEK].last_rotated == _OLD_DATE
    assert "rotate-key has not completed" in caplog.text

    for path in planted:
        path.unlink()
    assert main(["rotate-key", "--db", str(db)]) == 0
    assert "OK:" in capsys.readouterr().out
    rows = asyncio.run(_rows(db, key_b))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[_DEK].last_rotated != _OLD_DATE
    assert rows[_DEK].tracked_since == _OLD_DATE
    assert rows[ROTATION_RECORD_ID].fingerprint == ""

    # A closed record no longer holds anything back, and the key is already stamped.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.secret_rotation"):
        after = asyncio.run(_serve_reconcile(db, key_b))
    assert after[_DEK] == rows[_DEK]
    assert "rotate-key has not completed" not in caplog.text


def test_a_run_the_store_pass_aborts_leaves_the_record_open(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The record is opened first, so a run that never reaches the stamp step is held too. A killed
    process stands where this abort does: neither gets as far as anything written last."""
    db, uploads, key_a, key_b = rig

    async def refuse(self: MessageStore) -> int:
        raise CipherError("no configured key decrypts this value")

    monkeypatch.setattr(MessageStore, "reencrypt_to_active", refuse)
    _env(monkeypatch, key_b, key_a, uploads)
    assert main(["rotate-key", "--db", str(db)]) == 1
    capsys.readouterr()
    assert asyncio.run(_serve_reconcile(db, key_b, key_a))[_DEK].last_rotated == _OLD_DATE


def test_a_refused_audit_step_leaves_the_record_open(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The other way a run ends PARTIAL. Its stamp was withheld already; the start must not supply
    it."""
    db, uploads, key_a, key_b = rig

    async def refuse(self: MessageStore) -> tuple[bool, str]:
        return False, "refused for the test"

    monkeypatch.setattr(MessageStore, "roll_audit_key_epoch", refuse)
    _env(monkeypatch, key_b, key_a, uploads)
    assert main(["rotate-key", "--db", str(db)]) == 1
    assert "Do NOT remove" in capsys.readouterr().err
    assert asyncio.run(_serve_reconcile(db, key_b, key_a))[_DEK].last_rotated == _OLD_DATE


def test_a_partial_run_rolls_the_chain_and_it_verifies_after_a_start_on_the_new_key_alone(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Owner ruling 2026-10-30. A Windows service runs with no retired key in its list, so a start
    after a PARTIAL run can have the new key alone. Left unrolled, the first audit row it wrote
    would break the chain for good. So a skip rolls, and this start's row must verify, by
    ``audit-verify`` itself. The note must offer no way back to the prior key."""
    db, uploads, key_a, key_b = rig
    _plant_unopenable_upload(uploads)
    _env(monkeypatch, key_b, key_a, uploads)
    assert main(["rotate-key", "--db", str(db)]) == 1
    captured = capsys.readouterr()
    assert "PARTIAL:" in captured.out and "OK:" not in captured.out
    assert "a new range under the active key opens" in captured.out
    assert "you cannot go back to the prior key" in captured.out
    assert "back out" not in captured.out

    async def a_start_on_the_new_key_alone() -> None:
        store = await _open(db, key_b)
        try:
            await store.record_audit("test.after_partial", actor="u")
        finally:
            await store.close()

    asyncio.run(a_start_on_the_new_key_alone())
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED")
    assert main(["audit-verify", "--db", str(db)]) == 0, capsys.readouterr()


def test_a_re_run_after_a_skip_finds_the_chain_rolled_and_completes(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The earlier run's roll must not refuse the next: the active key already keys the current
    range, so the roll is a verified no-op, and the stamp and the close follow it."""
    db, uploads, key_a, key_b = rig
    planted = _plant_unopenable_upload(uploads)
    _env(monkeypatch, key_b, key_a, uploads)
    assert main(["rotate-key", "--db", str(db)]) == 1
    capsys.readouterr()
    rows = asyncio.run(_rows(db, key_b, key_a))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))  # no stamp from a skipped run
    assert rows[ROTATION_RECORD_ID].fingerprint == dek_fingerprint(_key_id(key_b))

    for path in planted:
        path.unlink()
    assert main(["rotate-key", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "OK: audit chain already under the active key" in out
    rows = asyncio.run(_rows(db, key_b))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[_DEK].last_rotated != _OLD_DATE
    assert rows[ROTATION_RECORD_ID].fingerprint == ""


def test_a_run_with_the_same_key_opens_no_record(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Sealing uploads with the key already in use rotates nothing, so nothing is held back."""
    db, uploads, key_a, _key_b = rig
    _env(monkeypatch, key_a, "", uploads)
    assert main(["rotate-key", "--db", str(db)]) == 0
    capsys.readouterr()
    assert ROTATION_RECORD_ID not in asyncio.run(_rows(db, key_a))


def test_a_key_changed_with_no_rotate_key_still_stamps(tmp_path: Path) -> None:
    """Out of band, with no record at all: as it did before the record."""
    db, key_a, key_b = tmp_path / "oob.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))
    rows = asyncio.run(_serve_reconcile(db, key_b, key_a))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[_DEK].last_rotated != _OLD_DATE


def test_a_key_changed_by_hand_over_a_closed_record_still_stamps(tmp_path: Path) -> None:
    """A closed record is a blank, not an unreadable one. Read as unreadable, it would withhold every
    hand change after the first completed rotation, for good."""
    db, key_a, key_b = tmp_path / "closed.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))

    async def open_then_close() -> None:
        store = await _open(db, key_a)
        try:
            await open_rotation_record(store, _key_id(key_b), "2026-10-30")
            await close_rotation_record(store, "2026-10-30")
        finally:
            await store.close()

    asyncio.run(open_then_close())
    rows = asyncio.run(_serve_reconcile(db, key_b, key_a))
    assert rows[ROTATION_RECORD_ID].fingerprint == ""
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))


def test_a_record_naming_another_key_does_not_hold_this_one(tmp_path: Path) -> None:
    """A run stopped on key B, and the operator then set key C by hand. C has no run behind it, so it
    is an out-of-band change and stamps."""
    db, key_a, key_b, key_c = (
        tmp_path / "other.db",
        generate_key(),
        generate_key(),
        generate_key(),
    )
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))

    async def record_b() -> None:
        store = await _open(db, key_a)
        try:
            await open_rotation_record(store, _key_id(key_b), "2026-10-30")
        finally:
            await store.close()

    asyncio.run(record_b())
    rows = asyncio.run(_serve_reconcile(db, key_c, key_a))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_c))


@pytest.mark.parametrize(
    "stored",
    [
        "garbage",
        "sha256-16:",
        "sha256-16:NOTHEX",
        "sha3-16:" + "a" * 16,
        "a" * 16,  # untagged: a read of it as a key id would call it another key, and stamp
        "sha256-16:ab",  # the same, truncated
    ],
)
def test_an_unreadable_record_fails_toward_not_stamping(
    tmp_path: Path, stored: str, caplog: pytest.LogCaptureFixture
) -> None:
    db, key_a, key_b = tmp_path / "bad.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))

    async def plant() -> None:
        store = await _open(db, key_a)
        try:
            await store.upsert_secret_rotation_meta(
                ROTATION_RECORD_ID,
                fingerprint=stored,
                tracked_since="2026-10-30",
                last_rotated="2026-10-30",
            )
        finally:
            await store.close()

    asyncio.run(plant())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.secret_rotation"):
        rows = asyncio.run(_serve_reconcile(db, key_b, key_a))
    assert rows[_DEK].last_rotated == _OLD_DATE
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))
    assert "the rotation record could not be read" in caplog.text


def test_a_store_with_no_stamp_yet_ages_from_the_record_and_persists_nothing(
    tmp_path: Path,
) -> None:
    """Nothing is written, so the completing run still stamps. The key's age runs from the day the
    record opened, and a re-run's open keeps that day. A floor of today would restart at every
    start, and a key held that way could never go overdue."""
    db, key = tmp_path / "first.db", generate_key()

    async def run() -> tuple[bool, str | None, datetime.date, datetime.date]:
        store = await _open(db, key)
        try:
            await open_rotation_record(store, _key_id(key), "2020-02-02")
            await open_rotation_record(store, _key_id(key), "2026-10-30")
            stamps = await reconcile_rotation_meta(
                store,
                SecretRotationSettings(),
                dek_key_id=_key_id(key),
                enforcement=SecurityEnforcement.WARN,
                env_values={},
            )
            rows = await store.get_secret_rotation_meta()
            stamp = stamps[_DEK]
            return _DEK in rows, stamp.fingerprint, stamp.tracked_since, stamp.last_rotated
        finally:
            await store.close()

    persisted, tracked, since, rotated = asyncio.run(run())
    assert not persisted
    assert tracked == dek_fingerprint(_key_id(key))
    assert since == rotated == datetime.date(2020, 2, 2)


async def _plant_record(db: Path, key: str, fingerprint: str, day: str) -> None:
    store = await _open(db, key)
    try:
        await store.upsert_secret_rotation_meta(
            ROTATION_RECORD_ID, fingerprint=fingerprint, tracked_since=day, last_rotated=day
        )
    finally:
        await store.close()


async def _age(db: Path, key: str) -> datetime.date:
    """The date a start reads the DEK's age from, through the real reconcile."""
    store = await _open(db, key)
    try:
        stamps = await reconcile_rotation_meta(
            store,
            SecretRotationSettings(),
            dek_key_id=_key_id(key),
            enforcement=SecurityEnforcement.WARN,
            env_values={},
        )
        return stamps[_DEK].last_rotated
    finally:
        await store.close()


@pytest.mark.parametrize("stored", ["garbage", "sha256-16:" + "ab" * 8])
def test_opening_over_an_open_record_keeps_its_dates(tmp_path: Path, stored: str) -> None:
    """A damaged record, and one naming another key. With no stamp the key's age runs from these
    dates, so a run that only starts must not make it young: that would lift an overdue refusal."""
    db, key = tmp_path / "keep.db", generate_key()

    async def run() -> SecretRotationMetaRow:
        await _plant_record(db, key, stored, "2020-02-02")
        store = await _open(db, key)
        try:
            await open_rotation_record(store, _key_id(key), "2026-10-30")
            return (await store.get_secret_rotation_meta())[ROTATION_RECORD_ID]
        finally:
            await store.close()

    row = asyncio.run(run())
    assert row.fingerprint == dek_fingerprint(_key_id(key))  # replaced, so a later close finds it
    assert (row.tracked_since, row.last_rotated) == ("2020-02-02", "2020-02-02")
    assert asyncio.run(_age(db, key)) == datetime.date(2020, 2, 2)


def test_opening_over_a_closed_record_dates_it_from_today(tmp_path: Path) -> None:
    """The control: a blank is no rotation in progress, so its dates say nothing about this one."""
    db, key = tmp_path / "fresh.db", generate_key()

    async def run() -> str:
        await _plant_record(db, key, "", "2020-02-02")
        store = await _open(db, key)
        try:
            await open_rotation_record(store, _key_id(key), "2026-10-30")
            return (await store.get_secret_rotation_meta())[ROTATION_RECORD_ID].last_rotated
        finally:
            await store.close()

    assert asyncio.run(run()) == "2026-10-30"


@pytest.mark.parametrize("day", ["not a date", ""])
def test_a_record_whose_dates_do_not_parse_reads_as_an_undetermined_age(
    tmp_path: Path, day: str
) -> None:
    """Written out of band. They are copied as text, and must crash neither the open nor the
    reader. An undetermined age is not a young one, so it refuses under enforce."""
    db, key = tmp_path / "dates.db", generate_key()

    async def run() -> datetime.date:
        await _plant_record(db, key, "garbage", day)
        store = await _open(db, key)
        try:
            await open_rotation_record(store, _key_id(key), "2026-10-30")
        finally:
            await store.close()
        return await _age(db, key)

    last_rotated = asyncio.run(run())
    assert last_rotated == datetime.date.min
    with pytest.raises(StoreKeyRotationOverdueError):
        enforce_store_key_expiry(
            SecretRotationSettings(),
            {_DEK: _held_stamp(key, last_rotated)},
            enforcement=SecurityEnforcement.ENFORCE,
            dek_key_id=_key_id(key),
        )


def test_an_overdue_refusal_stands_after_a_partial_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The whole path, through the command. A damaged record dated long ago, no stamp, one run that
    stops short. The age must still read as overdue, so the start is refused under enforce."""
    monkeypatch.chdir(tmp_path)
    db, uploads = tmp_path / "overdue.db", tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    asyncio.run(_plant_record(db, key_a, "garbage", "2020-02-02"))
    _plant_unopenable_upload(uploads)
    _env(monkeypatch, key_b, key_a, uploads)
    assert main(["rotate-key", "--db", str(db)]) == 1
    capsys.readouterr()

    last_rotated = asyncio.run(_age(db, key_b))
    assert last_rotated == datetime.date(2020, 2, 2)
    with pytest.raises(StoreKeyRotationOverdueError):
        enforce_store_key_expiry(
            SecretRotationSettings(),
            {_DEK: _held_stamp(key_b, last_rotated)},
            enforcement=SecurityEnforcement.ENFORCE,
            dek_key_id=_key_id(key_b),
        )


def _held_stamp(key: str, day: datetime.date) -> SecretStamp:
    return SecretStamp(
        class_id=_DEK,
        label="store data-encryption key",
        fingerprint=dek_fingerprint(_key_id(key)),
        tracked_since=day,
        last_rotated=day,
        max_age_days=SecretRotationSettings().store_key_max_age_days,
    )


def test_an_unreadable_record_logs_only_that_it_is_unreadable(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Nothing says a run ever started, so the line about an unfinished one would be false."""
    db, key_a, key_b = tmp_path / "one.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))

    async def plant() -> None:
        store = await _open(db, key_a)
        try:
            await store.upsert_secret_rotation_meta(
                ROTATION_RECORD_ID,
                fingerprint="garbage",
                tracked_since="2026-10-30",
                last_rotated="2026-10-30",
            )
        finally:
            await store.close()

    asyncio.run(plant())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.secret_rotation"):
        asyncio.run(_serve_reconcile(db, key_b, key_a))
    assert "the rotation record could not be read" in caplog.text
    assert "rotate-key has not completed" not in caplog.text


def test_the_record_is_never_read_as_a_credential(tmp_path: Path) -> None:
    """The reconcile's stamps are what the watcher and the expiry refusals read, and the rotation
    pass selects by the sealed tag. The row must reach neither, and a connector credential that
    happens to be keyed the same must not be written over it."""
    db, key = tmp_path / "cred.db", generate_key()
    settings = SecretRotationSettings()

    async def run() -> None:
        store = await _open(db, key)
        try:
            await open_rotation_record(store, "ab" * 8, "2026-10-30")
            before = (await store.get_secret_rotation_meta())[ROTATION_RECORD_ID]
            stamps = await reconcile_rotation_meta(
                store,
                settings,
                dek_key_id=_key_id(key),
                enforcement=SecurityEnforcement.WARN,
                env_values={},
                extra_values={ROTATION_RECORD_ID: "a synthetic credential value"},
            )
            assert ROTATION_RECORD_ID not in stamps
            watched = secrets_from_settings_and_stamps(settings, stamps)
            assert ROTATION_RECORD_ID not in {w.class_id for w in watched}
            assert (await store.get_secret_rotation_meta())[ROTATION_RECORD_ID] == before
            await store.reencrypt_to_active()
            assert (await store.get_secret_rotation_meta())[ROTATION_RECORD_ID] == before
        finally:
            await store.close()

    asyncio.run(run())


def test_closing_writes_nothing_where_no_run_opened_a_record(tmp_path: Path) -> None:
    db, key = tmp_path / "none.db", generate_key()

    async def run() -> dict[str, SecretRotationMetaRow]:
        store = await _open(db, key)
        try:
            await close_rotation_record(store, "2026-10-30")
            return await store.get_secret_rotation_meta()
        finally:
            await store.close()

    assert asyncio.run(run()) == {}
