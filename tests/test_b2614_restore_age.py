# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``restore`` refuses an old archive unless told it is meant (BACKLOG #2614).

A restore undoes every account change made after the archive was taken, so ``restore`` refuses an
archive older than ``--max-age-days`` (7 by default), or one that does not say when it was taken,
unless ``--allow-old-archive`` is given. It prints the time of the archive's newest audit row and
says that every disable, delete, role change and reset after it must be re-applied by hand.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest

from messagefoundry.__main__ import _RESTORE_MAX_AGE_DAYS, main
from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline.dr_backup import (
    BackupError,
    BackupRunner,
    _refuse_an_old_archive,
    run_restore,
)
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

_DAY = 86400.0


async def _archive(tmp_path: Path, key: str, *, taken: float) -> str:
    """A real archive whose manifest says it was taken at ``taken``."""
    store = await MessageStore.open(tmp_path / "msg.db", cipher=make_cipher(key))
    try:
        await store.record_audit("synthetic_probe", actor="t", detail="{}")
        runner = BackupRunner(
            store,
            BackupSettings(enabled=True, destination=str(tmp_path / "b")),
            store_settings=StoreSettings(path=str(tmp_path / "msg.db"), encryption_key=key),
            config_dir=None,
        )
        result = await runner.run_once(now=taken)
        assert result is not None
        return result.archive_path
    finally:
        await store.close()


def _toml(tmp_path: Path, key: str) -> str:
    path = tmp_path / "svc.toml"
    path.write_text(f'[store]\nencryption_key = "{key}"\n', encoding="utf-8")
    return str(path)


def _error(out: str) -> str:
    return str(json.loads(out.strip().splitlines()[-1])["error"])


def test_the_default_limit_is_a_week() -> None:
    assert _RESTORE_MAX_AGE_DAYS == 7.0


def test_an_archive_past_the_limit_is_refused_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = generate_key()
    archive = asyncio.run(_archive(tmp_path, key, taken=time.time() - 10 * _DAY))
    toml = _toml(tmp_path, key)
    dest = tmp_path / "restored" / "msg.db"

    assert main(["restore", archive, "--to", str(dest), "--service-config", toml, "--json"]) == 1
    error = _error(capsys.readouterr().out)
    assert error.startswith("restore failed (age):")
    assert "10.0 days ago, past the 7-day limit" in error
    assert "Its newest audit row is 20" in error  # an ISO time, not "unknown"
    assert "re-applied by hand" in error and "--allow-old-archive" in error
    assert not dest.exists()

    # A wider limit restores it, and so does the explicit flag: the refusal is the age, nothing else.
    argv = ["restore", archive, "--to", str(dest), "--service-config", toml, "--json"]
    assert main([*argv, "--max-age-days", "30"]) == 0
    assert dest.exists()
    second = tmp_path / "again" / "msg.db"
    assert main(["restore", archive, "--to", str(second), "--service-config", toml,
                 "--allow-old-archive", "--json"]) == 0  # fmt: skip
    assert second.exists()


def test_a_fresh_archive_restores_and_says_what_to_reapply(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = generate_key()
    archive = asyncio.run(_archive(tmp_path, key, taken=time.time()))
    toml = _toml(tmp_path, key)
    dest = tmp_path / "restored" / "msg.db"

    assert main(["restore", archive, "--to", str(dest), "--service-config", toml]) == 0
    out = capsys.readouterr().out
    assert "newest audit row in it 20" in out
    assert "must be re-applied by hand" in out
    # Worded from the restore's own count (none here: the archive holds no session), never as
    # "every session" whether or not its revoke ran.
    assert "The restore ended 0 open session(s) in the store it placed" in out
    assert "every session the archive held" not in out

    json_dest = tmp_path / "json" / "msg.db"
    argv = ["restore", archive, "--to", str(json_dest), "--service-config", toml, "--json"]
    assert main(argv) == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["last_audit_at"].startswith("20") and payload["last_audit_at"].endswith("Z")
    assert len(payload["archive_sha256"]) == 64
    assert payload["sessions_revoked"] == 0


def test_an_archive_that_does_not_say_when_it_was_taken_is_refused() -> None:
    with pytest.raises(BackupError) as info:
        _refuse_an_old_archive(
            archive_created_at=None, last_audit_at=None, max_age_seconds=7 * _DAY, now=time.time()
        )
    assert info.value.kind == "age_undated"
    assert "does not say when it was taken" in str(info.value)
    assert "newest audit row is unknown" in str(info.value)


def test_the_limit_is_inclusive_and_checks_nothing_inside_it() -> None:
    now = 1_000_000.0
    _refuse_an_old_archive(
        archive_created_at=now - 7 * _DAY, last_audit_at=None, max_age_seconds=7 * _DAY, now=now
    )
    with pytest.raises(BackupError):
        _refuse_an_old_archive(
            archive_created_at=now - 7 * _DAY - 1,
            last_audit_at=None,
            max_age_seconds=7 * _DAY,
            now=now,
        )


async def test_the_primitive_checks_no_age_unless_asked(tmp_path: Path) -> None:
    """``run_restore`` with no limit restores any age: only the CLI applies the default, so the
    refusal stays one operator decision and not a hidden one inside the primitive."""
    key = generate_key()
    archive = await _archive(tmp_path, key, taken=1.0)
    dest = tmp_path / "restored" / "msg.db"
    settings = StoreSettings(path=str(dest), encryption_key=key)
    with pytest.raises(BackupError) as info:
        await run_restore(
            archive, dest_store_path=dest, store_settings=settings, max_age_seconds=7 * _DAY
        )
    assert info.value.kind == "age" and not dest.exists()
    result = await run_restore(archive, dest_store_path=dest, store_settings=settings)
    assert result.archive_created_at == 1.0


@pytest.mark.parametrize("bad", ["0", "-1", "nan", "inf", "soon"])
def test_a_max_age_that_would_refuse_everything_is_rejected_at_parse(
    bad: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as info:
        main(["restore", "a.mfbak", "--to", str(tmp_path / "x.db"), "--max-age-days", bad])
    assert info.value.code == 2
    assert "--max-age-days" in capsys.readouterr().err


def test_an_archive_dated_in_the_future_or_before_1970_is_refused_cleanly() -> None:
    now = 1_800_000_000.0
    with pytest.raises(BackupError) as ahead:
        _refuse_an_old_archive(
            archive_created_at=now + 30 * _DAY,
            last_audit_at=None,
            max_age_seconds=7 * _DAY,
            now=now,
        )
    assert ahead.value.kind == "age_undated" and "after now" in str(ahead.value)
    # A little lead is an ordinary clock and passes.
    _refuse_an_old_archive(
        archive_created_at=now + 60, last_audit_at=None, max_age_seconds=7 * _DAY, now=now
    )
    with pytest.raises(BackupError) as early:  # a BackupError, never a platform OSError
        _refuse_an_old_archive(
            archive_created_at=-86_400.0 * 400,
            last_audit_at=-5.0,
            max_age_seconds=7 * _DAY,
            now=now,
        )
    assert early.value.kind == "age"
