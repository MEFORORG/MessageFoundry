# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``rotate-key --close-without-roll REASON``: the dedicated way out of a rotation record that no
roll can close (BACKLOG #4935, owner ruling 2026-11-04, "Dedicated exit").

A chain the roll refuses for good, under any key, held the rotation record open for good, and the
ways out it named were two levers the owner ruled are not the intended exit. The flag closes the record
and stamps the key, once a run re-seals the data with no skip, behind an audit row that carries the
reason. It does nothing in every other case, and says so.
"""

from __future__ import annotations

import asyncio
import datetime
import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import ROTATION_CLOSED_WITHOUT_ROLL_ACTION, main
from messagefoundry.pipeline.secret_rotation import ROTATION_RECORD_ID, dek_fingerprint
from messagefoundry.store.crypto import generate_key
from tests.test_rotate_key_rotation_record import (
    _DEK,
    _OLD_DATE,
    _env,
    _key_id,
    _open,
    _plant_unopenable_upload,
    _refuse_reencrypt,
    _rows,
    _seed,
    _seed_keyless_chain,
    _serve_reconcile,
)

_REASON = "chain broken by a start on the new key alone; ticket 42"


def _closed_rows(db: Path, key: str, *retired: str) -> list[dict[str, object]]:
    async def read() -> list[dict[str, object]]:
        store = await _open(db, key, *retired)
        try:
            return [
                dict(r) for r in await store.list_audit(action=ROTATION_CLOSED_WITHOUT_ROLL_ACTION)
            ]
        finally:
            await store.close()

    return asyncio.run(read())


def _broken_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> tuple[Path, Path, str, str]:
    """A store whose rotation stopped before the roll, then took an audit row from a start on the
    new key alone: the BACKLOG #4934 break, which no later roll clears."""
    from messagefoundry.store.store import MessageStore

    monkeypatch.chdir(tmp_path)
    db, uploads = tmp_path / "rot.db", tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    asyncio.run(_seed(db, uploads, key_a))
    with monkeypatch.context() as patch:
        patch.setattr(MessageStore, "reencrypt_to_active", _refuse_reencrypt)
        _env(monkeypatch, key_b, key_a, uploads)
        assert main(["rotate-key", "--db", str(db)]) == 1

    async def a_start_on_the_new_key_alone() -> None:
        store = await _open(db, key_b)
        try:
            await store.record_audit("test.after_stop", actor="u")
        finally:
            await store.close()

    asyncio.run(a_start_on_the_new_key_alone())
    capsys.readouterr()
    return db, uploads, key_a, key_b


def test_the_refusal_names_the_dedicated_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db, _, _, _ = _broken_chain(tmp_path, monkeypatch, capsys)
    assert main(["rotate-key", "--db", str(db)]) == 1
    err = capsys.readouterr().err
    assert '--close-without-roll "<reason>"' in err, err


def test_a_broken_chain_closes_with_an_audited_reason_and_a_start_then_stamps_nothing_new(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db, _, key_a, key_b = _broken_chain(tmp_path, monkeypatch, capsys)
    assert main(["rotate-key", "--db", str(db), "--close-without-roll", f"  {_REASON} "]) == 1
    captured = capsys.readouterr()
    assert "refusing to roll a broken audit chain" in captured.err
    assert "--close-without-roll closed the rotation record" in captured.err
    assert "note: no run will roll this audit chain" not in captured.err
    assert "OK:" not in captured.out
    rows = asyncio.run(_rows(db, key_b, key_a))
    today = datetime.datetime.now(tz=datetime.UTC).date().isoformat()
    assert rows[ROTATION_RECORD_ID].fingerprint == ""
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[_DEK].last_rotated == today
    audited = _closed_rows(db, key_b, key_a)
    assert len(audited) == 1
    assert str(audited[0]["actor"]).startswith("cli:")
    detail = json.loads(str(audited[0]["detail"]))
    assert detail["reason"] == _REASON
    assert detail["roll_refusal"].startswith("refusing to roll a broken audit chain")
    # A serve start now finds the key stamped, so it opens no record and holds nothing.
    after = asyncio.run(_serve_reconcile(db, key_b, key_a))
    assert after[ROTATION_RECORD_ID].fingerprint == ""
    assert after[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))


def test_a_chain_with_no_genesis_row_closes_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    db, uploads = tmp_path / "keyless.db", tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    asyncio.run(_seed_keyless_chain(db, uploads, key_a))
    _env(monkeypatch, key_b, key_a, uploads)
    assert main(["rotate-key", "--db", str(db), "--close-without-roll", _REASON]) == 1
    err = capsys.readouterr().err
    assert "does not open with a genesis row naming its key" in err
    assert "--close-without-roll closed the rotation record" in err
    rows = asyncio.run(_rows(db, key_b, key_a))
    assert rows[ROTATION_RECORD_ID].fingerprint == ""
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))
    assert len(_closed_rows(db, key_b, key_a)) == 1


def test_a_run_with_a_skip_closes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db, uploads, key_a, key_b = _broken_chain(tmp_path, monkeypatch, capsys)
    _plant_unopenable_upload(uploads)
    assert main(["rotate-key", "--db", str(db), "--close-without-roll", _REASON]) == 1
    err = capsys.readouterr().err
    assert "--close-without-roll closed nothing" in err
    rows = asyncio.run(_rows(db, key_b, key_a))
    assert rows[ROTATION_RECORD_ID].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[_DEK].last_rotated == _OLD_DATE
    assert _closed_rows(db, key_b, key_a) == []


def test_a_same_key_run_closes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A run with the key already in use opens no record, and its key was never rotated, so the
    flag must not stamp it."""
    monkeypatch.chdir(tmp_path)
    db, uploads, key_a = tmp_path / "same.db", tmp_path / "uploads", generate_key()
    asyncio.run(_seed_keyless_chain(db, uploads, key_a))
    _env(monkeypatch, key_a, "", uploads)
    assert main(["rotate-key", "--db", str(db), "--close-without-roll", _REASON]) == 1
    assert "--close-without-roll closed nothing" in capsys.readouterr().err
    rows = asyncio.run(_rows(db, key_a))
    assert ROTATION_RECORD_ID not in rows
    assert rows[_DEK].last_rotated == _OLD_DATE
    assert _closed_rows(db, key_a) == []


def test_a_chain_that_rolls_closes_as_usual_and_writes_no_close_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    db, uploads = tmp_path / "rot.db", tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    asyncio.run(_seed(db, uploads, key_a))
    _env(monkeypatch, key_b, key_a, uploads)
    assert main(["rotate-key", "--db", str(db), "--close-without-roll", _REASON]) == 0
    captured = capsys.readouterr()
    assert "OK:" in captured.out
    assert "--close-without-roll was not used" in captured.err
    rows = asyncio.run(_rows(db, key_b, key_a))
    assert rows[ROTATION_RECORD_ID].fingerprint == ""
    assert _closed_rows(db, key_b, key_a) == []


@pytest.mark.parametrize("reason", ["", "   ", "x" * 1001])
def test_a_blank_or_too_long_reason_changes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    reason: str,
) -> None:
    db, _, key_a, key_b = _broken_chain(tmp_path, monkeypatch, capsys)
    before = {p.name: p.read_bytes() for p in tmp_path.glob("rot.db*")}
    assert main(["rotate-key", "--db", str(db), "--close-without-roll", reason]) == 2
    err = capsys.readouterr().err
    assert "Nothing was changed." in err
    assert "Traceback" not in err
    assert {p.name: p.read_bytes() for p in tmp_path.glob("rot.db*")} == before
