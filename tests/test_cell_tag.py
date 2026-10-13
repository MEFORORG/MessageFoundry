# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Message cells bound to their channel and preset criteria bound to their owner (BACKLOG #2593).

The unit half pins the builders: the bound column is in the tag, each cell and each table has its own
tag, and the tag keeps the cell's name. The integration half runs the cross-backend contract in
``tests/_cell_tag_contract.py`` on SQLite; the Postgres and SQL Server legs run the same contract from
``tests/test_postgres_store.py`` and ``tests/test_sqlserver_store.py``. The SQLite-only half covers
the on-open seal pass, rotation and the restore-verify cell list.
"""

from __future__ import annotations

import ast
import pathlib
import sqlite3
from typing import Any

import pytest

import messagefoundry
from messagefoundry.store import MessageStore
from messagefoundry.store.cell_tag import (
    MESSAGE_TAG_CELLS,
    CellTagError,
    message_cell_aad,
    open_message_cell,
    preset_criteria_aad,
    row_tag_aad,
    row_tag_columns,
)
from messagefoundry.store.cipher_cells import SQLITE_CIPHER_CELLS
from messagefoundry.store.crypto import (
    AesGcmCipher,
    CipherError,
    aad_cell_name,
    cell_aad,
    generate_key,
    make_cipher,
)
from messagefoundry.store.store import MessageStatus
from tests._cell_tag_contract import assert_cell_tag_contract

_RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|CT9|P|2.5.1\rPID|1||SYNTH-300\r"


def test_the_channel_and_the_cell_are_in_the_message_tag() -> None:
    base = message_cell_aad("raw", message_id="m1", channel_id="IB_A")
    assert message_cell_aad("raw", message_id="m1", channel_id="IB_B") != base
    assert message_cell_aad("raw", message_id="m2", channel_id="IB_A") != base
    assert message_cell_aad("summary", message_id="m1", channel_id="IB_A") != base
    assert base != cell_aad("messages", "raw", "m1")  # not the old id-only tag
    for column in MESSAGE_TAG_CELLS:
        aad = message_cell_aad(column, message_id="m1", channel_id="IB_A")
        assert aad_cell_name(aad) == ("messages", column)
    with pytest.raises(ValueError, match="not a tagged message cell"):
        message_cell_aad("status", message_id="m1", channel_id="IB_A")


def test_the_owner_is_in_the_preset_tag() -> None:
    base = preset_criteria_aad(preset_id="p1", owner_user_id="u1")
    assert preset_criteria_aad(preset_id="p1", owner_user_id="u2") != base
    assert preset_criteria_aad(preset_id="p2", owner_user_id="u1") != base
    assert aad_cell_name(base) == ("search_presets", "criteria")
    assert base != cell_aad("search_presets", "criteria", "p1")


def test_row_tag_reads_the_bound_columns_off_a_row() -> None:
    assert row_tag_columns("messages", "raw") == ("id", "channel_id")
    assert row_tag_columns("search_presets", "criteria") == ("id", "owner_user_id")
    assert row_tag_columns("users", "totp_secret") == ("id",)
    row = {"id": "m1", "channel_id": "IB_A"}
    assert row_tag_aad("messages", "error", row) == message_cell_aad(
        "error", message_id="m1", channel_id="IB_A"
    )
    assert row_tag_aad("users", "totp_secret", {"id": "u1"}) == cell_aad(
        "users", "totp_secret", "u1"
    )
    with pytest.raises(KeyError):  # a pass that forgot to select the channel fails closed
        row_tag_aad("messages", "raw", {"id": "m1"})


def test_open_message_cell_refuses_a_moved_cell_and_alerts() -> None:
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    seen: list[tuple[str, str]] = []
    cipher.set_tag_failure_hook(lambda table, reason: seen.append((table, reason)))
    sealed = cipher.encrypt("SYNTH", aad=message_cell_aad("raw", message_id="m1", channel_id="A"))
    assert open_message_cell(cipher, "raw", sealed, message_id="m1", channel_id="A") == "SYNTH"
    assert open_message_cell(cipher, "error", None, message_id="m1", channel_id="A") is None
    assert not seen  # control: nothing alerted
    with pytest.raises(CellTagError, match="integrity") as refused:
        open_message_cell(cipher, "raw", sealed, message_id="m1", channel_id="B")
    assert issubclass(CellTagError, CipherError)
    assert refused.value.channel_id == "B" and refused.value.row_ref == "m1"
    assert seen and seen[0][0] == "messages" and "m1" in seen[0][1]
    # A key that is not configured is the cipher's own error, not a tag failure.
    other = make_cipher(generate_key(), write_v2=True)
    with pytest.raises(CipherError) as missing:
        open_message_cell(other, "raw", sealed, message_id="m1", channel_id="A")
    assert not isinstance(missing.value, CellTagError)


class _NoKeyringView:
    """A cipher that, like Vault Transit, cannot say which keys it holds."""

    def __init__(self, inner: AesGcmCipher) -> None:
        self._inner = inner
        self.encrypts = True

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        return self._inner.decrypt(stored, aad=aad)

    def is_encrypted(self, stored: str) -> bool:
        return self._inner.is_encrypted(stored)


def test_a_cipher_that_cannot_name_its_keys_keeps_its_own_error() -> None:
    """Under such a cipher a failed open may be an unreachable provider, so it is not reported as an
    integrity failure: the read still refuses, with the cipher's own error and no alert."""
    inner = make_cipher(generate_key(), write_v2=True)
    assert isinstance(inner, AesGcmCipher)
    seen: list[str] = []
    inner.set_tag_failure_hook(lambda table, reason: seen.append(reason))
    sealed = inner.encrypt("SYNTH", aad=message_cell_aad("raw", message_id="nk1", channel_id="A"))
    with pytest.raises(CipherError) as refused:
        open_message_cell(
            _NoKeyringView(inner),  # type: ignore[arg-type]
            "raw",
            sealed,
            message_id="nk1",
            channel_id="B",
        )
    assert not isinstance(refused.value, CellTagError) and not seen
    with pytest.raises(CellTagError):  # control: the keyring itself names it a tag failure
        open_message_cell(inner, "raw", sealed, message_id="nk1", channel_id="B")


def test_a_failed_cell_is_reported_once_per_interval() -> None:
    """A list view meets the same failed row on every poll; it alerts once, not every time."""
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    seen: list[str] = []
    cipher.set_tag_failure_hook(lambda table, reason: seen.append(reason))
    sealed = cipher.encrypt(
        "SYNTH", aad=message_cell_aad("raw", message_id="once1", channel_id="A")
    )
    for _ in range(3):
        with pytest.raises(CellTagError):
            open_message_cell(cipher, "raw", sealed, message_id="once1", channel_id="B")
    other = cipher.encrypt("SYNTH", aad=message_cell_aad("raw", message_id="once2", channel_id="A"))
    with pytest.raises(CellTagError):  # control: another row still alerts
        open_message_cell(cipher, "raw", other, message_id="once2", channel_id="B")
    assert len(seen) == 2 and "once1" in seen[0] and "once2" in seen[1]


async def test_the_scoped_message_read_hides_a_failed_row_out_of_scope() -> None:
    """The API's one by-id read: out of scope a row that fails its tag is the same 404 as any other
    refused row, with the channel denial audited; in scope it is a 423, never a 500."""
    from types import SimpleNamespace

    from fastapi import HTTPException
    from starlette.requests import Request

    from messagefoundry.api.message_scope import get_scoped_message, read_scoped_message

    audits: list[str] = []

    class _Store:
        async def get_message(self, message_id: str) -> None:
            raise CellTagError("messages", "raw", message_id, "IB_SECRET")

        async def record_audit(self, action: str, **_: object) -> None:
            audits.append(action)

    engine: Any = SimpleNamespace(store=_Store())
    request = Request({"type": "http", "client": ("127.0.0.1", 1), "headers": []})
    out: Any = SimpleNamespace(username="u", can_access_channel=lambda c: c != "IB_SECRET")
    inside: Any = SimpleNamespace(username="u", can_access_channel=lambda c: True)
    assert await read_scoped_message(engine, out, "m-scope", request) is None
    assert audits == ["auth.channel_denied"]
    with pytest.raises(HTTPException) as hidden:
        await get_scoped_message(engine, out, "m-scope", request)
    assert hidden.value.status_code == 404
    with pytest.raises(HTTPException) as refused:
        await get_scoped_message(engine, inside, "m-scope", request)
    assert refused.value.status_code == 423
    assert await read_scoped_message(engine, inside, "m-scope", request) is None  # export skips


_STORE_DIR = pathlib.Path(messagefoundry.__file__).resolve().parent / "store"


def _literal_cells(path: pathlib.Path, tables: set[str]) -> int:
    count = 0
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", getattr(node.func, "attr", None)) == "cell_aad"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value in tables
        ):
            count += 1
    return count


def test_one_builder_builds_every_message_and_preset_tag() -> None:
    """No store module builds a message cell's or a preset's associated data except through the
    builders, whose own ``cell_aad`` frame names the table by variable, not by literal."""
    files = sorted(_STORE_DIR.rglob("*.py"))
    assert len(files) >= 3, files  # the walk found the store modules
    counts = {p.name: n for p in files if (n := _literal_cells(p, {"messages", "search_presets"}))}
    assert counts == {}, counts
    # Positive control: the same instrument finds the literal cells another table still uses.
    assert _literal_cells(_STORE_DIR / "store.py", {"queue"}) > 0
    for backend in ("store.py", "postgres.py", "sqlserver.py"):
        source = (_STORE_DIR / backend).read_text(encoding="utf-8")
        assert "message_cell_aad(" in source and "preset_criteria_aad(" in source, backend


async def test_cell_tag_contract_sqlite(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "cell-tag.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key(), write_v2=True))
    side = sqlite3.connect(db, timeout=30)  # a writer with no key, outside the store
    side.row_factory = sqlite3.Row
    try:

        async def raw(sql: str, params: tuple[Any, ...]) -> None:
            side.execute(sql, params)
            side.commit()

        async def fetch(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
            return [dict(r) for r in side.execute(sql, params).fetchall()]

        await assert_cell_tag_contract(store, raw, fetch)
    finally:
        side.close()
        await store.close()


async def test_the_seal_pass_binds_legacy_plaintext_to_the_channel(tmp_path: pathlib.Path) -> None:
    """A keyless store's plaintext is sealed under the new tag on its first keyed open."""
    db = tmp_path / "seal.db"
    keyless = await MessageStore.open(db)
    try:
        mid = await keyless.record_received(
            channel_id="IB_S", raw=_RAW, status=MessageStatus.RECEIVED, summary="SYNTH-S"
        )
        await keyless.upsert_search_preset(
            preset_id="p-seal", owner_user_id="u-seal", name="n", criteria='{"c": 1}'
        )
    finally:
        await keyless.close()
    keyed = await MessageStore.open(db, cipher=make_cipher(generate_key(), write_v2=True))
    side = sqlite3.connect(db, timeout=30)
    try:
        stored = side.execute("SELECT raw FROM messages WHERE id=?", (mid,)).fetchone()[0]
        assert keyed.cipher().is_encrypted(stored)
        record = await keyed.get_message(mid)
        assert record is not None and record["raw"] == _RAW and record["summary"] == "SYNTH-S"
        preset = await keyed.get_search_preset(preset_id="p-seal", owner_user_id="u-seal")
        assert preset is not None and preset["criteria"] == '{"c": 1}'
        side.execute("UPDATE messages SET channel_id='IB_OTHER' WHERE id=?", (mid,))
        side.commit()
        with pytest.raises(CellTagError):
            await keyed.get_message(mid)
    finally:
        side.close()
        await keyed.close()


async def test_rotation_rebinds_the_tag_and_steps_over_a_moved_cell(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``rotate-key`` re-seals each message cell and each preset under its own tag. A cell that
    fails its tag under a held key is left as it is and counted, so it cannot block the rotation."""
    db = tmp_path / "rotate.db"
    old_key, new_key = generate_key(), generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(old_key, write_v2=True))
    side = sqlite3.connect(db, timeout=30)
    try:
        keep = await store.record_received(
            channel_id="IB_R", raw=_RAW, status=MessageStatus.RECEIVED, summary="SYNTH-R"
        )
        moved = await store.record_received(
            channel_id="IB_R", raw=_RAW, status=MessageStatus.RECEIVED, summary="SYNTH-R"
        )
        await store.upsert_search_preset(
            preset_id="p-rot", owner_user_id="u-rot", name="n", criteria='{"c": 2}'
        )
        side.execute("UPDATE messages SET channel_id='IB_ELSE' WHERE id=?", (moved,))
        side.commit()
    finally:
        await store.close()

    rotated = await MessageStore.open(
        db, cipher=make_cipher(new_key, retired_b64=[old_key], write_v2=True)
    )
    try:
        with caplog.at_level("WARNING"):
            assert await rotated.reencrypt_to_active() >= 3
        assert "rotation left 1 messages.raw value(s)" in caplog.text
        assert "rotation left 1 messages.summary value(s)" in caplog.text
        record = await rotated.get_message(keep)
        assert record is not None and record["raw"] == _RAW  # re-sealed under the new key and tag
        preset = await rotated.get_search_preset(preset_id="p-rot", owner_user_id="u-rot")
        assert preset is not None and preset["criteria"] == '{"c": 2}'
        with pytest.raises(CellTagError):  # still refused after the rotation
            await rotated.get_message(moved)
    finally:
        side.close()
        await rotated.close()


async def test_the_restore_verify_cell_list_opens_message_and_preset_cells(
    tmp_path: pathlib.Path,
) -> None:
    """The restore verify reads every sealed value through ``SQLITE_CIPHER_CELLS``. A message cell
    and a preset's criteria open under the tag its entry builds, and a moved row does not."""
    db = tmp_path / "verify.db"
    cipher = make_cipher(generate_key(), write_v2=True)
    store = await MessageStore.open(db, cipher=cipher)
    side = sqlite3.connect(db, timeout=30)
    side.row_factory = sqlite3.Row
    try:
        mid = await store.record_received(
            channel_id="IB_V", raw=_RAW, status=MessageStatus.RECEIVED, metadata='{"a": 1}'
        )
        await store.upsert_search_preset(
            preset_id="p-ver", owner_user_id="u-ver", name="n", criteria='{"c": 3}'
        )
        cells = {(c.table, c.column): c for c in SQLITE_CIPHER_CELLS}
        for (table, column), key, expected in (
            (("messages", "raw"), mid, _RAW),
            (("messages", "metadata"), mid, '{"a": 1}'),
            (("search_presets", "criteria"), "p-ver", '{"c": 3}'),
        ):
            spec = cells[(table, column)]
            cols = ", ".join(spec.aad_columns)
            row = side.execute(
                f"SELECT {cols}, {column} AS v FROM {table} WHERE id=?", (key,)
            ).fetchone()
            values = [row[c] for c in spec.aad_columns]
            assert cipher.decrypt(row["v"], aad=spec.aad(*values)) == expected
        side.execute("UPDATE messages SET channel_id='IB_ELSE' WHERE id=?", (mid,))
        side.commit()
        spec = cells[("messages", "raw")]
        row = side.execute("SELECT id, channel_id, raw FROM messages WHERE id=?", (mid,)).fetchone()
        with pytest.raises(CipherError):
            cipher.decrypt(row["raw"], aad=spec.aad(row["id"], row["channel_id"]))
    finally:
        side.close()
        await store.close()
