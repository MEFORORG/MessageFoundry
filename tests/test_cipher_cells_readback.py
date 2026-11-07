# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The full restore-verify reads every composite-key cipher cell back through the cipher (BACKLOG #1719).

Before this, ``_decrypt_check`` walked ``MessageStore._CIPHER_COLUMNS`` alone. A corrupted value in
``response``, ``shared_body``, ``attachment_chunk``, ``message_events``, ``connection_event`` or
``alert_instance`` passed ``PRAGMA quick_check``, every row count, and the full verify, and surfaced
only when something next read that row. ``state`` and ``reference`` were caught, but only because the
store happens to decrypt them eagerly at open.

Each cell here is written through the REAL store writer on a keyed store, so the AAD columns declared
in ``messagefoundry/store/cipher_cells.py`` are proven against what the writer actually bound rather
than against a second copy of it. Every value is synthetic (CLAUDE.md section 9).
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import shutil
import sqlite3
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

import messagefoundry.store.base as store_base
import messagefoundry.store.cipher_cells as cipher_cells_module
from messagefoundry.__main__ import main
from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupRunner, run_restore_verify
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.base import build_store_cipher
from messagefoundry.store.cipher_cells import (
    COMPOSITE_CIPHER_CELLS,
    DEFAULT_CHUNK_ROWS,
    POSITION,
    POSTGRES_CIPHER_CELLS,
    SQLITE_CIPHER_CELLS,
    SQLSERVER_CIPHER_CELLS,
    CipherAudit,
    CipherCell,
    CipherCellSource,
    CipherWalkInterrupted,
    audit_cipher_cells,
    audit_server_cipher_cells,
    connect_readonly,
    read_cipher_cells,
)
from messagefoundry.store.crypto import _V4_PREFIX, MARKER_PREFIX, Cipher, CipherError, generate_key
from messagefoundry.store.store import Stage
from tests.test_store_cipher_sweep_parity import _covered_cells, _parsed

#: Every value the fixture writes, keys included, carries this. A FAIL reason must never contain it:
#: that would be a plaintext, or a composite key column (a ``state`` or ``reference`` key can be PHI).
_SYNTH = "SYNTH-"
_RAW = "MSH|^~\\&|SYNTH-RAW"

_IDS = [f"{c.table}.{c.column}" for c in COMPOSITE_CIPHER_CELLS]


async def _populate(store: MessageStore) -> None:
    """Write at least one sealed value into every composite cipher cell, each through its own writer."""
    # Two destinations sharing one body put it in shared_body; the third stays inline. The routine
    # 'received' event carries a sealed message_events.detail.
    await store.enqueue_message(
        channel_id="IB_SYNTH",
        raw=_RAW,
        deliveries=[
            ("OB_A", "SYNTH-SHARED-BODY"),
            ("OB_B", "SYNTH-SHARED-BODY"),
            ("OB_C", "SYNTH-INLINE"),
        ],
    )
    item = next(i for i in await store.claim_ready() if i.destination_name == "OB_C")
    await store.complete_with_response(
        item.id,
        body="SYNTH-REPLY-BODY",
        outcome="accepted",
        detail="SYNTH-REPLY-DETAIL",
        response_headers={"X-Synth": "SYNTH-HDR-VALUE"},
    )

    # state.value rides the transform handoff, the way a live transform writes it.
    mid = await store.enqueue_ingress(channel_id="IB_STATE", raw=_RAW)
    ingress = await store.claim_next_fifo("IB_STATE", stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB_STATE",
        handlers=[("H", _RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo("IB_STATE", stage=Stage.ROUTED.value)
    assert routed is not None
    await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id="IB_STATE",
        deliveries=[("OB_D", "SYNTH-OUT")],
        state_ops=[("ns", "SYNTH-KEY", {"seq": 7})],
    )

    await store.write_reference_snapshot(
        name="synth_ref", version="1", rows={"SYNTH-CODE": "SYNTH-REF-VALUE"}
    )
    await store.put_attachment(["SYNTH-CHUNK-ONE", "SYNTH-CHUNK-TWO"], "text/plain")
    await store.record_connection_event(
        connection="IB_SYNTH",
        transport="mllp",
        direction="inbound",
        kind="framing_error",
        reason="SYNTH-CONN-REASON",
    )
    await store.upsert_alert_instance(
        event_type="synth_event",
        connection="IB_SYNTH",
        severity="warning",
        reason="SYNTH-ALERT-REASON",
    )


@pytest.fixture(scope="module")
def _template(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, StoreSettings]:
    """One populated, closed, keyed store, built once and copied per test.

    Built the way ``open_store`` builds one, so it writes the AAD-bound ``mfenc:v4`` format (v2 before ADR 0196).
    ``make_cipher``'s own default is v1, which binds NO AAD: a fixture on it would pass every AAD
    assertion here without checking one."""
    db = tmp_path_factory.mktemp("cipher-cells") / "msg.db"
    settings = StoreSettings(path=str(db), encryption_key=generate_key())

    async def _build() -> None:
        store = await MessageStore.open(db, cipher=build_store_cipher(settings))
        try:
            await _populate(store)
        finally:
            await store.close()

    asyncio.run(_build())
    return db, settings


def _copy(template: tuple[Path, StoreSettings], tmp_path: Path) -> tuple[Path, StoreSettings]:
    src, settings = template
    db = tmp_path / src.name
    for suffix in ("", "-wal", "-shm"):
        if Path(f"{src}{suffix}").exists():
            shutil.copyfile(f"{src}{suffix}", f"{db}{suffix}")
    return db, settings.model_copy(update={"path": str(db)})


async def _open(db: Path, settings: StoreSettings) -> MessageStore:
    return await MessageStore.open(db, cipher=build_store_cipher(settings))


def _sealed_count(conn: sqlite3.Connection, cell: CipherCell, prefix: str = MARKER_PREFIX) -> int:
    row = conn.execute(
        f"SELECT COUNT(*) FROM {cell.table} WHERE {cell.column} LIKE ?",  # declared constants
        (f"{prefix}%",),
    ).fetchone()
    return int(row[0])


def _flip_one_aead_byte(db: Path, cell: CipherCell) -> str:
    """Flip one bit inside the GCM tag of one sealed value in ``cell``; return that row's locator.

    Written through a separate connection, so it also works under a store that is still open."""
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            f"SELECT rowid, {cell.column}, {', '.join(cell.locator)} FROM {cell.table}"
            f" WHERE {cell.column} LIKE ? ORDER BY rowid LIMIT 1",  # declared constants
            (f"{MARKER_PREFIX}%",),
        ).fetchone()
        assert row is not None, f"no sealed value in {cell.table}.{cell.column} to corrupt"
        rowid, stored, *where = row
        head, _, payload = str(stored).rpartition(":")
        blob = bytearray(base64.b64decode(payload))
        blob[-1] ^= 0x01  # the last byte is inside the GCM tag
        conn.execute(
            f"UPDATE {cell.table} SET {cell.column} = ? WHERE rowid = ?",  # declared constants
            (f"{head}:{base64.b64encode(bytes(blob)).decode()}", rowid),
        )
        conn.commit()
    finally:
        conn.close()
    return cell.locate(*where)


async def _backup(store: MessageStore, settings: StoreSettings, dest: Path) -> str:
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(dest)),
        store_settings=settings,
        config_dir=None,
    )
    result = await runner.run_once(now=1.0)
    assert result is not None
    return result.archive_path


async def test_every_composite_cell_is_written_and_read_back(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """PASS on a good archive, and the count proves every sealed value was opened.

    The count is compared to the number of sealed values in the source over EVERY declared cell, so a
    cell the verify silently skipped (a wrong column name, a missing table) cannot hide inside a
    nonzero total.
    """
    db, settings = _copy(_template, tmp_path)
    conn = sqlite3.connect(db)
    try:
        for cell in COMPOSITE_CIPHER_CELLS:
            sealed = _sealed_count(conn, cell)
            assert sealed >= 1, (
                f"the fixture wrote no sealed {cell.table}.{cell.column}, so nothing below proves "
                "the verify reads it"
            )
            # Every one AAD-bound, or the PASS below says nothing about the declared AAD columns.
            assert _sealed_count(conn, cell, _V4_PREFIX) == sealed, cell
        expected = sum(_sealed_count(conn, cell) for cell in SQLITE_CIPHER_CELLS)
    finally:
        conn.close()

    store = await _open(db, settings)
    try:
        archive = await _backup(store, settings, tmp_path / "b")
    finally:
        await store.close()

    res = await run_restore_verify(archive, store_settings=settings, full=True)
    assert res.status == "PASS", res.reason
    assert res.decrypted_cells == expected


@pytest.mark.parametrize("cell", COMPOSITE_CIPHER_CELLS, ids=_IDS)
async def test_a_flipped_byte_in_each_composite_cell_fails_the_full_verify(
    tmp_path: Path, _template: tuple[Path, StoreSettings], cell: CipherCell
) -> None:
    """One bit-flipped value per cell is FAIL, and the reason names the cell without its plaintext.

    The flip lands while the store is still open, so the store's own open-time cache warm-up does not
    stop the backup being taken. ``state`` and ``reference`` are also decrypted when the verify opens
    the snapshot, so for those two the open may report the failure first; the direct test below proves
    this pass catches them on its own.
    """
    db, settings = _copy(_template, tmp_path)
    store = await _open(db, settings)
    try:
        _flip_one_aead_byte(db, cell)
        archive = await _backup(store, settings, tmp_path / "b")
    finally:
        await store.close()

    res = await run_restore_verify(archive, store_settings=settings, full=True)
    assert res.status == "FAIL", res.reason
    reason = res.reason or ""
    if cell.table not in ("state", "reference"):
        assert f"{cell.table}.{cell.column} {cell.locator[0]}=" in reason, reason
    assert _SYNTH not in reason, f"the FAIL reason leaked a plaintext or a key: {reason}"


@pytest.mark.parametrize("cell", COMPOSITE_CIPHER_CELLS, ids=_IDS)
def test_the_decrypt_pass_itself_names_each_corrupted_cell(
    tmp_path: Path, _template: tuple[Path, StoreSettings], cell: CipherCell
) -> None:
    """The walk alone, on the store file, with no open in front of it to catch anything first.

    This is what proves the declaration's AAD for ``state`` and ``reference``, whose corruption the
    full verify's open would otherwise report before this pass ran. The clean-file PASS it starts from
    is the first test above.
    """
    db, settings = _copy(_template, tmp_path)
    locator = _flip_one_aead_byte(db, cell)
    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "FAIL", message
    assert f"{cell.table}.{cell.column} {locator} did not decrypt" in message, message
    assert _SYNTH not in message, f"the FAIL reason leaked a plaintext or a key: {message}"


def test_an_id_keyed_failure_still_names_the_row_id(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """An id-keyed cell keeps naming its synthetic ``id``, which an operator can look up, rather than
    the snapshot's ``rowid``. Only a key that can itself be PHI is withheld."""
    db, settings = _copy(_template, tmp_path)
    raw = next(c for c in SQLITE_CIPHER_CELLS if (c.table, c.column) == ("messages", "raw"))
    assert raw.locator == ("id",)
    where = _flip_one_aead_byte(db, raw)
    assert where.startswith("id=") and "rowid" not in where, where

    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "FAIL", message
    assert f"messages.raw {where} did not decrypt" in message, message


async def test_a_reply_that_looks_sealed_is_not_a_key_mismatch(tmp_path: Path) -> None:
    """A partner reply can begin with the at-rest marker. Sealed and opened under the right key it is
    a good cell, so the verify must PASS; reading the decrypted PLAINTEXT's prefix as "no key" would
    send the operator to fix a key configuration that is fine."""
    db = tmp_path / "msg.db"
    settings = StoreSettings(path=str(db), encryption_key=generate_key())
    store = await _open(db, settings)
    try:
        await store.enqueue_message(channel_id="IB_SYNTH", raw=_RAW, deliveries=[("OB_A", "X")])
        item = (await store.claim_ready())[0]
        await store.complete_with_response(
            item.id, body=f"{MARKER_PREFIX}SYNTH-looks-sealed", outcome="accepted"
        )
    finally:
        await store.close()

    status, message, cells = dr_backup._decrypt_check(db, settings)
    assert status == "PASS", message
    assert cells >= 1


async def test_a_value_moved_between_rows_fails_its_tag(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """A ciphertext moved to another row fails here as it would at a live read. Two sealed
    ``connection_event.reason`` values are individually valid; swapped, each fails, because the writer
    bound each to its own row's natural key. This proves the pass enforces the writer's binding. It
    does not prove the declaration's AAD columns, which the round-trip PASS test above does."""
    db, settings = _copy(_template, tmp_path)
    store = await _open(db, settings)
    try:
        await store.record_connection_event(
            connection="IB_OTHER",
            transport="mllp",
            direction="inbound",
            kind="closed",
            reason="SYNTH-CONN-REASON-2",
        )
    finally:
        await store.close()

    conn = sqlite3.connect(db)
    try:
        rows = conn.execute(
            "SELECT rowid, reason FROM connection_event WHERE reason LIKE ? ORDER BY rowid",
            (f"{MARKER_PREFIX}%",),
        ).fetchall()
        assert len(rows) >= 2
        (r1, v1), (r2, v2) = rows[0], rows[1]
        conn.execute("UPDATE connection_event SET reason=? WHERE rowid=?", (v2, r1))
        conn.execute("UPDATE connection_event SET reason=? WHERE rowid=?", (v1, r2))
        conn.commit()
    finally:
        conn.close()

    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "FAIL", message
    assert "connection_event.reason" in message, message


async def test_a_keyless_store_plaintext_that_resembles_the_marker_passes(tmp_path: Path) -> None:
    """SQLite's LIKE ignores case; the marker does not. On a keyless store, a reply spelled like the
    marker in another case is plaintext, and must not be read as a sealed cell nobody can open."""
    db = tmp_path / "msg.db"
    settings = StoreSettings(path=str(db))
    store = await _open(db, settings)
    try:
        await store.enqueue_message(channel_id="IB_SYNTH", raw=_RAW, deliveries=[("OB_A", "X")])
        item = (await store.claim_ready())[0]
        reply = MARKER_PREFIX.upper() + "SYNTH-plaintext"
        await store.complete_with_response(item.id, body=reply, outcome="accepted")
    finally:
        await store.close()

    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "PASS", message


# --- cipher-audit: the same walk over a LIVE store (BACKLOG #1719, step 1) -------------------------


def _audit(
    db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], *extra: str
) -> tuple[int, dict[str, Any]]:
    """Run ``cipher-audit --json`` on ``db`` from a directory with no service settings file."""
    monkeypatch.chdir(db.parent)
    rc = main(["cipher-audit", "--db", str(db), "--json", *extra])
    out = capsys.readouterr().out
    payload = json.loads(out.strip().splitlines()[-1])
    assert _SYNTH not in out, f"cipher-audit printed a plaintext or a key: {out}"
    return rc, payload


def _keyed(monkeypatch: pytest.MonkeyPatch, settings: StoreSettings) -> None:
    assert settings.encryption_key is not None
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", settings.encryption_key)


def _sealed_by_cell(db: Path) -> dict[str, int]:
    conn = sqlite3.connect(db)
    try:
        return {f"{c.table}.{c.column}": _sealed_count(conn, c) for c in SQLITE_CIPHER_CELLS}
    finally:
        conn.close()


def _cells(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["cell"]: row for row in payload["cells"]}


async def test_cipher_audit_reads_every_sealed_value_of_a_live_store(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """PASS, run beside an OPEN store, and each cell's count is the number of sealed values in it,
    so a cell the audit skipped cannot hide inside a nonzero total."""
    db, settings = _copy(_template, tmp_path)
    _keyed(monkeypatch, settings)
    expected = _sealed_by_cell(db)
    store = await _open(db, settings)
    try:
        rc, payload = _audit(db, monkeypatch, capsys)
    finally:
        await store.close()
    assert rc == 0, payload
    assert payload["status"] == "PASS" and payload["keyed"] is True
    got = _cells(payload)
    assert set(got) == set(expected)
    assert {name: row["opened"] for name, row in got.items()} == expected
    assert all(row["failed"] == 0 and row["unmarked"] == 0 for row in got.values()), got
    assert payload["opened"] == sum(expected.values()) > len(COMPOSITE_CIPHER_CELLS)


def test_cipher_audit_reports_every_failure_and_keeps_counting(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unlike the restore-verify, the audit does not stop at the first bad value: two corrupted
    cells are both counted, each names its first locator, and every other cell is still read."""
    db, settings = _copy(_template, tmp_path)
    _keyed(monkeypatch, settings)
    expected = _sealed_by_cell(db)
    by_name = {f"{c.table}.{c.column}": c for c in SQLITE_CIPHER_CELLS}
    raw_at = _flip_one_aead_byte(db, by_name["messages.raw"])
    body_at = _flip_one_aead_byte(db, by_name["response.body"])

    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 1 and payload["status"] == "FAIL", payload
    got = _cells(payload)
    assert payload["failed"] == 2
    assert f"messages.raw {raw_at} did not decrypt" in got["messages.raw"]["first_failure"]
    assert f"response.body {body_at} did not decrypt" in got["response.body"]["first_failure"]
    assert payload["opened"] == sum(expected.values()) - 2


def test_a_damaged_marker_passes_the_restore_walk_and_fails_the_audit(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The marker hole. A value whose ``mfenc:`` prefix is damaged is not selected by the marker.
    The audit counts it as unmarked, and in a keyed store, where the store refuses such a value at
    read, that is a FAIL; the restore-verify's walk reads it the same way (BACKLOG #1719, the
    marker limb). Under the audited ``allow_unmarked_ciphertext`` opt-out the store reads it as
    plaintext, so it is reported and passes."""
    db, settings = _copy(_template, tmp_path)
    _keyed(monkeypatch, settings)
    ident = _damage_one_marker(db)

    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "FAIL", message
    assert message.startswith(f"messages.raw id={ident} carries no at-rest marker"), message

    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 1 and payload["status"] == "FAIL", payload
    raw = _cells(payload)["messages.raw"]
    assert raw["unmarked"] == 1 and raw["failed"] == 0
    assert raw["first_unmarked"] == f"messages.raw id={ident} carries no at-rest marker"

    monkeypatch.setenv("MEFOR_STORE_ALLOW_UNMARKED_CIPHERTEXT", "true")
    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 0 and payload["status"] == "PASS", payload
    assert payload["unmarked"] == 1 and "allow_unmarked_ciphertext" in payload["reason"]
    opted_out = settings.model_copy(update={"allow_unmarked_ciphertext": True})
    status, message, _ = dr_backup._decrypt_check(db, opted_out)
    assert status == "PASS", message


def _damage_one_marker(db: Path) -> str:
    """Change the first letter of one sealed ``messages.raw`` value's marker; return its row id.
    Through a separate connection, so it also works under a store that is still open."""
    conn = sqlite3.connect(db)
    try:
        rowid, value, ident = conn.execute(
            "SELECT rowid, raw, id FROM messages WHERE raw LIKE ? ORDER BY rowid LIMIT 1",
            (f"{MARKER_PREFIX}%",),
        ).fetchone()
        conn.execute("UPDATE messages SET raw = ? WHERE rowid = ?", ("x" + value[1:], rowid))
        conn.commit()
    finally:
        conn.close()
    return str(ident)


async def test_a_full_restore_verify_fails_an_archived_value_whose_marker_is_damaged(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """The restore path's marker limb (BACKLOG #1719). The archive holds a ``messages.raw`` value
    whose marker is damaged, on a surface the keyed store sealed, so the store refuses it at read.
    The full verify used to PASS it: its walk selected by the marker and never read it. It now
    reads it, and FAILs naming the row, never the value."""
    db, settings = _copy(_template, tmp_path)
    store = await _open(db, settings)
    try:
        ident = _damage_one_marker(db)
        archive = await _backup(store, settings, tmp_path / "b")
    finally:
        await store.close()
    res = await run_restore_verify(archive, store_settings=settings, full=True)
    assert res.status == "FAIL", res.reason
    reason = res.reason or ""
    assert f"messages.raw id={ident} carries no at-rest marker" in reason, reason
    assert _SYNTH not in reason


async def test_the_full_verify_reads_the_cells_before_its_open_can_seal_one(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """Under the opt-out the verify's own keyed open seals an unmarked value as plaintext, so a
    walk after the open counted a damaged value as one more cell that decrypted. The walk now reads
    the archive first: the damaged value is not among the cells it opened, and the verify passes
    only because the opt-out reads unmarked values as plaintext, as ``cipher-audit`` says."""
    db, settings = _copy(_template, tmp_path)
    opted_out = settings.model_copy(update={"allow_unmarked_ciphertext": True})
    sealed = sum(_sealed_by_cell(db).values())
    store = await _open(db, settings)
    try:
        _damage_one_marker(db)
        archive = await _backup(store, settings, tmp_path / "b")
    finally:
        await store.close()
    res = await run_restore_verify(archive, store_settings=opted_out, full=True)
    assert res.status == "PASS", res.reason
    assert res.decrypted_cells == sealed - 1, (res.decrypted_cells, sealed)


def test_a_shell_without_the_key_reports_key_mismatch(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No key in this shell resolves keyless; the store holds sealed values, so the keyring is the
    cause, and the exit says so rather than calling the store damaged."""
    db, _settings = _copy(_template, tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 4 and payload["status"] == "KEY_MISMATCH", payload
    assert "resolved no key" in payload["reason"]


def test_a_server_backend_whose_store_is_unreachable_could_not_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A PostgreSQL store the open cannot reach: exit 2, could not start, never PASS's 0 or FAIL's
    1. It was exit 3, NOT COVERED, while this command read SQLite only (BACKLOG #1719)."""

    async def unreachable(settings: StoreSettings, **_kw: Any) -> object:
        raise ConnectionRefusedError("synthetic: no server")

    monkeypatch.setattr(store_base, "open_store", unreachable)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 2 and "error" in payload, out
    assert "db.invalid/mefor" in payload["error"], payload


def test_the_audit_reads_a_path_with_uri_characters_and_writes_nothing(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A live path can hold a space, ``#`` or ``%``. Unquoted in a ``file:`` URI, ``#`` would end
    the path. The read-only open must also leave the file's bytes as they were."""
    odd = tmp_path / "live # 50% store"
    odd.mkdir()
    db, settings = _copy(_template, odd)
    _keyed(monkeypatch, settings)
    before = db.read_bytes()
    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 0, payload
    assert payload["opened"] == sum(_sealed_by_cell(db).values())
    assert db.read_bytes() == before

    # The restore-verify's walk takes the same URI builder now.
    status, message, cells = dr_backup._decrypt_check(db, settings)
    assert status == "PASS" and cells == payload["opened"], message


def test_table_narrows_the_audit_and_an_unknown_table_is_refused(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db, settings = _copy(_template, tmp_path)
    _keyed(monkeypatch, settings)
    rc, payload = _audit(db, monkeypatch, capsys, "--table", "response")
    assert rc == 0, payload
    assert set(_cells(payload)) == {"response.body", "response.detail", "response.resp_headers"}

    monkeypatch.chdir(tmp_path)
    assert main(["cipher-audit", "--db", str(db), "--table", "nope"]) == 2
    assert "no cipher-covered table named nope" in capsys.readouterr().err


def test_a_missing_store_is_refused_and_not_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "absent.db"
    assert main(["cipher-audit", "--db", str(missing)]) == 2
    assert "no store at" in capsys.readouterr().err
    assert not missing.exists()


def _first_sealed(db: Path, table: str, column: str) -> tuple[int, str]:
    conn = sqlite3.connect(db)
    try:
        rowid, value = conn.execute(
            f"SELECT rowid, {column} FROM {table} WHERE {column} LIKE ? ORDER BY rowid LIMIT 1",
            (f"{MARKER_PREFIX}%",),
        ).fetchone()
    finally:
        conn.close()
    return int(rowid), str(value)


def _set(db: Path, table: str, column: str, rowid: int, value: object) -> None:
    conn = sqlite3.connect(db)
    try:
        conn.execute(f"UPDATE {table} SET {column} = ? WHERE rowid = ?", (value, rowid))
        conn.commit()
    finally:
        conn.close()


_MARKER_RX = re.compile(re.escape(MARKER_PREFIX) + ".*", re.DOTALL | re.IGNORECASE | re.ASCII)


def _like_that_skips_blobs(pattern: object, value: object) -> bool:
    """``like(pattern, value)`` as a ``SQLITE_LIKE_DOESNT_MATCH_BLOBS`` build runs it, for the one
    pattern a walk could use: a BLOB never matches."""
    assert pattern == f"{MARKER_PREFIX}%", pattern
    return isinstance(value, str) and _MARKER_RX.fullmatch(value) is not None


#: At least two ways a connection's LIKE can differ from this machine's default build (see
#: ``_sealed_test`` in store/cipher_cells.py), each with a probe that is true when it is in force.
#: Not every way: an ICU build, for one, is not emulated here.
_LIKE_BUILDS: dict[str, tuple[Callable[[sqlite3.Connection], None], str]] = {
    "like-skips-blobs": (
        lambda c: c.create_function("like", 2, _like_that_skips_blobs, deterministic=True),
        "SELECT NOT (x'6d66656e633a' LIKE 'mfenc:%')",
    ),
    "case-sensitive-like": (
        lambda c: c.execute("PRAGMA case_sensitive_like = ON").close(),
        "SELECT NOT ('MFENC:' LIKE 'mfenc:%')",
    ),
}


@pytest.fixture(params=["native-like", *_LIKE_BUILDS])
def sqlite_like_build(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Run a test under this machine's own LIKE, then under each of :data:`_LIKE_BUILDS`, whatever
    this machine's SQLite was built with. Every connection the walk opens, the restore-verify's
    and ``cipher-audit``'s, gets the variant."""
    if request.param == "native-like":
        yield
        return
    install, probe = _LIKE_BUILDS[str(request.param)]
    opened: list[sqlite3.Connection] = []

    def connect(path: str | Path, *, busy_timeout: float) -> sqlite3.Connection:
        conn = connect_readonly(path, busy_timeout=busy_timeout)
        install(conn)
        assert conn.execute(probe).fetchone()[0] == 1, "the LIKE variant is not in force"
        opened.append(conn)
        return conn

    monkeypatch.setattr(dr_backup, "connect_readonly", connect)
    monkeypatch.setattr(cipher_cells_module, "connect_readonly", connect)
    yield
    # The control: the variant reached the walk, so this run is not a second native one.
    assert opened, "the walk never opened a connection through the patched connect_readonly"


@pytest.mark.usefixtures("sqlite_like_build")
@pytest.mark.parametrize("shape", ["intact", "flipped", "plaintext"])
def test_a_value_stored_as_a_blob_fails_as_a_blob(
    tmp_path: Path, _template: tuple[Path, StoreSettings], shape: str
) -> None:
    """A BLOB in a cipher-covered cell is selected as sealed under every LIKE, and fails: the
    store's reader cannot take one as a sealed cell, intact, damaged or never marked at all. Where
    LIKE skipped a BLOB a damaged one passed the restore-verify unread (engine PR 2608, the
    ubuntu leg)."""
    db, settings = _copy(_template, tmp_path)
    rowid, value = _first_sealed(db, "messages", "raw")
    if shape == "flipped":
        head, _, payload = value.rpartition(":")
        blob = bytearray(base64.b64decode(payload))
        blob[-1] ^= 0x01
        value = f"{head}:{base64.b64encode(bytes(blob)).decode()}"
    elif shape == "plaintext":
        value = "MSH|^~\\&|BLOB-PLAINTEXT"
    _set(db, "messages", "raw", rowid, value.encode())
    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "FAIL" and "messages.raw" in message and "BLOB" in message, message


def test_a_keyless_walk_fails_a_blob_rather_than_blame_the_key(tmp_path: Path) -> None:
    """A keyless restore-verify of a store whose one marked value is a BLOB, not even UTF-8 after
    the marker. No key would open a BLOB, so the verdict is FAIL naming it, not a KEY_MISMATCH that
    sends the operator to find a key, and not the PASS of a walk that skipped it."""
    db = tmp_path / "msg.db"
    settings = StoreSettings(path=str(db))

    async def write() -> None:
        store = await _open(db, settings)
        try:
            await store.enqueue_message(channel_id="IB_SYNTH", raw=_RAW, deliveries=[("OB", "X")])
        finally:
            await store.close()

    asyncio.run(write())
    conn = sqlite3.connect(db)
    try:
        conn.execute("UPDATE messages SET raw = ?", (MARKER_PREFIX.encode() + b"v4:\xff\xfe",))
        conn.commit()
    finally:
        conn.close()
    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "FAIL" and "messages.raw" in message and "BLOB" in message, message


def _keyless_store(db: Path) -> None:
    """A store written with no key: one message, no ``keyed_surface`` row."""

    async def write() -> None:
        store = await _open(db, StoreSettings(path=str(db)))
        try:
            await store.enqueue_message(channel_id="IB_SYNTH", raw=_RAW, deliveries=[("OB", "X")])
        finally:
            await store.close()

    asyncio.run(write())


def _plant(db: Path, sql: str, params: tuple[object, ...]) -> None:
    """Run one write; a write that touched no row is a fixture that no longer tests anything."""
    conn = sqlite3.connect(db)
    try:
        assert conn.execute(sql, params).rowcount > 0, f"planted nothing: {sql}"
        conn.commit()
    finally:
        conn.close()


_BLOB_ROWS = {
    "state": ("INSERT INTO state (namespace, key, value, set_at) VALUES ('ns', 'k', ?, 0)",),
    "reference": ("INSERT INTO reference (name, version, key, value) VALUES ('r', '1', 'k', ?)",),
}


@pytest.mark.usefixtures("sqlite_like_build")
@pytest.mark.parametrize("table", sorted(_BLOB_ROWS))
def test_cipher_audit_with_no_key_fails_a_json_cell_blob(
    tmp_path: Path,
    table: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A BLOB in ``state.value`` or ``reference.value`` of a keyless store: the store's reader hands
    it back as bytes and its JSON decode raises, so the store does not start. cipher-audit with no
    key must not call that store clean."""
    db = tmp_path / "msg.db"
    _keyless_store(db)
    _plant(db, _BLOB_ROWS[table][0], (b"not json",))
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc != 0 and payload["status"] == "FAIL", payload
    assert "holds a BLOB" in _cells(payload)[f"{table}.value"]["first_failure"]


def _verdicts(
    db: Path,
    settings: StoreSettings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[tuple[str, str], tuple[str, str]]:
    """((status, reason) of restore-verify's decrypt pass, the same of cipher-audit) for one file
    under one shell. The decrypt pass, not the full verify, whose store open runs first."""
    status, message, _cells = dr_backup._decrypt_check(db, settings)
    if settings.encryption_key is None:
        monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    else:
        _keyed(monkeypatch, settings)
    _rc, payload = _audit(db, monkeypatch, capsys)
    return (status, message), (str(payload["status"]), str(payload["reason"]))


@pytest.mark.usefixtures("sqlite_like_build")
@pytest.mark.parametrize("keyed_record", [False, True], ids=["unrecorded", "keyed-surface"])
@pytest.mark.parametrize("order", ["blob-first", "sealed-first", "blob-only"])
def test_restore_verify_and_cipher_audit_agree_whatever_the_row_order(
    tmp_path: Path,
    order: str,
    keyed_record: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One BLOB, with one sealed text value in either walk order (``messages.raw`` is walked before
    ``message_events.detail``) or none, read with no key, on a store with and without its keyed
    record. Both commands give one verdict: a store recorded as keyed, or a sealed value no key
    opened, is a key mismatch wherever the BLOB sits; a BLOB alone in an unrecorded store fails."""
    db = tmp_path / "msg.db"
    _keyless_store(db)
    sealed, blob = f"{MARKER_PREFIX}v4:aesgcm:k:00:AAAA", b"MSH|^~\\&|BLOB-PLAINTEXT"
    if order == "blob-only":
        _plant(db, "UPDATE messages SET raw = ?", (blob,))
    else:
        first, second = (blob, sealed) if order == "blob-first" else (sealed, blob)
        _plant(db, "UPDATE messages SET raw = ?", (first,))
        _plant(db, "UPDATE message_events SET detail = ?", (second,))
    if keyed_record:
        _plant(
            db,
            "INSERT INTO keyed_surface (surface_table, surface_column, keyed_at) VALUES (?, ?, 0)",
            ("messages", "raw"),
        )
    (restore, said), (audit, reason) = _verdicts(
        db, StoreSettings(path=str(db)), monkeypatch, capsys
    )
    expected = "FAIL" if order == "blob-only" and not keyed_record else "KEY_MISMATCH"
    assert restore == audit == expected, (restore, audit)
    if order == "blob-first" and not keyed_record:
        # The mismatch decides, and the BLOB it met first, which no key clears, is still named.
        assert "also found before it" in said and "holds a BLOB" in said, said
        assert "also found before it" in reason and "holds a BLOB" in reason, reason


@pytest.mark.usefixtures("sqlite_like_build")
@pytest.mark.parametrize("with_key", [False, True], ids=["no-key", "key"])
def test_a_keyed_snapshot_holding_only_unmarked_blobs_fails_both(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    with_key: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Every sealed value purged to ``''`` and one plaintext BLOB left, in a store a keyed open
    recorded. Neither command may PASS it, with the key or without, and they agree."""
    db, settings = _copy(_template, tmp_path)
    conn = sqlite3.connect(db)
    try:
        for cell in SQLITE_CIPHER_CELLS:
            conn.execute(
                f"UPDATE {cell.table} SET {cell.column} = '' WHERE {cell.column} LIKE ?",
                (f"{MARKER_PREFIX}%",),
            )
        rowid = conn.execute("SELECT rowid FROM messages ORDER BY rowid LIMIT 1").fetchone()[0]
        conn.execute("UPDATE messages SET raw = ? WHERE rowid = ?", (b"BLOB-PLAINTEXT", rowid))
        conn.commit()
    finally:
        conn.close()
    shell = settings if with_key else settings.model_copy(update={"encryption_key": None})
    (restore, _said), (audit, _reason) = _verdicts(db, shell, monkeypatch, capsys)
    assert restore == audit, (restore, audit)
    assert restore == ("FAIL" if with_key else "KEY_MISMATCH"), restore


def test_a_planted_keyed_record_cannot_forge_a_report_line(tmp_path: Path) -> None:
    """The keyed-record line quotes ``keyed_surface`` text from the file, so it is escaped."""
    db = tmp_path / "msg.db"
    _keyless_store(db)
    _plant(
        db,
        "INSERT INTO keyed_surface (surface_table, surface_column, keyed_at) VALUES (?, ?, 0)",
        ("x\nPASS: archive verified", "raw"),
    )
    status, message, _ = dr_backup._decrypt_check(db, StoreSettings(path=str(db)))
    assert status == "KEY_MISMATCH" and "\n" not in message, message


@pytest.mark.usefixtures("sqlite_like_build")
def test_a_marker_in_another_case_fails_even_under_the_opt_out(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Under ``allow_unmarked_ciphertext`` the cipher returns an unmarked value as it is, so a
    sealed value whose marker case was changed would count as opened with no tag checked."""
    db, settings = _copy(_template, tmp_path)
    _keyed(monkeypatch, settings)
    monkeypatch.setenv("MEFOR_STORE_ALLOW_UNMARKED_CIPHERTEXT", "true")
    rowid, value = _first_sealed(db, "messages", "raw")
    _set(db, "messages", "raw", rowid, MARKER_PREFIX.upper() + value[len(MARKER_PREFIX) :])
    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 1 and payload["failed"] == 1, payload
    assert "not spelled" in _cells(payload)["messages.raw"]["first_failure"]


def test_another_key_is_named_as_a_possible_cause(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A shell holding a different key fails every value; each failure says its marker names a key
    these settings do not hold, without calling it anything softer than FAIL."""
    db, _settings = _copy(_template, tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 1 and payload["status"] == "FAIL", payload
    assert "names a key these settings do not hold" in payload["reason"]


def test_a_keyless_shell_on_a_keyed_store_with_no_sealed_value_is_a_key_mismatch(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Every sealed value purged to ``''``: the walk alone finds nothing, but the store records
    its keyed surfaces, so a shell with no key is still the wrong shell. No counts are printed."""
    db, _settings = _copy(_template, tmp_path)
    conn = sqlite3.connect(db)
    try:
        for cell in SQLITE_CIPHER_CELLS:
            conn.execute(
                f"UPDATE {cell.table} SET {cell.column} = '' WHERE {cell.column} LIKE ?",
                (f"{MARKER_PREFIX}%",),
            )
        conn.commit()
    finally:
        conn.close()
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 4 and payload["status"] == "KEY_MISMATCH", payload
    assert payload["opened"] is None and payload["cells"] == []


def test_a_file_that_is_not_a_store_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty file is a valid SQLite database holding none of the cells: could not start, never
    a PASS over nothing."""
    monkeypatch.chdir(tmp_path)
    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    assert main(["cipher-audit", "--db", str(empty)]) == 2
    assert "not a MessageFoundry store" in capsys.readouterr().err


def test_a_queue_row_pointed_at_another_body_fails(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """``body_ref`` is not in the queue tag, so the payload still opens when it is changed; the
    reader refuses the row because its sealed reference differs, and so must the walk."""
    db, settings = _copy(_template, tmp_path)
    conn = sqlite3.connect(db)
    try:
        rowid = conn.execute(
            "SELECT rowid FROM queue WHERE body_ref IS NOT NULL ORDER BY rowid LIMIT 1"
        ).fetchone()[0]
        conn.execute("UPDATE queue SET body_ref = ? WHERE rowid = ?", ("0" * 64, rowid))
        conn.commit()
    finally:
        conn.close()
    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "FAIL" and "differs from its body_ref" in message, message


def test_plaintext_on_a_surface_never_sealed_is_legacy_not_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A store written keyless, audited before any keyed open: its plaintext is what the next
    keyed open seals, not a stripped marker. It is reported, and the audit passes."""
    db = tmp_path / "msg.db"

    async def write() -> None:
        store = await _open(db, StoreSettings(path=str(db)))
        try:
            await store.enqueue_message(channel_id="IB_SYNTH", raw=_RAW, deliveries=[("OB", "X")])
        finally:
            await store.close()

    asyncio.run(write())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 0 and payload["status"] == "PASS", payload
    assert payload["legacy"] >= 1 and payload["unmarked"] == 0, payload
    assert "next keyed open seals" in payload["reason"]


def test_a_cell_the_store_lacks_is_named_not_counted_as_empty(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db, settings = _copy(_template, tmp_path)
    _keyed(monkeypatch, settings)
    conn = sqlite3.connect(db)
    try:
        conn.execute("DROP TABLE alert_instance")
        conn.commit()
    finally:
        conn.close()
    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 0, payload
    assert _cells(payload)["alert_instance.reason"]["present"] is False
    assert "not read: alert_instance.reason" in payload["reason"]


def test_a_locator_cannot_forge_a_report_line(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    db, settings = _copy(_template, tmp_path)
    raw = next(c for c in SQLITE_CIPHER_CELLS if (c.table, c.column) == ("messages", "raw"))
    rowid, _value = _first_sealed(db, "messages", "raw")
    _set(db, "messages", "id", rowid, "x\nPASS: forged")
    _flip_one_aead_byte(db, raw)
    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "FAIL" and "\n" not in message and "id=x\\nPASS: forged" in message, message


def test_a_schema_change_part_way_stops_the_walk(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """A VACUUM between chunks may renumber rowids; the walk stops rather than finish on a subset."""
    db, settings = _copy(_template, tmp_path)
    reader = connect_readonly(db, busy_timeout=5.0)
    writer = sqlite3.connect(db, isolation_level=None)
    try:
        walk = read_cipher_cells(reader, build_store_cipher(settings), chunk_rows=1)
        next(walk)
        writer.execute("VACUUM")
        with pytest.raises(CipherWalkInterrupted):
            list(walk)
    finally:
        reader.close()
        writer.close()


def test_an_unreachable_key_service_stops_the_audit(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """Transit raises the same CipherError for an outage as for a bad value. The audit stops on
    the first outage instead of calling every later value damaged."""
    db, _settings = _copy(_template, tmp_path)

    class _Down:
        encrypts = True
        calls = 0

        def is_encrypted(self, stored: str) -> bool:
            return stored.startswith(MARKER_PREFIX)

        def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
            self.calls += 1
            try:
                raise ConnectionRefusedError("synthetic outage")
            except OSError as exc:
                raise CipherError("Transit decrypt failed") from exc

    down = _Down()
    reader = connect_readonly(db, busy_timeout=5.0)
    try:
        with pytest.raises(CipherError):
            audit_cipher_cells(reader, cast(Cipher, down))
    finally:
        reader.close()
    assert down.calls == 1, "the walk kept asking a key service that was down"


def test_chunks_read_every_row_and_hold_no_read_transaction_between_them(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """One row per chunk reads the same values as one large chunk, and between chunks the walk
    holds no snapshot: a TRUNCATE checkpoint, which an open reader blocks, completes. The control
    proves the checkpoint does report a held snapshot."""
    db, settings = _copy(_template, tmp_path)
    cipher = build_store_cipher(settings)
    reader = connect_readonly(db, busy_timeout=0.0)
    writer = sqlite3.connect(db, isolation_level=None, timeout=0.0)
    try:
        big = audit_cipher_cells(reader, cipher, chunk_rows=DEFAULT_CHUNK_ROWS)
        small = audit_cipher_cells(reader, cipher, chunk_rows=1)
        assert [(t.name, t.opened) for t in small.tallies] == [
            (t.name, t.opened) for t in big.tallies
        ]
        assert max(t.opened for t in big.tallies) > 1, "no cell held two rows to chunk"

        # A real change: SQLite skips writing a row an UPDATE leaves as it was, so no frame.
        writer.execute("CREATE TABLE synth_probe (n INTEGER)")

        def write_a_frame() -> None:
            writer.execute("INSERT INTO synth_probe VALUES (1)")

        def checkpoint_blocked() -> bool:
            """Write a frame, then try to empty the WAL: a reader holding a snapshot that reads the
            WAL blocks that, and the pragma's first column reports it."""
            write_a_frame()
            busy, _log, _done = writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            return bool(busy)

        # Each arm reads after a write, so its snapshot reads the WAL rather than the file alone.
        write_a_frame()
        walk = read_cipher_cells(reader, cipher, chunk_rows=1)
        assert next(walk).kind == "opened"
        assert not checkpoint_blocked(), "the walk held a read transaction between chunks"
        walk.close()

        # Control: an open read transaction on the same connection does block it.
        write_a_frame()
        reader.execute("BEGIN")
        reader.execute("SELECT count(*) FROM messages").fetchone()
        assert checkpoint_blocked(), "the instrument cannot see a held snapshot"
        reader.execute("COMMIT")
    finally:
        reader.close()
        writer.close()


# --- the server stores' inventories and walk (BACKLOG #1719) ----------------------------------


@pytest.mark.parametrize(
    ("backend", "cells"),
    [("postgres.py", POSTGRES_CIPHER_CELLS), ("sqlserver.py", SQLSERVER_CIPHER_CELLS)],
    ids=["postgres", "sqlserver"],
)
def test_each_server_inventory_names_exactly_its_backends_cipher_cells(
    backend: str, cells: tuple[CipherCell, ...]
) -> None:
    """Each server inventory is pinned to its backend's own ``cell_aad`` calls, read with the
    instrument the sweep parity guard holds the sweeps to. A ciphered column added to that backend
    reds this until the inventory names it, and an entry no writer seals reds it too.

    Equality, so the control below can show the pin is not satisfied by any list."""
    covered = _covered_cells(_parsed(backend))
    declared = [(c.table, c.column) for c in cells]
    assert len(declared) == len(set(declared)), f"a cell is declared twice: {sorted(declared)}"
    assert set(declared) == covered, (
        f"messagefoundry/store/cipher_cells.py has drifted from {backend}'s cell_aad calls.\n"
        f"  sealed by {backend}, not declared: {sorted(covered - set(declared))}\n"
        f"  declared, not sealed by {backend}: {sorted(set(declared) - covered)}"
    )
    # Control: the same comparison reds on an inventory one cell short.
    assert set(declared[1:]) != covered


def test_a_server_cell_is_paged_by_a_key_and_never_located_by_a_phi_key() -> None:
    """A server table has no rowid, so every server cell pages by named columns, and a cell whose
    key can be PHI is located by its position, as SQLite locates it by rowid, never by the key."""
    for cell in (*POSTGRES_CIPHER_CELLS, *SQLSERVER_CIPHER_CELLS):
        assert "rowid" not in cell.order and "rowid" not in cell.locator, cell
        if cell.table in ("state", "reference", "shared_body", "attachment_chunk"):
            assert cell.locator == (POSITION,), cell


class _SqliteSource:
    """A :class:`CipherCellSource` over a SQLite store file, so the server walk can be measured on
    the plain leg against values the REAL store writers sealed (the server writers bind the same
    AAD; the live server tests prove that). It pages by key as the server sources do, with SQLite
    row values, and records each chunk's limit."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.limits: dict[str, list[int]] = {}

    async def cipher_walk_columns(self, tables: Sequence[str]) -> dict[str, frozenset[str]]:
        found: dict[str, frozenset[str]] = {}
        for table in tables:
            names = frozenset(r[1] for r in self.conn.execute(f"PRAGMA table_info({table})"))
            if names:
                found[table] = names
        return found

    async def cipher_walk_keyed_surface(self) -> tuple[str, str] | None:
        row = self.conn.execute(
            "SELECT surface_table, surface_column FROM keyed_surface ORDER BY 1, 2 LIMIT 1"
        ).fetchone()
        return None if row is None else (str(row[0]), str(row[1]))

    async def cipher_walk_surface_sealed(self, table: str, column: str, *, keyed: bool) -> bool:
        if (
            keyed
            and self.conn.execute(
                "SELECT 1 FROM keyed_surface WHERE surface_table = ? AND surface_column = ?",
                (table, column),
            ).fetchone()
        ):
            return True
        return (
            self.conn.execute(
                f"SELECT 1 FROM {table} WHERE {column} LIKE ? LIMIT 1", (f"{MARKER_PREFIX}%",)
            ).fetchone()
            is not None
        )

    async def cipher_walk_chunk(
        self,
        table: str,
        column: str,
        select: Sequence[str],
        order: Sequence[str],
        after: Sequence[Any] | None,
        limit: int,
        *,
        sealed_only: bool,
    ) -> list[tuple[Any, ...]]:
        self.limits.setdefault(f"{table}.{column}", []).append(limit)
        where, params = [f"{column} IS NOT NULL"], []
        if sealed_only:
            where.append(f"lower(substr({column}, 1, ?)) = ?")
            params += [len(MARKER_PREFIX), MARKER_PREFIX.lower()]
        if after is not None:
            where.append(f"({', '.join(order)}) > ({', '.join('?' for _ in after)})")
            params += list(after)
        sql = (
            f"SELECT {', '.join((*select, column))} FROM {table} WHERE {' AND '.join(where)}"
            f" ORDER BY {', '.join(order)} LIMIT ?"
        )
        return [tuple(r) for r in self.conn.execute(sql, (*params, limit))]


def _server_audit(db: Path, cipher: Cipher, **kwargs: Any) -> tuple[CipherAudit, _SqliteSource]:
    conn = connect_readonly(db, busy_timeout=5.0)
    try:
        source = _SqliteSource(conn)
        audit = asyncio.run(
            audit_server_cipher_cells(
                cast(CipherCellSource, source), cipher, cells=POSTGRES_CIPHER_CELLS, **kwargs
            )
        )
    finally:
        conn.close()
    return audit, source


def _counts(audit: CipherAudit) -> list[tuple[str, int, int, int, int, int]]:
    return [(t.name, t.opened, t.failed, t.blob, t.unmarked, t.legacy) for t in audit.tallies]


@pytest.mark.parametrize("chunk_rows", [1, DEFAULT_CHUNK_ROWS])
def test_the_server_walk_reads_what_the_sqlite_walk_reads(
    tmp_path: Path, _template: tuple[Path, StoreSettings], chunk_rows: int
) -> None:
    """Paged by key instead of rowid, one row per chunk or many, the server walk opens exactly the
    values the SQLite walk opens, cell by cell, and every count is the number sealed in that cell."""
    db, settings = _copy(_template, tmp_path)
    cipher = build_store_cipher(settings)
    conn = connect_readonly(db, busy_timeout=5.0)
    try:
        sqlite_audit = audit_cipher_cells(conn, cipher)
    finally:
        conn.close()
    server_audit, _source = _server_audit(db, cipher, chunk_rows=chunk_rows)
    assert server_audit.key_mismatch is None and server_audit.failed == 0
    assert _counts(server_audit) == _counts(sqlite_audit)
    assert {t.name: t.opened for t in server_audit.tallies} == _sealed_by_cell(db)
    assert server_audit.opened > len(COMPOSITE_CIPHER_CELLS)


#: The server cells the fixture writes a sealed value into: every composite one, and one id-keyed.
_SERVER_WRITTEN = [
    c
    for c in POSTGRES_CIPHER_CELLS
    if (c.table, c.column) == ("messages", "raw")
    or any((c.table, c.column) == (k.table, k.column) for k in COMPOSITE_CIPHER_CELLS)
]


@pytest.mark.parametrize("cell", _SERVER_WRITTEN, ids=lambda c: f"{c.table}.{c.column}")
def test_the_server_walk_names_each_corrupted_cell_by_a_phi_free_locator(
    tmp_path: Path, _template: tuple[Path, StoreSettings], cell: CipherCell
) -> None:
    """One flipped byte per cell is one failure in that cell, named by table, column and locator:
    the id for an id-keyed cell, the position for a key that can be PHI. Never a value or a key."""
    db, settings = _copy(_template, tmp_path)
    sqlite_cell = next(
        c for c in SQLITE_CIPHER_CELLS if (c.table, c.column) == (cell.table, cell.column)
    )
    where = _flip_one_aead_byte(db, sqlite_cell)
    audit, _source = _server_audit(db, build_store_cipher(settings))
    tally = next(t for t in audit.tallies if (t.table, t.column) == (cell.table, cell.column))
    assert tally.failed == 1 and audit.failed == 1, _counts(audit)
    first = tally.first_failure or ""
    if cell.locator == (POSITION,):
        assert re.match(rf"{cell.table}\.{cell.column} position=\d+ did not decrypt", first), first
    else:
        assert first.startswith(f"{cell.table}.{cell.column} {where} did not decrypt"), first
    assert _SYNTH not in first, f"the failure line leaked a plaintext or a key: {first}"


def test_the_server_walk_counts_a_damaged_marker_and_plaintext_as_unmarked(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """A value whose marker is damaged, and a plain value, on a surface the keyed store sealed:
    both are unmarked, which the store refuses at read. The marker test is the walk's own, so
    ``MFENC:`` is still sealed, and fails as one rather than passing as plaintext."""
    db, settings = _copy(_template, tmp_path)
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute(
            "SELECT rowid, raw, id FROM messages WHERE raw LIKE ? ORDER BY id",
            (f"{MARKER_PREFIX}%",),
        ).fetchall()
        assert len(rows) >= 2, "the fixture holds too few messages for two shapes"
        (r1, v1, id1), (r2, _v2, _id2) = rows[:2]
        conn.execute("UPDATE messages SET raw = ? WHERE rowid = ?", ("x" + v1[1:], r1))
        conn.execute("UPDATE messages SET raw = ? WHERE rowid = ?", ("SYNTH-PLAIN", r2))
        r3, v3 = conn.execute(
            "SELECT rowid, body FROM response WHERE body LIKE ? LIMIT 1", (f"{MARKER_PREFIX}%",)
        ).fetchone()
        conn.execute("UPDATE response SET body = ? WHERE rowid = ?", (v3[:6].upper() + v3[6:], r3))
        conn.commit()
    finally:
        conn.close()
    audit, _source = _server_audit(db, build_store_cipher(settings))
    raw = next(t for t in audit.tallies if t.name == "messages.raw")
    assert raw.unmarked == 2 and raw.failed == 0, _counts(audit)
    assert raw.first_unmarked == f"messages.raw id={id1} carries no at-rest marker"
    body = next(t for t in audit.tallies if t.name == "response.body")
    assert body.failed == 1 and "is not spelled" in (body.first_failure or ""), _counts(audit)


def test_the_server_walk_reads_plaintext_on_a_surface_never_sealed_as_legacy(
    tmp_path: Path,
) -> None:
    """A store written with no key, read with one: nothing is sealed and no keyed open has recorded
    a surface, so every value is legacy plaintext the next keyed open seals, not a failure."""
    db = tmp_path / "msg.db"
    _keyless_store(db)
    keyed = StoreSettings(path=str(db), encryption_key=generate_key())
    audit, _source = _server_audit(db, build_store_cipher(keyed))
    assert audit.failed == 0 and audit.unmarked == 0 and audit.legacy >= 1, _counts(audit)


def test_a_keyless_server_walk_of_a_keyed_store_is_a_key_mismatch(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """No key and a store a keyed open recorded: the key mismatch, before any value is read."""
    db, _settings = _copy(_template, tmp_path)
    audit, source = _server_audit(db, build_store_cipher(StoreSettings(path=str(db))))
    assert audit.key_mismatch is not None and "resolved no key" in audit.key_mismatch
    assert source.limits == {}, "a value was read after the key mismatch was known"


def test_a_server_walk_with_no_keyed_record_meets_a_sealed_value_as_keyless(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """No ``keyed_surface`` record, so the walk itself meets a sealed value with no key: that
    reading decides the key mismatch, and the walk stops on it."""
    db, _settings = _copy(_template, tmp_path)
    _plant(db, "DELETE FROM keyed_surface", ())
    audit, source = _server_audit(db, build_store_cipher(StoreSettings(path=str(db))))
    assert audit.key_mismatch is not None and "keyless open" in audit.key_mismatch
    assert sum(len(v) for v in source.limits.values()) == 1, source.limits


def test_a_non_text_server_value_fails_as_a_blob(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """Every server cipher column is text; a value that comes back as anything else fails."""
    db, settings = _copy(_template, tmp_path)
    rowid, value = _first_sealed(db, "messages", "raw")
    _set(db, "messages", "raw", rowid, value.encode())
    audit, _source = _server_audit(db, build_store_cipher(settings))
    raw = next(t for t in audit.tallies if t.name == "messages.raw")
    assert raw.blob == 1 and "BLOB" in (raw.first_failure or ""), _counts(audit)


def test_the_server_walk_reads_large_rows_in_small_chunks(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """A server driver fetches a whole chunk at once, so ``attachment_chunk``, one 1 MiB slice a
    row, is read at most its cap at a time whatever ``chunk_rows`` asks; other cells are not."""
    db, settings = _copy(_template, tmp_path)
    _audit_result, source = _server_audit(db, build_store_cipher(settings), chunk_rows=500)
    cap = next(c.chunk_cap for c in POSTGRES_CIPHER_CELLS if c.table == "attachment_chunk")
    assert cap is not None and cap < 500
    assert set(source.limits["attachment_chunk.ciphertext"]) == {cap}
    assert set(source.limits["messages.raw"]) == {500}


def test_an_unreachable_key_service_stops_the_server_audit(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """As on SQLite: the first outage is raised, and no later value is sent to the key service."""
    db, _settings = _copy(_template, tmp_path)

    class _Down:
        encrypts = True
        calls = 0

        def is_encrypted(self, stored: str) -> bool:
            return stored.startswith(MARKER_PREFIX)

        def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
            self.calls += 1
            try:
                raise ConnectionRefusedError("synthetic outage")
            except OSError as exc:
                raise CipherError("Transit decrypt failed") from exc

    down = _Down()
    with pytest.raises(CipherError):
        _server_audit(db, cast(Cipher, down))
    assert down.calls == 1, "the walk kept asking a key service that was down"


# --- `cipher-audit` on a server backend (BACKLOG #1719) ----------------------------------------

_SERVER_TOML = {
    "postgres": (
        '[store]\nbackend = "postgres"\nserver = "db.invalid"\ndatabase = "mefor"\n'
        'username = "mefor"\n'
    ),
    "sqlserver": (
        '[store]\nbackend = "sqlserver"\nserver = "db.invalid"\ndatabase = "mefor"\n'
        'username = "mefor"\n'
    ),
}


class _FakeServerStore(_SqliteSource):
    """What ``open_store`` hands ``cipher-audit`` for a server backend, over a SQLite file: the
    walk's four reads, the store's cipher, and a close that is counted."""

    def __init__(self, conn: sqlite3.Connection, cipher: Cipher) -> None:
        super().__init__(conn)
        self._cipher = cipher
        self.closed = False

    def cipher(self) -> Cipher:
        return self._cipher

    async def close(self) -> None:
        self.closed = True
        self.conn.close()


def _run_server_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    backend: str,
    *extra: str,
) -> tuple[int, dict[str, Any], str]:
    cfg = tmp_path / "server.toml"
    cfg.write_text(_SERVER_TOML[backend], encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = main(["cipher-audit", "--service-config", str(cfg), "--json", *extra])
    out = capsys.readouterr().out
    assert _SYNTH not in out, f"cipher-audit printed a plaintext or a key: {out}"
    return rc, json.loads(out.strip().splitlines()[-1]), out


def _serve_from(
    monkeypatch: pytest.MonkeyPatch, db: Path, cipher: Cipher
) -> list[tuple[dict[str, Any], _FakeServerStore]]:
    """Make ``open_store`` hand back a fake server store over ``db``; return each call's
    arguments and handle."""
    opened: list[tuple[dict[str, Any], _FakeServerStore]] = []

    async def fake_open_store(settings: StoreSettings, **kw: Any) -> _FakeServerStore:
        handle = _FakeServerStore(connect_readonly(db, busy_timeout=5.0), cipher)
        opened.append((kw, handle))
        return handle

    monkeypatch.setattr(store_base, "open_store", fake_open_store)
    return opened


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
def test_cipher_audit_reads_every_sealed_value_of_a_server_store(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    backend: str,
) -> None:
    """PASS on a server backend, from a READ-ONLY open, with each cell's count the number sealed
    in it, and the handle closed after."""
    db, settings = _copy(_template, tmp_path)
    opened = _serve_from(monkeypatch, db, build_store_cipher(settings))
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, backend)
    assert rc == 0 and payload["status"] == "PASS", out
    assert payload["keyed"] is True
    assert {name: row["opened"] for name, row in _cells(payload).items()} == _sealed_by_cell(db)
    [(kw, handle)] = opened
    assert kw["read_only"] is True and handle.closed


def test_cipher_audit_fails_a_server_store_with_a_corrupted_cell(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A flipped byte is exit 1, FAIL, naming the cell and its position, never the key."""
    db, settings = _copy(_template, tmp_path)
    state = next(c for c in SQLITE_CIPHER_CELLS if c.table == "state")
    _flip_one_aead_byte(db, state)
    _serve_from(monkeypatch, db, build_store_cipher(settings))
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 1 and payload["status"] == "FAIL", out
    first = _cells(payload)["state.value"]["first_failure"]
    assert first.startswith("state.value position=1 did not decrypt"), first


def test_cipher_audit_of_a_keyed_server_store_with_no_key_is_a_key_mismatch(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db, _settings = _copy(_template, tmp_path)
    _serve_from(monkeypatch, db, build_store_cipher(StoreSettings(path=str(db))))
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 4 and payload["status"] == "KEY_MISMATCH", out


def test_a_server_walk_that_loses_its_connection_part_way_fails(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A connection lost after the walk began is FAIL with no counts, never a PASS over the cells
    read before it, and the handle is still closed."""
    db, settings = _copy(_template, tmp_path)
    opened = _serve_from(monkeypatch, db, build_store_cipher(settings))
    real_chunk = _SqliteSource.cipher_walk_chunk
    calls = 0

    async def flaky(self: _SqliteSource, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        nonlocal calls
        calls += 1
        if calls > 2:
            raise ConnectionResetError("synthetic: connection lost")
        return await real_chunk(self, *args, **kwargs)

    monkeypatch.setattr(_SqliteSource, "cipher_walk_chunk", flaky)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 1 and payload["status"] == "FAIL", out
    assert "stopped part way" in payload["reason"] and payload["opened"] is None, payload
    assert opened[0][1].closed


def test_a_server_database_with_no_store_tables_could_not_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A database holding none of the cipher tables is not a store this can audit: exit 2, not a
    PASS over cells all absent."""
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).close()
    _serve_from(monkeypatch, empty, build_store_cipher(StoreSettings(path=str(empty))))
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "sqlserver")
    assert rc == 2 and "none of the cipher-covered tables" in payload["error"], out


def test_table_narrows_a_server_audit_to_that_backends_inventory(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db, settings = _copy(_template, tmp_path)
    _serve_from(monkeypatch, db, build_store_cipher(settings))
    rc, payload, out = _run_server_cli(
        tmp_path, monkeypatch, capsys, "postgres", "--table", "state"
    )
    assert rc == 0 and set(_cells(payload)) == {"state.value"}, out
    rc, payload, out = _run_server_cli(
        tmp_path, monkeypatch, capsys, "postgres", "--table", "synth_none"
    )
    assert rc == 2 and "no cipher-covered table named synth_none" in payload["error"], out


def _hide_from_catalog(
    monkeypatch: pytest.MonkeyPatch, table: str, column: str | None = None
) -> None:
    """Make the catalog read leave out ``table`` (or only its ``column``), as a login with no grant
    on it sees the catalog. The rows stay; only the catalog hides them."""
    real = _SqliteSource.cipher_walk_columns

    async def hiding(self: _SqliteSource, tables: Sequence[str]) -> dict[str, frozenset[str]]:
        found = await real(self, tables)
        if column is None:
            found.pop(table, None)
        elif table in found:
            found[table] = found[table] - {column}
        return found

    monkeypatch.setattr(_SqliteSource, "cipher_walk_columns", hiding)


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
@pytest.mark.parametrize(
    ("table", "column", "hidden"),
    [
        ("search_presets", None, "search_presets.criteria"),
        ("messages", "summary", "messages.summary"),
    ],
    ids=["table", "column"],
)
def test_a_server_cell_the_catalog_hides_is_not_covered_never_a_pass(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    backend: str,
    table: str,
    column: str | None,
    hidden: str,
) -> None:
    """A table or column of the inventory that the catalog read does not show, as a missing grant
    hides it, was never read. Exit 3, NOT_COVERED, naming the cell and no value; never the PASS
    over the visible cells it read before. Control: the same store with nothing hidden PASSes."""
    db, settings = _copy(_template, tmp_path)
    _serve_from(monkeypatch, db, build_store_cipher(settings))
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, backend)
    assert rc == 0 and payload["status"] == "PASS", out
    _hide_from_catalog(monkeypatch, table, column)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, backend)
    assert rc == 3 and payload["status"] == "NOT_COVERED", out
    assert hidden in payload["reason"] and "not read" in payload["reason"], payload
    assert _cells(payload)[hidden]["present"] is False, payload


def test_a_failure_in_a_visible_server_cell_leads_a_hidden_one(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A damaged value the walk did read is still exit 1: a hidden cell never masks a FAIL."""
    db, settings = _copy(_template, tmp_path)
    _flip_one_aead_byte(db, next(c for c in SQLITE_CIPHER_CELLS if c.table == "state"))
    _serve_from(monkeypatch, db, build_store_cipher(settings))
    _hide_from_catalog(monkeypatch, "search_presets")
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "sqlserver")
    assert rc == 1 and payload["status"] == "FAIL", out


# --- round-1 review repairs: what reaches each exit (BACKLOG #1719) ---------


def test_a_server_open_without_its_driver_could_not_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A server open that raises a plain RuntimeError, as a missing driver extra does, read nothing:
    exit 2, could not start. It reached the dispatch floor's 1, which this command spends on FAIL."""

    async def no_driver(settings: StoreSettings, **_kw: Any) -> object:
        raise RuntimeError("synthetic: Postgres backend requires the 'postgres' extra")

    monkeypatch.setattr(store_base, "open_store", no_driver)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 2 and "error" in payload, out
    assert "db.invalid/mefor" in payload["error"], payload


def test_a_server_open_refused_keyless_is_a_key_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The open's own keyless refusal blames the key, exit 4, as the SQLite branch does."""
    from messagefoundry.store.crypto import StoreKeylessError

    async def keyless(settings: StoreSettings, **_kw: Any) -> object:
        raise StoreKeylessError("synthetic: the store is keyed and no key resolved")

    monkeypatch.setattr(store_base, "open_store", keyless)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 4 and payload["status"] == "KEY_MISMATCH", out


class _GrantDenied(OSError):
    """A driver error carrying an access-rule SQLSTATE, as asyncpg's does."""

    sqlstate = "42501"


def test_a_grant_the_server_walk_lacks_could_not_start(
    tmp_path: Path,
    _template: tuple[Path, StoreSettings],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A permission denied part way says nothing about a row: exit 2, as ``audit-verify`` splits
    it, never the 1 a damaged value earns. The handle is still closed."""
    db, settings = _copy(_template, tmp_path)
    opened = _serve_from(monkeypatch, db, build_store_cipher(settings))

    async def denied(self: _SqliteSource, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        raise _GrantDenied("synthetic: permission denied")

    monkeypatch.setattr(_SqliteSource, "cipher_walk_chunk", denied)
    rc, payload, out = _run_server_cli(tmp_path, monkeypatch, capsys, "postgres")
    assert rc == 2 and "error" in payload, out
    assert "42501" in payload["error"], payload
    assert opened[0][1].closed


def test_a_cipher_build_failure_in_the_full_walk_is_a_fail_verdict(
    tmp_path: Path, _template: tuple[Path, StoreSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk now runs before the open, outside the open's handler. A failure in its cipher build
    is still the FAIL verdict the open gave it, not an exception out of the verify."""
    from messagefoundry.store.keyprovider import KeyProviderError

    db, settings = _copy(_template, tmp_path)

    def build_fails(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
        raise KeyProviderError("synthetic: the key service did not answer")

    monkeypatch.setattr(dr_backup, "_decrypt_check", build_fails)
    status, reason, cells = dr_backup._full_open_check(db, settings)
    assert (status, cells) == ("FAIL", 0) and "key service" in reason, reason


def test_a_salt_reset_failure_keeps_the_walks_verdict(
    tmp_path: Path, _template: tuple[Path, StoreSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk read the archive first, so its verdict leads a later failure to reset the salt."""
    import messagefoundry.store.store as store_module

    db, settings = _copy(_template, tmp_path)
    walked = ("KEY_MISMATCH", "synthetic walk line", 0)
    monkeypatch.setattr(dr_backup, "_decrypt_check", lambda *_a, **_kw: walked)

    def reset_fails(_snap: Path) -> None:
        raise sqlite3.OperationalError("synthetic: database is locked")

    monkeypatch.setattr(store_module, "forget_store_salt", reset_fails)
    assert dr_backup._full_open_check(db, settings) == walked


def test_db_with_a_server_backend_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """--db names a SQLite file; under a server backend it would be ignored and the server store
    read instead. Refused, exit 2, before any open."""
    opened: list[object] = []

    async def must_not_open(settings: StoreSettings, **_kw: Any) -> object:
        opened.append(settings)
        raise AssertionError("cipher-audit opened a store it was not pointed at")

    monkeypatch.setattr(store_base, "open_store", must_not_open)
    rc, payload, out = _run_server_cli(
        tmp_path, monkeypatch, capsys, "postgres", "--db", str(tmp_path / "copy.db")
    )
    assert rc == 2 and "--db names a SQLite store" in payload["error"], out
    assert opened == []


def test_the_full_walk_failing_still_yields_to_an_incompatible_snapshot(
    tmp_path: Path, _template: tuple[Path, StoreSettings], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A walk that could not run is a FAIL verdict, but an incompatible snapshot's remedy still
    leads it, as the verdict order says."""
    from messagefoundry.store.keyprovider import KeyProviderError
    from messagefoundry.store.schema_verify import SchemaMismatchError

    db, settings = _copy(_template, tmp_path)

    def build_fails(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
        raise KeyProviderError("synthetic: the key service did not answer")

    def incompatible(coro: Any) -> Any:
        coro.close()
        raise SchemaMismatchError("synthetic: schema written by another build")

    monkeypatch.setattr(dr_backup, "_decrypt_check", build_fails)
    monkeypatch.setattr(dr_backup, "run_guarded", incompatible)
    status, reason, _cells = dr_backup._full_open_check(db, settings, engine_version="0.0.1")
    assert status == "FAIL" and "0.0.1" in reason and "key service" not in reason, reason
