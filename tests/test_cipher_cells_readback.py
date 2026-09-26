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
import shutil
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupRunner, run_restore_verify
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.base import build_store_cipher
from messagefoundry.store.cipher_cells import (
    COMPOSITE_CIPHER_CELLS,
    SQLITE_CIPHER_CELLS,
    CipherCell,
)
from messagefoundry.store.crypto import _V2_PREFIX, MARKER_PREFIX, generate_key
from messagefoundry.store.store import Stage

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
        kind="error",
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

    Built the way ``open_store`` builds one, so it writes the AAD-bound ``mfenc:v2`` format.
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
            f"SELECT rowid, {cell.locator}, {cell.column} FROM {cell.table}"
            f" WHERE {cell.column} LIKE ? ORDER BY rowid LIMIT 1",  # declared constants
            (f"{MARKER_PREFIX}%",),
        ).fetchone()
        assert row is not None, f"no sealed value in {cell.table}.{cell.column} to corrupt"
        rowid, locator, stored = row
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
    return str(locator)


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
            assert _sealed_count(conn, cell, _V2_PREFIX) == sealed, cell
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

    light = await run_restore_verify(archive, store_settings=settings)
    assert light.status == "PASS", "the light verify never opens a cell, so it must stay blind"

    res = await run_restore_verify(archive, store_settings=settings, full=True)
    assert res.status == "FAIL", res.reason
    reason = res.reason or ""
    if cell.table not in ("state", "reference"):
        assert f"{cell.table}.{cell.column} {cell.locator}=" in reason, reason
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
    assert f"{cell.table}.{cell.column} {cell.locator}={locator} did not decrypt" in message, (
        message
    )
    assert _SYNTH not in message, f"the FAIL reason leaked a plaintext or a key: {message}"


def test_an_id_keyed_failure_still_names_the_row_id(
    tmp_path: Path, _template: tuple[Path, StoreSettings]
) -> None:
    """An id-keyed cell keeps naming its synthetic ``id``, which an operator can look up, rather than
    the snapshot's ``rowid``. Only a key that can itself be PHI is withheld."""
    db, settings = _copy(_template, tmp_path)
    raw = next(c for c in SQLITE_CIPHER_CELLS if (c.table, c.column) == ("messages", "raw"))
    assert raw.locator == "id"
    mid = _flip_one_aead_byte(db, raw)

    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "FAIL", message
    assert f"messages.raw id={mid} did not decrypt" in message, message


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
    """The AAD is what makes this a per-cell check. Two sealed ``connection_event.reason`` values are
    individually valid; swapped between rows, each must fail, because each is bound to its own row's
    natural key. A declaration that bound nothing, or bound the wrong columns, would pass this."""
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
