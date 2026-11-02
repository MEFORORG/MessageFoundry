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
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

import pytest

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
    SQLITE_CIPHER_CELLS,
    CipherCell,
    CipherWalkInterrupted,
    audit_cipher_cells,
    connect_readonly,
    read_cipher_cells,
)
from messagefoundry.store.crypto import _V4_PREFIX, MARKER_PREFIX, Cipher, CipherError, generate_key
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
    """The marker hole. A value whose ``mfenc:`` prefix is damaged is not selected by the marker,
    so the restore-verify's walk never reads it and PASSes. The audit counts it as unmarked, and in
    a keyed store, where the store refuses such a value at read, that is a FAIL. Under the audited
    ``allow_unmarked_ciphertext`` opt-out the store reads it as plaintext, so it is reported and
    passes."""
    db, settings = _copy(_template, tmp_path)
    _keyed(monkeypatch, settings)
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

    # The restore-verify's walk still selects by the marker, so it does not read this value: the
    # marker limb that stays open on the restore path (BACKLOG #1719's remainder).
    status, message, _ = dr_backup._decrypt_check(db, settings)
    assert status == "PASS", message

    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 1 and payload["status"] == "FAIL", payload
    raw = _cells(payload)["messages.raw"]
    assert raw["unmarked"] == 1 and raw["failed"] == 0
    assert raw["first_unmarked"] == f"messages.raw id={ident} carries no at-rest marker"

    monkeypatch.setenv("MEFOR_STORE_ALLOW_UNMARKED_CIPHERTEXT", "true")
    rc, payload = _audit(db, monkeypatch, capsys)
    assert rc == 0 and payload["status"] == "PASS", payload
    assert payload["unmarked"] == 1 and "allow_unmarked_ciphertext" in payload["reason"]


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


def test_a_server_backend_is_not_covered_and_never_exit_0(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A PostgreSQL store: nothing is read, and the exit is neither PASS's 0 nor FAIL's 1."""
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        '[store]\nbackend = "postgres"\nserver = "db.invalid"\ndatabase = "mefor"\n'
        'username = "mefor"\n',
        encoding="utf-8",
    )
    rc = main(["cipher-audit", "--service-config", str(cfg), "--json"])
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rc == 3 and payload["status"] == "NOT_COVERED", payload


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
