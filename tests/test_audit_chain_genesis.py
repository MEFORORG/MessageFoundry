# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2594 -- a keyed store requires every audit row keyed, from a genesis row.

The shared behaviour cases live in ``tests/audit_chain_cases.py`` and run here against SQLite. The
same cases run against PostgreSQL and SQL Server from those backends' own test modules, on the CI
legs that have a live server. This file adds what is not backend behaviour: the shape of the schema
on all three backends, the typed encoder, the two parsers, and the CLI surface.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a first deployment
would have inherited.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import _build_parser
from messagefoundry.store import MessageStore
from messagefoundry.store import store as store_module
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.privilege import AUDIT_APPEND_ONLY_TABLES
from messagefoundry.store.store import (
    AUDIT_KEY_EPOCH_ACTION,
    AuditHeadMovedError,
    audit_append_secret,
    audit_genesis_detail,
    audit_mac_bytes,
    audit_next_link,
    build_audit_mac_keys,
    load_audit_chain,
    parse_audit_epoch,
    parse_audit_genesis,
)
from messagefoundry.store.typed_fields import encode_typed_fields
from tests.audit_chain_cases import CASES, ChainBackend

# --- the shared cases, on SQLite ----------------------------------------------------------------------


def _sqlite_backend(path: Path) -> ChainBackend:
    async def open_keyed(active: str, retired: tuple[str, ...]) -> MessageStore:
        cipher = make_cipher(active, retired)
        return await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())

    async def open_keyless() -> MessageStore:
        return await MessageStore.open(path)

    # A plain stdlib connection: the writer these cases stand in for never holds the store's key.
    async def execute(sql: str) -> None:
        _write(path, sql)

    async def fetch(sql: str) -> Sequence[Mapping[str, Any]]:
        conn = sqlite3.connect(path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(sql).fetchall()]
        finally:
            conn.close()

    async def reset() -> None:
        store = await MessageStore.open(path)  # builds the schema on first use
        await store.close()
        await execute("DELETE FROM audit_log")

    return ChainBackend(
        name="sqlite",
        open_keyed=open_keyed,
        open_keyless=open_keyless,
        execute=execute,
        fetch=fetch,
        reset=reset,
    )


def _write(path: Path, sql: str, params: tuple[Any, ...] = ()) -> None:
    """Run one statement as a writer that opened the file directly and holds no key."""
    conn = sqlite3.connect(path, timeout=10)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.__name__)
async def test_audit_chain_case_on_sqlite(
    case: Callable[[ChainBackend], Awaitable[None]], tmp_path: Path
) -> None:
    await case(_sqlite_backend(tmp_path / "chain.db"))


# --- nothing beside the chain says where its keying starts ------------------------------------------


async def test_a_fresh_store_has_no_table_beside_audit_log_for_the_chain(tmp_path: Path) -> None:
    """The first range's key is named by the chain's own first row, so the schema holds no second
    table for it. The control is ``audit_log`` itself, found by the same query."""
    path = tmp_path / "schema.db"
    store = await MessageStore.open(path)
    await store.close()
    with sqlite3.connect(path) as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "audit_log" in names
    assert "audit_chain_meta" not in names


@pytest.mark.parametrize("module", ["store", "postgres", "sqlserver"])
def test_no_backend_schema_or_statement_names_the_removed_table(module: str) -> None:
    """All three backends, from their source, so the server arms are checked without a live server.
    The control is ``audit_log``, which the same read must find in each."""
    source = (
        Path(__file__).resolve().parent.parent / "messagefoundry" / "store" / f"{module}.py"
    ).read_text(encoding="utf-8")
    assert "INSERT INTO audit_log" in source
    lines = source.splitlines()
    assert len(lines) > 1000  # the walk below has a population
    statements = [
        line
        for line in lines
        if "audit_chain_meta" in line and not line.lstrip().startswith(("#", "--"))
    ]
    assert not statements, statements


async def test_a_row_numbered_below_one_is_the_audit_verifys_to_report(tmp_path: Path) -> None:
    """SQLite's ``audit_log.seq`` carries no CHECK, deliberately. A row numbered below 1 is reported
    by the audit verify, and the store's own integrity check still passes: a CHECK there would
    fail that check on such a row, and with it every backup that verifies its restore. The
    control is the same store before the row is added, where both checks pass."""
    path = tmp_path / "integrity.db"
    store = await _keyed(path, generate_key())
    try:
        await store.record_audit("act", actor="u")
        assert await store.integrity_check() == (True, "ok")
        ok, message = await store.verify_audit_chain()
        assert ok, message
        _write(
            path,
            "INSERT INTO audit_log (seq, ts, actor, action, channel_id, detail, client, row_hash)"
            " VALUES (0, 1.0, 'someone', 'added', NULL, NULL, NULL, 'deadbeef')",
        )
        assert await store.integrity_check() == (True, "ok")
        ok, message = await store.verify_audit_chain()
        assert not ok and "seq=1" in (message or ""), message
    finally:
        await store.close()


@pytest.mark.parametrize("module", ["postgres", "sqlserver"])
def test_the_server_schemas_refuse_a_position_below_one(module: str) -> None:
    """From the source, so the server arms are pinned without a live server. The live refusal is the
    shared case ``a_row_added_below_the_genesis_row_does_not_change_what_the_chain_is``."""
    source = (
        Path(__file__).resolve().parent.parent / "messagefoundry" / "store" / f"{module}.py"
    ).read_text(encoding="utf-8")
    declared = [
        line for line in source.splitlines() if "seq" in line and "CHECK (seq >= 1)" in line
    ]
    assert len(declared) == 1, declared
    assert "BIGINT NOT NULL UNIQUE CHECK (seq >= 1)" in declared[0]


def test_the_append_only_table_list_is_the_audit_log_alone() -> None:
    assert AUDIT_APPEND_ONLY_TABLES == ("audit_log",)


# --- the keying rule comes from the handle -----------------------------------------------------------


def test_a_handle_that_holds_a_key_never_gets_a_keyless_append() -> None:
    """No argument describes a database row that could switch keying off. The control is a handle
    with no secret on a keyless chain, which is the keyless store mode."""
    key = b"k" * 32
    held = build_audit_mac_keys(None, key)
    for chain_keyed in (False, True):
        secret = audit_append_secret(
            chain_keyed=chain_keyed, range_key_id=None, mac_keys=held, mac_key=key, mac_fn=None
        )
        assert secret == (key, None)
    assert audit_append_secret(
        chain_keyed=False, range_key_id=None, mac_keys={}, mac_key=None, mac_fn=None
    ) == (None, None)
    with pytest.raises(RuntimeError, match="refusing to append a keyless audit row"):
        audit_append_secret(
            chain_keyed=True, range_key_id=None, mac_keys={}, mac_key=None, mac_fn=None
        )


# --- the next link -----------------------------------------------------------------------------------


def test_the_next_link_is_the_head_plus_one() -> None:
    assert audit_next_link(None, None) == (1, "")
    assert audit_next_link((41, "abc"), None) == (42, "abc")
    assert audit_next_link((41, "abc"), "abc") == (42, "abc")


def test_the_next_link_refuses_a_head_the_caller_did_not_seal() -> None:
    with pytest.raises(AuditHeadMovedError):
        audit_next_link((41, "abc"), "other")
    # "" means the caller requires an EMPTY log: the genesis row is written to nothing else.
    with pytest.raises(AuditHeadMovedError):
        audit_next_link((1, "abc"), "")
    with pytest.raises(AuditHeadMovedError):
        audit_next_link((1, ""), "")
    assert audit_next_link(None, "") == (1, "")


@pytest.mark.parametrize("head_seq", ["7", 7.5, -1, 2**63 - 1], ids=repr)
def test_the_next_link_requires_an_empty_log_before_it_reads_the_heads_number(
    head_seq: object,
) -> None:
    """A log that holds any row refuses the genesis append the same way, whatever number that row
    carries. The control is the same head with no such requirement, which is the other refusal."""
    with pytest.raises(AuditHeadMovedError):
        audit_next_link((head_seq, "abc"), "")
    with pytest.raises(RuntimeError, match="no usable sequence number"):
        audit_next_link((head_seq, "abc"), None)


@pytest.mark.parametrize("head_seq", [None, "7", 7.0, True])
def test_the_next_link_refuses_a_head_with_no_usable_sequence_number(head_seq: object) -> None:
    with pytest.raises(RuntimeError, match="no usable sequence number"):
        audit_next_link((head_seq, "abc"), None)


def test_the_next_link_refuses_a_head_it_cannot_count_on_from() -> None:
    """The column's highest value has no successor, and a negative head is not a chain position.
    Each is the designed refusal, naming ``audit-verify``, and never an overflow from the driver."""
    for head_seq in (2**63 - 1, 2**63, -1):
        with pytest.raises(RuntimeError, match="no usable sequence number"):
            audit_next_link((head_seq, "abc"), None)
    assert audit_next_link((2**63 - 2, "abc"), None) == (2**63 - 1, "abc")  # the control


# --- SQLite: a second connection to the same file ---------------------------------------------------


async def _keyed(path: Path, key: str) -> MessageStore:
    cipher = make_cipher(key)
    return await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())


def _add_a_row_from_another_connection(path: Path, seq: int) -> None:
    """What a second process appending at the same moment does to this handle: the position this
    handle just read as free is taken, and committed, before its own INSERT."""
    with sqlite3.connect(path, timeout=10) as conn:
        conn.execute(
            "INSERT INTO audit_log (seq, ts, actor, action, channel_id, detail, client, row_hash)"
            " VALUES (?, 1.0, 'peer', 'peer.row', NULL, NULL, NULL, 'feedface')",
            (seq,),
        )
        conn.commit()
    conn.close()


async def test_an_append_that_loses_its_position_to_another_connection_takes_the_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SQLite's writer lock belongs to one handle. A second connection that appends between this
    handle's head read and its INSERT takes the position; the UNIQUE constraint refuses the INSERT,
    and the append reads the head again under the write lock the refused INSERT took. The control
    is the same append with no second connection, which takes the next position at once."""
    path = tmp_path / "race.db"
    store = await _keyed(path, generate_key())
    try:
        await store.record_audit("first", actor="u")  # seq 2, after the genesis row
        real = store._audit_append_mac
        fired: list[int] = []

        def mac_after_a_peer_append() -> Any:
            # Called between the head read and the INSERT, which is the window under test.
            if not fired:
                fired.append(1)
                _add_a_row_from_another_connection(path, 3)
            return real()

        monkeypatch.setattr(store, "_audit_append_mac", mac_after_a_peer_append)
        await store.record_audit("second", actor="u")
        assert fired, "the window was never entered, so the pass below would prove nothing"
        cur = await store._db.execute("SELECT seq, action FROM audit_log ORDER BY seq")
        assert [tuple(r) for r in await cur.fetchall()] == [
            (1, AUDIT_KEY_EPOCH_ACTION),
            (2, "first"),
            (3, "peer.row"),
            (4, "second"),
        ]
    finally:
        await store.close()


async def test_an_append_that_named_its_head_is_refused_when_another_connection_moved_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same window, for an append that sealed the head first (a key rotation's range row). The
    second read finds a different head, so the append is refused and writes nothing."""
    path = tmp_path / "race-sealed.db"
    store = await _keyed(path, generate_key())
    try:
        _seq, head = await store.audit_anchor()
        real = store._audit_append_mac
        fired: list[int] = []

        def mac_after_a_peer_append() -> Any:
            if not fired:
                fired.append(1)
                _add_a_row_from_another_connection(path, 2)
            return real()

        monkeypatch.setattr(store, "_audit_append_mac", mac_after_a_peer_append)
        with pytest.raises(AuditHeadMovedError):
            await store.record_audit("sealed", actor="u", expect_prev=head)
        assert fired
        cur = await store._db.execute("SELECT seq, action FROM audit_log ORDER BY seq")
        assert [tuple(r) for r in await cur.fetchall()] == [
            (1, AUDIT_KEY_EPOCH_ACTION),
            (2, "peer.row"),
        ]
    finally:
        await store.close()


async def test_a_second_handle_that_loses_the_genesis_write_adopts_the_row_already_there(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two keyed handles reach an empty log together. The second one's genesis append finds a row
    there and is refused; the load suppresses that and adopts the first handle's row. Forced here by
    making the second handle's first read see the empty log it would have seen a moment earlier.
    The control is the genesis row count before the second load: one."""
    path = tmp_path / "two.db"
    key = generate_key()
    first = await _keyed(path, key)
    second = await _keyed(path, key)
    try:
        real = second._audit_genesis_row
        reads: list[int] = []

        async def empty_once() -> Any:
            reads.append(1)
            return None if len(reads) == 1 else await real()

        monkeypatch.setattr(second, "_audit_genesis_row", empty_once)
        await load_audit_chain(second, read_only=False)
        assert len(reads) == 2, "the load must read again after its refused append"
        assert second._audit_chain_keyed is True and second._audit_ranges_trusted
        cur = await first._db.execute("SELECT seq, action FROM audit_log")
        assert [tuple(r) for r in await cur.fetchall()] == [(1, AUDIT_KEY_EPOCH_ACTION)]
    finally:
        await first.close()
        await second.close()


# --- SQLite stores any type in any column: nothing a column holds may raise --------------------------


def test_the_mac_comparison_is_total_over_every_stored_type() -> None:
    """A value no engine build writes maps to bytes no digest can equal, and to different bytes
    from the text it resembles."""
    digest = "ab" * 32
    for stored in (b"ab" * 32, 7, 7.5, None, ""):
        assert audit_mac_bytes(stored) != audit_mac_bytes(digest)
    assert audit_mac_bytes(b"ab") != audit_mac_bytes("ab")
    assert audit_mac_bytes("ab") == b"ab"  # the control: text is its own bytes


@pytest.mark.parametrize("seq", [1, 3, 4], ids=["genesis-row", "later-row", "head-row"])
async def test_a_row_hash_stored_as_a_blob_is_a_reported_break(tmp_path: Path, seq: int) -> None:
    """The store still opens, the verify reports the row, and the anchor still answers. None of
    them raises. The control is the untouched chain, which verifies, and its anchor."""
    path = tmp_path / "blob.db"
    key = generate_key()
    store = await _keyed(path, key)
    try:
        for i in range(3):
            await store.record_audit("act", actor="u", detail=str(i))
        ok, message = await store.verify_audit_chain()
        assert ok, message
        position, head = await store.audit_anchor()
        assert position == 4 and len(head) == 64
    finally:
        await store.close()
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE audit_log SET row_hash = X'6162' WHERE seq = ?", (seq,))
        conn.commit()
    conn.close()
    store = await _keyed(path, key)  # must not raise
    try:
        ok, message = await store.verify_audit_chain()  # must not raise
        assert not ok and f"seq={seq}" in (message or ""), message
        # The anchor reads the head row. A head hash that is not text is reported as no hash,
        # which no recorded anchor matches; any other row leaves the anchor as it was.
        assert await store.audit_anchor() == (4, "" if seq == 4 else head)
    finally:
        await store.close()


async def test_the_anchor_is_total_over_a_head_whose_sequence_number_is_not_an_integer(
    tmp_path: Path,
) -> None:
    """Text sorts above every integer in SQLite, so such a row is the head. The anchor falls back to
    the row count rather than raising, and an append on that head is the designed refusal. The
    numbers are chosen so the fallback is told apart from its neighbours: 3 rows remain, the highest
    integer left is 2, and the anchor before the edit was 4."""
    path = tmp_path / "text-seq.db"
    store = await MessageStore.open(path)
    try:
        for i in range(4):
            await store.record_audit("act", actor="u", detail=str(i))
        assert (await store.audit_anchor())[0] == 4  # the control
        _write(path, "DELETE FROM audit_log WHERE seq = 1")
        _write(path, "UPDATE audit_log SET seq = 'zzy' WHERE seq = 3")
        _write(path, "UPDATE audit_log SET seq = 'zzz' WHERE seq = 4")
        seq, head = await store.audit_anchor()
        assert seq == 3 and len(head) == 64
        with pytest.raises(RuntimeError, match="no usable sequence number"):
            await store.record_audit("next", actor="u")
        ok, message = await store.verify_audit_chain()
        assert not ok, message
    finally:
        await store.close()


async def test_the_anchor_never_reads_a_log_that_holds_rows_as_empty(tmp_path: Path) -> None:
    """An anchor of 0 means an empty log to every caller. A log whose only row was renumbered below
    1 still holds a row, so its anchor is the row count. The control is the anchor of a log that
    really is empty."""
    path = tmp_path / "zero.db"
    store = await MessageStore.open(path)
    try:
        assert await store.audit_anchor() == (0, "")  # the control
        await store.record_audit("act", actor="u")
        _write(path, "UPDATE audit_log SET seq = 0")
        seq, head = await store.audit_anchor()
        assert seq == 1 and len(head) == 64
    finally:
        await store.close()


async def test_a_keyed_store_opens_and_reports_a_log_with_no_row_at_position_one(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The genesis row renumbered to a value that is not a position, which then sorts as the head.
    The open finds rows and no genesis row: it reports the chain and sets the posture flag. It does
    not raise, so the engine still starts and says what it found. The control is the same store
    before the edit, which opens with the flag clear."""
    path = tmp_path / "no-genesis.db"
    key = generate_key()
    store = await _keyed(path, key)
    try:
        for i in range(3):
            await store.record_audit("act", actor="u", detail=str(i))
        assert store.audit_chain_unkeyed() is False
    finally:
        await store.close()
    _write(path, "UPDATE audit_log SET seq = 7.5 WHERE seq = 1")
    with caplog.at_level("ERROR"):
        store = await _keyed(path, key)  # must not raise
    try:
        assert store.audit_chain_unkeyed() is True
        assert any("genesis row" in r.getMessage() for r in caplog.records)
        ok, message = await store.verify_audit_chain()
        assert not ok, message
    finally:
        await store.close()


async def test_every_row_is_compared_when_a_row_sits_below_the_genesis_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk compares every row's MAC whatever else it finds (ASVS 11.2.4). A row added below
    the genesis row must not leave the walk with no key to compare under. Counted at the one
    function that computes a row's expected MAC. The control is the untouched chain: one
    computation per row."""
    path = tmp_path / "below.db"
    store = await _keyed(path, generate_key())
    computed: list[object] = []
    real = store_module._audit_row_mac

    def counting(row: Any, prev: Any, key: Any, mac: Any) -> Any:
        computed.append(row["seq"])
        return real(row, prev, key, mac)

    monkeypatch.setattr(store_module, "_audit_row_mac", counting)
    try:
        for i in range(3):
            await store.record_audit("act", actor="u", detail=str(i))
        ok, message = await store.verify_audit_chain()
        assert ok, message
        assert computed == [1, 2, 3, 4]  # the control
        _write(
            path,
            "INSERT INTO audit_log (seq, ts, actor, action, channel_id, detail, client, row_hash)"
            " VALUES (0, 1.0, 'someone', 'added', NULL, NULL, NULL, 'deadbeef')",
        )
        computed.clear()
        ok, message = await store.verify_audit_chain()
        assert not ok and "seq=1" in (message or ""), message
        assert computed == [0, 1, 2, 3, 4]
    finally:
        await store.close()


# --- the genesis record ------------------------------------------------------------------------------


def test_a_genesis_record_round_trips_and_is_not_a_range_record() -> None:
    detail = audit_genesis_detail("0123456789abcdef")
    assert parse_audit_genesis(detail) == "0123456789abcdef"
    assert parse_audit_epoch(detail) is None  # it closes nothing, so it is not a range row


@pytest.mark.parametrize(
    "detail",
    [
        None,
        "",
        "not json",
        "[]",
        '{"genesis": 1}',
        '{"key_id": "k"}',
        '{"genesis": 2, "key_id": "k"}',
        '{"genesis": true, "key_id": "k"}',
        '{"genesis": 1, "key_id": ""}',
        '{"genesis": 1, "key_id": 5}',
        '{"genesis": 1, "key_id": "k", "closes": {}}',
        # A short id: pytest puts the parameter in an environment variable, which has a size limit.
        pytest.param("[" * 100_000, id="deeply-nested"),
        5,
        b'{"genesis": 1, "key_id": "k"}',
    ],
)
def test_a_malformed_genesis_record_is_none_and_never_an_exception(detail: object) -> None:
    assert parse_audit_genesis(detail) is None


def test_a_range_record_is_not_a_genesis_record() -> None:
    closes = {
        "key_id": "k",
        "from_seq": 1,
        "to_seq": 1,
        "rows": 1,
        "digest": "d",
        "prev_hash": "",
    }
    detail = json.dumps({"key_id": "n", "closes": closes, "handover": "t"})
    assert parse_audit_epoch(detail) is not None
    assert parse_audit_genesis(detail) is None


# --- the typed encoder -------------------------------------------------------------------------------


def test_the_encoder_tells_null_the_empty_string_and_the_text_none_apart() -> None:
    encodings = {encode_typed_fields([("f", value)]) for value in (None, "", "None")}
    assert len(encodings) == 3


def test_the_encoder_tells_types_and_field_boundaries_apart() -> None:
    assert encode_typed_fields([("f", 1)]) != encode_typed_fields([("f", 1.0)])
    assert encode_typed_fields([("f", 1)]) != encode_typed_fields([("f", "1")])
    assert encode_typed_fields([("f", "1")]) != encode_typed_fields([("f", b"1")])
    # A value cannot run into its neighbour, and a name cannot run into its value.
    assert encode_typed_fields([("a", "xy"), ("b", "z")]) != encode_typed_fields(
        [("a", "x"), ("b", "yz")]
    )
    assert encode_typed_fields([("ab", "c")]) != encode_typed_fields([("a", "bc")])
    # Order is the caller's, and it is part of the encoding.
    assert encode_typed_fields([("a", 1), ("b", 2)]) != encode_typed_fields([("b", 2), ("a", 1)])


def test_the_encoder_round_trips_floats_exactly_and_is_total_over_strings() -> None:
    assert encode_typed_fields([("f", 0.1 + 0.2)]) != encode_typed_fields([("f", 0.3)])
    assert encode_typed_fields([("f", float("nan"))])  # encodes; it does not raise
    assert encode_typed_fields([("f", "\ud800")])  # a lone surrogate encodes too


@pytest.mark.parametrize("value", [True, False, [1], {"a": 1}, object()])
def test_the_encoder_refuses_a_type_it_does_not_define(value: Any) -> None:
    with pytest.raises(TypeError):
        encode_typed_fields([("f", value)])


# --- the CLI surface ---------------------------------------------------------------------------------


def test_the_parser_offers_no_rekey_audit_command() -> None:
    """The control is the audit commands that remain, found by the same two reads: the parser's own
    subcommand table and the dispatch map behind it."""
    parser, dispatch = _build_parser()
    choices: set[str] = set()
    for action in parser._actions:
        table = getattr(action, "choices", None)
        if isinstance(table, dict):
            choices |= set(table)
    for commands in (choices, set(dispatch)):
        assert {"audit-verify", "audit-anchor", "rotate-key"} <= commands
        assert "rekey-audit" not in commands


async def test_a_keyed_store_lists_its_genesis_row_like_any_other(tmp_path: Path) -> None:
    """The genesis row is an ordinary audit row to a reader: it is listed, with the system actor."""
    cipher = make_cipher(generate_key())
    store = await MessageStore.open(
        tmp_path / "list.db", cipher=cipher, audit_mac_key=cipher.audit_mac_key()
    )
    try:
        rows = [dict(r) for r in await store.list_audit()]
        assert [(r["action"], r["actor"]) for r in rows] == [(AUDIT_KEY_EPOCH_ACTION, "system")]
    finally:
        await store.close()
