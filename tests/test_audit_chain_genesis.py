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

import sqlite3
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import _build_parser
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import make_cipher
from messagefoundry.store.privilege import AUDIT_APPEND_ONLY_TABLES
from messagefoundry.store.store import (
    AUDIT_KEY_EPOCH_ACTION,
    AuditHeadMovedError,
    audit_append_secret,
    audit_genesis_detail,
    audit_next_link,
    build_audit_mac_keys,
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
        with sqlite3.connect(path, timeout=10) as conn:
            conn.execute(sql)
            conn.commit()
        conn.close()

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
    statements = [
        line
        for line in source.splitlines()
        if "audit_chain_meta" in line and not line.lstrip().startswith(("#", "--"))
    ]
    assert not statements, statements


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


@pytest.mark.parametrize("head_seq", [None, "7", 7.0, True])
def test_the_next_link_refuses_a_head_with_no_usable_sequence_number(head_seq: object) -> None:
    with pytest.raises(RuntimeError, match="no usable sequence number"):
        audit_next_link((head_seq, "abc"), None)


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
    import json

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
    cipher = make_cipher(_key())
    store = await MessageStore.open(
        tmp_path / "list.db", cipher=cipher, audit_mac_key=cipher.audit_mac_key()
    )
    try:
        rows = [dict(r) for r in await store.list_audit()]
        assert [(r["action"], r["actor"]) for r in rows] == [(AUDIT_KEY_EPOCH_ACTION, "system")]
    finally:
        await store.close()


def _key() -> str:
    from messagefoundry.store.crypto import generate_key

    return generate_key()
