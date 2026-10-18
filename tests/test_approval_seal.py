# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Sealed dual-control approval requests on SQLite, and the static guards that keep them whole
(BACKLOG #2592).

The behavioural contract is ``tests/_approval_seal_contract.py``; the Postgres and SQL Server suites
run the same one on their own legs. This file runs it on SQLite, and adds what only one place needs
to hold: the column the seal leaves out, the table's columns, the gate's loaders, the list of every
statement that writes the table, ``rotate-key``'s re-seal, and what a keyed store does with a
request written before the seal.
"""

from __future__ import annotations

import ast
import asyncio
import logging
import pathlib
import sqlite3
import time
from collections.abc import AsyncIterator
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.auth.permissions import Permission
from messagefoundry.config.settings import ApprovalsSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import RowSealError
from messagefoundry.store.store import (
    APPROVAL_SEAL_EXCLUDED,
    ApprovalRow,
    MessageStore,
    approval_seal_ok,
)
from tests._approval_seal_contract import (
    _Hooked,
    _Sink,
    assert_approval_columns,
    assert_approval_seal_contract,
)
from tests._pending_approval_store_contract import _resolve, _StandingStore
from tests.test_role_seal import _literal_text, _raw_for

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_STORE_DIR = _ROOT / "messagefoundry" / "store"
_GATE = _ROOT / "messagefoundry" / "api" / "approvals.py"


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, Path]]:
    path = tmp_path / "sealed.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        yield store, path
    finally:
        await store.close()


def _gate(store: Any) -> ApprovalGate:
    async def run(_params: Any) -> dict[str, Any]:
        return {}

    gate = ApprovalGate(
        _StandingStore(store),
        ApprovalsSettings(enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=0.0),
        resolve_identity=_resolve,
    )
    gate.register("dead_letter_replay", "op", run, permission=Permission.MESSAGES_REPLAY)
    return gate


async def _request(gate: ApprovalGate, nonce: str) -> str:
    filed = await gate.guard(
        "dead_letter_replay", {"n": nonce}, requester="r", requester_user_id="r-id"
    )
    assert filed is not None
    return filed


async def test_the_approval_seal_contract_holds_on_sqlite(keyed: tuple[MessageStore, Path]) -> None:
    store, path = keyed
    await assert_approval_seal_contract(store, _raw_for(path))


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("messagefoundry.api.approvals", "approval_seal_ok"),
        ("messagefoundry.store.store", "approval_seal_ok"),
    ],
)
async def test_the_contract_fails_when_a_seal_check_is_switched_off(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch, module: str, name: str
) -> None:
    """The control for the contract: with the gate's check or the store's switched off it must
    fail, so a green contract is evidence that both checks run."""
    import importlib

    store, path = keyed
    monkeypatch.setattr(importlib.import_module(module), name, lambda sealer, row: True)
    with pytest.raises(AssertionError):
        await assert_approval_seal_contract(store, _raw_for(path))


def test_the_columns_an_approval_seal_leaves_out_are_pinned() -> None:
    # A change here is a decision about what a writer may alter unseen; it needs a reason beside it.
    assert dict(APPROVAL_SEAL_EXCLUDED).keys() == {"seal"}


def test_an_approval_seal_covers_every_other_field() -> None:
    row = ApprovalRow("a", "op", "{}", "r", "r-id", 1.0, "pending", None, None, None, None, "")
    assert [name for name, _ in row.seal_fields()] == [
        f.name for f in fields(ApprovalRow) if f.name not in APPROVAL_SEAL_EXCLUDED
    ]


async def test_the_approval_row_matches_the_table(keyed: tuple[MessageStore, Path]) -> None:
    _, path = keyed
    conn = sqlite3.connect(path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(pending_approvals)")}
    finally:
        conn.close()
    assert_approval_columns(columns)


async def test_a_keyless_store_writes_no_seal_and_checks_none(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "keyless.db")
    try:
        assert store.row_sealer() is None
        gate = _gate(store)
        approval_id = await _request(gate, "k")
        found = await store.get_pending_approval(approval_id)
        assert found is not None and ApprovalRow.from_mapping(found).seal == ""
        released = await gate.approve(approval_id, approver="a", approver_user_id="a-id")
        assert released["operation"] == "dead_letter_replay"
    finally:
        await store.close()


async def test_a_key_rotation_reseals_approvals_under_the_active_key(tmp_path: Path) -> None:
    """A request's seal verifies under a retired key the process holds; ``rotate-key``'s pass
    re-seals it under the active key, so dropping the retired key afterwards refuses nothing. The
    control is a store given only the new key before that pass: the request is refused there."""
    old, new = generate_key(), generate_key()
    path = tmp_path / "rotated.db"
    store = await MessageStore.open(path, cipher=make_cipher(old, write_v2=True))
    try:
        approval_id = await _request(_gate(store), "rot")
    finally:
        await store.close()

    only_new = await MessageStore.open(path, cipher=make_cipher(new, write_v2=True))
    try:
        with pytest.raises(ApprovalError):  # control
            await _gate(only_new)._load(approval_id, status="pending", wrong=str)
    finally:
        await only_new.close()

    rotated = await MessageStore.open(path, cipher=make_cipher(new, [old], write_v2=True))
    try:
        sealer = rotated.row_sealer()
        assert sealer is not None
        assert (
            await _gate(rotated)._load(approval_id, status="pending", wrong=str)
        ).id == approval_id
        await rotated.reencrypt_to_active()  # rotate-key's store pass, which runs the re-seal
        found = await rotated.get_pending_approval(approval_id)
        assert found is not None and sealer.is_active(ApprovalRow.from_mapping(found).seal)
    finally:
        await rotated.close()

    dropped = await MessageStore.open(path, cipher=make_cipher(new, write_v2=True))
    try:
        assert (
            await _gate(dropped)._load(approval_id, status="pending", wrong=str)
        ).id == approval_id
    finally:
        await dropped.close()


async def test_rotation_leaves_a_failing_request_as_it_is(
    keyed: tuple[MessageStore, Path],
) -> None:
    """The re-seal pass checks each row under the key it names before it re-seals it, so a row
    changed outside the store is counted and left failing. The control is the request the store
    wrote, which still verifies beside it."""
    store, path = keyed
    sealer = store.row_sealer()
    assert sealer is not None
    gate = _gate(store)
    good = await _request(gate, "good")
    bad = await _request(gate, "bad")
    foreign = f"mfseal:v1:not-this-key:{'0' * 64}"
    await _raw_for(path)("UPDATE pending_approvals SET seal=? WHERE id=?", (foreign, bad))
    assert await store.reseal_approval_records() == (0, 1)
    bad_row = await store.get_pending_approval(bad)
    assert bad_row is not None and ApprovalRow.from_mapping(bad_row).seal == foreign
    good_row = await store.get_pending_approval(good)
    assert good_row is not None and approval_seal_ok(sealer, ApprovalRow.from_mapping(good_row))


async def test_a_request_written_before_the_seal_is_named_at_open_and_refused(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A keyed store treats a blank seal as a failed one, so nothing seals a request at open. The
    open names how many open requests carry none, and leaves a decided one out of the count."""
    path = tmp_path / "legacy.db"
    key = generate_key()
    store = await MessageStore.open(path, cipher=make_cipher(key, write_v2=True))
    await store.close()
    raw = _raw_for(path)
    for approval_id, status in (("legacy-open", "pending"), ("legacy-done", "approved")):
        await raw(
            "INSERT INTO pending_approvals (id, operation, params, requester, requester_user_id,"
            " requested_at, status) VALUES (?,?,?,?,?,?,?)",
            (approval_id, "dead_letter_replay", "{}", "r", "r-id", time.time(), status),
        )
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        reopened = await MessageStore.open(path, cipher=make_cipher(key, write_v2=True))
    try:
        warned = [r.getMessage() for r in caplog.records if "approval request" in r.getMessage()]
        assert len(warned) == 1 and warned[0].startswith("1 open dual-control approval request")
        with pytest.raises(ApprovalError) as refusal:
            await _gate(reopened).approve("legacy-open", approver="a", approver_user_id="a-id")
        assert refusal.value.status == 409
    finally:
        await reopened.close()


async def test_a_value_no_honest_write_leaves_is_a_failed_seal_not_a_crash(
    keyed: tuple[MessageStore, Path],
) -> None:
    """SQLite keeps text in a REAL column, so a writer can leave a row no reader can type. Each
    reader treats it as a request that fails its seal: the queue still lists the sound request, a
    repeat files its own, and the store's move refuses it. The control is the sound request beside
    it, which is listed and released."""
    store, path = keyed
    gate = _gate(store)
    sound = await _request(gate, "sound")
    broken = await _request(gate, "broken")
    await _raw_for(path)(
        "UPDATE pending_approvals SET requested_at=? WHERE id=?", ("not-a-time", broken)
    )
    assert [e["id"] for e in await gate.list_pending()] == [sound]
    with pytest.raises(ApprovalError) as refusal:
        await gate.approve(broken, approver="a", approver_user_id="a-id")
    assert refusal.value.status == 409
    assert await _request(gate, "broken") != broken  # a repeat does not join it
    with pytest.raises(RowSealError):
        await store.decide_pending_approval(
            broken, status="rejected", approver="a", decided_at=time.time()
        )
    released = await gate.approve(sound, approver="a", approver_user_id="a-id")  # control
    assert released["operation"] == "dead_letter_replay"


class _PagingSink(_Sink):
    def __init__(self) -> None:
        super().__init__()
        self.lost: list[str] = []

    def audit_write_failed(self, name: str, *, action: str) -> None:
        self.lost.append(action)


@pytest.mark.parametrize("refusal", [RowSealError("approval"), OSError("store down")])
async def test_a_cancelled_claim_the_store_refuses_on_its_seal_is_reported_not_paged_lost(
    keyed: tuple[MessageStore, Path], refusal: Exception
) -> None:
    """An approve cancelled while its claim runs settles the claim itself. A claim the store
    refuses on the row's seal wrote nothing, so it raises the integrity alert and pages no lost
    audit row. The control is a claim that fails for any other reason, which pages the loss."""
    store, _ = keyed
    sink = _PagingSink()
    started = asyncio.Event()

    async def refuse(approval_id: str, **kw: Any) -> bool:
        if kw.get("status") != "executing":
            return bool(await store.decide_pending_approval(approval_id, **kw))
        started.set()
        await asyncio.sleep(0.05)
        raise refusal

    gate = ApprovalGate(
        _StandingStore(_Hooked(store, refuse)),
        ApprovalsSettings(enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=0.0),
        resolve_identity=_resolve,
        alert_sink=sink,
    )

    async def run(_params: Any) -> dict[str, Any]:
        return {}

    gate.register("dead_letter_replay", "op", run, permission=Permission.MESSAGES_REPLAY)
    approval_id = await _request(gate, "cancel")
    task = asyncio.ensure_future(gate.approve(approval_id, approver="a", approver_user_id="a-id"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    if isinstance(refusal, RowSealError):
        assert sink.lost == [] and len(sink.reasons) == 1
    else:
        assert sink.lost == ["approval.release_attempted"] and sink.reasons == []


# --- static guards --------------------------------------------------------------------------

_APPROVAL_READERS = frozenset(
    {
        "get_pending_approval",
        "list_pending_approvals",
        "list_interrupted_approvals",
        "list_executing_approvals",
    }
)
#: The gate functions that call a raw request reader, and which. Each hands what it reads to the
#: gate's seal check, except the second ``list_executing_approvals`` read in the restart reconcile,
#: which only logs a sibling's rows and never acts on them.
_GATE_READS: dict[str, frozenset[str]] = {
    "_load": frozenset({"get_pending_approval"}),
    "_read_back_request": frozenset({"get_pending_approval"}),
    "list_pending": frozenset({"list_pending_approvals"}),
    "list_interrupted": frozenset({"list_interrupted_approvals"}),
    "rejoin": frozenset({"list_pending_approvals"}),
    "_reconcile": frozenset({"list_executing_approvals"}),
}


def _gate_reader_calls(source: str) -> list[tuple[str, str, bool]]:
    """``(function, reader, checked)`` for each raw request read in the gate. ``checked`` says the
    read is the argument of a ``self._verified_rows(...)`` call."""
    tree = ast.parse(source)
    checked_calls: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_verified_rows"
        ):
            for arg in ast.walk(node):
                checked_calls.add(id(arg))
    found: list[tuple[str, str, bool]] = []
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for node in ast.walk(func):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in _APPROVAL_READERS
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "_store"
            ):
                found.append((func.name, node.attr, id(node) in checked_calls))
    return found


def test_the_gate_reads_requests_through_its_seal_check() -> None:
    """A raw request read outside the loaders would act on a row nobody checked."""
    calls = _gate_reader_calls(_GATE.read_text("utf-8"))
    # Liveness first: the walk finds every listed read, so an empty walk cannot pass.
    assert len(calls) >= len(_GATE_READS), calls
    assert {f for f, _, _ in calls} == set(_GATE_READS), calls
    stray = [(f, r) for f, r, _ in calls if r not in _GATE_READS[f]]
    assert not stray, stray
    # `_load` and `_read_back_request` check what they read themselves, through `_verified`; every
    # other read goes through `_verified_rows`, except the one reconcile read that only logs.
    unchecked = sorted(
        (f, r)
        for f, r, checked in calls
        if not checked and f not in ("_load", "_read_back_request")
    )
    assert unchecked == [("_reconcile", "list_executing_approvals")], unchecked


#: Where each backend may write ``pending_approvals``: each module-level statement and the one
#: function that may use it. Every other INSERT, UPDATE, MERGE or DELETE of the table is a problem.
_SEALING: dict[str, dict[str, frozenset[str]]] = {
    "store.py": {
        "_SQLITE_APPROVAL_INSERT": frozenset({"_write_approval"}),
        "_SQLITE_APPROVAL_INSERT_UNLESS_OPEN": frozenset({"_write_approval"}),
        "_SQLITE_APPROVAL_UPDATE": frozenset({"_write_approval"}),
    },
    "postgres.py": {
        "_PG_APPROVAL_INSERT": frozenset({"_write_approval"}),
        "_PG_APPROVAL_UPDATE": frozenset({"_write_approval"}),
    },
    "sqlserver.py": {
        "_MSSQL_APPROVAL_INSERT": frozenset({"_write_approval"}),
        "_MSSQL_APPROVAL_UPDATE": frozenset({"_write_approval"}),
    },
}


def _is_approval_write(text: str) -> bool:
    flat = " ".join(text.upper().split()) + " "
    return any(
        flat.startswith(verb + "PENDING_APPROVALS" + tail)
        for verb in ("INSERT INTO ", "UPDATE ", "MERGE ", "DELETE FROM ", "TRUNCATE TABLE ")
        for tail in (" ", "(")
    )


def _scan(source: str, sealing: dict[str, frozenset[str]]) -> tuple[list[str], int]:
    """Every ``pending_approvals`` write in ``source`` that is not where it may be, and how many
    writes the scan found."""
    tree = ast.parse(source)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def enclosing(node: ast.AST) -> str | None:
        walk: ast.AST | None = parents.get(node)
        while walk is not None:
            if isinstance(walk, ast.FunctionDef | ast.AsyncFunctionDef):
                return walk.name
            walk = parents.get(walk)
        return None

    def assigned_name(node: ast.AST) -> str | None:
        walk: ast.AST | None = parents.get(node)
        while walk is not None and not isinstance(walk, ast.FunctionDef | ast.AsyncFunctionDef):
            if isinstance(walk, ast.Assign) and isinstance(walk.targets[0], ast.Name):
                return walk.targets[0].id
            if isinstance(walk, ast.AnnAssign) and isinstance(walk.target, ast.Name):
                return walk.target.id
            walk = parents.get(walk)
        return None

    problems: list[str] = []
    writes = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.expr) or isinstance(parents.get(node), ast.BinOp):
            continue
        text = _literal_text(node)
        if text is None or not _is_approval_write(text):
            continue
        writes += 1
        func = enclosing(node)
        if func is None and assigned_name(node) in sealing:
            continue
        problems.append(f"{func or 'module'}: an unsealed pending_approvals write: {text[:70]}")
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for inner in ast.walk(fn):
            if (
                isinstance(inner, ast.Name)
                and inner.id in sealing
                and fn.name not in sealing[inner.id]
            ):
                problems.append(f"{fn.name}: uses {inner.id} outside its sealing function")
    return problems, writes


@pytest.mark.parametrize("module", sorted(_SEALING))
def test_every_approval_write_is_sealed(module: str) -> None:
    source = (_STORE_DIR / module).read_text("utf-8")
    problems, writes = _scan(source, _SEALING[module])
    assert not problems, "\n".join(problems)
    # Liveness: the scan finds each named statement as a write.
    assert writes == len(_SEALING[module]), f"{module}: found {writes} writes"
    used = {n.id for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Name)}
    assert set(_SEALING[module]) <= used, f"{module}: {set(_SEALING[module]) - used}"


def test_the_write_scan_catches_an_unsealed_write() -> None:
    planted = (
        "_STRAY = 'DELETE FROM pending_approvals'\n"
        "async def widen(self, a):\n"
        "    await self._db.execute('UPDATE pending_approvals SET params=? WHERE id=?', ('{}', a))\n"
        "async def plant(self, a):\n"
        "    await self._db.execute('INSERT INTO pending_approvals (id) VALUES (?)', (a,))\n"
        "async def stray(self):\n"
        "    await self._db.execute(_SQLITE_APPROVAL_UPDATE, ())\n"
    )
    problems, writes = _scan(planted, {"_SQLITE_APPROVAL_UPDATE": frozenset({"_write_approval"})})
    assert writes == 3 and len(problems) == 4, problems
