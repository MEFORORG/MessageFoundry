# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1560, the RESPONSE stage: replay must not re-ingress a reply retention erased.

The contract in ``tests/_erased_reply_contract.py`` runs here on SQLite and from
``tests/test_postgres_store.py`` and ``tests/test_sqlserver_store.py`` on their live legs. This file
adds what only SQLite can show: the real re-ingress worker step, a shared body, a streaming
attachment, and a structural gate that runs on every leg for the two server backends.
"""

from __future__ import annotations

import ast
import pathlib
import re
from typing import Any

import pytest

from messagefoundry.config.models import ContentType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Loopback, Registry, build_inbound_connection
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus, Stage
from messagefoundry.store.crypto import generate_key, make_cipher
from tests import _erased_reply_contract as contract
from tests._ast_sites import call_sites, code_names, code_strings, named_func, parse_source
from tests._queue_tag_contract import RawFetch, RawSql
from tests._store_audit import no_operator_audit

_STORE_DIR = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "store"
_DAY = contract.DAY


@pytest.fixture(params=["keyless", "keyed"])
async def store(request: pytest.FixtureRequest, tmp_path: pathlib.Path) -> Any:
    """Both cipher shapes: the reference is plaintext on one and a sealed cell on the other."""
    cipher = make_cipher(generate_key(), write_v2=True) if request.param == "keyed" else None
    s = await MessageStore.open(tmp_path / "erased_reply.db", cipher=cipher)
    yield s
    await s.close()


def _fetch(store: MessageStore) -> RawFetch:
    async def fetch(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        cur = await store._db.execute(sql, params)
        return [dict(r) for r in await cur.fetchall()]

    return fetch


def _raw(store: MessageStore) -> RawSql:
    async def raw(sql: str, params: tuple[Any, ...]) -> None:
        await store._db.execute(sql, params)
        await store._db.commit()

    return raw


@pytest.mark.parametrize("case", contract.CASES)
async def test_erased_reply_contract(store: MessageStore, case: Any) -> None:
    await case(store, _fetch(store), _raw(store))


def _runner(store: MessageStore) -> RegistryRunner:
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            contract.LOOP, Loopback(), router="route_loop", content_type=ContentType.HL7V2
        )
    )
    reg.add_router("route_loop", lambda msg: [])
    return RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )


async def test_the_real_worker_step_never_ingresses_an_erased_reply(store: MessageStore) -> None:
    """The worker's own step, not a stand-in: it reads ``""`` for an erased reply and peeks it, so
    ``ingress_handoff`` has to be what refuses. The control proves the same step still re-ingresses."""
    fetch, raw = _fetch(store), _raw(store)
    gone_mid, gone = await contract.dead_token(store, now=0.0, control="ER-W")
    kept_mid, _ = await contract.dead_token(store, now=0.0, control="ER-W-KEPT")
    assert await store.replay(gone_mid, now=1.0, audit=no_operator_audit) == 1
    assert await store.replay(kept_mid, now=1.0, audit=no_operator_audit) == 1
    await raw("UPDATE response SET body=NULL WHERE message_id=?", (gone_mid,))

    runner = _runner(store)
    for _ in range(2):
        item = await store.claim_next_fifo(contract.LOOP, now=2.0, stage=Stage.RESPONSE.value)
        assert item is not None
        await runner._process_response_item(contract.LOOP, item)

    assert (await contract.token_row(fetch, gone))["status"] == OutboxStatus.DEAD.value
    assert await contract.status_of(store, gone_mid) == MessageStatus.ERROR.value
    assert await contract.status_of(store, kept_mid) == MessageStatus.PROCESSED.value
    assert len(await contract.children(fetch)) == 1


async def test_a_reference_with_a_malformed_sequence_dead_letters(tmp_path: pathlib.Path) -> None:
    """A keyless claim checks no tag, so a damaged reference reaches the worker. A sequence that is
    not an integer must reach ``ingress_handoff``'s corrupt-reference branch, not raise out of the
    peek read and re-pend the token at the head of the loopback lane forever."""
    store = await MessageStore.open(tmp_path / "malformed.db")
    try:
        fetch, raw = _fetch(store), _raw(store)
        mid, token = await contract.dead_token(store, now=0.0, control="ER-SEQ")
        assert await store.replay(mid, now=1.0, audit=no_operator_audit) == 1
        await raw(
            "UPDATE queue SET payload=? WHERE id=?", (f"{mid}\x1fOB_X\x1fnot-a-number", token)
        )

        assert await store.response_body_for_work_row(token) is None
        runner = _runner(store)
        item = await store.claim_next_fifo(contract.LOOP, now=2.0, stage=Stage.RESPONSE.value)
        assert item is not None
        await runner._process_response_item(contract.LOOP, item)

        assert (await contract.token_row(fetch, token))["status"] == OutboxStatus.DEAD.value
        assert await contract.status_of(store, mid) == MessageStatus.ERROR.value
        assert await contract.children(fetch) == []
    finally:
        await store.close()


async def test_a_later_capture_does_not_revive_an_erased_token(store: MessageStore) -> None:
    """Why the reference is blanked rather than joined. The artifact's destination and sequence exist
    only inside the sealed reference, so a SQL join could bind on ``message_id`` alone. A message that
    captures a NEW reply after the purge would then read as replayable through its erased token."""
    fetch = _fetch(store)
    sibling = "OB_LATER"
    mid, token = await contract.dead_token(
        store, now=0.0, control="ER-LATER", extra=((sibling, contract.BODY),)
    )
    [row] = await store.claim_ready(destination_name=sibling, now=0.0)
    await store.dead_letter_now(row.id, "permanent reject", now=0.0)
    await store.purge_message_bodies(older_than=10 * _DAY, now=50 * _DAY)

    assert await store.replay(mid, now=60 * _DAY, audit=no_operator_audit) == 1
    [item] = await store.claim_ready(destination_name=sibling, now=60 * _DAY)
    await store.complete_with_response(
        item.id, body=contract.REPLY, outcome="accepted", now=60 * _DAY
    )
    bodies = await fetch("SELECT body FROM response WHERE message_id=?", (mid,))
    assert [b["body"] for b in bodies].count(None) == 1 and len(bodies) == 2  # the later capture

    assert await store.replay(mid, now=61 * _DAY, audit=no_operator_audit) == 0
    assert (await contract.token_row(fetch, token))["status"] == OutboxStatus.DEAD.value
    assert await contract.children(fetch) == []


async def test_a_shared_body_survives_for_the_delivery_that_still_needs_it(
    store: MessageStore,
) -> None:
    """Store-once on SQLite: one body, two destinations. One delivered and its reply's token died; the
    other died. The purge blanks the token, and the shared body stays for the dead delivery."""
    fetch = _fetch(store)
    mid = await store.enqueue_ingress(channel_id="IB", raw=contract.RAW, now=0.0)
    ingress = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value, now=0.0)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("h1", contract.RAW)],
        disposition=MessageStatus.ROUTED,
        now=0.0,
    )
    routed = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=0.0)
    assert routed is not None
    # One identical body to two destinations gives one shared_body row and two body_refs.
    await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_X", contract.BODY), ("OB_SHARED", contract.BODY)],
        now=0.0,
    )
    refs = await fetch("SELECT body_ref FROM queue WHERE message_id=?", (mid,))
    assert len(refs) == 2 and all(r["body_ref"] for r in refs)  # the control: it is store-once

    token = await contract.kill_reply(store, now=0.0)
    [dead] = await store.claim_ready(destination_name="OB_SHARED", now=0.0)
    await store.dead_letter_now(dead.id, "permanent reject", now=0.0)

    await store.purge_message_bodies(older_than=10 * _DAY, now=50 * _DAY)

    assert (await contract.token_row(fetch, token))["payload"] == ""
    assert await store.replay(mid, now=60 * _DAY, audit=no_operator_audit) == 1
    [item] = await store.claim_ready(destination_name="OB_SHARED", now=60 * _DAY)
    assert item.payload == contract.BODY
    await store.mark_done(item.id, now=60 * _DAY)
    assert await contract.status_of(store, mid) == MessageStatus.ERROR.value
    assert await contract.children(fetch) == []


async def test_an_erased_token_holds_no_streaming_attachment(store: MessageStore) -> None:
    """The attachment read shares ``_REPLAYABLE_BODY``, so a token that cannot be replayed must stop
    pinning the document in the same purge. The retained control keeps its linkage."""
    fetch = _fetch(store)

    async def token_holding(ref: str, *, now: float) -> str:
        mid = await store.enqueue_ingress(
            channel_id="IB_REAL", raw=contract.RAW, attachment_refs=[ref], now=now
        )
        item = await store.claim_next_fifo("IB_REAL", stage=Stage.INGRESS.value, now=now)
        assert item is not None
        await store.handoff(
            ingress_id=item.id,
            message_id=mid,
            channel_id="IB_REAL",
            deliveries=[("OB_X", contract.BODY)],
            disposition=MessageStatus.ROUTED,
            now=now,
        )
        await contract.kill_reply(store, now=now)
        return mid

    old = await store.put_attachment(["JVBERi0xLjQ=synthetic-old"], "application/pdf")
    new = await store.put_attachment(["JVBERi0xLjQ=synthetic-new"], "application/pdf")
    erased = await token_holding(old, now=0.0)
    kept = await token_holding(new, now=100 * _DAY)

    await store.purge_message_bodies(older_than=10 * _DAY, now=50 * _DAY)

    joins = "SELECT attachment_id FROM message_attachment WHERE message_id=?"
    assert await fetch(joins, (erased,)) == []
    assert len(await fetch(joins, (kept,))) == 1


# --- structural gate, every leg ------------------------------------------------------------------


_BACKENDS = ("store.py", "postgres.py", "sqlserver.py")


@pytest.mark.parametrize("module", _BACKENDS)
def test_every_backend_blanks_the_token_before_it_erases_the_reply(module: str) -> None:
    """The behaviour above needs a live server on two backends and a skipped suite reads as green, so
    the order the fix depends on is read off the source on every leg: the token's blank comes before
    the attachment release, and the artifact's erasure does not come before the blank."""
    source = (_STORE_DIR / module).read_text(encoding="utf-8")
    text = ast.get_source_segment(source, named_func(parse_source(source), "purge_message_bodies"))
    assert text is not None
    # Not the done/cancelled statement, which clears `last_error` in the same SET.
    statement = re.search(r"UPDATE queue SET payload=''(?!,)", text)
    assert statement is not None
    attachments = text.index("_release_message_attachments")
    erase = text.index("UPDATE response SET body=NULL")
    assert statement.start() < attachments and statement.start() < erase
    binds = text[statement.start() : attachments]
    assert "Stage.RESPONSE.value" in binds and "OutboxStatus.DEAD.value" in binds


def test_postgres_blanks_the_token_and_erases_the_reply_from_one_eligible_read() -> None:
    """Under READ COMMITTED each Postgres statement re-reads the eligible set, so the blank and the
    erase must be one statement over one CTE, or a commit between them splits the set. SQL Server
    reads its ``#eligible`` table, materialized once; SQLite holds the writer lock for the whole
    pass. A behavioural test would need a second connection committing between two statements, which
    one statement no longer has, so the shape is pinned here instead."""
    fn = named_func(
        parse_source((_STORE_DIR / "postgres.py").read_text(encoding="utf-8")),
        "purge_message_bodies",
    )
    texts = [
        ast.unparse(node.args[0])
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.JoinedStr)
    ]
    [statement] = [t for t in texts if "UPDATE response SET body=NULL" in t]
    assert "WITH elig AS ({eligible})" in statement  # the one read of the eligible set
    assert statement.count("{eligible}") == 1
    assert "UPDATE queue SET payload=''" in statement
    assert statement.count("message_id IN (SELECT id FROM elig)") == 2


@pytest.mark.parametrize("module", _BACKENDS)
def test_every_backend_blanks_only_the_erased_token_and_keeps_a_missing_rows(module: str) -> None:
    """``ingress_handoff`` on each backend names the erased error and blanks that token with it. A
    token whose row is missing is dead-lettered without the blank, so its reference stays."""
    tree = parse_source((_STORE_DIR / module).read_text(encoding="utf-8"))
    name = "ingress_handoff" if module == "postgres.py" else "_ingress_handoff_txn"
    fn = named_func(tree, name)
    assert "REINGRESS_ARTIFACT_ERASED" in code_names(fn)
    assert ", payload=''" in code_strings(fn)
    calls = [
        c for c in call_sites(fn, "_consume_dead") if "REINGRESS_ARTIFACT_ERASED" in ast.dump(c)
    ]
    assert len(calls) == 1
    assert [kw.arg for kw in calls[0].keywords] == ["erased"]
    # Only the erased branch blanks: a missing row is damage, and its reference is the evidence.
    blanking = [c for c in call_sites(fn, "_consume_dead") if c.keywords]
    assert blanking == calls


@pytest.mark.parametrize("module", _BACKENDS)
def test_every_backend_parses_the_whole_reference_inside_its_guard(module: str) -> None:
    """``response_body_for_work_row`` returns None for a malformed reference, so the sequence's
    ``int`` sits inside the same ``try`` as the split. Outside it, a bad sequence raised out of the
    worker's peek and blocked the loopback lane."""
    fn = named_func(
        parse_source((_STORE_DIR / module).read_text(encoding="utf-8")),
        "response_body_for_work_row",
    )
    guarded = {
        id(node)
        for t in ast.walk(fn)
        if isinstance(t, ast.Try)
        for stmt in t.body
        for node in ast.walk(stmt)
    }
    ints = [
        node
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "int"
    ]
    assert ints  # the control: the walk found the parse
    assert all(id(node) in guarded for node in ints)
