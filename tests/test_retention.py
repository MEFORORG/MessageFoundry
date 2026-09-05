# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Retention / purge enforcement (WP-12, PHI.md §8): body-purge keeps the message ROW while blanking
its PHI columns — ``metadata`` included, ASVS 14.2.7 — and never touches an in-flight or (for the
messages window) a dead body; dead-letters have their own window; WAL/VACUUM maintenance runs clean;
the RetentionRunner audits each working pass and alerts past max_db_mb. Time is injected throughout
for determinism."""

from __future__ import annotations

import gzip
import json
import logging
import os
import time

import pytest

from messagefoundry.config.settings import RetentionSettings
from messagefoundry.pipeline import retention as retention_mod
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.retention import RetentionRunner
from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.store.store import DbStatus

DAY = 86_400.0


@pytest.fixture
async def store(tmp_path):
    s = await MessageStore.open(tmp_path / "retention.db")
    yield s
    await s.close()


# --- helpers: drive a message to a terminal state -----------------------------


async def _delivered(
    store: MessageStore,
    *,
    now: float,
    raw: str = "MSH|^~\\&|raw-body",
    payload: str = "OUT|delivered-body",
    summary: str = "MRN001 DOE^JOHN",
    control: str = "CID-DONE",
) -> tuple[str, str]:
    """Enqueue → claim → mark_done, leaving the message fully terminal (one DONE outbound row)."""
    mid = await store.enqueue_message(
        channel_id="c1",
        raw=raw,
        deliveries=[("d1", payload)],
        control_id=control,
        message_type="ADT^A01",
        summary=summary,
        now=now,
    )
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=now)
    await store.mark_done(row["id"], now=now)
    return mid, row["id"]


async def _dead(
    store: MessageStore,
    *,
    now: float,
    raw: str = "MSH|^~\\&|raw-dead",
    payload: str = "OUT|dead-body",
    control: str = "CID-DEAD",
) -> tuple[str, str]:
    """Enqueue → claim → dead_letter_now, leaving one DEAD outbound row."""
    mid = await store.enqueue_message(
        channel_id="c1", raw=raw, deliveries=[("d1", payload)], control_id=control, now=now
    )
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=now)
    await store.dead_letter_now(row["id"], "permanent reject", now=now)
    return mid, row["id"]


async def _payload(store: MessageStore, outbox_id: str) -> str:
    cur = await store._db.execute("SELECT payload FROM queue WHERE id=?", (outbox_id,))
    return (await cur.fetchone())["payload"]


async def _set_meta(store: MessageStore, message_id: str, bag: dict[str, object]) -> None:
    """Attach a metadata bag the way ``transform_handoff`` does (encrypted, cell-AAD bound)."""
    from messagefoundry.store.crypto import cell_aad

    await store._db.execute(
        "UPDATE messages SET metadata=? WHERE id=?",
        (
            store._enc(json.dumps(bag), aad=cell_aad("messages", "metadata", message_id)),
            message_id,
        ),
    )
    await store._commit()


async def _raw_meta(store: MessageStore, message_id: str) -> str | None:
    """The metadata column as STORED (ciphertext or NULL) — not the decrypted view."""
    cur = await store._db.execute("SELECT metadata FROM messages WHERE id=?", (message_id,))
    row = await cur.fetchone()
    return None if row is None else row["metadata"]


# --- purge_message_bodies -----------------------------------------------------


async def test_purge_nulls_old_delivered_body_but_keeps_the_metadata_row(
    store: MessageStore,
) -> None:
    """The message ROW survives a purge (count-and-log); its PHI COLUMNS do not.

    Named for the row, not the column: as of ASVS 14.2.7 the ``metadata`` *column* is nulled by this
    same statement (see ``test_purge_nulls_metadata_with_the_body``). What is retained here is the
    disposition metadata — control id, message type, received-at — that backs the counts.
    """
    mid, outbox_id = await _delivered(store, now=0.0)

    purged = await store.purge_message_bodies(older_than=10 * DAY)

    assert purged == 1
    msg = await store.get_message(mid)
    assert msg is not None  # row kept — only the body was nulled
    assert msg["raw"] == ""  # PHI body purged
    assert msg["summary"] is None
    assert msg["error"] is None
    # Disposition metadata retained so counts/audit still reflect what arrived.
    assert msg["control_id"] == "CID-DONE"
    assert msg["message_type"] == "ADT^A01"
    assert msg["received_at"] == 0.0
    # The delivered (terminal) outbound payload is nulled too.
    assert await _payload(store, outbox_id) == ""


async def test_purge_nulls_metadata_with_the_body(store: MessageStore) -> None:
    """ASVS 14.2.7 — operator-attached PHI must not outlive the body it annotates."""
    mid, _ = await _delivered(store, now=0.0)
    await _set_meta(store, mid, {"user": {"mrn": "MRN001"}})
    assert await store.message_metadata_json(mid) is not None  # precondition

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1

    assert await _raw_meta(store, mid) is None  # NULL at rest, not ciphertext-of-empty
    assert await store.message_metadata_json(mid) is None  # and NULL on the read path


async def test_purge_sweeps_metadata_left_by_a_pre_upgrade_engine(store: MessageStore) -> None:
    """The upgrade case: a row purged BEFORE this feature has a blank body but live metadata.

    Guarded on ``raw <> '' OR metadata IS NOT NULL``, so the historical sweep happens on the first
    pass after upgrade — and is COUNTED, so it lands in the ``retention_purge`` audit row rather than
    destroying PHI with no evidence.
    """
    mid, _ = await _delivered(store, now=0.0)
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1  # the pre-upgrade purge
    # Re-attach metadata the way the old engine would have left it: body already blank.
    await _set_meta(store, mid, {"user": {"mrn": "MRN001"}})
    assert (await store.get_message(mid))["raw"] == ""

    purged = await store.purge_message_bodies(older_than=10 * DAY)

    assert purged == 1  # counted → audited, not a silent destruction
    assert await _raw_meta(store, mid) is None


async def test_purge_metadata_is_idempotent_after_the_sweep(store: MessageStore) -> None:
    """Once body AND metadata are blank the guard goes false — a third pass is a no-op."""
    mid, _ = await _delivered(store, now=0.0)
    await _set_meta(store, mid, {"user": {"mrn": "MRN001"}})
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await store.purge_message_bodies(older_than=10 * DAY) == 0


async def test_purge_skips_recent_messages(store: MessageStore) -> None:
    mid, _ = await _delivered(store, now=10 * DAY)
    # Cutoff (older_than) is before the message's received_at → not eligible.
    purged = await store.purge_message_bodies(older_than=9 * DAY)
    assert purged == 0
    assert (await store.get_message(mid))["raw"] == "MSH|^~\\&|raw-body"


async def test_purge_skips_pending_and_inflight_messages(store: MessageStore) -> None:
    a = await store.enqueue_message(
        channel_id="c1", raw="MSH|first", deliveries=[("d1", "p")], now=0.0
    )
    b = await store.enqueue_message(
        channel_id="c1", raw="MSH|second", deliveries=[("d1", "p")], now=0.0
    )
    await _set_meta(store, a, {"user": {"mrn": "INFLIGHT"}})
    await _set_meta(store, b, {"user": {"mrn": "PENDING"}})
    await store.claim_ready(1, now=0.0)  # claim just one → one INFLIGHT, one still PENDING

    purged = await store.purge_message_bodies(older_than=10 * DAY)

    assert purged == 0  # a body still in the pipeline must never be purged (at-least-once)
    assert (await store.get_message(a))["raw"] == "MSH|first"  # inflight — kept
    assert (await store.get_message(b))["raw"] == "MSH|second"  # pending — kept
    # The widened statement must not reach an in-flight row through its metadata arm either: the
    # `metadata IS NOT NULL` disjunct is OR-ed INSIDE the eligible-set guard, never around it.
    assert await store.message_metadata_json(a) is not None
    assert await store.message_metadata_json(b) is not None


async def test_purge_idempotent(store: MessageStore) -> None:
    await _delivered(store, now=0.0)
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await store.purge_message_bodies(older_than=10 * DAY) == 0  # nothing new


async def test_error_message_body_is_purged(store: MessageStore) -> None:
    from messagefoundry.store import MessageStatus

    eid = await store.record_received(
        channel_id="c1",
        raw="bad",
        status=MessageStatus.ERROR,
        error="parse: PID|MRN42 leak",
        now=0.0,
    )
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    msg = await store.get_message(eid)
    assert msg["raw"] == "" and msg["error"] is None  # the error column can embed PHI fragments


# --- the two windows are decoupled --------------------------------------------


async def test_messages_window_keeps_dead_payload_for_its_own_window(store: MessageStore) -> None:
    mid, dead_id = await _dead(store, now=0.0)

    # The message window nulls the inbound body but leaves the DEAD row's payload (replayable until
    # its own window) — and because replay re-queues the row's own payload, never messages.raw, this
    # can't break a later replay.
    await store.purge_message_bodies(older_than=10 * DAY)
    assert (await store.get_message(mid))["raw"] == ""
    assert await _payload(store, dead_id) == "OUT|dead-body"

    # The dead-letter window then nulls the dead payload, keeping the row + status.
    purged = await store.purge_dead_letters(older_than=10 * DAY)
    assert purged == 1
    assert await _payload(store, dead_id) == ""
    [row] = await store.outbox_for(mid)
    assert row["status"] == OutboxStatus.DEAD.value  # row + disposition kept


async def test_purge_dead_letters_respects_window_and_is_idempotent(store: MessageStore) -> None:
    _, dead_id = await _dead(store, now=5 * DAY)
    # Cutoff before it died → kept.
    assert await store.purge_dead_letters(older_than=1 * DAY) == 0
    assert await _payload(store, dead_id) == "OUT|dead-body"
    # Past the window → purged, then idempotent.
    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await store.purge_dead_letters(older_than=10 * DAY) == 0


# --- the dead-letter window reaches EVERY stage, not just outbound (#1188) ----
#
# A router raise dead-letters the INGRESS row and a handler raise dead-letters the ROUTED row
# (wiring_runner._apply_router_internal_error / _apply_transform_internal_error). Both rows carry the
# full raw body in `queue.payload`. They are `dead`, so they are neither pending nor inflight — which
# means purge_message_bodies finds the message ELIGIBLE and blanks `messages.raw`, and the message
# then reads as purged while a full raw PHI body survives in the queue row. Scoping the dead-letter
# purge to `stage='outbound'` left that body unreachable by any sweep (ASVS 14.2.7).
#
# Riding the dead-letter window is the symmetric answer, not a widening of convenience: `replay()`
# recovers "a dead-lettered ingress/routed row" by re-queueing it in place from its OWN payload, so
# such a row is replayable-until-purged in exactly the sense that justified giving dead outbound rows
# their own, later window.


async def _dead_ingress(
    store: MessageStore, *, now: float, raw: str = "MSH|^~\\&|raw-ingress-dead"
) -> tuple[str, str]:
    """Drive a message to a DEAD **ingress** row — the shape a router raise leaves behind."""
    from messagefoundry.store.store import Stage

    mid = await store.enqueue_ingress(channel_id="c1", raw=raw, control_id="CID-ING", now=now)
    item = await store.claim_next_fifo("c1", stage=Stage.INGRESS.value, now=now)
    assert item is not None
    await store.dead_letter_now(item.id, "router error: boom", now=now)
    return mid, item.id


async def _dead_routed(
    store: MessageStore, *, now: float, raw: str = "MSH|^~\\&|raw-routed-dead"
) -> tuple[str, str]:
    """Drive a message to a DEAD **routed** row — the shape a handler raise leaves behind."""
    from messagefoundry.store import MessageStatus
    from messagefoundry.store.store import Stage

    mid = await store.enqueue_ingress(channel_id="c1", raw=raw, control_id="CID-ROU", now=now)
    ingress = await store.claim_next_fifo("c1", stage=Stage.INGRESS.value, now=now)
    assert ingress is not None
    assert await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="c1",
        handlers=[("h1", raw)],
        disposition=MessageStatus.ROUTED,
        now=now,
    )
    item = await store.claim_next_fifo("c1", stage=Stage.ROUTED.value, now=now)
    assert item is not None
    await store.dead_letter_now(item.id, "handler error: boom", now=now)
    return mid, item.id


async def test_purge_dead_letters_reaches_a_dead_ingress_row(store: MessageStore) -> None:
    """A router-stage dead letter holds the whole raw body; it must ride the dead-letter window."""
    mid, ingress_id = await _dead_ingress(store, now=5 * DAY)
    assert await _payload(store, ingress_id) != ""  # precondition: the raw is in the queue row

    # The hazard this closes: the message window blanks `messages.raw`, so the message READS as
    # purged while the ingress row still holds the same body.
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (await store.get_message(mid))["raw"] == ""
    assert await _payload(store, ingress_id) != ""  # ...and the body is still here

    # Its own (later) window then blanks it, keeping the row + DEAD status (counts/disposition).
    assert await store.purge_dead_letters(older_than=1 * DAY) == 0  # window not yet elapsed
    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await _payload(store, ingress_id) == ""
    assert await store.purge_dead_letters(older_than=10 * DAY) == 0  # idempotent

    cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (ingress_id,))
    assert (await cur.fetchone())["status"] == OutboxStatus.DEAD.value


async def test_purge_dead_letters_reaches_a_dead_routed_row(store: MessageStore) -> None:
    """A transform-stage dead letter carries the raw the handler re-parses — same window."""
    _, routed_id = await _dead_routed(store, now=0.0)
    assert await _payload(store, routed_id) != ""

    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await _payload(store, routed_id) == ""
    assert await store.purge_dead_letters(older_than=10 * DAY) == 0

    cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (routed_id,))
    assert (await cur.fetchone())["status"] == OutboxStatus.DEAD.value


async def test_dead_ingress_row_does_not_pin_a_streaming_attachment_forever(
    store: MessageStore,
) -> None:
    """The same defect over-retained the DETACHED document, not only the queue body.

    ``_attachment_still_referenced_sql`` is already stage-agnostic: a ``dead`` row with a non-blank
    payload counts as a live holder whatever its stage. So an unreachable dead ingress row also kept
    the message's streaming attachment (a very large PHI document) alive with no sweep able to
    release it. Blanking the row on its own window makes the predicate go false and the decref fire."""
    ref = await store.put_attachment(["JVBERi0xLjQ=synthetic-report"], "application/pdf")
    mid = await store.enqueue_ingress(
        channel_id="c1",
        raw="MSH|^~\\&|raw-attached",
        control_id="CID-ATT",
        attachment_refs=[ref],
        now=0.0,
    )
    from messagefoundry.store.store import Stage

    item = await store.claim_next_fifo("c1", stage=Stage.INGRESS.value, now=0.0)
    assert item is not None
    await store.dead_letter_now(item.id, "router error: boom", now=0.0)

    # The message body purge cannot release it: the dead ingress row is still a live holder.
    await store.purge_message_bodies(older_than=10 * DAY)
    assert await _attachment_rows(store, mid) == 1

    # The dead-letter window blanks the row and releases the last holder in the same transaction.
    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await _attachment_rows(store, mid) == 0


async def _attachment_rows(store: MessageStore, message_id: str) -> int:
    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM message_attachment WHERE message_id=?", (message_id,)
    )
    return int((await cur.fetchone())["n"])


#: Stage predicates each backend's `purge_dead_letters` BODY may still carry, and why. The two body
#: statements (the payload blank and the attachment release) must be stage-agnostic on all three; the
#: ONE survivor is SQLite's store-once `body_ref` release, which is legitimately outbound-scoped
#: because `body_ref` is written only by `_insert_outbound_deliveries`.
_ALLOWED_STAGE_PREDICATES = {"sqlite": 1, "postgres": 0, "sqlserver": 0}


def test_no_backend_scopes_the_dead_letter_purge_to_one_stage() -> None:
    """The #1188 widening must hold on all THREE backends, and only one of them runs locally.

    The Postgres and SQL Server purges execute on hosted runners only, so a re-narrowing there would
    reach `main` unseen by anyone working on SQLite. This reads the shipped source instead: a stage
    predicate reappearing in a purge body reds here, on every runner, with no database.
    """
    import inspect

    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    backends = {
        "sqlite": MessageStore,
        "postgres": PostgresStore,
        "sqlserver": SqlServerStore,
    }
    for name, cls in backends.items():
        src = inspect.getsource(cls.purge_dead_letters)
        # Drop the docstring: it DISCUSSES the outbound stage at length, so counting the whole source
        # would measure the prose rather than the SQL.
        parts = src.split('"""')
        assert len(parts) >= 3, (
            f"{name}: purge_dead_letters lost its docstring; this parse is stale"
        )
        body = parts[2]
        found = body.count("stage=?") + body.count("stage=$1")
        assert found == _ALLOWED_STAGE_PREDICATES[name], (
            f"{name}: purge_dead_letters carries {found} stage predicate(s), expected "
            f"{_ALLOWED_STAGE_PREDICATES[name]}. Scoping this purge to one stage is the #1188 defect: "
            f"a dead ingress/routed row holds the full raw PHI body, its message still body-purges "
            f"(dead is neither pending nor inflight), and the body then survives with no sweep able to "
            f"reach it. If you added a legitimately outbound-only statement, raise the count here and "
            f"say why in the same commit."
        )


# --- purge_search_presets (ADR 0136 saved searches, ASVS 14.2.7 Tier 2) -------


async def _preset(store: MessageStore, name: str, *, now: float, owner: str = "alice") -> str:
    pid, _ = await store.upsert_search_preset(
        preset_id=f"p-{name}",
        owner_user_id=owner,
        name=name,
        criteria='{"content": "MRN001"}',  # a PHI-shaped needle — synthetic
        now=now,
    )
    return pid


async def _preset_names(store: MessageStore, owner: str = "alice") -> set[str]:
    return {r["name"] for r in await store.list_search_presets(owner)}


async def test_purge_search_presets_deletes_old_keeps_new(store: MessageStore) -> None:
    await _preset(store, "stale", now=0.0)
    await _preset(store, "fresh", now=40 * DAY)

    purged = await store.purge_search_presets(older_than=30 * DAY)

    assert purged == 1
    assert await _preset_names(store) == {"fresh"}


async def test_purge_search_presets_is_idempotent(store: MessageStore) -> None:
    await _preset(store, "stale", now=0.0)
    assert await store.purge_search_presets(older_than=30 * DAY) == 1
    assert await store.purge_search_presets(older_than=30 * DAY) == 0


async def test_purge_search_presets_keys_on_last_edited_or_used(store: MessageStore) -> None:
    """A re-save moves the window — `updated_at` is one half of the key the purge reads.

    #306 made the other half `last_used_at`; `test_purge_search_presets_keeps_a_read_but_unedited_preset`
    below covers the recall arm. A LIST is not a use (it never loads the criteria), so it must not move
    the window either — only the id-scoped recall does.
    """
    await _preset(store, "kept", now=0.0)
    await _preset(store, "kept", now=40 * DAY)  # same (owner, name) → re-save, id reused
    await _preset(store, "aged", now=0.0)
    await store.list_search_presets("alice")  # a list is not a use

    assert await store.purge_search_presets(older_than=30 * DAY) == 1

    assert await _preset_names(store) == {"kept"}


async def test_purge_search_presets_keeps_a_read_but_unedited_preset(store: MessageStore) -> None:
    """THE #306 BUG: a preset an operator RUNS but never re-saves must not age out.

    Before #306 the purge read `updated_at` alone, which only a save writes — so recalling this preset
    at day 40 left it purgeable and it was deleted. Now the recall stamps `last_used_at` and the purge
    keys on the LATER of the two.
    """
    await _preset(store, "daily-driver", now=0.0)  # saved once, never edited again
    await _preset(store, "abandoned", now=0.0)

    # Recall (not a list) at day 40 — this is what "used" means.
    got = await store.get_search_preset(
        preset_id="p-daily-driver", owner_user_id="alice", now=40 * DAY
    )
    assert got is not None

    assert await store.purge_search_presets(older_than=30 * DAY) == 1

    assert await _preset_names(store) == {"daily-driver"}


async def test_get_search_preset_stamps_last_used_at(store: MessageStore) -> None:
    """The recall is the only writer of `last_used_at`; the returned dict carries the PRE-stamp value."""
    await _preset(store, "p", now=0.0)

    async def _stamp() -> float | None:
        async with store._read() as db:
            cur = await db.execute("SELECT last_used_at FROM search_presets WHERE id='p-p'")
            row = await cur.fetchone()
        return None if row is None else row["last_used_at"]

    assert await _stamp() is None  # a fresh save leaves it unstamped

    first = await store.get_search_preset(preset_id="p-p", owner_user_id="alice", now=5 * DAY)
    assert first is not None and first["last_used_at"] is None  # pre-stamp snapshot
    assert await _stamp() == 5 * DAY

    second = await store.get_search_preset(preset_id="p-p", owner_user_id="alice", now=9 * DAY)
    assert second is not None and second["last_used_at"] == 5 * DAY  # the previous use
    assert await _stamp() == 9 * DAY  # every recall re-stamps

    # A miss (wrong owner) must not stamp anything.
    assert (
        await store.get_search_preset(preset_id="p-p", owner_user_id="mallory", now=99 * DAY)
        is None
    )
    assert await _stamp() == 9 * DAY


async def test_purge_search_presets_null_last_used_at_still_purges_on_updated_at(
    store: MessageStore,
) -> None:
    """Migration safety: a row written before the `last_used_at` column existed has NULL there.

    The null-safe greatest-of-two must fall back to `updated_at` — SQLite's 2-arg `max()` returns NULL
    if ANY argument is NULL, so without the COALESCE the whole predicate would go NULL and the row
    would be immortal. Simulated by NULLing the column directly (the migration's post-ALTER state).
    """
    await _preset(store, "legacy-stale", now=0.0)
    await _preset(store, "legacy-fresh", now=40 * DAY)
    async with store._lock:
        await store._db.execute("UPDATE search_presets SET last_used_at=NULL")
        await store._commit()

    assert await store.purge_search_presets(older_than=30 * DAY) == 1

    assert await _preset_names(store) == {"legacy-fresh"}


async def test_reopening_a_pre_306_db_migrates_last_used_at_in(tmp_path) -> None:
    """The upgrade path: a DB whose `search_presets` predates `last_used_at` gains it on the next open.

    Built by DROPping the column from a real store DB — the exact pre-#306 shape, since `_SCHEMA`'s
    `CREATE TABLE IF NOT EXISTS` will not re-shape an existing table. The surviving row keeps its
    `updated_at`, gets NULL for the new column, and stays purgeable on `updated_at` alone.
    """
    path = tmp_path / "pre306.db"
    s = await MessageStore.open(path)
    await _preset(s, "carried-over", now=0.0)
    await s.close()

    import aiosqlite

    async with aiosqlite.connect(path) as db:
        await db.execute("ALTER TABLE search_presets DROP COLUMN last_used_at")
        await db.commit()

    s = await MessageStore.open(path)  # the upgrade
    try:
        async with s._read() as db:
            cur = await db.execute("PRAGMA table_info(search_presets)")
            assert "last_used_at" in {r["name"] for r in await cur.fetchall()}
        got = await s.get_search_preset(preset_id="p-carried-over", owner_user_id="alice", now=1.0)
        assert got is not None  # the row survived the ALTER with its criteria intact
        # NULL last_used_at at purge time (undo the recall stamp above) still ages out on updated_at.
        async with s._lock:
            await s._db.execute("UPDATE search_presets SET last_used_at=NULL")
            await s._commit()
        assert await s.purge_search_presets(older_than=30 * DAY) == 1
    finally:
        await s.close()


async def test_purge_search_presets_is_owner_agnostic(store: MessageStore) -> None:
    """Retention is a global age sweep, not owner-scoped — unlike the operator's own DELETE."""
    await _preset(store, "a-stale", now=0.0, owner="alice")
    await _preset(store, "b-stale", now=0.0, owner="bob")

    assert await store.purge_search_presets(older_than=30 * DAY) == 2

    assert await _preset_names(store, "alice") == set()
    assert await _preset_names(store, "bob") == set()


# --- maintenance --------------------------------------------------------------


async def test_wal_checkpoint_and_vacuum_run_clean(store: MessageStore) -> None:
    await _delivered(store, now=0.0)
    await store.purge_message_bodies(older_than=10 * DAY)
    await store.wal_checkpoint()
    await store.vacuum()  # must not error (runs outside a txn) and must leave the DB usable
    cur = await store._db.execute("PRAGMA journal_mode")
    assert str((await cur.fetchone())[0]).lower() == "wal"
    ok, _ = await store.integrity_check()
    assert ok


# --- RetentionRunner ----------------------------------------------------------


class _RecordingSink:
    """An AlertSink that records storage_threshold calls (and ignores the delivery events)."""

    def __init__(self) -> None:
        self.storage: list[tuple[str, int, int]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:  # pragma: no cover - unused
        pass

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:  # noqa: E501  # pragma: no cover - unused
        pass

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        self.storage.append((path, size_bytes, limit_bytes))


async def test_run_once_purges_and_writes_one_audit_entry(store: MessageStore) -> None:
    await _delivered(store, now=0.0)
    runner = RetentionRunner(
        store, RetentionSettings(messages_days=1, dead_letter_days=1), clock=lambda: 10 * DAY
    )

    result = await runner.run_once()

    assert result.messages_purged == 1
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1
    detail = json.loads(audit[0]["detail"])
    assert detail["messages_purged"] == 1 and detail["messages_days"] == 1
    assert audit[0]["actor"] == "system"
    # No message content in the audit detail (no PHI) — only counts/cutoffs/sizes.
    assert "raw" not in audit[0]["detail"] and "DOE" not in audit[0]["detail"]


class _FollowerCoordinator:
    """A coordinator whose is_leader() is False — used to prove RetentionRunner no-ops on a follower."""

    node_id = "follower"

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def is_leader(self) -> bool:
        return False

    def reclaims_inflight(self) -> bool:
        return True

    def is_clustered(self) -> bool:
        return True

    async def config_version(self) -> int:
        return 0

    def config_version_cached(self) -> int:
        return 0

    async def bump_config_version(self) -> int:
        return 0


async def test_run_once_no_ops_on_follower(store: MessageStore) -> None:
    """Track B Step 4: retention is a leader-only WRITE singleton. On a follower (is_leader False)
    run_once returns an all-zero did-nothing pass and performs NO purge — so a delivered message that
    is past the window stays intact, and no audit row is written."""
    mid, outbox_id = await _delivered(store, now=0.0)
    runner = RetentionRunner(
        store,
        RetentionSettings(messages_days=1, dead_letter_days=1),
        clock=lambda: 10 * DAY,
        coordinator=_FollowerCoordinator(),
    )

    result = await runner.run_once()

    assert result.messages_purged == 0 and result.dead_purged == 0
    assert not result.did_work
    # Nothing purged: the raw body is still present, and no audit row was written.
    assert (await store.get_message(mid))["raw"] is not None
    assert [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"] == []


async def test_run_once_acts_as_leader_with_default_coordinator(store: MessageStore) -> None:
    """The default (no coordinator) is the NullCoordinator → always leader → purges exactly as before
    this gate existed (byte-identical to test_run_once_purges_and_writes_one_audit_entry)."""
    await _delivered(store, now=0.0)
    runner = RetentionRunner(store, RetentionSettings(messages_days=1), clock=lambda: 10 * DAY)
    result = await runner.run_once()
    assert result.messages_purged == 1


class _DemoteMidPurgeCoordinator(_FollowerCoordinator):
    """A coordinator that is leader for the FIRST ``is_leader()`` read (the top-of-pass gate) then NOT
    leader on subsequent reads — simulating leadership lost (a self-fence) BETWEEN the top gate and the
    L1 pre-purge re-check, so the pass must abandon the purge without touching any PHI body."""

    node_id = "demoting"

    def __init__(self) -> None:
        self._reads = 0

    def is_leader(self) -> bool:
        self._reads += 1
        return self._reads == 1  # leader only on the first (top-gate) read


async def test_run_once_demotion_mid_purge_leaves_bodies_intact(store: MessageStore) -> None:
    """L1 pre-purge re-check: if leadership is lost BETWEEN the top-of-pass gate and the purges, the pass
    returns a did-nothing result WITHOUT nulling any message body or writing an audit row — a demoted node
    must never purge PHI as a stale ex-leader (count-and-log: bodies stay for the new leader)."""
    mid, outbox_id = await _delivered(store, now=0.0)
    coord = _DemoteMidPurgeCoordinator()
    runner = RetentionRunner(
        store,
        RetentionSettings(messages_days=1, dead_letter_days=1),
        clock=lambda: 10 * DAY,
        coordinator=coord,
    )

    result = await runner.run_once()

    assert (
        coord._reads >= 2
    )  # the top gate passed (leader) then the pre-purge re-check saw the demotion
    assert not result.did_work
    assert result.messages_purged == 0 and result.dead_purged == 0
    # The PHI body + the delivered payload are untouched; no audit row written.
    msg = await store.get_message(mid)
    assert msg["raw"] == "MSH|^~\\&|raw-body"  # body intact, not nulled
    assert msg["summary"] is not None
    assert await _payload(store, outbox_id) == "OUT|delivered-body"  # payload intact
    assert [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"] == []


async def test_run_once_no_work_writes_no_audit(store: MessageStore) -> None:
    await _delivered(store, now=0.0)
    # Everything off → a pass does nothing and must not spam the audit log.
    runner = RetentionRunner(store, RetentionSettings(), clock=lambda: 10 * DAY)
    result = await runner.run_once()
    assert not result.did_work
    assert [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"] == []


async def test_max_db_mb_alert_fires(store: MessageStore, monkeypatch) -> None:
    big = DbStatus(
        path=store.path,
        size_bytes=5_000_000,
        disk_free_bytes=0,
        journal_mode="wal",
        messages=0,
        events=0,
        audit=0,
    )

    async def fake_status() -> DbStatus:
        return big

    monkeypatch.setattr(store, "db_status", fake_status)
    sink = _RecordingSink()
    runner = RetentionRunner(
        store, RetentionSettings(max_db_mb=1), alert_sink=sink, clock=lambda: 1000.0
    )

    result = await runner.run_once()

    assert result.over_limit
    assert sink.storage == [(store.path, 5_000_000, 1_000_000)]
    # over_limit counts as work → audited.
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1 and json.loads(audit[0]["detail"])["over_limit"] is True


async def test_run_once_vacuums_when_due(store: MessageStore) -> None:
    now = 1_000_000.0
    lt = time.localtime(now)
    at = f"{lt.tm_hour:02d}:{lt.tm_min:02d}"  # exactly now's local time → reached
    runner = RetentionRunner(store, RetentionSettings(vacuum_at=at), clock=lambda: now)

    result = await runner.run_once()
    assert result.vacuumed
    assert runner._last_vacuum_day == runner._day_key(now)
    # Same day → not due again.
    assert runner._vacuum_due(now) is False


def test_vacuum_due_disabled_when_unset(store: MessageStore) -> None:
    runner = RetentionRunner(store, RetentionSettings())
    assert runner._vacuum_due(1_000_000.0) is False


# --- between-phase duration cap (#121, ADR 0137) ------------------------------


async def test_run_once_cap_skips_phase_after_deadline(store: MessageStore, monkeypatch) -> None:
    """A pass that exceeds `max_pass_seconds` skips its next phase and does NOT advance that phase's
    last-run marker. Here the WAL-checkpoint runs (deadline not yet hit), then blows past the cap, so the
    DUE VACUUM is skipped: it never starts, `_last_vacuum_day` stays unadvanced (still due next pass), and
    the pass is marked `capped` + audited (metadata only)."""
    now = 1_000_000.0
    lt = time.localtime(now)
    at = f"{lt.tm_hour:02d}:{lt.tm_min:02d}"  # VACUUM is due at `now` (so only the cap can skip it)

    mono = {
        "t": 0.0
    }  # a controllable monotonic clock for the deadline (separate from the window clock)
    orig_wal = store.wal_checkpoint

    async def slow_wal() -> None:
        await orig_wal()
        mono["t"] = 100.0  # the WAL phase overruns the 5s cap

    monkeypatch.setattr(store, "wal_checkpoint", slow_wal)

    vacuum_calls = 0
    orig_vacuum = store.vacuum

    async def counting_vacuum() -> None:
        nonlocal vacuum_calls
        vacuum_calls += 1
        await orig_vacuum()

    monkeypatch.setattr(store, "vacuum", counting_vacuum)

    runner = RetentionRunner(
        store,
        RetentionSettings(max_pass_seconds=5, wal_checkpoint_seconds=1, vacuum_at=at),
        clock=lambda: now,
        monotonic=lambda: mono["t"],
    )
    result = await runner.run_once()

    assert result.wal_checkpointed is True  # ran before the deadline was hit
    assert runner._last_wal == now  # the phase that RAN advanced its marker
    assert result.capped is True  # the pass hit the cap after WAL
    assert result.vacuumed is False  # the DUE vacuum was skipped by the cap
    assert vacuum_calls == 0  # ...and never even started
    assert runner._last_vacuum_day is None  # a SKIPPED phase does NOT advance its last-run marker
    # A capped pass is audited so operators can see maintenance fell behind (metadata only — no PHI).
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1
    detail = json.loads(audit[0]["detail"])
    assert detail["capped"] is True and detail["max_pass_seconds"] == 5


async def test_run_once_cap_does_not_interrupt_running_vacuum(
    store: MessageStore, monkeypatch
) -> None:
    """A VACUUM in flight is NOT interrupted: the deadline is checked only BEFORE a phase starts. The pass
    crosses the cap DURING the vacuum, yet the vacuum still runs to completion and advances its marker;
    only the trailing size-check phase is skipped (so the pass is still marked `capped`)."""
    now = 1_000_000.0
    lt = time.localtime(now)
    at = f"{lt.tm_hour:02d}:{lt.tm_min:02d}"  # VACUUM is due at `now`

    mono = {"t": 0.0}
    orig_vacuum = store.vacuum

    async def slow_vacuum() -> None:
        # Already INSIDE the started VACUUM phase; the pass now overruns the cap. The vacuum must still
        # complete — a running VACUUM is never interrupted.
        mono["t"] = 100.0
        await orig_vacuum()

    monkeypatch.setattr(store, "vacuum", slow_vacuum)

    runner = RetentionRunner(
        store,
        RetentionSettings(max_pass_seconds=5, vacuum_at=at),
        clock=lambda: now,
        monotonic=lambda: mono["t"],
    )
    result = await runner.run_once()

    assert result.vacuumed is True  # completed — not interrupted mid-flight
    assert runner._last_vacuum_day == runner._day_key(now)  # the phase ran → its marker advanced
    assert result.capped is True  # the pass went over budget during the vacuum (size-check skipped)


async def test_run_once_cap_off_is_byte_identical(store: MessageStore) -> None:
    """`max_pass_seconds=0` (the default) disables the cap: nothing is ever skipped and `capped` stays
    False even if the monotonic clock races far ahead between phases."""
    now = 1_000_000.0
    lt = time.localtime(now)
    at = f"{lt.tm_hour:02d}:{lt.tm_min:02d}"
    runner = RetentionRunner(
        store,
        RetentionSettings(vacuum_at=at),  # max_pass_seconds defaults to 0 (off)
        clock=lambda: now,
        monotonic=lambda: 10_000.0,  # would trip any positive cap — but the cap is off
    )
    result = await runner.run_once()
    assert result.capped is False
    assert result.vacuumed is True
    assert runner._last_vacuum_day == runner._day_key(now)


def test_enabled_property(store: MessageStore) -> None:
    assert RetentionRunner(store, RetentionSettings()).enabled is False
    assert RetentionRunner(store, RetentionSettings(messages_days=1)).enabled is True
    assert RetentionRunner(store, RetentionSettings(max_db_mb=10)).enabled is True
    assert RetentionRunner(store, RetentionSettings(vacuum_at="03:30")).enabled is True
    # #120: app-log retention needs BOTH a window and a log_dir to enable the runner.
    assert RetentionRunner(store, RetentionSettings(app_log_days=7)).enabled is False
    assert RetentionRunner(store, RetentionSettings(app_log_days=7), log_dir="x").enabled is True
    assert RetentionRunner(store, RetentionSettings(app_log_days=0), log_dir="x").enabled is False
    # #119: the compression window alone (no delete window) must start the runner too — omit it from
    # the OR-chain and a compress-only deployment gets no task at all.
    assert RetentionRunner(store, RetentionSettings(app_log_compress_days=7)).enabled is False
    assert (
        RetentionRunner(store, RetentionSettings(app_log_compress_days=7), log_dir="x").enabled
        is True
    )
    # ASVS 14.2.7: `enabled` is a hand-maintained OR-chain — omit the preset window and a deployment
    # that configures ONLY it gets no runner at all, so the purge would silently never run.
    assert RetentionRunner(store, RetentionSettings(search_preset_days=1)).enabled is True


# --- application log-file retention (#120) ------------------------------------


async def test_app_log_retention_deletes_old_log_files_only(store: MessageStore, tmp_path) -> None:
    """The sweep deletes only ``.log``/``.txt`` files older than ``app_log_days`` (by mtime) from the
    configured ``log_dir``; the actively-written file, recent files, non-log files, and subdirectories
    are left alone. The pass is audited (metadata only — the window + count, never file content)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "engine-2026-07-01.log"
    old_txt = logs / "stderr-old.txt"
    fresh_log = logs / "engine.log"  # the currently-written file (recent mtime) → kept
    other = logs / "keep.db"  # not a .log/.txt → kept even though old
    (logs / "archive").mkdir()  # a subdirectory → never touched
    for p in (old_log, old_txt, fresh_log, other):
        p.write_text("x")
    old = now - 10 * DAY
    fresh = now - 1 * DAY
    os.utime(old_log, (old, old))
    os.utime(old_txt, (old, old))
    os.utime(other, (old, old))
    os.utime(fresh_log, (fresh, fresh))

    runner = RetentionRunner(
        store, RetentionSettings(app_log_days=7), clock=lambda: now, log_dir=str(logs)
    )
    result = await runner.run_once()

    assert result.app_logs_deleted == 2
    assert result.did_work
    assert not old_log.exists() and not old_txt.exists()
    assert fresh_log.exists() and other.exists() and (logs / "archive").is_dir()
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1
    detail = json.loads(audit[0]["detail"])
    assert detail["app_logs_deleted"] == 2 and detail["app_log_days"] == 7


async def test_app_log_retention_noop_without_window_or_dir(store: MessageStore, tmp_path) -> None:
    """No window (``app_log_days=0``) OR no ``log_dir`` → nothing is swept and no audit row is written
    (a deployment that doesn't use the feature is byte-identical)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    old = logs / "old.log"
    old.write_text("x")
    os.utime(old, (1 * DAY, 1 * DAY))
    now = 30 * DAY

    r1 = await RetentionRunner(
        store, RetentionSettings(app_log_days=7), clock=lambda: now
    ).run_once()
    assert r1.app_logs_deleted == 0 and not r1.did_work and old.exists()

    r2 = await RetentionRunner(
        store, RetentionSettings(app_log_days=0), clock=lambda: now, log_dir=str(logs)
    ).run_once()
    assert r2.app_logs_deleted == 0 and old.exists()


# --- application log-file compression (#119) ----------------------------------


async def test_app_log_compression_gzips_old_files_only(store: MessageStore, tmp_path) -> None:
    """The compressor gzips only ``.log``/``.txt`` files older than ``app_log_compress_days`` (by
    mtime), replacing each with a real gzip artifact that decompresses back to the original bytes.

    The currently-written file, recent files, non-log files and subdirectories are untouched; the
    archive inherits the source's mtime (so the `app_log_days` delete window keeps applying to it); the
    pass is audited with counts + bytes only, never a file name or any file content."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "engine-2026-07-01.log"
    old_txt = logs / "stderr-old.txt"
    fresh_log = logs / "engine.log"  # the currently-written file → kept uncompressed
    other = logs / "keep.db"  # not a .log/.txt → never compressed
    (logs / "archive").mkdir()  # a subdirectory → never touched
    # Bytes, not text: Windows would translate `\n` on write and the round-trip compare is exact.
    body = b"engine started\n" * 500  # compressible, so bytes_reclaimed is comfortably positive
    for p in (old_log, old_txt, fresh_log, other):
        p.write_bytes(body)
    old = now - 10 * DAY
    fresh = now - 1 * DAY
    for p in (old_log, old_txt, other):
        os.utime(p, (old, old))
    os.utime(fresh_log, (fresh, fresh))

    result = await RetentionRunner(
        store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
    ).run_once()

    assert result.app_logs_compressed == 2
    assert result.app_log_bytes_reclaimed > 0
    assert result.did_work
    # The originals are gone and each archive round-trips through the STDLIB gzip reader (an operator
    # must be able to `gzip -d` it) back to the exact original bytes.
    for src in (old_log, old_txt):
        assert not src.exists()
        gz = src.with_name(src.name + ".gz")
        assert gz.exists()
        assert gzip.decompress(gz.read_bytes()) == body
        # The archive inherits the source's mtime, so compressing does NOT reset the delete clock.
        assert gz.stat().st_mtime == pytest.approx(old, abs=2)
    # Untouched: the live file, the non-log file, the subdirectory. No staging file survives.
    assert fresh_log.exists() and fresh_log.read_bytes() == body
    assert other.exists() and not (logs / "keep.db.gz").exists()
    assert (logs / "archive").is_dir()
    assert not list(logs.glob("*.mftmp"))

    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1
    detail = json.loads(audit[0]["detail"])
    assert detail["app_logs_compressed"] == 2 and detail["app_log_compress_days"] == 7
    assert detail["app_log_bytes_reclaimed"] == result.app_log_bytes_reclaimed
    # Counts and sizes only — never a file name, never any file content.
    assert "engine started" not in audit[0]["detail"]
    assert "engine-2026-07-01" not in audit[0]["detail"]


async def test_app_log_compression_skips_when_free_space_is_short(
    store: MessageStore, tmp_path, monkeypatch, caplog
) -> None:
    """The free-space precheck: with no room for the source + its archive + margin, the file is SKIPPED
    and logged — never compressed. A maintenance pass must not be what fills the volume."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    old_log.write_text("payload\n" * 100)
    os.utime(old_log, (now - 10 * DAY, now - 10 * DAY))
    # Far below the `size + max(10%, 1 MiB)` bar for any file.
    monkeypatch.setattr(RetentionRunner, "_free_bytes", staticmethod(lambda path: 64))

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
        ).run_once()

    assert result.app_logs_compressed == 0 and result.app_log_bytes_reclaimed == 0
    assert not result.did_work  # a skipped-only pass isn't work; nothing to audit
    assert old_log.exists() and not (logs / "old.log.gz").exists()
    assert "free" in caplog.text and "old.log" in caplog.text


async def test_app_log_compression_leaves_original_when_validation_fails(
    store: MessageStore, tmp_path, monkeypatch, caplog
) -> None:
    """Integrity validation is what makes the delete safe: when the written archive does NOT decompress
    back to the original, the ORIGINAL IS KEPT, no archive is left standing in for it, the staging file
    is cleaned up, and the failure is logged.

    RULE: without the read-back-and-compare, a codec/disk fault would silently replace a log file with an
    unreadable archive — the one failure mode that loses data irrecoverably."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    old_log.write_text("the only copy\n" * 50)
    os.utime(old_log, (now - 10 * DAY, now - 10 * DAY))
    # A "compressor" whose output is not a valid gzip stream: the write succeeds, the read-back fails.
    monkeypatch.setattr(
        "messagefoundry.pipeline.retention.gzip_compress", lambda data, **kw: b"\x1f\x8bnot-gzip"
    )

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
        ).run_once()

    assert result.app_logs_compressed == 0
    assert old_log.exists() and old_log.read_text() == "the only copy\n" * 50
    assert not (logs / "old.log.gz").exists()  # no half-archive left claiming to be the log
    assert not list(logs.glob("*.mftmp"))  # the staging file was cleaned up
    assert "integrity validation" in caplog.text and "original kept" in caplog.text


async def test_app_log_compression_leaves_original_when_bytes_differ(
    store: MessageStore, tmp_path, monkeypatch, caplog
) -> None:
    """A *valid* gzip stream carrying the WRONG bytes must fail validation too — the check is a
    byte-for-byte compare, not merely "does it decompress"."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    old_log.write_text("real content\n" * 20)
    os.utime(old_log, (now - 10 * DAY, now - 10 * DAY))
    monkeypatch.setattr(
        "messagefoundry.pipeline.retention.gzip_compress",
        lambda data, **kw: gzip.compress(b"different content"),
    )

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
        ).run_once()

    assert result.app_logs_compressed == 0
    assert old_log.exists() and old_log.read_text() == "real content\n" * 20
    assert not (logs / "old.log.gz").exists()
    assert "integrity validation" in caplog.text


async def test_app_log_compression_leaves_a_file_that_would_not_shrink(
    store: MessageStore, tmp_path
) -> None:
    """A file whose archive would not be SMALLER than the source is left exactly as it is.

    RULE: NSSM's `service.err.log` is routinely 0 bytes and a gzip member still carries an 18-byte
    header/trailer, so the naive version replaces an empty log with a LARGER file and reports negative
    bytes reclaimed — a disk-saving maintenance pass that costs disk."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    empty = logs / "service.err.log"
    empty.write_bytes(b"")
    already = logs / "blob.log"  # incompressible: gzip of random bytes is larger than the source
    already.write_bytes(os.urandom(4096))
    for p in (empty, already):
        os.utime(p, (now - 10 * DAY, now - 10 * DAY))

    result = await RetentionRunner(
        store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
    ).run_once()

    assert result.app_logs_compressed == 0
    assert result.app_log_bytes_reclaimed == 0  # never negative
    assert empty.exists() and empty.read_bytes() == b""
    assert already.exists()
    assert not list(logs.glob("*.gz"))
    assert not list(logs.glob("*.mftmp"))


async def test_app_log_compression_never_clobbers_an_existing_archive(
    store: MessageStore, tmp_path
) -> None:
    """An existing ``<name>.gz`` (a prior pass, or a crash between the rename and the unlink) is left
    exactly as it is — the source is skipped rather than re-archived over the top of it."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    old_log.write_text("new bytes")
    existing = logs / "old.log.gz"
    existing.write_bytes(gzip.compress(b"the archive that was already there"))
    for p in (old_log, existing):
        os.utime(p, (now - 10 * DAY, now - 10 * DAY))

    result = await RetentionRunner(
        store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
    ).run_once()

    assert result.app_logs_compressed == 0
    assert old_log.exists()  # never deleted without a validated archive OF ITS OWN bytes
    assert gzip.decompress(existing.read_bytes()) == b"the archive that was already there"


async def test_app_log_compression_off_by_default_is_byte_identical(
    store: MessageStore, tmp_path
) -> None:
    """`app_log_compress_days = 0` (the default) compresses nothing, and — the subtle half — leaves the
    #120 delete sweep's eligible set exactly as it was: a `.gz` in the log directory is NOT swept.

    RULE: the sweep only extends to `*.log.gz`/`*.txt.gz` while compression is ON (those archives are
    this engine's own output). Sweeping them unconditionally would silently start deleting operator- or
    externally-produced `.gz` files on upgrade, with no config change."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    plain = logs / "old.log"
    archive = logs / "old-2026-06-01.log.gz"
    unrelated = logs / "bundle.gz"  # never an app-log archive, whatever the window
    for p in (plain, archive, unrelated):
        p.write_bytes(b"x")
        os.utime(p, (now - 10 * DAY, now - 10 * DAY))

    # Compression off: nothing compressed, and the sweep deletes ONLY the plain `.log`.
    result = await RetentionRunner(
        store, RetentionSettings(app_log_days=7), clock=lambda: now, log_dir=str(logs)
    ).run_once()
    assert result.app_logs_compressed == 0 and result.app_log_bytes_reclaimed == 0
    assert result.app_logs_deleted == 1
    assert not plain.exists() and archive.exists() and unrelated.exists()

    # Compression on: the same window now also ages out the archives this engine produces — so
    # compressing a log does not make it immortal — while a non-app-log `.gz` is still left alone.
    result = await RetentionRunner(
        store,
        RetentionSettings(app_log_days=7, app_log_compress_days=1),
        clock=lambda: now,
        log_dir=str(logs),
    ).run_once()
    assert result.app_logs_deleted == 1
    assert not archive.exists() and unrelated.exists()


async def test_app_log_compression_noop_without_window_or_dir(
    store: MessageStore, tmp_path
) -> None:
    """No window OR no ``log_dir`` → nothing is compressed and no audit row is written."""
    logs = tmp_path / "logs"
    logs.mkdir()
    old = logs / "old.log"
    old.write_text("x")
    os.utime(old, (1 * DAY, 1 * DAY))
    now = 30 * DAY

    r1 = await RetentionRunner(
        store, RetentionSettings(app_log_compress_days=7), clock=lambda: now
    ).run_once()
    assert r1.app_logs_compressed == 0 and not r1.did_work and old.exists()

    r2 = await RetentionRunner(
        store, RetentionSettings(app_log_compress_days=0), clock=lambda: now, log_dir=str(logs)
    ).run_once()
    assert r2.app_logs_compressed == 0 and old.exists()
    assert not (logs / "old.log.gz").exists()


async def test_app_log_compression_is_skipped_once_the_pass_cap_is_hit(
    store: MessageStore, tmp_path
) -> None:
    """#121: the compress phase sits behind the same between-phase deadline as its siblings — once the
    cap is hit it is skipped wholesale and re-runs next interval (the log file is simply still there)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    old_log.write_text("payload\n" * 100)
    os.utime(old_log, (now - 10 * DAY, now - 10 * DAY))
    mono = iter([0.0] + [99.0] * 50)  # first read = pass start, every later read is past the cap

    result = await RetentionRunner(
        store,
        RetentionSettings(app_log_compress_days=7, max_pass_seconds=5),
        clock=lambda: now,
        monotonic=lambda: next(mono),
        log_dir=str(logs),
    ).run_once()

    assert result.capped is True
    assert result.app_logs_compressed == 0
    assert old_log.exists() and not (logs / "old.log.gz").exists()


async def test_app_log_compression_keeps_the_source_when_the_artifact_at_dest_is_bad(
    store: MessageStore, tmp_path, monkeypatch, caplog
) -> None:
    """What authorizes deleting the log is a validation of the bytes **at ``dest``**, read back AFTER the
    rename — not a validation of the staging path before it.

    RULE: `validate(tmp)` → `replace(tmp, dest)` → `remove(source)` deletes the only copy of a log on the
    strength of a check against a *path*, not against the artifact the operator is left holding; anything
    that rewrites `tmp` in that window makes the delete unauthorized while it still reports SUCCESS. Here
    the staged check passes and the destination check fails — the log must survive."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    body = "the only copy\n" * 50
    old_log.write_text(body)
    os.utime(old_log, (now - 10 * DAY, now - 10 * DAY))

    real_verify = retention_mod._verify_archive

    def verify(path, original, *, name):
        # Passes for the staged file; the artifact that lands at `<name>.gz` does NOT validate.
        if path.endswith(".mftmp"):
            return real_verify(path, original, name=name)
        return False

    monkeypatch.setattr(retention_mod, "_verify_archive", verify)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
        ).run_once()

    assert result.app_logs_compressed == 0  # never reported to the operator as a success
    assert result.app_log_bytes_reclaimed == 0
    assert old_log.exists() and old_log.read_text() == body  # the only copy is still here
    assert "did not validate AFTER" in caplog.text
    assert not list(logs.glob("*.mftmp"))


async def test_app_log_compression_survives_a_racing_rewrite_of_the_staging_file(
    store: MessageStore, tmp_path, monkeypatch
) -> None:
    """A concurrent writer that rewrites the STAGED archive between its validation and the rename must
    never produce "source deleted + corrupt dest".

    RULE: concurrent compressors of one log directory are the DEFAULT deployment, not an exotic race —
    `discover_shard_specs` hands every shard the same `--service-config`, so `[logging].log_dir` and the
    compression window are identical in every shard process, each shard starts its own RetentionRunner,
    and `--shard` forbids `[cluster]` (every shard is its own leader under `NullCoordinator`)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    body = b"engine started\n" * 500
    old_log.write_bytes(body)
    os.utime(old_log, (now - 10 * DAY, now - 10 * DAY))

    real_replace = os.replace

    def racing_replace(src, dst, **kwargs):
        # The racer wins the window: the validated staging bytes are swapped for garbage an instant
        # before the rename carries "whatever is at that path" into place.
        if str(src).endswith(".mftmp"):
            with open(src, "wb") as fh:
                fh.write(b"\x1f\x8bcorrupt")
        return real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", racing_replace)

    result = await RetentionRunner(
        store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
    ).run_once()

    dest = logs / "old.log.gz"
    # THE invariant: the log is never traded for an artifact that does not round-trip back to it.
    assert old_log.exists() or gzip.decompress(dest.read_bytes()) == body
    assert old_log.exists() and old_log.read_bytes() == body
    assert result.app_logs_compressed == 0  # and it is not reported as compressed


async def test_app_log_compression_stages_through_an_unpredictable_exclusive_temp_file(
    store: MessageStore, tmp_path, monkeypatch
) -> None:
    """The archive is staged through a FRESHLY CREATED, randomly named file — never the predictable
    ``<source>.gz.mftmp``. A decoy parked at the old path is neither truncated nor renamed away.

    RULE: `open("<source>.gz.mftmp", "wb")` truncates whatever is already there and follows a symlink to
    it (CWE-59/CWE-377). With a name derived from the source, in a directory the service writes to, that
    is an arbitrary-file-overwrite and a targeted log-destruction primitive — and it collides by
    construction with the sibling shards compressing the very same directory."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    body = b"engine started\n" * 500
    old_log.write_bytes(body)
    os.utime(old_log, (now - 10 * DAY, now - 10 * DAY))
    decoy = logs / "old.log.gz.mftmp"  # exactly the old, predictable staging path
    decoy.write_bytes(b"do not clobber me")

    staged: list[str] = []
    real_replace = os.replace

    def recording_replace(src, dst, **kwargs):
        staged.append(str(src))
        return real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", recording_replace)

    result = await RetentionRunner(
        store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
    ).run_once()

    assert result.app_logs_compressed == 1  # the compression itself still works
    assert gzip.decompress((logs / "old.log.gz").read_bytes()) == body
    # The file at the predictable path was neither written through nor consumed by the rename.
    assert decoy.exists() and decoy.read_bytes() == b"do not clobber me"
    assert staged and staged[0] != str(decoy)
    # ...and it is still beside `dest` in the log directory, so the rename stays a same-filesystem atomic.
    assert os.path.dirname(staged[0]) == str(logs)
    assert os.path.basename(staged[0]).startswith("mfgz-")


async def test_app_log_compression_stops_mid_directory_at_the_pass_cap(
    store: MessageStore, tmp_path, monkeypatch, caplog
) -> None:
    """#121: the deadline is re-read PER FILE, so the phase compresses until the cap and leaves the rest
    of the directory for the next pass.

    RULE: checking the deadline only BEFORE the phase is dispatched makes `max_pass_seconds`
    unenforceable here — the phase is an unbounded loop over up-to-64 MiB files, so a single dispatch
    runs the entire directory however long that takes, straight past the cap."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    for n in ("a.log", "b.log", "c.log"):
        p = logs / n
        p.write_bytes(b"payload\n" * 500)
        os.utime(p, (now - 10 * DAY, now - 10 * DAY))

    mono = {"t": 0.0}
    real_compress_one = RetentionRunner._compress_one

    def one_then_overrun(self, source, dest, *, atime, mtime):
        out = real_compress_one(self, source, dest, atime=atime, mtime=mtime)
        mono["t"] = 99.0  # compressing that ONE file took the pass past its 5s cap
        return out

    monkeypatch.setattr(RetentionRunner, "_compress_one", one_then_overrun)

    with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store,
            RetentionSettings(app_log_compress_days=7, max_pass_seconds=5),
            clock=lambda: now,
            monotonic=lambda: mono["t"],
            log_dir=str(logs),
        ).run_once()

    assert result.capped is True
    assert result.app_logs_compressed == 1  # stopped mid-directory, not after all three
    assert len(list(logs.glob("*.log.gz"))) == 1
    assert len(list(logs.glob("*.log"))) == 2  # deferred, not dropped — next pass picks them up
    assert not list(logs.glob("*.mftmp"))
    assert "stopped at the pass cap" in caplog.text


# --- RetentionRunner drives the preset purge (ADR 0136, ASVS 14.2.7) ----------


async def test_runner_purges_presets_on_its_own_window(store: MessageStore) -> None:
    now = 100 * DAY
    await _preset(store, "stale", now=0.0)
    await _preset(store, "fresh", now=now)

    result = await RetentionRunner(
        store, RetentionSettings(search_preset_days=30), clock=lambda: now
    ).run_once()

    assert result.search_presets_purged == 1
    assert await _preset_names(store) == {"fresh"}


async def test_runner_keeps_presets_forever_by_default(store: MessageStore) -> None:
    """The upgrade guarantee: a body window set, a preset window UNSET → nothing is deleted.

    `search_preset_days` does NOT inherit `messages_days` (unlike connection events). A PHI instance
    always has a bounded body window, so inheritance would delete every preset not re-saved inside it
    on the first pass after upgrade — silently, with no config change and no recovery.
    """
    now = 100 * DAY
    await _preset(store, "ancient", now=0.0)
    await _delivered(store, now=0.0)

    result = await RetentionRunner(
        store, RetentionSettings(messages_days=1), clock=lambda: now
    ).run_once()

    assert result.messages_purged == 1  # the body window DID run
    assert result.search_presets_purged == 0  # ...and the preset window did not
    assert await _preset_names(store) == {"ancient"}


async def test_runner_audits_a_preset_only_pass(store: MessageStore) -> None:
    """A pass whose ONLY work is a preset purge must still write its audit row.

    `did_work` is a hand-maintained OR-chain; omit the new field and this purge becomes unauditable.
    """
    now = 100 * DAY
    await _preset(store, "stale", now=0.0)

    result = await RetentionRunner(
        store, RetentionSettings(search_preset_days=30), clock=lambda: now
    ).run_once()

    assert result.did_work is True
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1
    detail = json.loads(audit[0]["detail"])
    assert detail["search_presets_purged"] == 1 and detail["search_preset_days"] == 30
    # Counts only — a preset's criteria is a PHI-shaped needle and must never reach the audit.
    assert "MRN001" not in audit[0]["detail"] and "criteria" not in audit[0]["detail"]


# --- settings validation ------------------------------------------------------


def test_settings_validation() -> None:
    with pytest.raises(ValueError):
        RetentionSettings(vacuum_at="25:00")
    with pytest.raises(ValueError):
        RetentionSettings(messages_days=-1)
    with pytest.raises(ValueError):
        RetentionSettings(app_log_days=-1)
    with pytest.raises(ValueError):
        RetentionSettings(app_log_compress_days=-1)
    assert RetentionSettings().app_log_compress_days == 0  # #119 default off
    with pytest.raises(ValueError):
        RetentionSettings(search_preset_days=-1)
    with pytest.raises(ValueError):
        RetentionSettings(purge_interval_seconds=0)
    # #121: max_pass_seconds has its OWN non-negative float validator (0 = off, negative rejected).
    with pytest.raises(ValueError):
        RetentionSettings(max_pass_seconds=-1)
    assert RetentionSettings().max_pass_seconds == 0.0  # default off
    assert RetentionSettings(max_pass_seconds=14400).max_pass_seconds == 14400.0
    assert RetentionSettings(vacuum_at="3:30").vacuum_time() == (3, 30)
    assert RetentionSettings(vacuum_at="").vacuum_time() is None


# --- Engine wiring ------------------------------------------------------------


async def test_engine_starts_and_stops_retention_runner(tmp_path) -> None:
    engine = await Engine.create(
        tmp_path / "engine.db", retention_settings=RetentionSettings(messages_days=1)
    )
    await engine.start()
    try:
        assert engine._retention_runner is not None
        assert engine._retention_runner.enabled is True
    finally:
        await engine.stop()


async def test_engine_without_retention_settings_has_no_runner(tmp_path) -> None:
    engine = await Engine.create(tmp_path / "engine2.db")
    await engine.start()
    try:
        assert engine._retention_runner is None
    finally:
        await engine.stop()
