# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Retention / purge enforcement (WP-12, PHI.md §8): body-purge keeps the message ROW while blanking
its PHI columns — ``metadata`` included, ASVS 14.2.7 — and never touches an in-flight or (for the
messages window) a dead body; dead-letters have their own window; WAL/VACUUM maintenance runs clean;
the RetentionRunner audits each working pass and alerts past max_db_mb. Time is injected throughout
for determinism."""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import os
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import (
    EgressSettings,
    RetentionSettings,
    StoreBackend,
    StoreSettings,
)
from messagefoundry.config.wiring import (
    MLLP,
    File,
    Registry,
    build_inbound_connection,
    build_outbound_connection,
    load_config,
)
from messagefoundry.pipeline import retention as retention_mod
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.cluster import NullCoordinator
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.retention import RetentionRunner
from messagefoundry.store import MessageStore, OutboxStatus, open_store
from messagefoundry.store.store import DbStatus, DiskFreeStatus
from tests._log_absence import assert_capture_sees

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
    fetched_row = await cur.fetchone()
    assert fetched_row is not None
    return fetched_row["payload"]


async def _set_meta(store: MessageStore, message_id: str, bag: dict[str, object]) -> None:
    """Attach a metadata bag the way ``transform_handoff`` does (encrypted, cell-AAD bound)."""
    from messagefoundry.store.cell_tag import message_cell_aad

    cur = await store._db.execute("SELECT channel_id FROM messages WHERE id=?", (message_id,))
    row = await cur.fetchone()
    assert row is not None
    tag = message_cell_aad("metadata", message_id=message_id, channel_id=row[0])
    await store._db.execute(
        "UPDATE messages SET metadata=? WHERE id=?",
        (store._enc(json.dumps(bag), aad=tag), message_id),
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
    fetched = await store.get_message(mid)
    assert fetched is not None
    assert fetched["raw"] == ""

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
    fetched = await store.get_message(mid)
    assert fetched is not None
    assert fetched["raw"] == "MSH|^~\\&|raw-body"


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
    fetched = await store.get_message(a)
    assert fetched is not None
    assert fetched["raw"] == "MSH|first"  # inflight — kept
    fetched = await store.get_message(b)
    assert fetched is not None
    assert fetched["raw"] == "MSH|second"  # pending — kept
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
    assert msg is not None
    assert msg["raw"] == "" and msg["error"] is None  # the error column can embed PHI fragments


# --- the two windows are decoupled --------------------------------------------


async def test_messages_window_keeps_dead_payload_for_its_own_window(store: MessageStore) -> None:
    mid, dead_id = await _dead(store, now=0.0)

    # The message window nulls the inbound body but leaves the DEAD row's payload (replayable until
    # its own window) — and because replay re-queues the row's own payload, never messages.raw, this
    # can't break a later replay.
    await store.purge_message_bodies(older_than=10 * DAY)
    fetched = await store.get_message(mid)
    assert fetched is not None
    assert fetched["raw"] == ""
    assert await _payload(store, dead_id) == "OUT|dead-body"

    # The dead-letter window then nulls the dead payload, keeping the row + status.
    purged = await store.purge_dead_letters(older_than=10 * DAY)
    assert purged.bodies == 1
    assert await _payload(store, dead_id) == ""
    [row] = await store.outbox_for(mid)
    assert row["status"] == OutboxStatus.DEAD.value  # row + disposition kept


async def test_purge_dead_letters_respects_window_and_is_idempotent(store: MessageStore) -> None:
    _, dead_id = await _dead(store, now=5 * DAY)
    # Cutoff before it died → kept.
    assert (await store.purge_dead_letters(older_than=1 * DAY)).bodies == 0
    assert await _payload(store, dead_id) == "OUT|dead-body"
    # Past the window → purged, then idempotent.
    assert (await store.purge_dead_letters(older_than=10 * DAY)).bodies == 1
    assert (await store.purge_dead_letters(older_than=10 * DAY)).bodies == 0


async def _dead_with_only_an_error(store: MessageStore, *, now: float) -> str:
    """A dead row whose body is already blank and whose ``last_error`` still holds text."""
    _, dead_id = await _dead(store, now=now)
    await store._db.execute("UPDATE queue SET payload='' WHERE id=?", (dead_id,))
    await store._commit()
    return dead_id


async def _last_error(store: MessageStore, outbox_id: str) -> str | None:
    cur = await store._db.execute("SELECT last_error FROM queue WHERE id=?", (outbox_id,))
    row = await cur.fetchone()
    assert row is not None
    return row["last_error"]


async def test_purge_dead_letters_counts_a_cleared_error_apart_from_bodies(
    store: MessageStore,
) -> None:
    """BACKLOG #4996. A row already blank purges no body, so ``bodies`` leaves it out, and
    ``errors_cleared`` counts the error text it nulled. A body-blanked row is counted in both."""
    blank_id = await _dead_with_only_an_error(store, now=5 * DAY)
    _, full_id = await _dead(store, now=5 * DAY, control="CID-DEAD-2")
    assert await _last_error(store, blank_id) is not None  # the premise

    purge = await store.purge_dead_letters(older_than=10 * DAY)
    assert (purge.bodies, purge.errors_cleared) == (1, 2)
    assert await _last_error(store, blank_id) is None
    assert await _payload(store, full_id) == ""
    again = await store.purge_dead_letters(older_than=10 * DAY)
    assert (again.bodies, again.errors_cleared) == (0, 0)  # idempotent


async def test_a_pass_that_only_clears_dead_error_text_is_audited(store: MessageStore) -> None:
    """BACKLOG #4996. Error text may carry PHI, so a pass whose only change was nulling a dead row's
    ``last_error`` is work, and it writes its ``retention_purge`` row. Its body count stays 0, so
    the row does not claim a body was purged. The control: a second pass with nothing left writes
    no row."""
    dead_id = await _dead_with_only_an_error(store, now=0.0)
    runner = RetentionRunner(store, RetentionSettings(dead_letter_days=1), clock=lambda: 30 * DAY)

    result = await runner.run_once()
    assert (result.dead_purged, result.dead_errors_cleared) == (0, 1)
    assert result.did_work
    assert await _last_error(store, dead_id) is None
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1
    detail = json.loads(audit[0]["detail"])
    assert (detail["dead_purged"], detail["dead_errors_cleared"]) == (0, 1)

    assert not (await runner.run_once()).did_work
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1


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
    fetched = await store.get_message(mid)
    assert fetched is not None
    assert fetched["raw"] == ""
    assert await _payload(store, ingress_id) != ""  # ...and the body is still here

    # Its own (later) window then blanks it, keeping the row + DEAD status (counts/disposition).
    assert (
        await store.purge_dead_letters(older_than=1 * DAY)
    ).bodies == 0  # window not yet elapsed
    assert (await store.purge_dead_letters(older_than=10 * DAY)).bodies == 1
    assert await _payload(store, ingress_id) == ""
    assert (await store.purge_dead_letters(older_than=10 * DAY)).bodies == 0  # idempotent

    cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (ingress_id,))
    fetched_row = await cur.fetchone()
    assert fetched_row is not None
    assert fetched_row["status"] == OutboxStatus.DEAD.value


async def test_purge_dead_letters_reaches_a_dead_routed_row(store: MessageStore) -> None:
    """A transform-stage dead letter carries the raw the handler re-parses — same window."""
    _, routed_id = await _dead_routed(store, now=0.0)
    assert await _payload(store, routed_id) != ""

    assert (await store.purge_dead_letters(older_than=10 * DAY)).bodies == 1
    assert await _payload(store, routed_id) == ""
    assert (await store.purge_dead_letters(older_than=10 * DAY)).bodies == 0

    cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (routed_id,))
    fetched_row = await cur.fetchone()
    assert fetched_row is not None
    assert fetched_row["status"] == OutboxStatus.DEAD.value


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
    assert (await store.purge_dead_letters(older_than=10 * DAY)).bodies == 1
    assert await _attachment_rows(store, mid) == 0


async def _attachment_rows(store: MessageStore, message_id: str) -> int:
    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM message_attachment WHERE message_id=?", (message_id,)
    )
    fetched_row = await cur.fetchone()
    assert fetched_row is not None
    return int(fetched_row["n"])


#: Stage predicates each backend's `purge_dead_letters` BODY may still carry, and why. The body
#: statements (the payload blank, the `last_error` clear and the attachment release) must be
#: stage-agnostic on all three; the ONE survivor on each is the store-once `body_ref` release, which
#: is legitimately outbound-scoped because `body_ref` is written only by
#: `_insert_outbound_deliveries` (on the server backends only a restored row carries one, BACKLOG
#: #5740).
_ALLOWED_STAGE_PREDICATES = {"sqlite": 1, "postgres": 1, "sqlserver": 1}


def test_no_backend_scopes_the_dead_letter_purge_to_one_stage() -> None:
    """The #1188 widening must hold on all THREE backends, and only one of them runs locally.

    The Postgres and SQL Server purges execute on hosted runners only, so a re-narrowing there would
    reach `main` unseen by anyone working on SQLite. This reads the shipped source instead: a stage
    predicate reappearing in a purge body reds here, on every runner, with no database.
    """
    import inspect

    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    backends: dict[str, type[Any]] = {
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
    fetched_row = await cur.fetchone()
    assert fetched_row is not None
    assert str(fetched_row[0]).lower() == "wal"
    ok, _ = await store.integrity_check()
    assert ok


# --- purge residue (vault BACKLOG #2619) ----------------------------------------


def test_purge_residue_knobs_ship_on() -> None:
    assert StoreSettings().secure_delete is True
    assert RetentionSettings().wal_checkpoint_seconds == 3600.0


async def _secure_delete_reads(store: MessageStore) -> int:
    cur = await store._db.execute("PRAGMA secure_delete")
    row = await cur.fetchone()
    await cur.close()
    assert row is not None
    return int(row[0])


@pytest.mark.parametrize("secure_delete", [True, False])
async def test_a_purged_body_leaves_no_bytes_in_the_file(tmp_path, secure_delete: bool) -> None:
    """With ``secure_delete`` on, the bytes of a purged body are gone from the SQLite file. The
    ``False`` case is the control: the same purge leaves the body readable in free space, which
    proves the byte search below can see it."""
    db = tmp_path / f"residue_{secure_delete}.db"
    store = await MessageStore.open(db, secure_delete=secure_delete)
    try:
        assert await _secure_delete_reads(store) == int(secure_delete)
        marker = "RESIDUE-MARKER-2619"
        # Big enough to spill onto overflow pages, which a purge frees to the freelist.
        raw = "MSH|^~\\&|" + marker + "|" + "X" * 6000
        await _delivered(store, now=0.0, raw=raw, summary="S")
        await store.wal_checkpoint()  # the body is in the main file, as auto-checkpoint leaves it
        assert marker.encode() in db.read_bytes()
        assert await store.purge_message_bodies(older_than=10 * DAY) == 1
        await store.wal_checkpoint()
    finally:
        await store.close()
    assert (marker.encode() in db.read_bytes()) is (not secure_delete)


async def test_open_store_threads_the_secure_delete_setting(tmp_path) -> None:
    for flag in (True, False):
        settings = StoreSettings(path=str(tmp_path / f"o_{flag}.db"), secure_delete=flag)
        store = await open_store(settings, create=True, keyless_chain_refusal=None)
        try:
            assert isinstance(store, MessageStore)
            assert await _secure_delete_reads(store) == int(flag)
        finally:
            await store.close()


async def test_the_default_pass_truncates_the_wal_after_its_purge(store: MessageStore) -> None:
    """Stock ``[retention]`` truncates the ``-wal`` file after its purge, so frames that held a
    purged body do not stay on disk past the write point. The pass's own audit row is written after
    the truncate, so the file is not empty; what is checked is that the body is gone from it."""
    marker = b"WAL-MARKER-2619"
    await _delivered(store, now=0.0, raw="MSH|^~\\&|" + marker.decode() + "|" + "Y" * 6000)
    wal = f"{store.path}-wal"
    with open(wal, "rb") as fh:
        assert marker in fh.read()  # the control: the search can see the body in the WAL
    runner = RetentionRunner(store, RetentionSettings(messages_days=1), clock=lambda: 30 * DAY)
    result = await runner.run_once()
    assert result.messages_purged == 1
    assert result.wal_checkpointed is True
    with open(wal, "rb") as fh:
        assert marker not in fh.read()
    with open(str(store.path), "rb") as fh:
        assert marker not in fh.read()


async def test_wal_checkpoint_says_so_when_a_reader_pins_the_wal(store: MessageStore) -> None:
    """A read transaction that started on WAL frames makes TRUNCATE give up after the busy timeout,
    and the store now says so (vault BACKLOG #2619). The control is the same call once the reader
    is gone, which finishes. The busy timeout is cut to keep the test fast; the outcome is SQLite's
    busy flag either way."""
    await _delivered(store, now=0.0)
    cur = await store._db.execute("PRAGMA busy_timeout=50")
    await cur.close()
    reader = sqlite3.connect(str(store.path))
    try:
        reader.execute("BEGIN")
        reader.execute("SELECT count(*) FROM messages").fetchone()
        assert await store.wal_checkpoint() is False
    finally:
        reader.close()
    assert await store.wal_checkpoint() is True
    assert os.path.getsize(f"{store.path}-wal") == 0


async def test_a_pass_whose_truncate_did_not_finish_warns_and_records_it(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The pass used to say nothing when its truncate gave up. Now it logs a WARNING that names the
    file and not the content, and the pass result records it. The control is the same pass with a
    truncate that finishes: no warning, nothing recorded."""
    marker = "UNTRUNCATED-MARKER-2619"
    await _delivered(store, now=0.0, raw="MSH|^~\\&|" + marker, summary=marker)

    async def busy() -> bool:
        return False

    settings = RetentionSettings(messages_days=1, wal_checkpoint_seconds=1)
    caplog.set_level(logging.WARNING, logger=retention_mod.__name__)
    clean = await RetentionRunner(store, settings, clock=lambda: 30 * DAY).run_once()
    assert clean.wal_checkpointed is True
    assert clean.wal_left_untruncated is False
    assert_capture_sees(caplog, retention_mod.__name__)
    assert not [r for r in caplog.records if "WAL truncate" in r.getMessage()]

    monkeypatch.setattr(store, "wal_checkpoint", busy)
    # A second purgeable message, so the second pass is audited too.
    await _delivered(store, now=DAY, raw="MSH|^~\\&|" + marker, summary=marker, control="CID-2")
    result = await RetentionRunner(store, settings, clock=lambda: 31 * DAY).run_once()
    assert result.wal_checkpointed is True
    assert result.wal_left_untruncated is True
    warned = [r for r in caplog.records if "WAL truncate did not finish" in r.getMessage()]
    assert len(warned) == 1
    assert warned[0].levelno == logging.WARNING
    assert f"{os.path.abspath(store.path)}-wal" in warned[0].getMessage()
    assert marker not in caplog.text
    # Each pass purged, so each wrote an audit row, and the row says whether the WAL kept the frames.
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    left = sorted(json.loads(r["detail"])["wal_left_untruncated"] for r in audit)
    assert left == [False, True]


async def test_a_purge_pass_with_no_truncate_records_null_not_false(store: MessageStore) -> None:
    """A pass that ran no truncate must not record ``false``, which would read as "truncated"."""
    await _delivered(store, now=0.0)
    settings = RetentionSettings(messages_days=1, wal_checkpoint_seconds=0)
    result = await RetentionRunner(store, settings, clock=lambda: 30 * DAY).run_once()
    assert result.messages_purged == 1 and result.wal_checkpointed is False
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert [json.loads(r["detail"])["wal_left_untruncated"] for r in audit] == [None]


async def test_wal_cadence_survives_a_backward_wall_clock_step(store: MessageStore) -> None:
    """BACKLOG #6526: the wall clock steps back a day after the first truncate, then both clocks
    run forward a full cadence, and the third pass still truncates. Only the step makes the wall
    clock read the cadence as unelapsed, so this fails on a wall-clock cadence for that reason
    alone. The control is the second pass, one second short of the cadence, which does not."""
    wall = {"t": 30 * DAY}
    mono = {"t": 500.0}
    runner = RetentionRunner(
        store,
        RetentionSettings(wal_checkpoint_seconds=3600),
        clock=lambda: wall["t"],
        monotonic=lambda: mono["t"],
    )
    assert (await runner.run_once()).wal_checkpointed is True  # never run yet, so due at once
    wall["t"] -= DAY
    wall["t"] += 3599.0
    mono["t"] += 3599.0
    assert (await runner.run_once()).wal_checkpointed is False  # the control: not yet due
    wall["t"] += 1.0
    mono["t"] += 1.0
    assert (await runner.run_once()).wal_checkpointed is True


async def test_wal_cadence_ignores_an_explicit_now(store: MessageStore) -> None:
    """``run_once(now=...)`` sets the retention windows, not the WAL cadence: two passes at the same
    monotonic instant truncate once, whatever ``now`` each is handed."""
    runner = RetentionRunner(
        store, RetentionSettings(wal_checkpoint_seconds=3600), monotonic=lambda: 10.0
    )
    assert (await runner.run_once(now=30 * DAY)).wal_checkpointed is True
    assert (await runner.run_once(now=40 * DAY)).wal_checkpointed is False


async def test_a_capped_pass_leaves_the_wal_marker_unadvanced(store: MessageStore) -> None:
    """A WAL truncate the #121 cap skips keeps the marker its last truncate set, so it stays due.
    Pass 1 truncates at monotonic 0. Pass 2 is past the cadence but capped before the WAL phase,
    and the marker stays 0. Pass 3 is uncapped and truncates, which it could not do had the skip
    moved the marker to pass 2's reading."""
    clock = {"start": 0.0, "later": 0.0, "first": True}

    def mono() -> float:
        # The pass reads `start` once as its start time; every later read is `later`.
        if clock["first"]:
            clock["first"] = False
            return float(clock["start"])
        return float(clock["later"])

    runner = RetentionRunner(
        store,
        RetentionSettings(max_pass_seconds=1, wal_checkpoint_seconds=3600),
        monotonic=mono,
    )
    assert (await runner.run_once()).wal_checkpointed is True
    assert runner._last_wal == 0.0
    clock.update(start=5000.0, later=1e9, first=True)
    result = await runner.run_once()
    assert result.capped is True and result.wal_checkpointed is False
    assert runner._last_wal == 0.0
    clock.update(start=9000.0, later=9000.0, first=True)
    result = await runner.run_once()
    assert result.capped is False and result.wal_checkpointed is True


# --- RetentionRunner ----------------------------------------------------------


class _RecordingSink(LoggingAlertSink):
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


class _FollowerCoordinator(NullCoordinator):
    """A coordinator whose is_leader() is False — used to prove RetentionRunner no-ops on a follower."""

    def __init__(self) -> None:
        super().__init__("follower")

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

    async def bump_config_version(self, *, digest: str | None) -> int:
        return 0


async def test_run_once_no_ops_on_follower(store: MessageStore) -> None:
    """Track B Step 4: retention's store phases are a leader-only WRITE singleton. On a follower
    (is_leader False) run_once performs NO purge — so a delivered message that is past the window
    stays intact — and, with no app-log phase configured, writes no audit row (BACKLOG #6526)."""
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
    fetched = await store.get_message(mid)
    assert fetched is not None
    assert fetched["raw"] == "MSH|^~\\&|raw-body"
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
    leadership read before the first purge phase (`_halt`, BACKLOG #6526), so the pass must abandon the
    purge without touching any PHI body."""

    node_id = "demoting"

    def __init__(self) -> None:
        self._reads = 0

    def is_leader(self) -> bool:
        self._reads += 1
        return self._reads == 1  # leader only on the first (top-gate) read


async def test_run_once_demotion_mid_purge_leaves_bodies_intact(store: MessageStore) -> None:
    """The read before the first purge phase: if leadership is lost BETWEEN the top-of-pass gate and the
    purges, the pass
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
    )  # the top gate passed (leader) then the read before the first purge phase saw the demotion
    assert not result.did_work
    assert result.messages_purged == 0 and result.dead_purged == 0
    # The PHI body + the delivered payload are untouched; no audit row written.
    msg = await store.get_message(mid)
    assert msg is not None
    assert msg["raw"] == "MSH|^~\\&|raw-body"  # body intact, not nulled
    assert msg["summary"] is not None
    assert await _payload(store, outbox_id) == "OUT|delivered-body"  # payload intact
    assert [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"] == []


async def _retention_audit_details(store: MessageStore) -> list[dict[str, Any]]:
    return [json.loads(r["detail"]) for r in await store.list_audit(action="retention_purge")]


async def test_a_pass_that_fails_after_a_purge_still_audits_the_purge(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #6526, S07-44: each purge phase commits on its own, so a later phase that raises must
    not leave the earlier, already-committed body purge with no ``retention_purge`` row. The pass
    still raises, and its row records the phases that finished and that it was interrupted."""
    await _delivered(store, now=0.0)

    async def state_purge_fails(*_a: object, **_k: object) -> int:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store, "purge_state", state_purge_fails)
    runner = RetentionRunner(
        store, RetentionSettings(messages_days=1, state_max_age_days=1), clock=lambda: 10 * DAY
    )

    with pytest.raises(sqlite3.OperationalError):
        await runner.run_once()

    details = await _retention_audit_details(store)
    assert [d["messages_purged"] for d in details] == [1]
    assert details[0]["interrupted"] is True


async def test_a_pass_stopped_after_a_purge_still_audits_the_purge(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #6526, S07-44: ``stop()`` cancels a running pass at once. A pass cancelled after its
    body purge committed writes the ``retention_purge`` row for that purge before it ends."""
    await _delivered(store, now=0.0)
    entered = asyncio.Event()

    async def state_purge_hangs(*_a: object, **_k: object) -> int:
        entered.set()
        await asyncio.Event().wait()
        return 0

    monkeypatch.setattr(store, "purge_state", state_purge_hangs)
    runner = RetentionRunner(
        store, RetentionSettings(messages_days=1, state_max_age_days=1), clock=lambda: 10 * DAY
    )
    runner.start()
    try:
        await asyncio.wait_for(entered.wait(), 10)
    finally:
        await runner.stop()

    details = await _retention_audit_details(store)
    assert [d["messages_purged"] for d in details] == [1]
    assert details[0]["interrupted"] is True


class _SwitchableCoordinator(_FollowerCoordinator):
    """A coordinator whose leadership a test flips between phases of one pass."""

    node_id = "switchable"

    def __init__(self) -> None:
        self.leader = True

    def is_leader(self) -> bool:
        return self.leader


async def test_leadership_lost_between_phases_stops_the_later_purges(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #6526, S07-45: every purge phase awaits the store, and leadership can be lost during
    any of those awaits. A node demoted after its body purge must not go on to purge dead letters as
    a stale ex-leader. The purge it already committed is still audited, and the row says why the
    pass stopped."""
    await _delivered(store, now=0.0)
    _dead_mid, dead_row = await _dead(store, now=0.0)
    coord = _SwitchableCoordinator()
    real_purge = store.purge_message_bodies

    async def purge_then_demote(*a: Any, **k: Any) -> int:
        purged = await real_purge(*a, **k)
        coord.leader = False
        return purged

    monkeypatch.setattr(store, "purge_message_bodies", purge_then_demote)
    runner = RetentionRunner(
        store,
        RetentionSettings(messages_days=1, dead_letter_days=1),
        clock=lambda: 10 * DAY,
        coordinator=coord,
    )

    result = await runner.run_once()

    # The dead letter stays for the new leader.
    assert await _payload(store, dead_row) == "OUT|dead-body"
    # Both message rows were past the body window; the dead row's payload is the dead-letter phase's.
    assert result.messages_purged == 2 and result.dead_purged == 0
    assert result.leadership_lost
    details = await _retention_audit_details(store)
    assert [d["messages_purged"] for d in details] == [2]
    assert details[0]["leadership_lost"] is True


async def test_a_standby_sweeps_and_compresses_its_own_app_logs(
    store: MessageStore, tmp_path: Path
) -> None:
    """BACKLOG #6526, S07-46: ``[logging].log_dir`` is each host's own directory, so a standby must
    age out and compress its own application logs. It still purges nothing in the shared store: the
    old message body stays for the leader. The deletion is audited like the leader's."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    to_delete = logs / "engine-old.log"
    to_compress = logs / "engine-recent.log"
    body = b"engine started\n" * 500
    for p, age in ((to_delete, 10 * DAY), (to_compress, 5 * DAY)):
        p.write_bytes(body)
        os.utime(p, (now - age, now - age))
    mid, _ = await _delivered(store, now=0.0)
    runner = RetentionRunner(
        store,
        RetentionSettings(messages_days=1, app_log_days=7, app_log_compress_days=3),
        clock=lambda: now,
        coordinator=_FollowerCoordinator(),
        log_dir=str(logs),
    )

    result = await runner.run_once()

    assert not to_delete.exists()
    assert not to_compress.exists()
    assert gzip.decompress((logs / "engine-recent.log.gz").read_bytes()) == body
    assert result.app_logs_deleted == 1 and result.app_logs_compressed == 1
    assert result.standby and result.messages_purged == 0
    msg = await store.get_message(mid)
    assert msg is not None and msg["raw"] == "MSH|^~\\&|raw-body"
    details = await _retention_audit_details(store)
    assert len(details) == 1
    assert details[0]["standby"] is True and details[0]["app_logs_deleted"] == 1
    assert details[0]["messages_purged"] == 0


async def test_a_standby_pass_that_fails_after_its_sweep_still_audits_the_sweep(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #6526, S07-44 on a standby: the sweep's deletions are counted as soon as the sweep
    ends, so compression failing after it still leaves a row recording them."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old = logs / "engine-old.log"
    old.write_text("x")
    os.utime(old, (now - 10 * DAY, now - 10 * DAY))
    runner = RetentionRunner(
        store,
        RetentionSettings(app_log_days=7, app_log_compress_days=3),
        clock=lambda: now,
        coordinator=_FollowerCoordinator(),
        log_dir=str(logs),
    )

    def compress_fails(*_a: object) -> tuple[int, int]:
        raise OSError("volume went away")

    monkeypatch.setattr(runner, "_compress_app_logs", compress_fails)

    with pytest.raises(OSError, match="volume went away"):
        await runner.run_once()

    assert not old.exists()
    details = await _retention_audit_details(store)
    assert [d["app_logs_deleted"] for d in details] == [1]
    assert details[0]["interrupted"] is True and details[0]["standby"] is True


async def test_a_pass_stopped_while_writing_its_audit_row_still_writes_it(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #6526, S07-44: a ``stop()`` that lands while the pass's own audit row is being
    written cancels only the wait for the row, not the write."""
    await _delivered(store, now=0.0)
    entered = asyncio.Event()
    release = asyncio.Event()
    real_record = store.record_audit

    async def slow_record(*a: Any, **k: Any) -> Any:
        entered.set()
        await release.wait()
        return await real_record(*a, **k)

    monkeypatch.setattr(store, "record_audit", slow_record)
    runner = RetentionRunner(store, RetentionSettings(messages_days=1), clock=lambda: 10 * DAY)
    runner.start()
    try:
        await asyncio.wait_for(entered.wait(), 10)
        stopping = asyncio.create_task(runner.stop())
        await asyncio.sleep(0)
        release.set()
        await asyncio.wait_for(stopping, 10)  # stop() waits for the row still being written
    finally:
        release.set()
        await runner.stop()

    assert [d["messages_purged"] for d in await _retention_audit_details(store)] == [1]


async def test_a_pass_stopped_inside_a_purge_names_the_phase(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #6526, S07-44: a purge cancelled while its COMMIT is in flight may have committed,
    and its count is lost with the call. The pass writes its row even with nothing else done,
    naming the phase it ended in."""
    await _delivered(store, now=0.0)
    entered = asyncio.Event()

    async def purge_hangs(*_a: object, **_k: object) -> int:
        entered.set()
        await asyncio.Event().wait()
        return 0

    monkeypatch.setattr(store, "purge_message_bodies", purge_hangs)
    runner = RetentionRunner(store, RetentionSettings(messages_days=1), clock=lambda: 10 * DAY)
    runner.start()
    try:
        await asyncio.wait_for(entered.wait(), 10)
    finally:
        await runner.stop()

    details = await _retention_audit_details(store)
    assert [d["interrupted_phase"] for d in details] == ["messages"]
    assert details[0]["interrupted"] is True and details[0]["messages_purged"] == 0


async def test_a_strip_that_raises_partway_is_audited_with_its_phase(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #6526, S07-44: the embedded-document strip commits batch by batch, so one that
    raises may have stripped documents its count never reports. The pass writes its row even with
    nothing else done, naming the phase it ended in."""
    runner = RetentionRunner(store, RetentionSettings(), clock=lambda: 10 * DAY)
    monkeypatch.setattr(runner, "_resolve_document_prune", lambda: ({"c1": 1}, {"c1": 1024}, {}))

    async def strip_fails(*_a: object, **_k: object) -> object:
        raise RuntimeError("cipher ceiling reached")

    monkeypatch.setattr(store, "strip_embedded_documents", strip_fails)

    with pytest.raises(RuntimeError, match="cipher ceiling reached"):
        await runner.run_once()

    details = await _retention_audit_details(store)
    assert [d["interrupted_phase"] for d in details] == ["documents_strip"]
    assert details[0]["interrupted"] is True and details[0]["documents_stripped"] == 0


async def test_leadership_lost_during_one_strip_threshold_skips_the_next(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #6526, S07-45: each prune threshold is its own store call of many batches, so a
    node demoted during one does not go on to strip the next as a stale ex-leader."""
    from messagefoundry.store.document_strip import StripResult

    coord = _SwitchableCoordinator()
    runner = RetentionRunner(store, RetentionSettings(), clock=lambda: 10 * DAY, coordinator=coord)
    monkeypatch.setattr(
        runner,
        "_resolve_document_prune",
        lambda: ({"c1": 1, "c2": 1}, {"c1": 1024, "c2": 4096}, {}),
    )
    calls: list[int] = []

    async def strip_then_demote(*_a: object, min_bytes: int, **_k: object) -> StripResult:
        calls.append(min_bytes)
        coord.leader = False
        return StripResult(messages_stripped=1, documents_stripped=1, bytes_reclaimed=10)

    monkeypatch.setattr(store, "strip_embedded_documents", strip_then_demote)

    result = await runner.run_once()

    assert calls == [1024]
    assert result.leadership_lost and result.documents_stripped == 1


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
        disk_free_status=DiskFreeStatus.OBSERVED,
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

    async def slow_wal() -> bool:
        finished = await orig_wal()
        mono["t"] = 100.0  # the WAL phase overruns the 5s cap
        return finished

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
    assert runner._last_wal == 0.0  # the phase that RAN advanced its (monotonic) marker
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
    # BACKLOG #290: the low-disk floor ships ON (1024 MiB), and on a SQLite store it needs the runner,
    # so stock settings now enable it. "Everything off" has to turn the floor off explicitly.
    # Vault BACKLOG #2619: the WAL truncate ships ON too, so "everything off" turns both off.
    # BACKLOG #1421: the audit-log growth warning ships ON as well, so it is the third knob off here.
    assert RetentionRunner(store, RetentionSettings()).enabled is True
    off = {"min_free_disk_mb": 0, "wal_checkpoint_seconds": 0, "audit_log_warn_rows": 0}
    assert RetentionRunner(store, RetentionSettings.model_validate(off)).enabled is False

    # Every knob below is checked with every default-ON knob in `off` OFF, so each one is seen enabling the
    # runner alone.
    def enabled(log_dir: str | None = None, **knobs: object) -> bool:
        settings = RetentionSettings.model_validate({**off, **knobs})
        return RetentionRunner(store, settings, log_dir=log_dir).enabled

    assert enabled(wal_checkpoint_seconds=3600) is True
    assert enabled(audit_log_warn_rows=1) is True
    assert enabled(messages_days=1) is True
    assert enabled(max_db_mb=10) is True
    assert enabled(vacuum_at="03:30") is True
    # #120: app-log retention needs BOTH a window and a log_dir to enable the runner.
    assert enabled(app_log_days=7) is False
    assert enabled(app_log_days=7, log_dir="x") is True
    assert enabled(app_log_days=0, log_dir="x") is False
    # #119: the compression window alone (no delete window) must start the runner too — omit it from
    # the OR-chain and a compress-only deployment gets no task at all.
    assert enabled(app_log_compress_days=7) is False
    assert enabled(app_log_compress_days=7, log_dir="x") is True
    # ASVS 14.2.7: `enabled` is a hand-maintained OR-chain — omit the preset window and a deployment
    # that configures ONLY it gets no runner at all, so the purge would silently never run.
    assert enabled(search_preset_days=1) is True


# --- audit-log growth warning (BACKLOG #1421) ---------------------------------


def _growth_only(rows: int, **extra: Any) -> RetentionSettings:
    """Only the audit-log growth warning on (plus ``extra``), so nothing else in the pass logs."""
    return RetentionSettings(
        min_free_disk_mb=0, wal_checkpoint_seconds=0, audit_log_warn_rows=rows, **extra
    )


def _spy_anchor(monkeypatch: pytest.MonkeyPatch, store: MessageStore) -> list[None]:
    """Replace ``audit_anchor`` with one that records each call and reports a huge log."""
    calls: list[None] = []

    async def anchor() -> tuple[int, str]:
        calls.append(None)
        return 10**9, "head"

    monkeypatch.setattr(store, "audit_anchor", anchor)
    return calls


async def _fill_audit(store: MessageStore, n: int) -> int:
    for i in range(n):
        await store.record_audit(
            "auth.permission_granted",
            actor=f"synthetic-growth-{i}",
            detail=json.dumps({"permission": "monitoring:view", "path": "/stats"}),
        )
    return await store.count_audit(limit=None)


def _growth_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "audit_log_warn_rows" in r.getMessage()]


def test_the_audit_growth_warning_ships_on_and_refuses_a_negative() -> None:
    assert RetentionSettings().audit_log_warn_rows == 4_000_000
    with pytest.raises(ValueError):
        RetentionSettings(audit_log_warn_rows=-1)


async def test_the_pass_warns_above_the_audit_threshold(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    rows = await _fill_audit(store, 3)
    runner = RetentionRunner(store, _growth_only(rows - 1), clock=lambda: 1000.0)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await runner.run_once()
    assert result.audit_log_over_warn is True
    warned = _growth_warnings(caplog)
    assert len(warned) == 1 and warned[0].levelno == logging.WARNING
    message = warned[0].getMessage()
    # On an intact chain the newest sequence number the check reads is the row count.
    assert f"holds about {rows} rows" in message and f"threshold of {rows - 1}" in message
    # Two numbers and setting names only: no row's contents reach the log.
    assert "synthetic-growth" not in message and "/stats" not in message
    # A warning changes nothing, and an audit row here would grow the table it warns about.
    assert result.did_work is False
    assert await store.count_audit(limit=None) == rows


async def test_the_pass_is_quiet_at_and_below_the_audit_threshold(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """The control: the same table, a threshold equal to its count and one far above it."""
    rows = await _fill_audit(store, 3)
    for threshold in (rows, 4_000_000):
        runner = RetentionRunner(store, _growth_only(threshold), clock=lambda: 1000.0)
        with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
            result = await runner.run_once()
        assert result.audit_log_over_warn is False
    assert _growth_warnings(caplog) == []


async def test_audit_threshold_zero_never_reads_the_log(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _spy_anchor(monkeypatch, store)
    result = await RetentionRunner(store, _growth_only(0), clock=lambda: 1000.0).run_once()
    assert result.audit_log_over_warn is False
    assert calls == []


async def test_a_failed_audit_read_is_logged_and_the_pass_goes_on(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A backend that cannot answer degrades with a logged reason, and the purges still run."""

    async def boom() -> tuple[int, str]:
        raise RuntimeError("read unavailable")

    purged: list[float] = []

    async def fake_purge(*, older_than: float, **kw: object) -> int:
        purged.append(older_than)
        return 0

    monkeypatch.setattr(store, "audit_anchor", boom)
    monkeypatch.setattr(store, "purge_message_bodies", fake_purge)
    settings = _growth_only(1, messages_days=1)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(store, settings, clock=lambda: 10 * DAY).run_once()
    assert result.audit_log_over_warn is False
    assert len(purged) == 1
    skipped = [r for r in caplog.records if "audit_log growth check skipped" in r.getMessage()]
    assert len(skipped) == 1 and skipped[0].levelno == logging.WARNING


async def test_the_audit_warning_applies_to_a_server_backend(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Unlike the disk floor, the runner does not gate this check on the SQLite backend: a store
    reporting a server backend is still checked. The store under it is SQLite, so this pins the
    runner's gating only; each backend's own ``audit_anchor`` is that backend's suite's to test."""
    rows = await _fill_audit(store, 2)
    monkeypatch.setattr(store, "backend", StoreBackend.SQLSERVER)
    runner = RetentionRunner(store, _growth_only(rows - 1), clock=lambda: 1000.0)
    assert runner.enabled is True
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await runner.run_once()
    assert result.audit_log_over_warn is True
    assert len(_growth_warnings(caplog)) == 1


async def test_a_capped_pass_still_warns_about_audit_growth(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check runs before the #121 duration cap, so a pass that ran out of time still warns."""
    calls = _spy_anchor(monkeypatch, store)
    ticks = iter([0.0] + [1e9] * 100)  # the cap is hit at the first between-phase check
    runner = RetentionRunner(
        store,
        _growth_only(1, max_pass_seconds=1, messages_days=1),
        clock=lambda: 10 * DAY,
        monotonic=lambda: next(ticks),
    )
    result = await runner.run_once()
    assert result.capped is True
    assert result.audit_log_over_warn is True
    assert len(calls) == 1


async def test_a_follower_does_not_read_the_audit_log(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """audit_log is the shared store's table, so only the node that runs retention warns."""
    calls = _spy_anchor(monkeypatch, store)
    runner = RetentionRunner(
        store, _growth_only(1), clock=lambda: 1000.0, coordinator=_FollowerCoordinator()
    )
    result = await runner.run_once()
    assert result.audit_log_over_warn is False
    assert calls == []


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


_CHANGES = [
    "append",
    "replace",
    "replace_same_size",
    "rewrite_same_size",
    "rewrite_same_size_same_mtime",
    "metadata_only",
]


def _mutate_source(old_log: Path, change: str, *, old: float, late: bytes) -> bytes:
    """Change ``old_log`` the way ``change`` names and return what it should then hold. Every case but
    ``rewrite_same_size`` puts the old mtime back, so the size, the file id or the ctime must betray it;
    the ``*_same_size`` cases keep the size, so only the file id (replace), the mtime (rewrite) or the
    ctime alone (rewrite with the mtime put back) can."""
    body = old_log.read_bytes()
    if change == "metadata_only":
        # Only the ctime moves (an attribute flip, as backup software clears the archive bit): the
        # content and the mtime are untouched. Past a coarse ctime tick first, as below.
        time.sleep(0.05)
        os.chmod(old_log, stat.S_IREAD)
        os.chmod(old_log, stat.S_IREAD | stat.S_IWRITE)
        return body
    if change == "append":
        with open(old_log, "ab") as fh:
            fh.write(late)
        expected = body + late
    elif change in ("replace", "replace_same_size"):
        expected = late if change == "replace" else b"R" * len(body)
        rotated = old_log.with_name("rotated.tmp")
        rotated.write_bytes(expected)
        os.replace(rotated, old_log)
    else:
        # Past a coarse ctime tick (Linux stamps ctime from a jiffy clock), so the rewrite's ctime is new.
        time.sleep(0.05)
        expected = b"W" * len(body)
        with open(old_log, "r+b") as fh:
            fh.write(expected)
        if change == "rewrite_same_size":
            os.utime(old_log, (old + 1, old + 1))
            return expected
    os.utime(old_log, (old, old))
    return expected


@pytest.mark.parametrize("change", _CHANGES)
async def test_app_log_compression_keeps_a_source_that_changed_after_placement(
    store: MessageStore, tmp_path, monkeypatch, caplog, change: str
) -> None:
    """A log appended to, rewritten, or replaced (rotated) at the same path after its archive was placed
    must NOT be unlinked: the validated archive describes only the bytes read at the START, so removing
    the path would destroy whatever was written into it since. BACKLOG #6805.

    RULE: the read-back at ``dest`` proves the archive matches ``data``; it says nothing about whether
    ``source`` still holds only ``data``. The unlink must also check that the path is still the same
    file (device + file id) with the same size and times as when it was read."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old = now - 10 * DAY
    old_log = logs / "old.log"
    body = b"engine started\n" * 500
    old_log.write_bytes(body)
    os.utime(old_log, (old, old))
    expected: list[bytes] = []

    real_verify = retention_mod._verify_archive

    def verify_then_mutate(path, original, *, name):
        ok = real_verify(path, original, name=name)
        if not path.endswith(".mftmp") and not expected:
            # The window between the dest read-back and the unlink: a writer touches the source path
            # (once; the code may read `dest` back again before removing a redundant archive).
            expected.append(_mutate_source(old_log, change, old=old, late=b"late line\n"))
        return ok

    monkeypatch.setattr(retention_mod, "_verify_archive", verify_then_mutate)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
        ).run_once()

    assert (
        old_log.exists() and old_log.read_bytes() == expected[0]
    )  # nothing written mid-pass is lost
    archive = logs / "old.log.gz"
    if change in ("append", "metadata_only"):
        # The kept source still holds every archived byte, so the archive this pass placed is removed:
        # left beside the source it would make every later pass skip this path, forever when no
        # `app_log_days` window is set. The next pass retries.
        assert not archive.exists()
    else:
        # The source no longer holds the archived bytes: under a replace the archive may be the only
        # copy of the old content, so it is kept.
        assert gzip.decompress(archive.read_bytes()) == body
    assert result.app_logs_compressed == 0 and result.app_log_bytes_reclaimed == 0
    assert "changed after its archive was placed" in caplog.text


@pytest.mark.parametrize("change", _CHANGES)
async def test_app_log_compression_places_nothing_for_a_source_that_changed_before_placement(
    store: MessageStore, tmp_path, monkeypatch, caplog, change: str
) -> None:
    """A source that changed between the read and the rename gets no archive at all: a stale partial
    ``<name>.gz`` would block every later compression of that path (BACKLOG #6805)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old = now - 10 * DAY
    old_log = logs / "old.log"
    old_log.write_bytes(b"engine started\n" * 500)
    os.utime(old_log, (old, old))
    expected: list[bytes] = []

    real_verify = retention_mod._verify_archive

    def verify_then_mutate(path, original, *, name):
        ok = real_verify(path, original, name=name)
        if path.endswith(".mftmp"):
            expected.append(_mutate_source(old_log, change, old=old, late=b"late line\n"))
        return ok

    monkeypatch.setattr(retention_mod, "_verify_archive", verify_then_mutate)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
        ).run_once()

    assert old_log.read_bytes() == expected[0]
    assert not (logs / "old.log.gz").exists()
    assert not list(logs.glob("*.mftmp"))
    assert result.app_logs_compressed == 0
    assert "changed during compression; nothing placed" in caplog.text


async def test_app_log_compression_skips_a_file_rotated_in_between_scan_and_read(
    store: MessageStore, tmp_path, monkeypatch, caplog
) -> None:
    """A fresh file rotated into an aged path after the scan, and before the read, is not compressed:
    the scan's age no longer describes it (BACKLOG #6805)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    old_log.write_bytes(b"engine started\n" * 500)
    os.utime(old_log, (now - 10 * DAY, now - 10 * DAY))
    fresh = b"fresh rotated content\n" * 200

    def rotate_then_allow(self, size, *, name):
        rotated = logs / "rotated.tmp"
        rotated.write_bytes(fresh)
        os.utime(rotated, (now, now))
        os.replace(rotated, old_log)
        return True

    monkeypatch.setattr(RetentionRunner, "_has_free_space", rotate_then_allow)

    with caplog.at_level(logging.DEBUG, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
        ).run_once()

    assert old_log.read_bytes() == fresh
    assert not (logs / "old.log.gz").exists()
    assert not list(logs.glob("*.mftmp"))  # rejected before anything was staged
    assert result.app_logs_compressed == 0
    assert "not the file the scan aged" in caplog.text


async def test_app_log_compression_never_renames_over_an_archive_that_appeared_meanwhile(
    store: MessageStore, tmp_path, monkeypatch, caplog
) -> None:
    """A ``<name>.gz`` a peer compressor placed after the scan is never renamed over: it may be the
    only copy of a longer read whose source the peer is about to remove (BACKLOG #6805)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    body = b"engine started\n" * 500
    old_log.write_bytes(body)
    os.utime(old_log, (now - 10 * DAY, now - 10 * DAY))
    peer = gzip.compress(body + b"a longer read by a peer\n")

    real_verify = retention_mod._verify_archive

    def verify_then_peer_places(path, original, *, name):
        ok = real_verify(path, original, name=name)
        if path.endswith(".mftmp"):
            (logs / "old.log.gz").write_bytes(peer)
        return ok

    monkeypatch.setattr(retention_mod, "_verify_archive", verify_then_peer_places)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
        ).run_once()

    assert (logs / "old.log.gz").read_bytes() == peer
    assert old_log.read_bytes() == body
    assert not list(logs.glob("*.mftmp"))
    assert result.app_logs_compressed == 0
    assert "an archive appeared meanwhile" in caplog.text


async def test_app_log_compression_keeps_the_archive_when_the_source_goes_before_its_removal(
    store: MessageStore, tmp_path, monkeypatch
) -> None:
    """Removing a redundant archive must not lose the last copy: if the source is removed (by a peer
    compressor, say) between the check that it still holds every archived byte and the archive's
    removal, the archive survives (BACKLOG #6805)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old = now - 10 * DAY
    old_log = logs / "old.log"
    body = b"engine started\n" * 500
    old_log.write_bytes(body)
    os.utime(old_log, (old, old))
    mutated: list[bytes] = []

    real_verify = retention_mod._verify_archive

    def verify_then_append(path, original, *, name):
        ok = real_verify(path, original, name=name)
        if not path.endswith(".mftmp") and not mutated:
            mutated.append(_mutate_source(old_log, "append", old=old, late=b"late line\n"))
        return ok

    real_holds = retention_mod._source_still_holds
    calls: list[bool] = []

    def holds_then_peer_removes(source, read_st, data):
        ok = real_holds(source, read_st, data)
        if not calls:
            old_log.unlink()  # the peer archived the longer read elsewhere and removed the source
        calls.append(ok)
        return ok

    monkeypatch.setattr(retention_mod, "_verify_archive", verify_then_append)
    monkeypatch.setattr(retention_mod, "_source_still_holds", holds_then_peer_removes)

    result = await RetentionRunner(
        store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
    ).run_once()

    assert calls and calls[0] is True  # the branch that removes a redundant archive was reached
    assert not old_log.exists()
    assert gzip.decompress((logs / "old.log.gz").read_bytes()) == body  # the last copy survives
    assert not list(logs.glob("*.mfclaim"))
    assert result.app_logs_compressed == 0


async def test_app_log_compression_reports_a_source_that_vanished_after_placement(
    store: MessageStore, tmp_path, monkeypatch, caplog
) -> None:
    """A source removed (by a peer compressor, say) after the archive was placed keeps the archive and
    is reported as vanished, not as kept (BACKLOG #6805)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_log = logs / "old.log"
    body = b"engine started\n" * 500
    old_log.write_bytes(body)
    os.utime(old_log, (now - 10 * DAY, now - 10 * DAY))

    real_verify = retention_mod._verify_archive

    def verify_then_remove(path, original, *, name):
        ok = real_verify(path, original, name=name)
        if not path.endswith(".mftmp") and old_log.exists():
            old_log.unlink()
        return ok

    monkeypatch.setattr(retention_mod, "_verify_archive", verify_then_remove)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
        ).run_once()

    assert gzip.decompress((logs / "old.log.gz").read_bytes()) == body
    assert result.app_logs_compressed == 0
    assert "vanished after its archive was placed" in caplog.text


async def test_app_log_sweep_ages_out_claimed_archives_with_the_archives(
    store: MessageStore, tmp_path
) -> None:
    """A claimed archive (``<name>.gz.<pid>-<ns>.mfclaim``) holds log content, so the
    ``app_log_days`` sweep ages it out on its own mtime, under the same gate as the ``.gz``
    archives: only while compression is on, and only for a name the compressor produces
    (BACKLOG #6805)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old_claim = logs / "old.log.gz.4242-123456789.mfclaim"
    old_txt_claim = logs / "OLD.TXT.GZ.1-2.MFCLAIM"
    fresh_claim = logs / "fresh.log.gz.4242-987654321.mfclaim"
    foreign = [
        logs / "old.log.4242-1.mfclaim",  # not claimed from an archive
        logs / "bundle.gz.4242-1.mfclaim",  # not an app-log archive
        logs / "old.log.gz.x-1.mfclaim",  # not a pid
        logs / "old.log.gz.4242.mfclaim",  # no time tag
        logs / "old.log.gz.1-2.mfclaim.3-4.mfclaim",  # a claim of a claim is never produced
    ]
    for p in (old_claim, old_txt_claim, fresh_claim, *foreign):
        p.write_bytes(b"x")
        os.utime(p, (now - 10 * DAY, now - 10 * DAY))
    os.utime(fresh_claim, (now - 1 * DAY, now - 1 * DAY))

    # Compression off: no archive is swept, and neither is a claim.
    result = await RetentionRunner(
        store, RetentionSettings(app_log_days=7), clock=lambda: now, log_dir=str(logs)
    ).run_once()
    assert result.app_logs_deleted == 0 and old_claim.exists() and old_txt_claim.exists()

    result = await RetentionRunner(
        store,
        RetentionSettings(app_log_days=7, app_log_compress_days=1),
        clock=lambda: now,
        log_dir=str(logs),
    ).run_once()
    assert result.app_logs_deleted == 2
    assert not old_claim.exists() and not old_txt_claim.exists()
    assert fresh_claim.exists()
    assert all(p.exists() for p in foreign)


def _claim_fixture(tmp_path: Path) -> tuple[Path, Path, os.stat_result, bytes]:
    """A source log and a valid archive of it at ``dest``, with the ``fstat`` read through it."""
    source = tmp_path / "old.log"
    data = b"engine started\n" * 50
    source.write_bytes(data)
    dest = tmp_path / "old.log.gz"
    dest.write_bytes(gzip.compress(data))
    with open(source, "rb") as fh:
        read_st = os.fstat(fh.fileno())
    return source, dest, read_st, data


def _remove_failing_on_claims(monkeypatch, error: OSError) -> None:
    """Make ``os.remove`` raise ``error`` for a claim name and behave normally for anything else."""
    real_remove = os.remove

    def remove(path, *args, **kwargs):
        if str(path).lower().endswith(".mfclaim"):
            raise error
        real_remove(path, *args, **kwargs)

    monkeypatch.setattr(os, "remove", remove)


def _peer_removes_claims_first(monkeypatch) -> None:
    """Make a peer's sweep win the race for every claim: the claim is gone when ``os.remove`` runs,
    so it raises ``FileNotFoundError`` for real."""
    real_remove = os.remove

    def remove(path, *args, **kwargs):
        if str(path).lower().endswith(".mfclaim"):
            real_remove(path)
        real_remove(path, *args, **kwargs)

    monkeypatch.setattr(os, "remove", remove)


def test_drop_redundant_archive_is_false_when_the_claim_cannot_be_removed(
    tmp_path, monkeypatch, caplog
) -> None:
    """A claim whose removal fails is NOT reported as removed: the archive's bytes are still on disk
    under the claim name, a WARNING names it, and the sweep recognises the name the producer made
    (BACKLOG #6805)."""
    source, dest, read_st, data = _claim_fixture(tmp_path)
    _remove_failing_on_claims(monkeypatch, PermissionError("locked"))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        dropped = retention_mod._drop_redundant_archive(
            str(source), read_st, data, str(dest), name="old.log"
        )

    assert dropped is False
    claims = list(tmp_path.glob("*.mfclaim"))
    assert len(claims) == 1 and gzip.decompress(claims[0].read_bytes()) == data
    assert "could not be removed" in caplog.text
    assert retention_mod._is_app_log_name(claims[0].name, include_archives=True)


def test_drop_redundant_archive_counts_a_claim_a_peer_already_removed(
    tmp_path, monkeypatch, caplog
) -> None:
    """A claim already gone when its removal runs (a peer's ``app_log_days`` sweep took it) is
    counted as removed, not logged as a failure (BACKLOG #6805)."""
    source, dest, read_st, data = _claim_fixture(tmp_path)
    _peer_removes_claims_first(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        assert_capture_sees(caplog, retention_mod.__name__)
        dropped = retention_mod._drop_redundant_archive(
            str(source), read_st, data, str(dest), name="old.log"
        )

    assert dropped is True
    assert not list(tmp_path.glob("*.mfclaim")) and not dest.exists()
    assert "could not be removed" not in caplog.text


@pytest.mark.parametrize("dest_gone", [True, False])
def test_drop_redundant_archive_reports_an_archive_gone_before_its_claim(
    tmp_path, monkeypatch, caplog, dest_gone: bool
) -> None:
    """An archive removed (by a peer engine shard's ``app_log_days`` sweep, say) after it was
    validated and before it could be claimed is reported as already gone, never as kept: no file
    remains to keep. A FileNotFoundError with the archive still there (Windows raises it for a claim
    path too long, say) is still reported as kept (BACKLOG #6805)."""
    source, dest, read_st, data = _claim_fixture(tmp_path)
    real_rename = os.rename

    def peer_sweeps_then_rename(src, dst, *args, **kwargs):
        if str(src) == str(dest):
            if not dest_gone:
                raise FileNotFoundError("the claim path is too long")
            dest.unlink()  # the peer wins the race; the rename below raises FileNotFoundError
        real_rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "rename", peer_sweeps_then_rename)
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.pipeline.retention"):
        assert_capture_sees(caplog, retention_mod.__name__)
        dropped = retention_mod._drop_redundant_archive(
            str(source), read_st, data, str(dest), name="old.log"
        )

    assert dropped is False
    assert not list(tmp_path.glob("*.mfclaim"))
    gone_line = (
        "the archive 'old.log.gz' could not be found when it was to be claimed (already gone, or "
        "its directory unreachable); this pass does not remove it"
    )
    if dest_gone:
        assert not dest.exists()
        assert gone_line in caplog.text
        assert "it is kept" not in caplog.text and "could not be claimed" not in caplog.text
    else:
        assert gzip.decompress(dest.read_bytes()) == data
        assert gone_line not in caplog.text
        assert "could not be claimed for removal; it is kept" in caplog.text


async def test_app_log_compression_does_not_say_a_gone_archive_holds_the_bytes(
    store: MessageStore, tmp_path, monkeypatch, caplog
) -> None:
    """When the source changed after its archive was placed and the archive is gone (a peer engine
    shard's ``app_log_days`` sweep, say) before the redundant-archive removal reads it, the WARNING
    must not say the archive holds the bytes read: nothing is there, and the kept source holds them
    (BACKLOG #6805)."""
    logs = tmp_path / "logs"
    logs.mkdir()
    now = 30 * DAY
    old = now - 10 * DAY
    old_log = logs / "old.log"
    old_log.write_bytes(b"engine started\n" * 500)
    os.utime(old_log, (old, old))
    archive = logs / "old.log.gz"
    expected: list[bytes] = []

    real_verify = retention_mod._verify_archive

    def verify_then_mutate_then_sweep(path, original, *, name):
        if not path.endswith(".mftmp") and expected and archive.exists():
            archive.unlink()  # the peer's sweep, before the removal's first read of `dest`
        ok = real_verify(path, original, name=name)
        if not path.endswith(".mftmp") and not expected:
            expected.append(_mutate_source(old_log, "append", old=old, late=b"late line\n"))
        return ok

    monkeypatch.setattr(retention_mod, "_verify_archive", verify_then_mutate_then_sweep)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        result = await RetentionRunner(
            store, RetentionSettings(app_log_compress_days=7), clock=lambda: now, log_dir=str(logs)
        ).run_once()

    assert old_log.read_bytes() == expected[0]  # the source is kept
    assert not archive.exists() and not list(logs.glob("*.mfclaim"))
    assert result.app_logs_compressed == 0
    assert "changed after its archive was placed" in caplog.text
    assert "holds the bytes" not in caplog.text
    assert "may remain in the source" in caplog.text


def test_drop_redundant_archive_reports_a_claim_gone_before_its_put_back(
    tmp_path, monkeypatch, caplog
) -> None:
    """A claim removed (by a peer's ``app_log_days`` sweep, say) before it could be put back is
    reported as gone, not as KEPT under a name that no longer exists (BACKLOG #6805)."""
    source, dest, read_st, data = _claim_fixture(tmp_path)
    answers = iter([True, False])  # holds before the claim, changed after it

    def holds_then_peer_sweeps(*args):
        answer = next(answers)
        if not answer:
            for claim in tmp_path.glob("*.mfclaim"):
                claim.unlink()
        return answer

    monkeypatch.setattr(retention_mod, "_source_still_holds", holds_then_peer_sweeps)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        dropped = retention_mod._drop_redundant_archive(
            str(source), read_st, data, str(dest), name="old.log"
        )

    assert dropped is False
    assert not list(tmp_path.glob("*.mfclaim")) and not dest.exists()
    assert "could not be found to put it back" in caplog.text
    assert "KEPT as" not in caplog.text


@pytest.mark.parametrize("fail", ["link", "remove"])
def test_drop_redundant_archive_warns_when_a_put_back_leaves_the_claim(
    tmp_path, monkeypatch, caplog, fail: str
) -> None:
    """When the post-claim re-check fails, the archive is put back. A put-back that cannot link, or
    that links but cannot then remove the claim, leaves the claim and says so at WARNING, never at
    DEBUG only (BACKLOG #6805)."""
    source, dest, read_st, data = _claim_fixture(tmp_path)
    answers = iter([True, False])  # holds before the claim, changed after it
    monkeypatch.setattr(retention_mod, "_source_still_holds", lambda *a: next(answers))

    def refuse_link(*args, **kwargs):
        raise OSError("no hard links here")

    if fail == "link":
        monkeypatch.setattr(os, "link", refuse_link)
    else:
        _remove_failing_on_claims(monkeypatch, PermissionError("locked"))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        dropped = retention_mod._drop_redundant_archive(
            str(source), read_st, data, str(dest), name="old.log"
        )

    assert dropped is False
    assert len(list(tmp_path.glob("*.mfclaim"))) == 1
    if fail == "link":
        assert not dest.exists()
        assert "the source or the claimed archive changed" in caplog.text
    else:
        assert gzip.decompress(dest.read_bytes()) == data
        assert "was linked back but could not be removed" in caplog.text


def test_drop_redundant_archive_put_back_counts_a_claim_a_peer_already_removed(
    tmp_path, monkeypatch, caplog
) -> None:
    """After a put-back links the archive back to ``dest``, a claim a peer already removed is not
    a failure: ``dest`` holds the archive and no WARNING says the claim was kept (BACKLOG #6805)."""
    source, dest, read_st, data = _claim_fixture(tmp_path)
    answers = iter([True, False])  # holds before the claim, changed after it
    monkeypatch.setattr(retention_mod, "_source_still_holds", lambda *a: next(answers))
    _peer_removes_claims_first(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.retention"):
        assert_capture_sees(caplog, retention_mod.__name__)
        dropped = retention_mod._drop_redundant_archive(
            str(source), read_st, data, str(dest), name="old.log"
        )

    assert dropped is False
    assert gzip.decompress(dest.read_bytes()) == data
    assert not list(tmp_path.glob("*.mfclaim"))
    assert "could not be removed" not in caplog.text


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
        tmp_path / "engine.db",
        retention_settings=RetentionSettings(messages_days=1),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    await engine.start()
    try:
        assert engine._retention_runner is not None
        assert engine._retention_runner.enabled is True
    finally:
        await engine.stop()


async def test_engine_without_retention_settings_has_no_runner(tmp_path) -> None:
    engine = await Engine.create(
        tmp_path / "engine2.db", egress_settings=EgressSettings(deny_by_default=False)
    )
    await engine.start()
    try:
        assert engine._retention_runner is None
    finally:
        await engine.stop()


# --- a reload that first sets a per-connection window starts passes (BACKLOG #6804) -------------

# Every default-ON knob off, so only the graph can give the runner something to do.
_ALL_OFF = {"min_free_disk_mb": 0, "wal_checkpoint_seconds": 0, "audit_log_warn_rows": 0}


def _write_retention_graph(cfg: Path, inbox: Path, outdir: Path, *, window: str = "") -> None:
    """One file inbound -> router -> handler -> file outbound; ``window`` adds keyword arguments to
    the inbound (a leading ``i:``) or the outbound (``o:``), such as a per-connection window."""
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    outdir.mkdir(parents=True, exist_ok=True)
    ib_kw = f", {window[2:]}" if window.startswith("i:") else ""
    ob_kw = f", {window[2:]}" if window.startswith("o:") else ""
    (cfg / "cfg.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        f"inbound('IB_RET', File(directory={str(inbox)!r}, pattern='*.hl7', poll_seconds=0.05), "
        f"router='r'{ib_kw})\n"
        f"outbound('OB_RET', File(directory={str(outdir)!r}, filename='{{MSH-10}}.hl7'){ob_kw})\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OB_RET', msg)\n",
        encoding="utf-8",
    )


def test_enabled_by_a_per_connection_window(store: MessageStore) -> None:
    """A per-connection messages_days or dead_letter_days above 0 purges with the global window
    off, so it gives the runner something to do on its own; 0 keeps forever and does not."""
    off = RetentionSettings.model_validate(_ALL_OFF)

    def enabled(*, messages_days: int | None = None, dead_letter_days: int | None = None) -> bool:
        reg = Registry()
        reg.add_inbound(
            build_inbound_connection("IB", MLLP(port=2610), router="r", messages_days=messages_days)
        )
        reg.add_outbound(
            build_outbound_connection(
                "OB", File(directory="./out"), dead_letter_days=dead_letter_days
            )
        )
        return RetentionRunner(store, off, registry_source=lambda: reg).enabled

    assert enabled() is False
    assert enabled(messages_days=3) is True
    assert enabled(dead_letter_days=3) is True
    assert enabled(messages_days=0, dead_letter_days=0) is False


async def test_a_disabled_runner_with_a_registry_idles(store: MessageStore) -> None:
    """With a registry wired, the loop runs even when nothing is set, and runs no pass until the
    live graph sets a window; with no registry a disabled runner spawns no loop."""
    passes: list[None] = []
    settings = RetentionSettings.model_validate({**_ALL_OFF, "purge_interval_seconds": 0.01})
    holder: dict[str, Registry] = {"reg": Registry()}
    runner = RetentionRunner(store, settings, registry_source=lambda: holder["reg"])

    async def _counting(now: float | None = None) -> Any:
        passes.append(None)

    runner.run_once = _counting  # type: ignore[method-assign]
    runner.start()
    try:
        assert runner._task is not None
        await asyncio.sleep(0.1)
        assert passes == [], "an idle runner ran a pass with nothing configured"
        reg = Registry()
        reg.add_inbound(
            build_inbound_connection("IB", MLLP(port=2611), router="r", messages_days=1)
        )
        holder["reg"] = reg
        for _ in range(200):
            if passes:
                break
            await asyncio.sleep(0.01)
        assert passes, "the loop did not pick up a window the live graph set"
        holder["reg"] = Registry()
        await asyncio.sleep(0.05)
        settled = len(passes)
        await asyncio.sleep(0.1)
        assert len(passes) == settled, "the loop kept running passes after the window was cleared"
    finally:
        await runner.stop()
    assert runner._task is None

    bare = RetentionRunner(store, settings)
    bare.start()
    assert bare._task is None


async def test_wake_runs_a_pass_only_when_it_makes_the_loop_active(store: MessageStore) -> None:
    """A reload's wake() on an active loop adds no pass; one that gives an idle loop a window runs
    one at once. The 3600 s interval means no pass below can come from the timer."""
    passes: list[None] = []
    settings = RetentionSettings.model_validate({**_ALL_OFF, "purge_interval_seconds": 3600})
    window = Registry()
    window.add_inbound(build_inbound_connection("IB", MLLP(port=2612), router="r", messages_days=1))
    holder: dict[str, Registry] = {"reg": window}
    runner = RetentionRunner(store, settings, registry_source=lambda: holder["reg"])

    async def _counting(now: float | None = None) -> Any:
        passes.append(None)

    runner.run_once = _counting  # type: ignore[method-assign]
    runner.start()
    try:
        for _ in range(200):
            if passes:
                break
            await asyncio.sleep(0.01)
        assert len(passes) == 1
        runner.wake()  # a reload while active
        await asyncio.sleep(0.1)
        assert len(passes) == 1, "a reload added a pass to an already-active loop"
    finally:
        await runner.stop()

    holder["reg"] = Registry()
    passes.clear()
    runner.start()
    try:
        await asyncio.sleep(0.1)
        assert passes == [], "a restarted idle loop ran a pass (a stale wake was left set)"
        holder["reg"] = window
        runner.wake()  # the reload that makes it active
        for _ in range(200):
            if passes:
                break
            await asyncio.sleep(0.01)
        assert len(passes) == 1, "the reload that gave the idle loop a window ran no pass"
    finally:
        await runner.stop()


async def test_a_wake_before_the_first_iteration_runs_one_pass(store: MessageStore) -> None:
    """A reload that wakes the loop between start() and its first iteration gets one pass, not
    two back to back: the 3600 s interval means a second pass could only come from a stale wake."""
    passes: list[None] = []
    settings = RetentionSettings.model_validate({**_ALL_OFF, "purge_interval_seconds": 3600})
    holder: dict[str, Registry] = {"reg": Registry()}
    runner = RetentionRunner(store, settings, registry_source=lambda: holder["reg"])

    async def _counting(now: float | None = None) -> Any:
        passes.append(None)

    runner.run_once = _counting  # type: ignore[method-assign]
    runner.start()  # idle: the task exists but has not run yet
    try:
        window = Registry()
        window.add_inbound(
            build_inbound_connection("IB", MLLP(port=2613), router="r", messages_days=1)
        )
        holder["reg"] = window
        runner.wake()  # the reload, before the loop's first iteration
        await asyncio.sleep(0.15)
        assert len(passes) == 1, f"expected one pass, got {len(passes)}"
    finally:
        await runner.stop()


@pytest.mark.parametrize(
    "window",
    ["i:messages_days=1", "i:prune_documents_after=1", "o:dead_letter_days=1"],
    ids=["messages_days", "prune", "dead_letter_days"],
)
async def test_reload_that_sets_a_window_runs_a_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, window: str
) -> None:
    """BACKLOG #6804: the engine started with nothing for retention to do, then a reload set a
    per-connection window. A pass must run without a restart, on the same single loop."""
    passes: list[None] = []
    real_run_once = RetentionRunner.run_once

    async def _counting_run_once(self: RetentionRunner, now: float | None = None) -> Any:
        passes.append(None)
        return await real_run_once(self, now)

    monkeypatch.setattr(RetentionRunner, "run_once", _counting_run_once)
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    idle_cfg, window_cfg = tmp_path / "idle", tmp_path / "window"
    _write_retention_graph(idle_cfg, inbox, outdir)
    _write_retention_graph(window_cfg, inbox, outdir, window=window)

    engine = await Engine.create(
        tmp_path / "engine.db",
        retention_settings=RetentionSettings.model_validate(
            # An interval no test waits out: only the reload's wake can run the pass in time.
            {**_ALL_OFF, "purge_interval_seconds": 3600}
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(load_config(idle_cfg))
    await engine.start()
    try:
        runner = engine._retention_runner
        assert runner is not None
        task = runner._task
        assert task is not None
        await asyncio.sleep(0.1)
        assert runner.enabled is False and passes == []

        outcome = await engine.reload_detail(window_cfg)
        assert outcome.applied is True and outcome.failures == ()
        assert runner.enabled is True
        for _ in range(200):
            if passes:
                break
            await asyncio.sleep(0.01)
        assert passes, "a reload that set a per-connection window left retention off"
        assert runner._task is task, "the reload started a second retention loop"
    finally:
        await engine.stop()
    assert runner._task is None and task.done()
