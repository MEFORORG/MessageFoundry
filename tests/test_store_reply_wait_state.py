# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``reply_wait_state`` — the metadata-only poll read behind the ADR 0154 D3 sync-reply wait.

Two properties carry this module, and both are correctness rather than convenience.

**Terminality is defined by exclusion, never by enumeration.** An enumerated terminal set
(``UNROUTED``/``FILTERED``/``NOT_DEPLOYED``/``ERROR``) omits ``PROCESSED`` — which is exactly what the
finalizer sets when a *sibling* handler delivered while the awaited destination's ``Send`` was
declined, filtered out, or never emitted. The wait would then hang for the whole ``reply_timeout``
instead of failing fast. ``test_terminality_covers_every_message_status`` iterates the enum so a new
member forces an explicit decision instead of silently inheriting that bug.

**An empty row list is not evidence of exclusion.** Routed rows carry a NULL ``destination_name``, so
a sibling handler still upstream is structurally invisible to the destination-keyed query. Reading
"no rows" as "excluded" is the defect ADR 0154 revision 1 shipped: a ``502`` for a message the engine
then delivered normally.
"""

from __future__ import annotations

from pathlib import Path

from messagefoundry.store.store import MessageStatus, MessageStore, ReplyWaitState

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
REPLY = '{"status":"ok","id":"partner-1"}'


def test_terminality_covers_every_message_status() -> None:
    # The load-bearing test. Exclusion must be TOTAL against the enum: every member is classified,
    # and a member added later fails here rather than silently becoming "keep waiting" forever.
    still_running = {MessageStatus.RECEIVED, MessageStatus.ROUTED}
    for status in MessageStatus:
        state = ReplyWaitState(message_status=status.value, row_states=(), latest_response_seq=None)
        expected = status not in still_running
        assert state.message_is_terminal is expected, (
            f"{status.value!r} classified wrongly — if this is a NEW MessageStatus member, decide "
            "explicitly whether a reply can still arrive for it; do not let it default"
        )

    # Named explicitly so the intent survives a refactor of the loop above: PROCESSED is terminal,
    # and it is the member an enumerated list forgets.
    assert ReplyWaitState(MessageStatus.PROCESSED.value, (), None).message_is_terminal
    assert not ReplyWaitState(MessageStatus.ROUTED.value, (), None).message_is_terminal


def test_a_vanished_message_is_terminal() -> None:
    # Nothing can arrive for a message that is gone; the caller resolves it as degraded rather than
    # blocking for the full timeout.
    assert ReplyWaitState(
        message_status=None, row_states=(), latest_response_seq=None
    ).message_is_terminal


async def test_reports_status_rows_and_no_reply_before_capture(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "wait.db")
    try:
        mid = await store.enqueue_message(
            channel_id="IB_HTTP", raw=ADT, deliveries=[("OB_PARTNER", ADT)]
        )
        state = await store.reply_wait_state(mid, "OB_PARTNER")

        assert state.message_status is not None
        assert not state.message_is_terminal  # still flowing — the wait must continue
        assert state.row_states  # the awaited destination has a queued row
        assert state.latest_response_seq is None  # nothing captured yet
    finally:
        await store.close()


async def test_a_sibling_handlers_row_does_not_look_like_exclusion(tmp_path: Path) -> None:
    # AC-6 in miniature, at the store layer. The awaited destination has NO row yet while a sibling
    # is upstream, so row_states is empty — and that must NOT read as "excluded".
    store = await MessageStore.open(tmp_path / "sibling.db")
    try:
        mid = await store.enqueue_message(
            channel_id="IB_HTTP", raw=ADT, deliveries=[("OB_OTHER", ADT)]
        )
        state = await store.reply_wait_state(mid, "OB_PARTNER")  # a destination with no rows at all

        assert state.row_states == ()
        assert not state.message_is_terminal, (
            "an empty row list plus a non-terminal message must mean KEEP WAITING — reading it as "
            "exclusion is the 502-for-a-delivered-message defect"
        )
    finally:
        await store.close()


async def test_latest_response_seq_appears_once_a_reply_commits(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "capture.db")
    try:
        mid = await store.enqueue_message(
            channel_id="IB_HTTP", raw=ADT, deliveries=[("OB_PARTNER", ADT)]
        )
        assert (await store.reply_wait_state(mid, "OB_PARTNER")).latest_response_seq is None

        items = await store.claim_ready(destination_name="OB_PARTNER")
        assert items, "expected the queued outbound row to be claimable"
        await store.complete_with_response(items[0].id, body=REPLY, outcome="accepted")

        state = await store.reply_wait_state(mid, "OB_PARTNER")
        assert state.latest_response_seq == 1

        # ... and the body is reachable exactly once, through the existing decrypting read.
        captured = [r for r in await store.correlate_response(mid) if r.kind == "response"]
        assert [c.body for c in captured] == [REPLY]
    finally:
        await store.close()


async def test_an_ack_sent_row_is_never_mistaken_for_the_partners_reply(tmp_path: Path) -> None:
    # ADR 0021 ack_sent rows share the response table. The inbound ACK *we* returned must not satisfy
    # a wait for the partner's reply — otherwise the listener echoes our own ACK back to the caller.
    store = await MessageStore.open(tmp_path / "acksent.db")
    try:
        mid = await store.enqueue_message(
            channel_id="IB_HTTP", raw=ADT, deliveries=[("OB_PARTNER", ADT)]
        )
        await store.record_ack_sent(
            message_id=mid,
            inbound_name="IB_HTTP",
            ack_body=None,
            ack_code="AA",
            ack_phase="ingest",
            outcome="accepted",
        )
        state = await store.reply_wait_state(mid, "OB_PARTNER")
        assert state.latest_response_seq is None, "an ack_sent row satisfied a partner-reply wait"
    finally:
        await store.close()


async def test_the_read_decrypts_nothing(tmp_path: Path) -> None:
    # The poll runs per tick while a caller is blocked, so it must stay metadata-only. Proven by
    # construction: every field is a non-encrypted column, and an encrypted store returns the same
    # values as a plaintext one for the same graph.
    from messagefoundry.store.crypto import generate_key, make_cipher

    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        mid = await store.enqueue_message(
            channel_id="IB_HTTP", raw=ADT, deliveries=[("OB_PARTNER", ADT)]
        )
        items = await store.claim_ready(destination_name="OB_PARTNER")
        await store.complete_with_response(items[0].id, body=REPLY, outcome="accepted")

        state = await store.reply_wait_state(mid, "OB_PARTNER")
        assert state.latest_response_seq == 1  # readable without touching the encrypted body
        assert isinstance(state.message_status, str)
    finally:
        await store.close()
