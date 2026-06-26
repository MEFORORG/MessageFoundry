# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""P1b — the inbound "Response Sent" ACK/NAK store layer (ADR 0021 §§1-6).

Covers the PHI fail-safe the design review flagged: a NAK never stores a body; an AA body is stored
only when the store is encrypted; the detail is safe_text-scrubbed; and ``ack_sent`` rows surface
through ``correlate_response`` under a sentinel destination that leaves outbound reply ordering intact.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from messagefoundry.store.crypto import PREFIX, generate_key, make_cipher
from messagefoundry.store.store import MessageStore

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
AA = "MSH|^~\\&|R|RF|S|F|20260101||ACK^A01|MSG1|P|2.5.1\rMSA|AA|MSG1\r"


def _response_rows(db_path: Path) -> list[tuple]:
    con = sqlite3.connect(db_path)
    try:
        return con.execute(
            "SELECT destination_name, kind, ack_code, ack_phase, body FROM response"
        ).fetchall()
    finally:
        con.close()


async def test_aa_body_encrypted_when_store_encrypted(tmp_path: Path) -> None:
    db = tmp_path / "ack_enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        mid = await store.enqueue_message(channel_id="IB_X", raw=ADT, deliveries=[("d", ADT)])
        await store.record_ack_sent(
            message_id=mid,
            inbound_name="IB_X",
            ack_body=AA,
            ack_code="AA",
            ack_phase="ingest",
            outcome="accepted",
        )
        rows = await store.correlate_response(mid)
        ack = next(r for r in rows if r.kind == "ack_sent")
        assert ack.ack_code == "AA" and ack.ack_phase == "ingest"
        assert ack.body == AA  # decrypted round-trip
        # ciphertext on disk, PHI not visible
        disk = next(r for r in _response_rows(db) if r[1] == "ack_sent")
        assert disk[4].startswith(PREFIX) and "MSA" not in disk[4]
    finally:
        await store.close()


async def test_aa_body_null_when_store_unencrypted(tmp_path: Path) -> None:
    # Fail-safe: an unencrypted (identity-cipher) store must NOT persist the AA frame in the clear.
    db = tmp_path / "ack_plain.db"
    store = await MessageStore.open(db)  # no cipher → identity
    try:
        mid = await store.enqueue_message(channel_id="IB_X", raw=ADT, deliveries=[("d", ADT)])
        await store.record_ack_sent(
            message_id=mid,
            inbound_name="IB_X",
            ack_body=AA,
            ack_code="AA",
            ack_phase="ingest",
            outcome="accepted",
        )
        ack = next(r for r in await store.correlate_response(mid) if r.kind == "ack_sent")
        assert ack.ack_code == "AA"  # metadata is still captured…
        assert ack.body is None  # …but the body is NOT stored on an unencrypted store
        disk = next(r for r in _response_rows(db) if r[1] == "ack_sent")
        assert disk[4] is None
    finally:
        await store.close()


async def test_nak_never_stores_a_body(tmp_path: Path) -> None:
    db = tmp_path / "ack_nak.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        mid = await store.enqueue_message(channel_id="IB_X", raw=ADT, deliveries=[("d", ADT)])
        # A NAK passes ack_body=None; the offending field value lives only in the scrubbed detail.
        await store.record_ack_sent(
            message_id=mid,
            inbound_name="IB_X",
            ack_body=None,
            ack_code="AR",
            ack_phase="parse",
            outcome="rejected",
            detail=f"bad PID: {ADT}",
        )
        ack = next(r for r in await store.correlate_response(mid) if r.kind == "ack_sent")
        assert ack.ack_code == "AR" and ack.body is None
        assert ack.detail is not None and "DOE" not in ack.detail  # safe_text-scrubbed (#120)
    finally:
        await store.close()


async def test_seq_is_kind_scoped_and_disjoint_from_outbound(tmp_path: Path) -> None:
    # An ack_sent row and an outbound response row for the same message coexist; the ack sorts under a
    # sentinel destination, so outbound per-destination ordering is unaffected and seqs don't collide.
    db = tmp_path / "ack_mix.db"
    store = await MessageStore.open(db)
    try:
        mid = await store.enqueue_message(channel_id="IB_X", raw=ADT, deliveries=[("d", ADT)])
        item = (await store.claim_ready())[0]
        await store.complete_with_response(item.id, body="PARTNER-REPLY", outcome="accepted")
        await store.record_ack_sent(
            message_id=mid,
            inbound_name="IB_X",
            ack_body=None,
            ack_code="AA",
            ack_phase="ingest",
            outcome="accepted",
        )
        rows = await store.correlate_response(mid)
        by_kind = {r.kind: r for r in rows}
        assert by_kind["response"].destination_name == "d"
        assert by_kind["response"].response_seq == 1  # outbound reply unaffected by the ack row
        assert by_kind["ack_sent"].destination_name.startswith("\x1fack:")
        assert by_kind["ack_sent"].response_seq == 1  # its own kind-scoped sequence
        # a second ack for the same message increments only the ack lane
        await store.record_ack_sent(
            message_id=mid,
            inbound_name="IB_X",
            ack_body=None,
            ack_code="AA",
            ack_phase="ingest",
            outcome="accepted",
        )
        acks = [r for r in await store.correlate_response(mid) if r.kind == "ack_sent"]
        assert sorted(r.response_seq for r in acks) == [1, 2]
    finally:
        await store.close()


async def test_outbound_response_defaults_to_kind_response(tmp_path: Path) -> None:
    # A plain captured outbound reply (ADR 0013) must keep kind='response' (the column DEFAULT).
    db = tmp_path / "ack_default.db"
    store = await MessageStore.open(db)
    try:
        mid = await store.enqueue_message(channel_id="IB_X", raw=ADT, deliveries=[("d", ADT)])
        item = (await store.claim_ready())[0]
        await store.complete_with_response(item.id, body="REPLY", outcome="accepted")
        row = (await store.correlate_response(mid))[0]
        assert row.kind == "response" and row.ack_code is None and row.ack_phase is None
    finally:
        await store.close()
