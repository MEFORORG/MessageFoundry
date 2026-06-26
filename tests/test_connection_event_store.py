# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""P1a — the `connection_event` store layer (Corepoint-style transport/lifecycle log, #46).

Covers the invariants the design review flagged as load-bearing: metadata-only + `reason`
encrypted at rest, the nullable NO-FK `message_id`, count-and-log isolation (a connection event
never inflates message counts or touches disposition), and age-based retention.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from messagefoundry.store.crypto import PREFIX, generate_key, make_cipher
from messagefoundry.store.store import MessageStore

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def _col_at_rest(db_path: Path, column: str) -> object:
    """Read a connection_event column straight from the DB file, bypassing decryption."""
    con = sqlite3.connect(db_path)
    try:
        row = con.execute(f"SELECT {column} FROM connection_event").fetchone()
        return row[0] if row else None
    finally:
        con.close()


async def test_record_and_list_round_trip(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "ce.db")
    try:
        await store.record_connection_event(
            connection="IB_ACME_ADT",
            transport="mllp",
            direction="inbound",
            kind="established",
            peer_host="10.0.0.5",
            now=100.0,
        )
        await store.record_connection_event(
            connection="IB_ACME_ADT",
            transport="mllp",
            direction="inbound",
            kind="closed",
            peer_host="10.0.0.5",
            reason="clean eof",
            now=200.0,
        )
        await store.record_connection_event(
            connection="OB_PARTNER_ADT",
            transport="mllp",
            direction="outbound",
            kind="connection_lost",
            message_id="m-1",
            reason="connect refused",
            now=150.0,
        )
        events = await store.list_connection_events()
        # newest-first by ts
        assert [e.kind for e in events] == ["closed", "connection_lost", "established"]
        lost = events[1]
        assert lost.direction == "outbound" and lost.message_id == "m-1"
        assert lost.reason == "connect refused"
        # filters
        ib = await store.list_connection_events(connection="IB_ACME_ADT")
        assert {e.kind for e in ib} == {"established", "closed"}
        kinds = await store.list_connection_events(kinds=["established"])
        assert [e.kind for e in kinds] == ["established"]
        since = await store.list_connection_events(since=175.0)
        assert [e.kind for e in since] == ["closed"]
    finally:
        await store.close()


async def test_reason_encrypted_at_rest(tmp_path: Path) -> None:
    db = tmp_path / "ce_enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        await store.record_connection_event(
            connection="IB",
            transport="mllp",
            direction="inbound",
            kind="framing_error",
            reason="boom",
            now=1.0,
        )
        # the metadata-only non-PHI columns stay plaintext; reason is ciphertext on disk…
        assert _col_at_rest(db, "kind") == "framing_error"
        assert _col_at_rest(db, "connection") == "IB"
        reason_disk = _col_at_rest(db, "reason")
        assert isinstance(reason_disk, str) and reason_disk.startswith(PREFIX)
        assert "boom" not in reason_disk
        # …and the read path decrypts it back
        events = await store.list_connection_events()
        assert events[0].reason == "boom"
    finally:
        await store.close()


async def test_reason_is_safe_text_scrubbed(tmp_path: Path) -> None:
    # A hostile garbage frame whose error text embeds HL7-shaped PHI must never land verbatim.
    store = await MessageStore.open(tmp_path / "ce_scrub.db")
    try:
        await store.record_connection_event(
            connection="IB",
            transport="mllp",
            direction="inbound",
            kind="framing_error",
            reason=f"bad frame: {ADT}",
            now=1.0,
        )
        events = await store.list_connection_events()
        assert "DOE" not in (events[0].reason or "")  # PID segment scrubbed by safe_text (#120)
    finally:
        await store.close()


async def test_reason_truncated(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "ce_trunc.db")
    try:
        await store.record_connection_event(
            connection="IB",
            transport="mllp",
            direction="inbound",
            kind="framing_error",
            reason="x" * 500,
            now=1.0,
        )
        events = await store.list_connection_events()
        assert events[0].reason is not None and len(events[0].reason) <= 200
    finally:
        await store.close()


async def test_message_id_is_nullable_and_not_a_foreign_key(tmp_path: Path) -> None:
    # An inbound lifecycle event has no message; an outbound event may carry a message_id that does
    # NOT reference any messages row (deliberately NO FK) — both must insert without error.
    store = await MessageStore.open(tmp_path / "ce_fk.db")
    try:
        await store.record_connection_event(
            connection="IB",
            transport="mllp",
            direction="inbound",
            kind="established",
            now=1.0,
        )
        await store.record_connection_event(
            connection="OB",
            transport="mllp",
            direction="outbound",
            kind="connection_lost",
            message_id="does-not-exist",
            now=2.0,
        )
        events = await store.list_connection_events()
        assert {e.message_id for e in events} == {None, "does-not-exist"}
    finally:
        await store.close()


async def test_does_not_inflate_counts_or_change_disposition(tmp_path: Path) -> None:
    # Count-and-log invariant: a connection_event row (even one whose message_id is a real message)
    # writes no messages/queue row, so message counts and disposition are untouched.
    store = await MessageStore.open(tmp_path / "ce_count.db")
    try:
        mid = await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("d", ADT)])
        before = await store.count_messages()
        status_before = (await store.get_message(mid))["status"]  # type: ignore[index]
        await store.record_connection_event(
            connection="OB",
            transport="mllp",
            direction="outbound",
            kind="connection_lost",
            message_id=mid,
            reason="x",
            now=1.0,
        )
        assert await store.count_messages() == before
        assert (await store.get_message(mid))["status"] == status_before  # type: ignore[index]
    finally:
        await store.close()


async def test_retention_deletes_old_events(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "ce_ret.db")
    try:
        await store.record_connection_event(
            connection="IB",
            transport="mllp",
            direction="inbound",
            kind="established",
            now=100.0,
        )
        await store.record_connection_event(
            connection="IB",
            transport="mllp",
            direction="inbound",
            kind="closed",
            now=200.0,
        )
        deleted = await store.purge_connection_events(older_than=150.0)
        assert deleted == 1
        remaining = await store.list_connection_events()
        assert [e.kind for e in remaining] == ["closed"]
    finally:
        await store.close()
