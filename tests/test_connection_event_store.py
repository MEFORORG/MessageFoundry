# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""P1a — the `connection_event` store layer (Corepoint-style transport/lifecycle log, #46).

Covers the invariants the design review flagged as load-bearing: metadata-only + `reason`
encrypted at rest, the nullable NO-FK `message_id`, count-and-log isolation (a connection event
never inflates message counts or touches disposition), and age-based retention.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from messagefoundry.store.crypto import MARKER_PREFIX, generate_key, make_cipher
from messagefoundry.store.store import MessageStore

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
# 48 lowercase words, 329 characters, none of which the redactor rewrites.
_WORDS = ("after", "partial", "read", "of", "segment", "terminator", "framing", "error")
_LONG_REASON = " ".join(_WORDS[i % len(_WORDS)] for i in range(48))
_TRUNCATION_NOTE = re.compile(r"…\(\+(\d+) chars\)\Z")


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
        events = await store.list_connection_events(allowed_channels=None)
        # newest-first by ts
        assert [e.kind for e in events] == ["closed", "connection_lost", "established"]
        lost = events[1]
        assert lost.direction == "outbound" and lost.message_id == "m-1"
        assert lost.reason == "connect refused"
        # filters
        ib = await store.list_connection_events(connection="IB_ACME_ADT", allowed_channels=None)
        assert {e.kind for e in ib} == {"established", "closed"}
        kinds = await store.list_connection_events(kinds=["established"], allowed_channels=None)
        assert [e.kind for e in kinds] == ["established"]
        since = await store.list_connection_events(since=175.0, allowed_channels=None)
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
            reason="boom!",
            now=1.0,
        )
        # the metadata-only non-PHI columns stay plaintext; reason is ciphertext on disk…
        assert _col_at_rest(db, "kind") == "framing_error"
        assert _col_at_rest(db, "connection") == "IB"
        reason_disk = _col_at_rest(db, "reason")
        # The version-agnostic marker: which columns are enciphered is the claim, not which mfenc
        # format the writer emits. That is the cipher's choice — v1 from make_cipher's default here,
        # v2 via build_cipher (write_v2=[store].aad_bind) or under MEFOR_TEST_FORCE_AAD_BIND.
        assert isinstance(reason_disk, str) and reason_disk.startswith(MARKER_PREFIX)
        # '!' is outside the base64 alphabet, so this fails only on real plaintext; a bare "boom" can
        # turn up in random ciphertext by chance (the rule in tests/test_store_encryption.py).
        assert "boom!" not in reason_disk
        # …and the read path decrypts it back
        events = await store.list_connection_events(allowed_channels=None)
        assert events[0].reason == "boom!"
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
        events = await store.list_connection_events(allowed_channels=None)
        assert "DOE" not in (events[0].reason or "")  # PID segment scrubbed by safe_text (#120)
    finally:
        await store.close()


async def test_reason_truncated(tmp_path: Path) -> None:
    # The store bounds `reason` with safe_text(reason, limit=200) (BACKLOG #1797). That keeps a head
    # of at most 200 characters, cut back to a whole token, then appends the truncation note
    # (_TRUNCATION_NOTE). So the stored value can be longer than 200. A one-token input keeps no head
    # at all (the next test). Here "terminator" spans 195 to 205, so it straddles the bound and goes.
    store = await MessageStore.open(tmp_path / "ce_trunc.db")
    try:
        await store.record_connection_event(
            connection="IB",
            transport="mllp",
            direction="inbound",
            kind="framing_error",
            reason=_LONG_REASON,
            now=1.0,
        )
        events = await store.list_connection_events(allowed_channels=None)
    finally:
        await store.close()
    reason = events[0].reason
    assert reason is not None
    note = _TRUNCATION_NOTE.search(reason)
    assert note is not None, f"the truncation note was cut: {reason[-20:]!r}"
    head = reason[: note.start()]
    assert 0 < len(head) <= 200
    # Whole tokens: the head is a prefix of the input, and a space follows it there...
    assert _LONG_REASON.startswith(head) and _LONG_REASON[len(head)] == " "
    # ...and the token after it is the one that straddles the bound, so nothing more could fit.
    assert _LONG_REASON.index(" ", len(head) + 1) > 200
    # The count is every character held back, so head plus count is the whole input.
    assert len(head) + int(note.group(1)) == len(_LONG_REASON)
    # Not a hard 200: the note rides past the bound, and nothing slices it off.
    assert len(reason) > 200


async def test_reason_one_long_token_keeps_no_head(tmp_path: Path) -> None:
    # The other edge: a token longer than the bound has no whole-token prefix, so none of it is kept.
    store = await MessageStore.open(tmp_path / "ce_token.db")
    try:
        await store.record_connection_event(
            connection="IB",
            transport="mllp",
            direction="inbound",
            kind="framing_error",
            reason="x" * 500,
            now=1.0,
        )
        events = await store.list_connection_events(allowed_channels=None)
    finally:
        await store.close()
    assert events[0].reason == "…(+500 chars)"


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
        events = await store.list_connection_events(allowed_channels=None)
        assert {e.message_id for e in events} == {None, "does-not-exist"}
    finally:
        await store.close()


async def test_does_not_inflate_counts_or_change_disposition(tmp_path: Path) -> None:
    # Count-and-log invariant: a connection_event row (even one whose message_id is a real message)
    # writes no messages/queue row, so message counts and disposition are untouched.
    store = await MessageStore.open(tmp_path / "ce_count.db")
    try:
        mid = await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("d", ADT)])
        before = await store.count_messages(allowed_channels=None)
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
        assert await store.count_messages(allowed_channels=None) == before
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
        remaining = await store.list_connection_events(allowed_channels=None)
        assert [e.kind for e in remaining] == ["closed"]
    finally:
        await store.close()
