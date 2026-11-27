# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5650 added item 3: a value that is not text, a planted BLOB say, in a queue ``payload``
or in a cell a list-shaped read opens (``queue.last_error`` on ``GET /dead-letters``).

The store writes these cells as text only, so a non-text value was written outside the store. A
keyed cipher handed one raised ``TypeError``, which escaped every ``CipherError`` containment: a
claim did not dead-letter the row and a list read failed with an unhandled error. A keyless cipher
returned the bytes unchanged, so a non-text value reached the caller.

Now :func:`open_queue_cell` raises :class:`QueueTagError` with cause ``non-text``, drift, as a blank
payload is, so a claim dead-letters the row with its audit row and alert. :func:`open_listed_cell`
raises a :class:`CipherError`, which fails the read as every refusal other than a key the store does
not hold does (owner ruling 2026-11-19, BACKLOG #5970). Synthetic data only.
"""

from __future__ import annotations

import json
import pathlib
import sqlite3
from typing import Any

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStore
from messagefoundry.store.cell_tag import open_listed_cell
from messagefoundry.store.crypto import CipherError, cell_aad, generate_key, make_cipher
from messagefoundry.store.queue_tag import (
    QUEUE_TAG_CAUSES,
    QUEUE_TAG_FAILED_ACTION,
    QueueTagError,
    open_queue_cell,
)

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG5650|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
BLOB = b"PLANTED-5650"


def _row(**changes: Any) -> dict[str, Any]:
    return {
        "id": "row-5650",
        "message_id": "msg-5650",
        "stage": "outbound",
        "channel_id": "IB_A",
        "destination_name": "OB_A",
        "handler_name": None,
        "body_ref": None,
        **changes,
    }


@pytest.mark.parametrize("keyed", [True, False], ids=["keyed", "keyless"])
@pytest.mark.parametrize("body_ref", [None, "a" * 64], ids=["inline", "ref"])
def test_a_non_text_queue_payload_is_a_queue_tag_error(keyed: bool, body_ref: str | None) -> None:
    cipher = make_cipher(generate_key() if keyed else None, write_v2=True)
    with pytest.raises(QueueTagError) as refused:
        open_queue_cell(cipher, _row(payload=BLOB, body_ref=body_ref))
    assert refused.value.drift and refused.value.cause == "non-text"
    assert refused.value.cause in QUEUE_TAG_CAUSES
    assert "PLANTED" not in str(refused.value)


@pytest.mark.parametrize("keyed", [True, False], ids=["keyed", "keyless"])
def test_a_non_text_listed_cell_fails_the_read_as_a_cipher_error(keyed: bool) -> None:
    cipher = make_cipher(generate_key() if keyed else None, write_v2=True)
    aad = cell_aad("queue", "last_error", "row-5650")
    with pytest.raises(CipherError) as refused:
        open_listed_cell(cipher, BLOB, aad, table="queue")
    assert "PLANTED" not in str(refused.value)
    # CONTROL: the same open of a text cell the cipher wrote still opens.
    assert open_listed_cell(cipher, cipher.encrypt("boom", aad=aad), aad, table="queue") == "boom"


def _plant(db: pathlib.Path, column: str) -> None:
    side = sqlite3.connect(db, timeout=30)  # a writer with no key, outside the store
    try:
        side.execute(f"UPDATE queue SET {column}=? WHERE stage='outbound'", (BLOB,))
        side.commit()
    finally:
        side.close()


async def test_a_planted_blob_payload_is_dead_lettered_by_the_claim(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "blob_payload.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        await store.enqueue_message(
            channel_id="IB_A", raw=RAW, deliveries=[("OB_A", "p")], now=10.0
        )
        _plant(db, "payload")
        assert await store.claim_ready(now=10.0, destination_name="OB_A") == []
        dead = await store.list_dead(allowed_channels=None)
        assert [d["destination_name"] for d in dead] == ["OB_A"]
    finally:
        await store.close()
    # The claim dead-lettered the row before the fix too, through its catch-all for an
    # undecryptable row, but as a TypeError: no tag-failed audit row and no alert.
    side = sqlite3.connect(db, timeout=30)
    try:
        details = [
            json.loads(d)
            for (d,) in side.execute(
                "SELECT detail FROM audit_log WHERE action=?", (QUEUE_TAG_FAILED_ACTION,)
            )
        ]
    finally:
        side.close()
    assert [d["cause"] for d in details] == ["non-text"]


async def test_a_planted_blob_last_error_fails_the_dead_letter_list_as_a_cipher_error(
    tmp_path: pathlib.Path,
) -> None:
    db = tmp_path / "blob_last_error.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        await store.enqueue_message(
            channel_id="IB_A", raw=RAW, deliveries=[("OB_A", "p")], now=10.0
        )
        item = (await store.claim_ready(now=10.0, destination_name="OB_A"))[0]
        await store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1), now=10.0)
        # CONTROL: the dead letter lists before the plant.
        assert len(await store.list_dead(allowed_channels=None)) == 1
        _plant(db, "last_error")
        with pytest.raises(CipherError):
            await store.list_dead(allowed_channels=None)
    finally:
        await store.close()
