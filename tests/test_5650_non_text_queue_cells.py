# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5650 added item 3: a value that is not text, a planted BLOB say, in a queue ``payload``
or in a cell a list-shaped read opens (``queue.last_error`` on ``GET /dead-letters``).

The store writes these cells as text only, so a non-text value was written outside the store. A
keyed cipher handed one raised ``TypeError``, which escaped every ``CipherError`` containment: a
claim dead-lettered the row only through its catch-all, with no tag-failed audit row and no alert,
and a list read failed with an unhandled ``TypeError``. A keyless cipher returned the bytes
unchanged, so a claim handed them to delivery and a list read handed them back.

Now :func:`open_queue_cell` raises :class:`QueueTagError` with cause ``non-text``, drift, as a blank
payload is, so a claim dead-letters the row with its audit row, and on a keyed store its alert (a
keyless cipher has no alert hook). :func:`open_listed_cell` raises
:class:`NonTextListedCellError`, a :class:`CipherError`, which fails the read as every refusal other
than a key the store does not hold does (owner ruling 2026-11-19, BACKLOG #5970). Synthetic data
only.
"""

from __future__ import annotations

import json
import pathlib
import sqlite3
from typing import Any

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStore
from messagefoundry.store.cell_tag import NonTextListedCellError, open_listed_cell
from messagefoundry.store.crypto import (
    AesGcmCipher,
    CipherError,
    cell_aad,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import (
    QUEUE_TAG_CAUSES,
    QUEUE_TAG_FAILED_ACTION,
    QueueTagError,
    open_queue_cell,
    queue_row_aad,
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
    # CONTROL: a text payload the cipher sealed for the same row still opens.
    row = _row(body_ref=body_ref)
    sealed = cipher.encrypt(body_ref or "SYNTH-BODY", aad=queue_row_aad(row))
    assert open_queue_cell(cipher, {**row, "payload": sealed}) == (body_ref or "SYNTH-BODY")


@pytest.mark.parametrize("keyed", [True, False], ids=["keyed", "keyless"])
def test_a_non_text_listed_cell_fails_the_read_as_a_cipher_error(keyed: bool) -> None:
    cipher = make_cipher(generate_key() if keyed else None, write_v2=True)
    aad = cell_aad("queue", "last_error", "row-5650")
    with pytest.raises(NonTextListedCellError) as refused:
        open_listed_cell(cipher, BLOB, aad, table="queue")
    # A CipherError, so the read fails as every refusal but a key not held does (#5970).
    assert isinstance(refused.value, CipherError) and "PLANTED" not in str(refused.value)
    # CONTROL: the same open of a text cell the cipher wrote still opens.
    assert open_listed_cell(cipher, cipher.encrypt("boom", aad=aad), aad, table="queue") == "boom"


def _plant(db: pathlib.Path, column: str, message_id: str) -> None:
    side = sqlite3.connect(db, timeout=30)  # a writer with no key, outside the store
    try:
        side.execute(
            f"UPDATE queue SET {column}=? WHERE stage='outbound' AND message_id=?",
            (BLOB, message_id),
        )
        side.commit()
    finally:
        side.close()


@pytest.mark.parametrize("keyed", [True, False], ids=["keyed", "keyless"])
async def test_a_planted_blob_payload_is_dead_lettered_by_the_claim(
    tmp_path: pathlib.Path, keyed: bool
) -> None:
    db = tmp_path / "blob_payload.db"
    cipher = make_cipher(generate_key() if keyed else None, write_v2=True)
    alerts: list[str] = []
    if keyed:
        assert isinstance(cipher, AesGcmCipher)
        cipher.set_tag_failure_hook(lambda _table, reason: alerts.append(reason))
    store = await MessageStore.open(db, cipher=cipher)
    try:
        planted = await store.enqueue_message(
            channel_id="IB_A", raw=RAW, deliveries=[("OB_A", "p")], now=10.0
        )
        kept = await store.enqueue_message(
            channel_id="IB_A", raw=RAW, deliveries=[("OB_A", "q")], now=10.0
        )
        _plant(db, "payload", planted)
        # CONTROL: the text row claimed beside it is still delivered.
        claimed = await store.claim_ready(now=10.0, destination_name="OB_A")
        assert [(c.message_id, c.payload) for c in claimed] == [(kept, "q")]
        dead = await store.list_dead(allowed_channels=None)
        assert [d["message_id"] for d in dead] == [planted]
    finally:
        await store.close()
    # A keyed claim dead-lettered the row before the fix too, through its catch-all for an
    # undecryptable row, but as a TypeError: no tag-failed audit row and no alert. A keyless claim
    # delivered the bytes.
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
    words = QUEUE_TAG_CAUSES["non-text"]
    assert len(alerts) == (1 if keyed else 0) and all(words in a for a in alerts), alerts


@pytest.mark.parametrize("keyed", [True, False], ids=["keyed", "keyless"])
async def test_a_planted_blob_last_error_fails_the_dead_letter_list_as_a_cipher_error(
    tmp_path: pathlib.Path, keyed: bool
) -> None:
    db = tmp_path / "blob_last_error.db"
    cipher = make_cipher(generate_key() if keyed else None, write_v2=True)
    store = await MessageStore.open(db, cipher=cipher)
    try:
        mid = await store.enqueue_message(
            channel_id="IB_A", raw=RAW, deliveries=[("OB_A", "p")], now=10.0
        )
        item = (await store.claim_ready(now=10.0, destination_name="OB_A"))[0]
        await store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1), now=10.0)
        # CONTROL: the dead letter lists before the plant.
        assert len(await store.list_dead(allowed_channels=None)) == 1
        _plant(db, "last_error", mid)
        with pytest.raises(NonTextListedCellError):
            await store.list_dead(allowed_channels=None)
    finally:
        await store.close()
