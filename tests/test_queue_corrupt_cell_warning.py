# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A corrupt queue cell's WARNING carries no text of the cipher's (BACKLOG #5982).

A :class:`CorruptQueueCellError` names the cipher's own refusal, for example ``malformed
ciphertext (bad base64, key_id=...)``. Its report and a claim's dead-letter WARNING name the row,
its stage and the cause in :data:`QUEUE_TAG_CAUSES`'s words, and the cipher's reason goes to a
DEBUG record only. Synthetic data only.
"""

from __future__ import annotations

import json
import logging
import pathlib
import sqlite3
from typing import Any

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import AesGcmCipher, generate_key, make_cipher
from messagefoundry.store.queue_tag import (
    QUEUE_TAG_FAILED_ACTION,
    CorruptQueueCellError,
    QueueTagError,
    alert_queue_tag_failure,
    open_queue_cell,
    queue_row_aad,
    unopenable_log_text,
)
from messagefoundry.store.store import OutboxStatus, Stage

#: Words only the cipher's own refusal texts hold, never the queue-tag report's.
_CIPHER_WORDS = ("malformed ciphertext", "key_id=")

_RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|QC1|P|2.5.1\rPID|1||SYNTH-100||DOE^JANE\r"


def _row(**changes: Any) -> dict[str, Any]:
    return {
        "id": "row-5982-corrupt",
        "message_id": "msg-5982",
        "stage": "outbound",
        "channel_id": "IB_C",
        "destination_name": "OB_C",
        "handler_name": None,
        "body_ref": None,
        **changes,
    }


def _bad_base64(sealed: str) -> str:
    """``sealed`` with its ciphertext replaced by five characters, which cannot decode. The marker
    still names the held key, so the cipher refuses it as corrupt rather than unknown."""
    return f"{sealed.rsplit(':', 1)[0]}:AAAAA"


def _cipher_texts(records: list[logging.LogRecord], level: int) -> list[str]:
    return [
        r.getMessage()
        for r in records
        if r.levelno == level and any(word in r.getMessage() for word in _CIPHER_WORDS)
    ]


def test_a_corrupt_cell_alert_warns_without_the_ciphers_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry.store.queue_tag")
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    seen: list[str] = []
    cipher.set_tag_failure_hook(lambda _table, reason: seen.append(reason))
    row = _row()
    sealed = cipher.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
    with pytest.raises(CorruptQueueCellError) as corrupt:
        open_queue_cell(cipher, {**row, "payload": _bad_base64(sealed)})
    assert "malformed ciphertext" in str(corrupt.value)  # control: the error does hold the text

    alert_queue_tag_failure(cipher, row, error=corrupt.value, outcome="the read was refused")

    warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warned) == 1 and "is corrupt" in warned[0] and "row-5982-cor" in warned[0], warned
    assert _cipher_texts(caplog.records, logging.WARNING) == []
    # The cipher's reason is still on record for a reader who turns DEBUG on.
    assert len(_cipher_texts(caplog.records, logging.DEBUG)) == 1, caplog.records
    assert len(seen) == 1 and not any(word in seen[0] for word in _CIPHER_WORDS), seen


def test_unopenable_log_text_names_a_corrupt_cell_by_its_class_alone() -> None:
    corrupt = CorruptQueueCellError("corrupt (malformed ciphertext (bad base64, key_id='ab'))")
    assert unopenable_log_text(corrupt) == "CorruptQueueCellError"
    # Control: any other refusal keeps its text, as before.
    drift = QueueTagError("integrity: does not open under its own tag (key_id='ab')", cause="tag")
    assert unopenable_log_text(drift) == str(drift)


async def test_a_claim_of_a_corrupt_cell_warns_without_the_ciphers_text(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    db = tmp_path / "corrupt-cell.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key(), write_v2=True))
    side = sqlite3.connect(db, timeout=30)  # a writer with no key, outside the store
    side.row_factory = sqlite3.Row
    try:
        mid = await store.enqueue_message(
            channel_id="IB_QC", raw=_RAW, deliveries=[("OB_QC", "SYNTH-BODY-C")]
        )
        [row] = side.execute(
            "SELECT id, payload FROM queue WHERE message_id=? AND stage=?",
            (mid, Stage.OUTBOUND.value),
        ).fetchall()
        side.execute(
            "UPDATE queue SET payload=? WHERE id=?", (_bad_base64(row["payload"]), row["id"])
        )
        side.commit()
        caplog.clear()

        assert await store.claim_next_fifo("OB_QC") is None

        [after] = side.execute("SELECT status FROM queue WHERE id=?", (row["id"],)).fetchall()
        assert after["status"] == OutboxStatus.DEAD.value
        audited = side.execute(
            "SELECT detail FROM audit_log WHERE action=?", (QUEUE_TAG_FAILED_ACTION,)
        ).fetchall()
        assert [json.loads(a["detail"])["cause"] for a in audited] == ["corrupt"], audited
        warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("CorruptQueueCellError" in m and row["id"] in m for m in warned), warned
        assert _cipher_texts(caplog.records, logging.WARNING) == []
        assert _cipher_texts(caplog.records, logging.DEBUG), (
            caplog.records
        )  # the instrument sees it
    finally:
        side.close()
        await store.close()
