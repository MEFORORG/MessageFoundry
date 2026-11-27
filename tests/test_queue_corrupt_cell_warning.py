# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A queue-tag refusal's WARNING carries no text of the cipher's (BACKLOG #5982).

A :class:`CorruptQueueCellError` names the cipher's own refusal, for example ``malformed
ciphertext (bad base64, key_id=...)``. Its report names the row, its stage and the cause in
:data:`QUEUE_TAG_CAUSES`'s words, and no record carries the cipher's reason. The claims'
dead-letter WARNINGs are covered in tests/test_claim_transient_open.py. Synthetic data only.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from messagefoundry.store.crypto import AesGcmCipher, CipherError, generate_key, make_cipher
from messagefoundry.store.queue_tag import (
    CorruptQueueCellError,
    QueueTagError,
    alert_queue_tag_failure,
    open_queue_cell,
    queue_row_aad,
    unopenable_log_text,
)

#: Words only the cipher's own refusal texts hold, never the queue-tag report's.
_CIPHER_WORDS = ("malformed ciphertext", "key_id=")


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


def _cipher_texts(records: list[logging.LogRecord]) -> list[str]:
    return [r.getMessage() for r in records if any(w in r.getMessage() for w in _CIPHER_WORDS)]


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
    assert _cipher_texts(caplog.records) == []  # at any level, DEBUG included
    assert len(seen) == 1 and not any(word in seen[0] for word in _CIPHER_WORDS), seen


def test_unopenable_log_text_names_a_queue_tag_refusal_by_class_and_cause() -> None:
    corrupt = CorruptQueueCellError("corrupt (malformed ciphertext (bad base64, key_id='ab'))")
    assert unopenable_log_text(corrupt) == "CorruptQueueCellError (cause corrupt)"
    drift = QueueTagError("integrity: does not open under its own tag (key_id='ab')", cause="tag")
    assert unopenable_log_text(drift) == "QueueTagError (cause tag)"
    # Control: an error that is not a queue-tag refusal keeps its text, as before.
    other = CipherError("no configured key decrypts this value (key_id='ab')")
    assert unopenable_log_text(other) == str(other)
