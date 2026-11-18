# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A corrupt queue payload under a held key is not drift (BACKLOG #5884).

Bad base64, a ciphertext too short for a tag, and a plaintext whose tag verified but is not UTF-8
say the cell is unreadable, not that it was sealed for another row. They raise
:class:`CorruptQueueCellError`, which every claim and read still contains as a
:class:`QueueTagError`, but which writes no tag-failed audit row and raises no
``integrity_drift`` alert, as the tagged-cell path's ``CorruptCellError`` does. Synthetic data only.
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from messagefoundry.store.crypto import (
    AesGcmCipher,
    UnauthenticatedCipherError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import (
    CorruptQueueCellError,
    QueueTagError,
    alert_queue_tag_failure,
    open_queue_cell,
    queue_row_aad,
    report_queue_tag_failure,
)


def _row(**changes: Any) -> dict[str, Any]:
    return {
        "id": "row-5884",
        "message_id": "msg-5884",
        "stage": "outbound",
        "channel_id": "IB_A",
        "destination_name": "OB_A",
        "handler_name": None,
        "body_ref": None,
        **changes,
    }


class _Sink:
    def __init__(self) -> None:
        self.audits: list[str] = []

    async def record_audit(self, action: str, **_kw: Any) -> None:
        self.audits.append(action)


def _cipher_and_hook() -> tuple[AesGcmCipher, str, list[str]]:
    key_b64 = generate_key()
    cipher = make_cipher(key_b64, write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    seen: list[str] = []
    cipher.set_tag_failure_hook(lambda _table, reason: seen.append(reason))
    return cipher, key_b64, seen


def _corrupt_payloads(cipher: AesGcmCipher, key_b64: str, sealed: str) -> dict[str, str]:
    marker = sealed.rsplit(":", 1)[0]
    # v1 seals with no associated data, so a hand-built value can hold bytes that are not UTF-8.
    key_id = make_cipher(key_b64).encrypt("x").split(":")[2]
    nonce = bytes(12)
    blob = AESGCM(base64.b64decode(key_b64)).encrypt(nonce, b"SYNTH" + bytes([0xFF]), None)
    return {
        "bad base64": f"{marker}:AAAAA",  # five characters cannot decode
        "too short": f"{marker}:AAAA",
        "not valid UTF-8": f"mfenc:v1:{key_id}:{base64.b64encode(nonce + blob).decode('ascii')}",
    }


def test_a_corrupt_payload_under_a_held_key_is_corrupt_not_drift() -> None:
    cipher, key_b64, _seen = _cipher_and_hook()
    row = _row()
    sealed = cipher.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
    assert open_queue_cell(cipher, {**row, "payload": sealed}) == "SYNTH-BODY"  # control

    # Control: a cell sealed for another row is drift, not corruption.
    with pytest.raises(QueueTagError) as moved:
        open_queue_cell(cipher, {**row, "channel_id": "IB_B", "payload": sealed})
    assert type(moved.value) is QueueTagError and moved.value.drift
    assert isinstance(moved.value.__cause__, UnauthenticatedCipherError)

    for cause, payload in _corrupt_payloads(cipher, key_b64, sealed).items():
        assert cipher.holds_key_for(payload)  # the marker still names a held key
        with pytest.raises(CorruptQueueCellError, match="is corrupt") as corrupt:
            open_queue_cell(cipher, {**row, "payload": payload})
        assert not corrupt.value.drift
        assert isinstance(corrupt.value, QueueTagError)  # still contained as one
        assert cause in str(corrupt.value.__cause__)


def test_a_corrupt_payload_is_logged_never_audited_or_alerted() -> None:
    cipher, key_b64, seen = _cipher_and_hook()
    row = _row()
    sealed = cipher.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
    sink = _Sink()
    for payload in _corrupt_payloads(cipher, key_b64, sealed).values():
        with pytest.raises(CorruptQueueCellError) as corrupt:
            open_queue_cell(cipher, {**row, "payload": payload})
        asyncio.run(report_queue_tag_failure(sink, cipher, row, error=corrupt.value))
        alert_queue_tag_failure(cipher, row, error=corrupt.value, outcome="the read was refused")
    assert sink.audits == [] and seen == []

    # Control: drift is still audited and alerted.
    with pytest.raises(QueueTagError) as moved:
        open_queue_cell(cipher, {**row, "channel_id": "IB_B", "payload": sealed})
    asyncio.run(report_queue_tag_failure(sink, cipher, row, error=moved.value))
    assert sink.audits == ["integrity.queue_tag_failed"] and len(seen) == 1
