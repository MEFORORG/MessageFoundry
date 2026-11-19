# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A corrupt queue payload under a held key is not drift (BACKLOG #5884).

Bad base64, a ciphertext too short for a tag, and a plaintext whose tag verified but is not UTF-8
say the cell is unreadable, not that it was sealed for another row. They raise
:class:`CorruptQueueCellError`, which every claim and read still contains as a
:class:`QueueTagError`, and which keeps its tag-failed audit row and ``integrity_drift`` alert,
each saying corrupt rather than drift. Synthetic data only.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
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
        self.details: list[str] = []

    async def record_audit(self, action: str, *, detail: str | None = None, **_kw: Any) -> None:
        self.audits.append(action)
        self.details.append(detail or "")


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


def test_a_corrupt_payload_keeps_its_audit_and_alert_naming_no_payload(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="messagefoundry.store.queue_tag")
    cipher, key_b64, seen = _cipher_and_hook()
    row = _row()
    sealed = cipher.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
    corrupt_payloads = _corrupt_payloads(cipher, key_b64, sealed)
    for payload in corrupt_payloads.values():
        sink = _Sink()
        seen.clear()
        with pytest.raises(CorruptQueueCellError) as corrupt:
            open_queue_cell(cipher, {**row, "payload": payload})
        asyncio.run(report_queue_tag_failure(sink, cipher, row, error=corrupt.value))
        # Exactly one audit row, saying corrupt, and one alert, saying corrupt.
        assert sink.audits == ["integrity.queue_tag_failed"]
        assert json.loads(sink.details[0])["cause"] == "corrupt"
        assert len(seen) == 1 and "is corrupt" in seen[0] and "SYNTH" not in seen[0]
        assert "SYNTH" not in sink.details[0]
        # The read path alerts with no audit row, as drift does there.
        alert_queue_tag_failure(cipher, row, error=corrupt.value, outcome="the read was refused")
        assert sink.audits == ["integrity.queue_tag_failed"] and len(seen) == 2
    corrupt_records = [r for r in caplog.records if "is corrupt" in r.getMessage()]
    assert len(corrupt_records) == 2 * len(corrupt_payloads)
    for record in corrupt_records:
        assert "outbound" in record.getMessage() and "SYNTH" not in record.getMessage()
        # A record keeps its args, and an exception's traceback keeps the claim frame's locals.
        assert all(isinstance(arg, str) for arg in record.args or ())
        assert record.exc_info is None

    # Control: drift is still audited and alerted, and its cause says so.
    sink = _Sink()
    seen.clear()
    with pytest.raises(QueueTagError) as moved:
        open_queue_cell(cipher, {**row, "channel_id": "IB_B", "payload": sealed})
    asyncio.run(report_queue_tag_failure(sink, cipher, row, error=moved.value))
    assert sink.audits == ["integrity.queue_tag_failed"] and len(seen) == 1
    assert json.loads(sink.details[0])["cause"] == "tag"
    assert "failed its integrity tag" in seen[0]


def test_a_real_transit_cipher_verdict_stays_drift() -> None:
    """The corrupt-vs-drift split reads only ``holds_key_for``. A real :class:`TransitCipher` has
    none, so a Transit verdict that is not an AEAD failure still reads as drift."""
    pytest.importorskip("hvac")
    from hvac.exceptions import InvalidRequest  # type: ignore[import-untyped]  # noqa: PLC0415

    from messagefoundry.store.crypto_transit import TransitCipher  # noqa: PLC0415

    class _Transit:
        error: Exception | None = None

        def decrypt_data(self, **_kw: Any) -> Any:
            assert self.error is not None
            raise self.error

    class _Client:
        def __init__(self, transit: _Transit) -> None:
            self.secrets = type("S", (), {"transit": transit})()

    transit = _Transit()
    cipher = TransitCipher(_Client(transit), "mefor-store")
    assert not callable(getattr(cipher, "holds_key_for", None))
    row = {**_row(), "payload": "mfenc:v3:vault:v1:AAAA"}
    verdicts = [
        "ciphertext version is disallowed by policy (too old)",  # not an AEAD failure
        "cipher: message authentication failed",  # control: an AEAD failure
    ]
    for text in verdicts:
        transit.error = InvalidRequest(errors=[text])
        with pytest.raises(QueueTagError) as refused:
            open_queue_cell(cipher, row)
        assert type(refused.value) is QueueTagError and refused.value.drift, text

    # Positive control: the same non-AEAD verdict from a cipher that DOES name its keys is corrupt,
    # so the split above is the missing ``holds_key_for`` and nothing else.
    class _Naming(TransitCipher):
        def holds_key_for(self, stored: str) -> bool:
            return True

    naming = _Naming(_Client(transit), "mefor-store")
    transit.error = InvalidRequest(errors=[verdicts[0]])
    with pytest.raises(CorruptQueueCellError):
        open_queue_cell(naming, row)
