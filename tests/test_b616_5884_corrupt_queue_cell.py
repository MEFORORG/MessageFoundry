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

from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import (
    QUEUE_CORRUPT_SUBJECT,
    QUEUE_TAG_SUBJECT,
    alert_cell_tag_failure,
)
from messagefoundry.store.crypto import (
    AesGcmCipher,
    CipherError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import (
    QUEUE_CORRUPT_ALERT_TABLE,
    QUEUE_TAG_CAUSES,
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
    # BACKLOG #5982: the cipher's error is named by class, never chained, so no traceback prints it.
    assert "(UnauthenticatedCipherError)" in str(moved.value) and "key_id" not in str(moved.value)
    assert moved.value.__cause__ is None and moved.value.__context__ is None

    for cause, payload in _corrupt_payloads(cipher, key_b64, sealed).items():
        assert cipher.holds_key_for(payload)  # the marker still names a held key
        with pytest.raises(CipherError, match=cause):  # control: the cipher's own reason
            cipher.decrypt(payload, aad=queue_row_aad(row))
        with pytest.raises(CorruptQueueCellError, match="is corrupt") as corrupt:
            open_queue_cell(cipher, {**row, "payload": payload})
        assert not corrupt.value.drift
        assert isinstance(corrupt.value, QueueTagError)  # still contained as one
        assert cause not in str(corrupt.value) and corrupt.value.__cause__ is None


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

    # Neither of the drift verdicts above claims more than the cipher said: only the AEAD failure
    # names the tag; the other cannot say whether the cell is corrupt or moved.
    for text, cause in zip(verdicts, ("unknown", "tag"), strict=True):
        transit.error = InvalidRequest(errors=[text])
        with pytest.raises(QueueTagError) as refused:
            open_queue_cell(cipher, row)
        assert refused.value.cause == cause, text


def test_a_contradictory_cause_is_refused() -> None:
    with pytest.raises(ValueError, match="cause"):
        CorruptQueueCellError("c", cause="tag")
    with pytest.raises(ValueError, match="cause"):
        QueueTagError("t", cause="corrupt")


def test_each_refusal_names_only_the_cause_the_code_knows() -> None:
    """The audit detail's ``cause`` and the alert's words say what the raise site knows, never
    ``tag`` for a refusal no tag check made (BACKLOG #5884)."""
    cipher, _key_b64, seen = _cipher_and_hook()
    row = _row()
    sealed = cipher.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
    ref_row = _row(body_ref="a" * 64)
    sealed_ref = cipher.encrypt("a" * 64, aad=queue_row_aad(ref_row))
    keyless = make_cipher(None)
    cases: list[tuple[Any, dict[str, Any], str]] = [
        (cipher, {**row, "channel_id": "IB_B", "payload": sealed}, "tag"),
        (cipher, {**row, "payload": ""}, "blank"),
        (cipher, {**ref_row, "body_ref": "b" * 64, "payload": sealed_ref}, "ref"),
        (keyless, {**ref_row, "body_ref": "b" * 64, "payload": "a" * 64}, "ref-unsealed"),
    ]
    for case_cipher, case_row, expected in cases:
        with pytest.raises(QueueTagError) as refused:
            open_queue_cell(case_cipher, case_row)
        assert refused.value.cause == expected, expected
        sink = _Sink()
        seen.clear()
        asyncio.run(report_queue_tag_failure(sink, cipher, case_row, error=refused.value))
        assert json.loads(sink.details[0])["cause"] == expected
        words = QUEUE_TAG_CAUSES[refused.value.cause]
        assert seen == [f"a outbound queue row {words} and was dead-lettered (row row-5884)"]
        if expected != "tag":
            assert "integrity tag" not in seen[0]
    # A QueueTagError raised with no cause claims nothing it does not know.
    assert QueueTagError("t").cause == "unknown"
    assert CorruptQueueCellError("t").cause == "corrupt"


async def test_a_corrupt_alert_does_not_mute_a_drift_alert() -> None:
    """A corrupt cell's alert has its own subject, so the notifier's per-subject cooldown it
    starts never holds back a drift page raised at once after it (BACKLOG #5884)."""
    assert QUEUE_CORRUPT_ALERT_TABLE == QUEUE_CORRUPT_SUBJECT != QUEUE_TAG_SUBJECT

    class _Transport:
        name = "webhook"

        def __init__(self) -> None:
            self.events: list[dict[str, Any]] = []

        async def send(self, event: dict[str, Any], **_kw: Any) -> None:
            self.events.append(event)

    async def _pages(errors: list[QueueTagError]) -> list[str]:
        transport = _Transport()
        sink = NotifierAlertSink([transport], realert_seconds=3600.0)
        cipher, _key_b64, _seen = _cipher_and_hook()
        cipher.set_tag_failure_hook(
            lambda table, reason: alert_cell_tag_failure(sink, table, reason)
        )
        for error in errors:
            alert_queue_tag_failure(cipher, _row(), error=error, outcome="was dead-lettered")
        sink.start()
        await asyncio.sleep(0)
        await sink.aclose()
        return [str(event["connection"]) for event in transport.events]

    drift = QueueTagError("t", cause="tag")
    pages = await _pages([CorruptQueueCellError("c"), drift])
    assert pages == [QUEUE_CORRUPT_SUBJECT, QUEUE_TAG_SUBJECT]
    # Control: the cooldown is real, so a second drift page inside it is held back.
    assert await _pages([drift, drift]) == [QUEUE_TAG_SUBJECT]


def test_a_failed_audit_write_logs_no_exception_object(caplog: pytest.LogCaptureFixture) -> None:
    """The audit write's failure is logged by class and code only, with no ``exc_info``: through
    ``__context__`` the error can reach the claim frame and its opened bodies (BACKLOG #5884)."""
    caplog.set_level(logging.DEBUG, logger="messagefoundry.store.queue_tag")
    cipher, _key_b64, seen = _cipher_and_hook()

    class _FailingSink:
        async def record_audit(self, action: str, **_kw: Any) -> None:
            try:
                raise ValueError("SYNTH-OPENED-BODY")  # stands in for a claim frame's plaintext
            except ValueError:
                raise RuntimeError("driver said SYNTH-DRIVER-TEXT")  # noqa: B904 -- keeps context

    error = CorruptQueueCellError("c")
    asyncio.run(report_queue_tag_failure(_FailingSink(), cipher, _row(), error=error))
    assert len(seen) == 1  # the alert still fires
    failed = [r for r in caplog.records if "could not be written" in r.getMessage()]
    assert len(failed) == 1 and "RuntimeError" in failed[0].getMessage()
    assert failed[0].levelno == logging.ERROR
    for record in caplog.records:
        assert record.exc_info is None
        assert "SYNTH" not in record.getMessage()
        assert not any(isinstance(arg, BaseException) for arg in record.args or ())
