# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A queue-tag refusal carries no text of the cipher's (BACKLOG #5982).

The cipher's own refusal of a queue cell names at least a ``key_id`` cut from the stored value,
for example ``malformed ciphertext (bad base64, key_id=...)``. The :class:`QueueTagError`
:func:`open_queue_cell` raises for it names the cipher error's class only and chains nothing, so
neither its report, which names the row, its stage and the cause in :data:`QUEUE_TAG_CAUSES`'s
words, nor uvicorn's traceback of a read the API does not handle carries that text. The claims'
dead-letter WARNINGs are covered in tests/test_claim_transient_open.py. Synthetic data only.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import traceback
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

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
    # Control: the cipher's own refusal of this cell holds the words searched for below.
    with pytest.raises(CipherError, match="malformed ciphertext"):
        cipher.decrypt(_bad_base64(sealed), aad=queue_row_aad(row))
    with pytest.raises(CorruptQueueCellError) as corrupt:
        open_queue_cell(cipher, {**row, "payload": _bad_base64(sealed)})

    # The real refusal, and one built WITH the cipher's words, so the report itself is guarded:
    # the real one holds none of them, and a report that printed its error would pass on it.
    planted = CorruptQueueCellError("corrupt (malformed ciphertext (bad base64, key_id='ab'))")
    for error in (corrupt.value, planted):
        caplog.clear()
        seen.clear()
        alert_queue_tag_failure(cipher, row, error=error, outcome="the read was refused")

        warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warned) == 1 and "is corrupt" in warned[0], warned
        assert "row-5982-cor" in warned[0], warned
        assert _cipher_texts(caplog.records) == []  # at any level, DEBUG included
        assert len(seen) == 1 and not any(word in seen[0] for word in _CIPHER_WORDS), seen


def _refused_row(cipher: AesGcmCipher, kind: str) -> dict[str, Any]:
    """A row ``open_queue_cell`` refuses: a corrupt cell, or a cell sealed for another row."""
    row = _row()
    sealed = cipher.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
    if kind == "corrupt":
        return {**row, "payload": _bad_base64(sealed)}
    return {**row, "channel_id": "IB_MOVED", "payload": sealed}


@pytest.mark.parametrize("kind", ["corrupt", "tag"])
def test_a_queue_tag_refusal_carries_no_cipher_text_and_chains_nothing(kind: str) -> None:
    """The root of BACKLOG #5982 finding 3: the error itself is value-free, so no handler that
    prints it, its traceback or its chain can print the cipher's refusal."""
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    with pytest.raises(QueueTagError) as refused:
        open_queue_cell(cipher, _refused_row(cipher, kind))
    error = refused.value
    assert error.cause == kind
    assert not any(word in str(error) for word in _CIPHER_WORDS), str(error)
    # Raised outside the cipher's handler: no cause, and no context a traceback would print.
    assert error.__cause__ is None and error.__context__ is None
    printed = "".join(traceback.format_exception(error))
    assert type(error).__name__ in printed  # control: this is the error's own traceback
    assert not any(word in printed for word in _CIPHER_WORDS), printed


@pytest.mark.parametrize("kind", ["corrupt", "tag"])
async def test_an_unhandled_read_refusal_logs_no_cipher_text_under_uvicorn(
    kind: str, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5982 finding 1: a read refusal no route handles (``outbox_payloads_for`` re-raises
    a live row's :class:`QueueTagError`) reaches the app's catch-all, which answers 500, and
    Starlette then re-raises it to uvicorn, which logs its traceback at ERROR. Every record on the
    ROOT logger, at every level, is formatted with its traceback and searched."""
    caplog.set_level(logging.DEBUG)
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    row = _refused_row(cipher, kind)
    app = FastAPI()

    @app.exception_handler(Exception)
    async def _unhandled(_request: Request, exc: Exception) -> JSONResponse:
        # As the engine's own catch-all: the type only, and a generic 500.
        logging.getLogger("test.api").error("unhandled error: %s", type(exc).__name__)
        return JSONResponse({"detail": "internal error"}, status_code=500)

    @app.get("/read")
    async def _read() -> str:
        return open_queue_cell(cipher, row)

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, lifespan="off"))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(500):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started
        # Loopback only, never through a proxy the runner's environment names.
        async with httpx.AsyncClient(trust_env=False) as client:
            answer = await client.get(f"http://127.0.0.1:{port}/read")
    finally:
        server.should_exit = True
        await serving
        sock.close()
    assert answer.status_code == 500
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    printed = [formatter.format(record) for record in caplog.records]
    # Control: uvicorn did log the refusal's traceback, so the search below can see one.
    raised = "CorruptQueueCellError" if kind == "corrupt" else "QueueTagError"
    assert any("Traceback" in p and f"{raised}:" in p for p in printed), printed
    leaked = [p for p in printed if any(word in p for word in _CIPHER_WORDS)]
    assert leaked == [], leaked
    assert not any("SYNTH-BODY" in p for p in printed)


def test_unopenable_log_text_names_a_queue_tag_refusal_by_class_and_cause() -> None:
    corrupt = CorruptQueueCellError("corrupt (malformed ciphertext (bad base64, key_id='ab'))")
    assert unopenable_log_text(corrupt) == "CorruptQueueCellError (cause corrupt)"
    drift = QueueTagError("integrity: does not open under its own tag (key_id='ab')", cause="tag")
    assert unopenable_log_text(drift) == "QueueTagError (cause tag)"
    # A plain cipher error, a key not held or a marker not parsed, is named by its class alone:
    # its text can echo a field cut from the stored value (finding 2).
    other = CipherError("no configured key decrypts this value (key_id='ab')")
    assert unopenable_log_text(other) == "CipherError"
