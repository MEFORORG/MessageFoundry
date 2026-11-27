# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A refused queue cell carries no text of the cipher's (BACKLOG #5982).

The cipher's own refusal of a queue cell names at least a ``key_id`` cut from the stored value,
for example ``malformed ciphertext (bad base64, key_id=...)``. What :func:`open_queue_cell` raises
for a refused marked cell, a :class:`QueueTagError` or the cipher's own class rebuilt, names the
cipher error's class and a fixed code only and chains nothing, and is held in no reference cycle.
So neither a queue-tag report, which names the row, its stage and the cause in
:data:`QUEUE_TAG_CAUSES`'s words, nor uvicorn's traceback of a read the API does not handle
carries that text. The claims' dead-letter WARNINGs are covered in
tests/test_claim_transient_open.py. Synthetic data only.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import re
import socket
import traceback
import weakref
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from messagefoundry.store.crypto import (
    AesGcmCipher,
    CipherError,
    UnauthenticatedCipherError,
    UnmarkedCipherError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import (
    CorruptQueueCellError,
    QueueTagError,
    alert_queue_tag_failure,
    is_transient_open_failure,
    open_queue_cell,
    queue_row_aad,
    unopenable_log_text,
)
from tests.test_queue_tag import _raising_transit

#: Words only the cipher's own refusal texts hold, never the queue-tag report's.
_CIPHER_WORDS = ("malformed ciphertext", "key_id=", "no configured key", "at-rest marker")

#: Each kind of refused cell :func:`_refused_row` builds, with the class ``open_queue_cell``
#: raises for it and the fixed code its message names in place of the cipher's text.
_REFUSALS: dict[str, tuple[type[CipherError], str]] = {
    "corrupt": (CorruptQueueCellError, "bad_base64"),
    "tag": (QueueTagError, "tag_mismatch"),
    "unknown_key": (UnauthenticatedCipherError, "unknown_key"),
    "unknown_key_corrupt": (CipherError, "bad_base64"),
    "unparseable_marker": (CipherError, "unparseable_marker"),
}


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
    """A row ``open_queue_cell`` refuses under ``cipher``, one of :data:`_REFUSALS`'s kinds: a
    corrupt cell, a cell sealed for another row, a cell under a key ``cipher`` does not hold, whole
    or corrupt, and a marker no cipher of this build parses."""
    row = _row()
    if kind.startswith("unknown_key"):
        other = make_cipher(generate_key(), write_v2=True)
        unheld = other.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
        return {**row, "payload": _bad_base64(unheld) if kind.endswith("corrupt") else unheld}
    if kind == "unparseable_marker":
        return {**row, "payload": "mfenc:v9:AAAA"}
    sealed = cipher.encrypt("SYNTH-BODY", aad=queue_row_aad(row))
    if kind == "corrupt":
        return {**row, "payload": _bad_base64(sealed)}
    return {**row, "channel_id": "IB_MOVED", "payload": sealed}


@pytest.mark.parametrize("kind", sorted(_REFUSALS))
def test_a_refused_cell_carries_no_cipher_text_and_chains_nothing(kind: str) -> None:
    """The root of BACKLOG #5982 finding 3: the error itself is value-free, so no handler that
    prints it, its traceback or its chain can print the cipher's refusal. A plain cipher refusal,
    a key not held or a marker not parsed, keeps its class, and a claim reads it as before: not a
    key service's silence, so it is dead-lettered rather than set aside."""
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    row = _refused_row(cipher, kind)
    raised, code = _REFUSALS[kind]
    # Control: the cipher's own refusal of this cell holds the words searched for below, a key_id
    # for every kind whose marker names one.
    with pytest.raises(CipherError) as own:
        cipher.decrypt(row["payload"], aad=queue_row_aad(row))
    assert any(word in str(own.value) for word in _CIPHER_WORDS), str(own.value)
    assert ("key_id=" in str(own.value)) == (kind != "unparseable_marker"), str(own.value)
    with pytest.raises(CipherError) as refused:
        open_queue_cell(cipher, row)
    error = refused.value
    assert type(error) is raised
    if isinstance(error, QueueTagError):
        assert error.cause == kind
    else:
        assert type(error) is type(own.value)  # the cipher's own class, unchanged
    assert not is_transient_open_failure(error)
    assert f"({type(own.value).__name__}, {code})" in str(error), str(error)
    assert not any(word in str(error) for word in _CIPHER_WORDS), str(error)
    # Raised outside the cipher's handler: no cause, and no context a traceback would print.
    assert error.__cause__ is None and error.__context__ is None
    printed = "".join(traceback.format_exception(error))
    assert type(error).__name__ in printed  # control: this is the error's own traceback
    assert not any(word in printed for word in _CIPHER_WORDS), printed


def test_a_transit_refusal_carries_none_of_transits_text() -> None:
    """Under Vault Transit, which cannot name its keys, a refused marked cell is a
    :class:`QueueTagError`: cause ``tag`` for Vault's AEAD refusal, ``unknown`` for any other. The
    cipher's text names the Transit key and its cause is the hvac error; neither reaches the
    refusal."""
    pytest.importorskip("hvac")
    from hvac.exceptions import InvalidRequest  # type: ignore[import-untyped]  # noqa: PLC0415

    cipher, transit = _raising_transit()
    row = {**_row(), "payload": "mfenc:v3:vault:v1:AAAA"}
    for vault_says, cause, code in (
        ("cipher: message authentication failed", "tag", "tag_mismatch"),
        ("ciphertext version is disallowed by policy (too old)", "unknown", "refused"),
    ):
        transit.error = InvalidRequest(errors=[vault_says])
        # Control: the cipher's own refusal names its key and chains Vault's error.
        with pytest.raises(CipherError) as own:
            cipher.decrypt(row["payload"], aad=queue_row_aad(row))
        assert "mefor-store" in str(own.value) and own.value.__cause__ is not None
        with pytest.raises(QueueTagError) as refused:
            open_queue_cell(cipher, row)
        error = refused.value
        assert error.cause == cause and f"({type(own.value).__name__}, {code})" in str(error)
        assert error.__cause__ is None and error.__context__ is None
        printed = "".join(traceback.format_exception(error))
        assert "mefor-store" not in printed and vault_says not in printed, printed


def test_an_unmarked_value_and_a_key_service_silence_raise_the_ciphers_own_error() -> None:
    """What ``open_queue_cell`` passes on as the cipher raised it: an unmarked value's refusal,
    whose text names a column and a remedy and no value, and a key service's silence, whose cause
    a claim reads to set the row aside (BACKLOG #5765)."""
    cipher = make_cipher(generate_key(), write_v2=True)
    with pytest.raises(UnmarkedCipherError, match="queue.payload"):
        open_queue_cell(cipher, {**_row(), "payload": "SYNTH-PLAINTEXT"})
    requests = pytest.importorskip("requests")
    transit, fake = _raising_transit()
    fake.error = requests.exceptions.ConnectionError("connection refused")
    with pytest.raises(CipherError) as silent:
        open_queue_cell(transit, {**_row(), "payload": "mfenc:v3:vault:v1:AAAA"})
    assert is_transient_open_failure(silent.value) and silent.value.__cause__ is not None


class _Body:
    """Stands for another row's opened body, held in a frame of the caller that opens a cell."""


def _open_beside_a_body(cipher: AesGcmCipher, row: dict[str, Any], held: list[Any]) -> str:
    out = _Body()
    held.append(weakref.ref(out))
    return open_queue_cell(cipher, row)


@pytest.fixture
def no_cyclic_collector() -> Iterator[None]:
    enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if enabled:
            gc.enable()


@pytest.mark.parametrize("kind", sorted(_REFUSALS))
@pytest.mark.usefixtures("no_cyclic_collector")
def test_a_refusal_frees_the_callers_opened_bodies_without_the_cyclic_collector(kind: str) -> None:
    """BACKLOG #5982: the refusal's traceback holds ``open_queue_cell``'s frame and every caller's
    frame above it. Were the error also held in a local of that frame, the two would make a cycle,
    and a caller's other opened bodies would live on until the cyclic collector ran. With the
    collector off, the body must be gone as soon as the caught error is."""
    cipher = make_cipher(generate_key(), write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    held: list[Any] = []
    try:
        _open_beside_a_body(cipher, _refused_row(cipher, kind), held)
    except CipherError:
        pass
    else:
        pytest.fail("the cell opened")
    assert held[0]() is None, "the caller's opened body outlived the refusal"


@pytest.mark.parametrize("kind", sorted(_REFUSALS))
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
        for _ in range(400):  # up to 20 seconds, for a loaded runner
            if server.started:
                break
            await asyncio.sleep(0.05)
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
    # Anchored to a line start and the full class path, so ``CipherError`` cannot match a line
    # naming ``UnauthenticatedCipherError``.
    refusal = _REFUSALS[kind][0]
    raised = re.compile(rf"(?m)^{re.escape(f'{refusal.__module__}.{refusal.__qualname__}')}:")
    assert any("Traceback" in p and raised.search(p) for p in printed), printed
    assert len(printed) >= 1  # the absence search below walks a non-empty capture
    leaked = [p for p in printed if any(word in p for word in _CIPHER_WORDS)]
    assert leaked == [], leaked
    assert not any("SYNTH-BODY" in p for p in printed)


def test_unopenable_log_text_names_a_queue_tag_refusal_by_class_and_cause() -> None:
    corrupt = CorruptQueueCellError("corrupt (malformed ciphertext (bad base64, key_id='ab'))")
    assert unopenable_log_text(corrupt) == "CorruptQueueCellError (cause corrupt)"
    drift = QueueTagError("integrity: does not open under its own tag (key_id='ab')", cause="tag")
    assert unopenable_log_text(drift) == "QueueTagError (cause tag)"
    # Any other error is named by its class alone, whatever its text holds.
    other = CipherError("no configured key decrypts this value (key_id='ab')")
    assert unopenable_log_text(other) == "CipherError"
