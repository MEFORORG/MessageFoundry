# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3929: the store's async methods run a blocking cipher's calls off the event loop.

Under the ``vault_transit`` cipher every cell encrypt, cell decrypt and audit MAC is a Transit HTTP
round trip. The stores route those calls through :func:`~messagefoundry.store.row_seal.cipher_call`,
which hands them to the Transit pool when the cipher says it blocks on I/O, and runs them inline
when it does not. These tests drive the SQLite store through a real :class:`TransitCipher` over a
fake Transit client, and through the in-process AES-GCM cipher, and record which thread each call
ran on.
"""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("hvac", reason="the Transit cipher tests need the [vault] extra")

from messagefoundry.store import row_seal  # noqa: E402
from messagefoundry.store.crypto import (  # noqa: E402
    AesGcmCipher,
    cell_aad,
    cipher_blocks_on_io,
    generate_key,
    make_cipher,
)
from messagefoundry.store.crypto_transit import TransitCipher  # noqa: E402
from messagefoundry.store.store import MessageStatus, MessageStore  # noqa: E402
from tests.test_crypto_transit import _FakeClient, _FakeTransit  # noqa: E402

_KEY = "mefor-store"
#: How long each recorded Transit call holds its thread once armed: long against a loop tick.
_BLOCK = 0.3
_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\r"


class _RecordingTransit(_FakeTransit):
    """A fake Transit that records the thread of every call, and blocks each one once armed."""

    def __init__(self) -> None:
        super().__init__()
        self.threads: list[int] = []
        self.block = 0.0

    def _note(self) -> None:
        self.threads.append(threading.get_ident())
        if self.block:
            time.sleep(self.block)

    def encrypt_data(self, **kw: Any) -> dict[str, Any]:
        self._note()
        return super().encrypt_data(**kw)

    def decrypt_data(self, **kw: Any) -> dict[str, Any]:
        self._note()
        return super().decrypt_data(**kw)

    def generate_hmac(self, **kw: Any) -> dict[str, Any]:
        self._note()
        return super().generate_hmac(**kw)

    def verify_signed_data(self, **kw: Any) -> dict[str, Any]:
        self._note()
        return super().verify_signed_data(**kw)


def test_only_the_transit_cipher_says_it_blocks_on_io() -> None:
    transit = TransitCipher(_FakeClient(_FakeTransit()), _KEY)
    assert cipher_blocks_on_io(transit)
    assert cipher_blocks_on_io(transit.audit_mac_fn())
    assert not cipher_blocks_on_io(make_cipher(generate_key()))
    assert not cipher_blocks_on_io(make_cipher(None))
    assert not cipher_blocks_on_io(object())


async def test_transit_cell_and_audit_calls_run_off_the_loop(tmp_path: Path) -> None:
    transit = _RecordingTransit()
    store = await MessageStore.open(
        tmp_path / "t.db", cipher=TransitCipher(_FakeClient(transit), _KEY)
    )
    try:
        transit.threads.clear()
        loop_thread = threading.get_ident()
        mid = await store.record_received(
            channel_id="IB_TEST",
            raw=_RAW,
            status=MessageStatus.FILTERED,
            summary="synthetic",
            metadata="{}",
        )
        message = await store.get_message(mid)
        assert message is not None and message["raw"] == _RAW
        await store.record_audit("probe", actor="tester", detail="synthetic")
        ok, msg = await store.verify_audit_chain()
        assert ok, msg
        assert transit.threads, "the store made no Transit call, so this test measured nothing"
        assert loop_thread not in transit.threads
    finally:
        await store.close()


async def test_the_loop_keeps_serving_while_transit_blocks(tmp_path: Path) -> None:
    transit = _RecordingTransit()
    store = await MessageStore.open(
        tmp_path / "t.db", cipher=TransitCipher(_FakeClient(transit), _KEY)
    )
    try:
        transit.block = _BLOCK
        gaps: list[float] = []
        done = asyncio.Event()

        async def ticker() -> None:
            last = time.perf_counter()
            while not done.is_set():
                await asyncio.sleep(0.01)
                now = time.perf_counter()
                gaps.append(now - last)
                last = now

        task = asyncio.create_task(ticker())
        started = time.perf_counter()
        try:
            # A write: its cell encrypts ran inline on the loop before BACKLOG #3929.
            await store.record_received(
                channel_id="IB_TEST",
                raw=_RAW,
                status=MessageStatus.FILTERED,
                summary="synthetic",
                metadata="{}",
            )
        finally:
            done.set()
            await task
        assert time.perf_counter() - started >= _BLOCK, "the write made no blocked Transit call"
        assert gaps and max(gaps) < _BLOCK / 2
    finally:
        await store.close()


async def test_an_in_process_cipher_runs_inline_on_the_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refuse(*_: Any, **__: Any) -> Any:
        raise AssertionError("an in-process cipher call was handed to the Transit pool")

    monkeypatch.setattr(row_seal, "_in_transit_pool", refuse)
    threads: list[int] = []
    encrypt_threads: list[int] = []
    real_encrypt = AesGcmCipher.encrypt
    real_decrypt = AesGcmCipher.decrypt

    def encrypt(self: AesGcmCipher, *args: Any, **kw: Any) -> str:
        encrypt_threads.append(threading.get_ident())
        return real_encrypt(self, *args, **kw)

    def decrypt(self: AesGcmCipher, *args: Any, **kw: Any) -> str:
        threads.append(threading.get_ident())
        return real_decrypt(self, *args, **kw)

    monkeypatch.setattr(AesGcmCipher, "encrypt", encrypt)
    monkeypatch.setattr(AesGcmCipher, "decrypt", decrypt)
    store = await MessageStore.open(tmp_path / "a.db", cipher=make_cipher(generate_key()))
    try:
        encrypt_threads.clear()
        mid = await store.record_received(
            channel_id="IB_TEST",
            raw=_RAW,
            status=MessageStatus.FILTERED,
            summary="synthetic",
            metadata="{}",
        )
        message = await store.get_message(mid)
        assert message is not None and message["raw"] == _RAW
        # The write's encrypts run inline. The read's decrypt is not checked: get_message already
        # hands its record to asyncio.to_thread under every cipher.
        assert encrypt_threads, "the write made no cipher call, so this test measured nothing"
        assert set(encrypt_threads) == {threading.get_ident()}
        assert threads, "the read made no cipher call"
    finally:
        await store.close()


async def test_cipher_call_hops_only_for_a_blocking_cipher() -> None:
    loop_thread = threading.get_ident()
    transit = TransitCipher(_FakeClient(_FakeTransit()), _KEY)
    aad = cell_aad("t", "c", "1")
    assert await row_seal.cipher_call(transit, threading.get_ident) != loop_thread
    local = make_cipher(generate_key())
    assert await row_seal.cipher_call(local, threading.get_ident) == loop_thread
    sealed = await row_seal.cipher_call(transit, transit.encrypt, "x", aad=aad)
    assert await row_seal.cipher_call(transit, transit.decrypt, sealed, aad=aad) == "x"
