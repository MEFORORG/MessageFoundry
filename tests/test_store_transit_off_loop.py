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
from messagefoundry.store import store as store_module  # noqa: E402
from messagefoundry.store.crypto import (  # noqa: E402
    AesGcmCipher,
    cell_aad,
    cipher_blocks_on_io,
    generate_key,
    make_cipher,
)
from messagefoundry.store.crypto_transit import TransitCipher  # noqa: E402
from messagefoundry.store.store import (  # noqa: E402
    ConnectionEventWrite,
    MessageStatus,
    MessageStore,
    stamped_connection_event,
)
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
        self.hmacs = 0

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
        self.hmacs += 1
        self._note()
        return super().generate_hmac(**kw)

    def verify_signed_data(self, **kw: Any) -> dict[str, Any]:
        self.hmacs += 1
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
    cipher = TransitCipher(_FakeClient(transit), _KEY)
    # The serve path hands the cipher's MAC to the store as open_store does, so the audit chain
    # is keyed in Transit and its appends and walk make Transit calls too.
    store = await MessageStore.open(
        tmp_path / "t.db", cipher=cipher, audit_mac_fn=cipher.audit_mac_fn()
    )
    try:
        # The open already made Transit calls, MAC calls among them; count only what follows.
        transit.threads.clear()
        transit.hmacs = 0
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
        before_append = transit.hmacs
        await store.record_audit("probe", actor="tester", detail="synthetic")
        assert transit.hmacs > before_append, "the audit append made no Transit MAC call"
        before_walk = transit.hmacs
        ok, msg = await store.verify_audit_chain()
        assert ok, msg
        assert transit.hmacs > before_walk, "the audit walk made no Transit MAC call"
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
        transit.block = 0.0
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


#: The clock the loop thread reads in the connection-event tests, and the one any other thread reads.
_LOOP_NOW = 1_000.0
_OFF_LOOP_NOW = 2_000.0


class _ThreadClock:
    """Stands in for the store module's ``time``: ``time()`` answers by thread, everything else is
    the real module, so a stamp shows which thread took it."""

    def __init__(self, loop_thread: int) -> None:
        self._loop_thread = loop_thread

    def time(self) -> float:
        return _LOOP_NOW if threading.get_ident() == self._loop_thread else _OFF_LOOP_NOW

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


def test_a_connection_event_is_stamped_only_when_it_has_no_time() -> None:
    ev = ConnectionEventWrite(
        connection="IB_TEST",
        transport="mllp",
        direction="inbound",
        kind="established",
        peer_host=None,
        message_id=None,
        reason="synthetic",
        now=5.0,
    )
    assert stamped_connection_event(ev) is ev
    unstamped = ConnectionEventWrite(**{**ev, "now": None})
    stamped = stamped_connection_event(unstamped)
    assert stamped["now"] is not None and unstamped["now"] is None


async def test_a_connection_event_is_stamped_on_the_loop_under_transit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(
        tmp_path / "t.db", cipher=TransitCipher(_FakeClient(_RecordingTransit()), _KEY)
    )
    try:
        monkeypatch.setattr(store_module, "time", _ThreadClock(threading.get_ident()))
        await store.record_connection_event(
            connection="IB_ONE",
            transport="mllp",
            direction="inbound",
            kind="established",
            reason="a",
        )
        await store.record_connection_events(
            [
                ConnectionEventWrite(
                    connection="IB_BURST",
                    transport="mllp",
                    direction="inbound",
                    kind="established",
                    peer_host=None,
                    message_id=None,
                    reason="b",
                )
            ]
        )
        monkeypatch.undo()
        events = await store.list_connection_events(allowed_channels=None)
        stamps = {ev.connection: ev.ts for ev in events}
        # Both stamps were taken on the loop, as on origin/main, not on the Transit pool thread.
        assert stamps == {"IB_ONE": _LOOP_NOW, "IB_BURST": _LOOP_NOW}
    finally:
        await store.close()


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_converge_keeps_a_newer_own_sync_made_during_the_decrypt(backend: str) -> None:
    import importlib

    module = importlib.import_module(f"messagefoundry.store.{backend}")
    cls = module.PostgresStore if backend == "postgres" else module.SqlServerStore
    transit = _RecordingTransit()
    cipher = TransitCipher(_FakeClient(transit), _KEY)
    aad = cell_aad("reference", "value", "codes", "v1", "k")
    row = {"name": "codes", "version": "v1", "key": "k", "value": cipher.encrypt('"old"', aad=aad)}
    store = object.__new__(cls)
    store._cipher = cipher
    own = {"k": "own"}
    store._reference_cache = {"codes": own}
    store._reference_versions = {"codes": "v0"}

    async def fetchall(*_: Any, **__: Any) -> list[dict[str, Any]]:
        return [row]

    store._fetchall = fetchall
    transit.block = _BLOCK

    async def own_sync() -> None:
        # This handle's own sync commits v2 while the converge waits on the v1 decrypt.
        await asyncio.sleep(_BLOCK / 3)
        store._reference_cache["codes"] = own
        store._reference_versions["codes"] = "v2"

    sync = asyncio.create_task(own_sync())
    refreshed = await store.converge_reference_cache()
    await sync
    assert refreshed == []
    assert store._reference_versions == {"codes": "v2"}
    assert store._reference_cache["codes"] is own
