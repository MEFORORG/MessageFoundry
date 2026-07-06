# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Live-runner end-to-end for handler-callable ``db_lookup`` (SYNTHETIC-TEST-PLAN §1.0.a / §1.2).

``test_db_lookup.py`` covers the accessor + the bare executor (parameterization, the fail-closed
allowlist, PHI-free errors, dry-run-raises). What it does NOT reach — and what gates the EIHC/NPI
Corepoint feeds (the #1-risk path) — is the **live runner**: a Handler calling ``db_lookup`` inside a
real :class:`RegistryRunner`, where the call bridges off the event loop and back, and the message's
disposition flows. These drive a faked Clarity pool through the full pipeline and assert:

* the off-loop bridge resolves (the Handler runs on a worker thread, not the loop) → **PROCESSED**;
* a lookup-gated drop → **FILTERED** (never silently delivered);
* a lookup that **raises** → **ERROR**/dead-letter, *after* the ACK-on-receipt ingress commit (a
  post-ingress failure, so the sender was already AA'd — it is not NAK'd);
* a lookup that **times out** → **ERROR**/dead-letter (bounded by ``_LOOKUP_RESULT_TIMEOUT_SECONDS``).

Synthetic data only; no driver, no real DB (``transports.database._make_pool`` is faked).
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import db_lookup
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    ConnectionSpec,
    DatabaseLookupSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.transports import database

# An ADT carrying a Meditech provider id in PV1-7.1 for the NPI substitution.
ADT = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|NPI1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
    "PV1|1|I|^^^FAC||||MEDITECH123^SMITH^JOHN\r"
)

_Route = Callable[[Message], list[str]]
_Handler = Callable[[Message], Send | None]


# --- a faked aioodbc pool/conn/cursor (no driver, no DB) ----------------------


class _FakeCursor:
    def __init__(
        self, rows: list[tuple[Any, ...]], columns: list[str], error: Exception | None, delay: float
    ) -> None:
        self._rows = rows
        self._error = error
        self._delay = delay
        self.description = [(c,) for c in columns] if columns else None

    async def execute(self, sql: str, params: tuple[Any, ...]) -> None:
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._error is not None:
            raise self._error

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)


class _FakeConn:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    async def cursor(self) -> _FakeCursor:
        return self._cursor


class _FakePool:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor
        self.closed = False

    async def acquire(self) -> _FakeConn:
        return _FakeConn(self._cursor)

    async def release(self, conn: _FakeConn) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _patch_pool(
    monkeypatch: pytest.MonkeyPatch,
    *,
    rows: list[tuple[Any, ...]] | None = None,
    columns: list[str] | None = None,
    error: Exception | None = None,
    delay: float = 0.0,
) -> _FakePool:
    pool = _FakePool(_FakeCursor(rows or [], columns or [], error, delay))

    async def fake_make_pool(dsn: str, pool_max: int, *, autocommit: bool) -> _FakePool:
        return pool

    monkeypatch.setattr(database, "_make_pool", fake_make_pool)
    return pool


# --- harness -----------------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _registry(inbox: Path, outdir: Path, route: _Route, handler: _Handler) -> Registry:
    """A File-in → router → handler → File-out graph that declares a ``clarity`` DatabaseLookup (so the
    runner builds the live-lookup executor and the transform runs off-loop with the bridge active)."""
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", route)
    reg.add_handler("npi", handler)
    reg.add_lookup(
        DatabaseLookupSpec(name="clarity", settings={"server": "db.local", "database": "Clarity"})
    )
    return reg


async def _run(reg: Registry, store: MessageStore) -> RegistryRunner:
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    return runner


async def _until_status(
    store: MessageStore, status: str, *, channel_id: str = "file_in", timeout: float = 4.0
) -> None:
    for _ in range(int(timeout / 0.02)):
        if await store.list_messages(channel_id=channel_id, status=status):
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"no message reached {status} within {timeout}s")


def _route_to_npi(msg: Message) -> list[str]:
    return ["npi"]


def _npi_handler(seen_threads: list[bool]) -> _Handler:
    """A handler that substitutes PV1-7.1 with a live-looked-up NPI; drops (FILTERED) if the lookup
    returns nothing. ``seen_threads`` records whether it ran off the main thread (the off-loop proof)."""

    def handle(msg: Message) -> Send | None:
        seen_threads.append(threading.current_thread() is threading.main_thread())
        provider_id = msg["PV1-7.1"] or ""
        # Read-only SELECT (ADR 0010 carve-out enforced by _require_read_only — db_lookup refuses a
        # write/EXEC). A read-only mapping lookup, the canonical db_lookup use.
        rows = db_lookup(
            "clarity",
            "SELECT npi FROM mmc.Provider WHERE meditech_id = :id",
            {"id": provider_id},
        )
        if not rows:
            return None  # not found → gated drop (FILTERED), never silently delivered
        msg["PV1-7.1"] = str(rows[0]["npi"])
        return Send("file_out", msg)

    return handle


# --- tests -------------------------------------------------------------------


async def test_handler_db_lookup_substitutes_and_delivers(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The live lookup returns an NPI → the handler substitutes it and delivers → PROCESSED, and the
    # delivered body carries the looked-up NPI. Also proves the handler ran OFF the event loop.
    _patch_pool(monkeypatch, rows=[("1999999999",)], columns=["npi"])
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    seen_threads: list[bool] = []

    runner = await _run(_registry(inbox, outdir, _route_to_npi, _npi_handler(seen_threads)), store)
    try:
        await _until_status(store, MessageStatus.PROCESSED.value)
    finally:
        await runner.stop()

    written = (outdir / "NPI1.hl7").read_bytes().decode("utf-8")
    assert "1999999999" in written  # the live-looked-up NPI replaced the Meditech id
    assert "MEDITECH123" not in written
    assert seen_threads == [False]  # handler ran on a worker thread, not the loop (off-loop bridge)


async def test_handler_db_lookup_gated_drop_is_filtered(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The lookup finds nothing → the handler returns None → FILTERED, and nothing is delivered.
    _patch_pool(monkeypatch, rows=[], columns=["npi"])
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    runner = await _run(_registry(inbox, outdir, _route_to_npi, _npi_handler([])), store)
    try:
        await _until_status(store, MessageStatus.FILTERED.value)
    finally:
        await runner.stop()
    assert not (outdir / "NPI1.hl7").exists()


async def test_handler_db_lookup_error_dead_letters(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A driver error (carrying a SQLSTATE) → DbLookupError in the worker → the transform fails → ERROR /
    # dead-letter. This happens AFTER the ACK-on-receipt ingress commit, so the sender is not NAK'd.
    _patch_pool(monkeypatch, columns=["npi"], error=Exception("08S01", "connection reset"))
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    runner = await _run(_registry(inbox, outdir, _route_to_npi, _npi_handler([])), store)
    try:
        await _until_status(store, MessageStatus.ERROR.value)
    finally:
        await runner.stop()
    assert not (outdir / "NPI1.hl7").exists()


async def test_handler_db_lookup_timeout_dead_letters(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A lookup slower than the result timeout → the worker gives up → the transform fails → ERROR /
    # dead-letter (never a hung transform thread).
    monkeypatch.setattr(wiring_runner, "_LOOKUP_RESULT_TIMEOUT_SECONDS", 0.2)
    _patch_pool(monkeypatch, rows=[("1999999999",)], columns=["npi"], delay=2.0)
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    runner = await _run(_registry(inbox, outdir, _route_to_npi, _npi_handler([])), store)
    try:
        await _until_status(store, MessageStatus.ERROR.value)
    finally:
        await runner.stop()
    assert not (outdir / "NPI1.hl7").exists()
