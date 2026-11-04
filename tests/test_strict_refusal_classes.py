# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Strict validation's refusals are classed alike on MLLP and on the receipt path (BACKLOG #5078).

Three halves, each with a control:

* **A strict-validation failure answers AR on MLLP**, the final code, where it answered AE. The
  receipt path already answered it final (``422``, or ``413`` for validate()'s own size cap), and an
  AE invited a sender to retry a body that fails the same way every time. The engine's own MLLP
  outbound is driven end to end against the engine's own listener, and reads AR as permanent.
* **A strict-validation timeout splits on whether the validate began.** One that never began timed
  out waiting for a worker thread: nothing is known of the body, and no thread was left, so the
  receipt path answers it TEMPORARY (``503``). One that began stays final there. MLLP answers AE for
  both: its finality is contested, and this row does not change it.
* **Strict validation's size cap stays the engine default** whatever the inbound's
  ``max_message_bytes`` (documented in ``docs/HL7-VALIDATION.md``), and its refusal is final.

The worker-thread wait is produced, not simulated: ``asyncio.to_thread`` in ``wiring_runner`` is
pointed at a one-worker pool that a blocker holds, so the validate genuinely queues. Every fixture is
synthetic HL7. Deliberately ASCII-only.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Validation
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.pipeline import wiring_runner
from messagefoundry.store.store import MessageStatus, MessageStore
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.receipt import RefusalKind
from tests.test_wiring_engine import _mllp_client, _mllp_registry, _run, _until_message

#: Missing its required PID, so hl7apy refuses it at 2.5.1.
_NON_CONFORMANT = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|N5078|P|2.5.1\rEVN|A01|20260101\r"
_ADT = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M5078|P|2.5.1\rEVN|A01|20260101\rPID|1||100\r"
_STRICT_CAP = DEFAULT_MAX_MESSAGE_BYTES  # validate()'s own default cap


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    s = await MessageStore.open(tmp_path / "strict.db")
    yield s
    await s.close()


def _strict_ic(
    ctype: ConnectorType, *, timeout: float | None = None, **over: Any
) -> InboundConnection:
    return InboundConnection(
        "in",
        ConnectionSpec(ctype, {"host": "127.0.0.1", "port": 0}),
        router="r",
        content_type=ContentType.HL7V2,
        validation=Validation(strict=True, hl7_version="2.5.1", strict_timeout_s=timeout),
        **over,
    )


def _runner(store: MessageStore, ic: InboundConnection) -> wiring_runner.RegistryRunner:
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_router("r", lambda m: [])
    return wiring_runner.RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))


async def _error_rows(store: MessageStore) -> list[dict[str, Any]]:
    cur = await store._db.execute("SELECT status, error FROM messages")
    return [dict(r) for r in await cur.fetchall()]


# --- MLLP: a strict-validation failure is AR, end to end -----------------------------------------


async def test_the_engines_mllp_outbound_reads_a_strict_failure_as_final(
    store: MessageStore, tmp_path: Path
) -> None:
    """Mutation: answer the failure AE again. Red: the outbound's NAK is code AE, not permanent."""
    runner = await _run(_mllp_registry(tmp_path / "out", strict=True), store)
    try:
        port = runner._sources["mllp_in"].sockport  # type: ignore[attr-defined]
        with pytest.raises(NegativeAckError) as raised:
            await _mllp_client(port).send(_NON_CONFORMANT)
        await _until_message(store, MessageStatus.ERROR.value, channel_id="mllp_in")
    finally:
        await runner.stop()
    assert raised.value.code == "AR"
    assert raised.value.permanent is True


async def test_control_a_strict_timeout_stays_ae_and_is_retried(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: the same path, a validate that began and outran its timeout. Still AE, which the
    outbound retries, so the AR above is the failure's own class, not every strict refusal's."""
    release = threading.Event()

    def _stuck(*_: Any, **__: Any) -> Any:
        release.wait(5.0)

    monkeypatch.setattr(wiring_runner, "validate", _stuck)
    runner = await _run(_mllp_registry(tmp_path / "out", strict=True, strict_timeout_s=0.05), store)
    try:
        port = runner._sources["mllp_in"].sockport  # type: ignore[attr-defined]
        with pytest.raises(NegativeAckError) as raised:
            await _mllp_client(port).send(_ADT)
        await _until_message(store, MessageStatus.ERROR.value, channel_id="mllp_in")
    finally:
        release.set()
        await runner.stop()
    assert raised.value.code == "AE"
    assert raised.value.permanent is False


# --- the timeout: did the validate begin? --------------------------------------------------------


class _QueuedAsyncio:
    """``asyncio`` as ``wiring_runner`` sees it, with ``to_thread`` on a pool of our choosing."""

    def __init__(self, pool: ThreadPoolExecutor) -> None:
        self._pool = pool

    def __getattr__(self, name: str) -> Any:
        return getattr(asyncio, name)

    async def to_thread(self, func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        # As asyncio.to_thread does: the worker runs in a copy of the caller's context.
        loop = asyncio.get_running_loop()
        call = functools.partial(contextvars.copy_context().run, func, *args, **kwargs)
        return await loop.run_in_executor(self._pool, call)


class _OneWorker:
    """A one-worker pool behind ``wiring_runner``'s ``to_thread``, and the calls of a validate that
    hangs until ``release`` is set."""

    def __init__(
        self, pool: ThreadPoolExecutor, release: threading.Event, calls: list[int]
    ) -> None:
        self.pool = pool
        self.release = release
        self.calls = calls

    def hold(self) -> threading.Event:
        """Occupy the one worker the way unrelated off-loop work would under load, until the
        returned event is set."""
        held = threading.Event()
        self.pool.submit(held.wait, 5.0)
        return held


@pytest.fixture
def one_worker(monkeypatch: pytest.MonkeyPatch) -> Iterator[_OneWorker]:
    """A held-or-free one-worker pool and a counting, hanging validate (see :class:`_OneWorker`)."""
    pool = ThreadPoolExecutor(max_workers=1)
    release = threading.Event()
    calls: list[int] = []

    def _counting_hang(*_: Any, **__: Any) -> Any:
        calls.append(1)
        release.wait(5.0)

    monkeypatch.setattr(wiring_runner, "asyncio", _QueuedAsyncio(pool))
    monkeypatch.setattr(wiring_runner, "validate", _counting_hang)
    try:
        yield _OneWorker(pool, release, calls)
    finally:
        release.set()
        pool.shutdown(wait=True)


async def test_a_timeout_that_never_began_is_temporary_on_the_receipt_path(
    store: MessageStore, one_worker: _OneWorker
) -> None:
    """Mutation: class every timeout PERMANENT again. Red: the receipt is PERMANENT."""
    held = one_worker.hold()
    ic = _strict_ic(ConnectorType.HTTP, timeout=0.1)
    try:
        receipt = await _runner(store, ic)._handle_inbound_http(ic, _ADT.encode("ascii"))
    finally:
        held.set()
    assert receipt.refusal is RefusalKind.TEMPORARY
    rows = await _error_rows(store)
    assert len(rows) == 1 and rows[0]["status"] == MessageStatus.ERROR.value
    assert "strict-validation timed out after 0.1s before the validate began" in rows[0]["error"]
    # Nothing was left running: once the worker frees, the abandoned validate does not start. This
    # is the outcome, not a control for the lock: cancelling the executor future already skips a
    # queued job. The lock is pinned by the direct test of _StrictValidateRun below.
    await asyncio.sleep(0.2)
    assert one_worker.calls == []


async def test_control_a_timeout_that_began_stays_permanent_on_the_receipt_path(
    store: MessageStore, one_worker: _OneWorker
) -> None:
    """Control: the same pool with its worker free. The validate begins, hangs past the timeout,
    and stays PERMANENT, with the text the dry-run mirrors. A 1 s timeout, so a thread slow to be
    scheduled under GIL contention still begins inside it."""
    ic = _strict_ic(ConnectorType.HTTP, timeout=1.0)
    receipt = await _runner(store, ic)._handle_inbound_http(ic, _ADT.encode("ascii"))
    assert receipt.refusal is RefusalKind.PERMANENT
    rows = await _error_rows(store)
    assert rows[0]["error"].endswith("strict-validation timed out after 1.0s")
    assert one_worker.calls == [1]


async def test_a_validator_fault_is_temporary_on_the_receipt_path(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The receipt half of the fault arm below: a fault that may be the engine's is not final there
    either. Mutation: drop the fault branch. Red: PERMANENT."""
    import hl7apy.parser

    def _engine_fault(*_: Any, **__: Any) -> Any:
        raise MemoryError

    monkeypatch.setattr(hl7apy.parser, "parse_message", _engine_fault)
    ic = _strict_ic(ConnectorType.HTTP)
    receipt = await _runner(store, ic)._handle_inbound_http(ic, _ADT.encode("ascii"))
    assert receipt.refusal is RefusalKind.TEMPORARY


def test_a_fault_beside_a_version_mismatch_is_no_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    """A body that declares the wrong MSH-12 fails the same way every time, whatever else faulted, so
    the result is final; the same fault alone is a fault. Uses validate() directly."""
    import hl7apy.validation

    from messagefoundry.parsing.validate import validate

    def _validator_fault(*_: Any, **__: Any) -> Any:
        raise RuntimeError("validator fault")

    monkeypatch.setattr(hl7apy.validation.Validator, "validate", _validator_fault)
    mismatched = validate(_ADT, expected_version="2.3")
    assert not mismatched.ok and mismatched.fault is False
    alone = validate(_ADT, expected_version="2.5.1")
    assert not alone.ok and alone.fault is True


async def test_a_timeout_that_never_began_is_still_ae_on_mllp(
    store: MessageStore, one_worker: _OneWorker
) -> None:
    """MLLP answers both timeouts AE: only the stored reason says which kind it was."""
    held = one_worker.hold()
    ic = _strict_ic(ConnectorType.MLLP, timeout=0.1)
    try:
        ack = await _runner(store, ic)._handle_inbound(ic, _ADT.encode("ascii"))
    finally:
        held.set()
    assert ack is not None and "MSA|AE|" in ack
    # The wire carries the same text for both causes, so a sender cannot read pool state off MSA-3.
    assert "before the validate began" not in ack
    assert "strict-validation timed out after 0.1s" in ack
    rows = await _error_rows(store)
    assert "before the validate began" in rows[0]["error"]


async def test_a_validator_fault_stays_ae_on_mllp(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fault inside validate()'s defensive catch-all may be the engine's (a MemoryError under
    load), so it is not answered as final. Mutation: answer every ``not ok`` AR. Red: AR here."""
    import hl7apy.parser

    def _engine_fault(*_: Any, **__: Any) -> Any:
        raise MemoryError

    monkeypatch.setattr(hl7apy.parser, "parse_message", _engine_fault)
    ic = _strict_ic(ConnectorType.MLLP)
    ack = await _runner(store, ic)._handle_inbound(ic, _ADT.encode("ascii"))
    assert ack is not None and "MSA|AE|" in ack
    rows = await _error_rows(store)
    assert "strict-validation failed: parse error" in rows[0]["error"]


def test_an_abandoned_run_never_validates_and_a_begun_one_reports_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lock protocol on its own: abandon first and the run returns without validating; begin
    first and abandon reports that it began."""
    calls: list[int] = []
    monkeypatch.setattr(wiring_runner, "validate", lambda *a, **k: calls.append(1))

    first = wiring_runner._StrictValidateRun()
    assert first.abandon() is False
    assert first(_ADT, "2.5.1") is None
    assert calls == []

    second = wiring_runner._StrictValidateRun()
    second(_ADT, "2.5.1")
    assert calls == [1]
    assert second.abandon() is True


# --- the 16 MiB cap -------------------------------------------------------------------------------


def _hl7_of_length(n: int) -> str:
    head = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||"
    return head + "A" * (n - len(head))


async def test_a_strict_mllp_body_over_validates_own_cap_is_ar(store: MessageStore) -> None:
    """``max_message_bytes`` admits the body to the peek; strict validation keeps the engine
    default and refuses it as over-size, which is final: AR. Mutation: answer AE again."""
    ic = _strict_ic(ConnectorType.MLLP, max_message_bytes=2 * _STRICT_CAP)
    body = (_hl7_of_length(_STRICT_CAP + 1) + "\r").encode("ascii")
    ack = await _runner(store, ic)._handle_inbound(ic, body)
    assert ack is not None and "MSA|AR|" in ack
    rows = await _error_rows(store)
    assert "exceeds max size" in rows[0]["error"]


async def test_control_the_same_body_at_the_cap_reaches_hl7apy(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: exactly the cap passes the size check and reaches hl7apy, so the refusal above is the
    cap and not the body. hl7apy's parse is stubbed to a content failure so the test does not parse
    16 MiB; that failure is final too, AR."""
    import hl7apy.parser
    from hl7apy.exceptions import HL7apyException

    def _content_failure(*_: Any, **__: Any) -> Any:
        raise HL7apyException("a content failure, not size")

    monkeypatch.setattr(hl7apy.parser, "parse_message", _content_failure)
    ic = _strict_ic(ConnectorType.MLLP, max_message_bytes=2 * _STRICT_CAP)
    body = (_hl7_of_length(_STRICT_CAP) + "\r").encode("ascii")
    ack = await _runner(store, ic)._handle_inbound(ic, body)
    assert ack is not None and "MSA|AR|" in ack
    rows = await _error_rows(store)
    assert "a content failure, not size" in rows[0]["error"]
    assert "exceeds max size" not in rows[0]["error"]
