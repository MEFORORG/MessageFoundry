# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Strict validation's refusals are classed alike on MLLP and on the receipt path (BACKLOG #5078).

The matrix, owner ruling 2026-11-04 (decision log d20261104T032854299-7235a9). MLLP follows the
engine convention, AR for a final refusal and AE for one a re-send may clear:

=====================================  ===============  ================
Strict outcome                         receipt path     MLLP / TCP
=====================================  ===============  ================
the body fails validation              PERMANENT (422)  AR
an MSH-12 version mismatch             PERMANENT (422)  AR
over strict validation's own size cap  OVERSIZE (413)   AR
the validate began and timed out       PERMANENT (422)  AR
the timeout fired before it began      TEMPORARY (503)  AE
=====================================  ===============  ================

Every strict ``not ok`` is final. An earlier draft of this change split out a "validator fault",
an exception from ``validate()``'s defensive catch-all, as temporary. It was dropped after an
adversarial review: nothing inside ``validate()`` tells an hl7apy trip on a body from an engine
fault, and a body reaches that catch-all on its own, which the IndexError test below pins with a
real body rather than a monkeypatched parser.

The engine's own MLLP outbound is driven end to end against the engine's own listener, so AR is read
as permanent and AE as retryable by the real ``MLLPDestination``. The worker-thread wait is produced,
not simulated: the strict validate's ``to_thread`` is pointed at a one-worker pool that a blocker
holds, so the validate genuinely queues. Every fixture is synthetic HL7. Deliberately ASCII-only.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Validation
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing import ValidationResult
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.pipeline import wiring_runner
from messagefoundry.store.store import MessageStatus, MessageStore
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.receipt import RefusalKind
from tests.test_wiring_engine import _mllp_client, _mllp_registry, _run, _until_message

#: Missing its required PID, so hl7apy refuses it at 2.5.1.
_NON_CONFORMANT = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|N5078|P|2.5.1\rEVN|A01|20260101\r"
_ADT = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M5078|P|2.5.1\rEVN|A01|20260101\rPID|1||100\r"
#: Declares MSH-12 2.3 to an inbound expecting 2.5.1.
_WRONG_VERSION = _ADT.replace("|P|2.5.1\r", "|P|2.3\r")
#: MSH-2 runs into MSH-3 with no field separator. hl7apy's parser raises a plain ``IndexError`` on it,
#: not an ``HL7apyException``, so it reaches ``validate()``'s defensive catch-all from the body alone.
_GLUED_MSH2 = "MSH|^~\\&A|B|C|D|20260101||ADT^A01|G5078|P|2.5.1\rEVN|A01|20260101\rPID|1||100\r"
_STRICT_CAP = DEFAULT_MAX_MESSAGE_BYTES  # validate()'s own default cap
_OK = ValidationResult(True, "2.5.1", [])


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


async def _send_end_to_end(
    store: MessageStore, tmp_path: Path, body: str, *, timeout: float | None = None
) -> NegativeAckError:
    """Send ``body`` from the engine's own MLLP outbound to the engine's own strict listener and
    return the NAK the outbound raised, once the listener has recorded the ERROR row."""
    runner = await _run(
        _mllp_registry(tmp_path / "out", strict=True, strict_timeout_s=timeout), store
    )
    try:
        port = runner._sources["mllp_in"].sockport  # type: ignore[attr-defined]
        with pytest.raises(NegativeAckError) as raised:
            await _mllp_client(port).send(body)
        await _until_message(store, MessageStatus.ERROR.value, channel_id="mllp_in")
    finally:
        await runner.stop()
    return raised.value


# --- a strict-validation failure: final on both listeners ------------------------------------------


async def test_the_engines_mllp_outbound_reads_a_strict_failure_as_final(
    store: MessageStore, tmp_path: Path
) -> None:
    """Mutation: answer the failure AE again. Red: the outbound's NAK is code AE, not permanent."""
    nak = await _send_end_to_end(store, tmp_path, _NON_CONFORMANT)
    assert nak.code == "AR"
    assert nak.permanent is True


async def test_a_strict_failure_is_permanent_on_the_receipt_path(store: MessageStore) -> None:
    ic = _strict_ic(ConnectorType.HTTP)
    receipt = await _runner(store, ic)._handle_inbound_http(ic, _NON_CONFORMANT.encode("ascii"))
    assert receipt.refusal is RefusalKind.PERMANENT


@pytest.mark.parametrize("ctype", [ConnectorType.MLLP, ConnectorType.HTTP])
async def test_a_body_that_trips_validates_catch_all_is_final(
    store: MessageStore, ctype: ConnectorType
) -> None:
    """A real body, not a monkeypatched parser, reaches ``validate()``'s defensive catch-all, so that
    arm cannot be read as "the engine's fault". Mutation: answer the catch-all as temporary (AE /
    TEMPORARY), as the dropped draft did. Red: AE on MLLP, TEMPORARY on the receipt path."""
    ic = _strict_ic(ctype)
    runner = _runner(store, ic)
    if ctype is ConnectorType.MLLP:
        ack = await runner._handle_inbound(ic, _GLUED_MSH2.encode("ascii"))
        assert ack is not None and "MSA|AR|" in ack
    else:
        receipt = await runner._handle_inbound_http(ic, _GLUED_MSH2.encode("ascii"))
        assert receipt.refusal is RefusalKind.PERMANENT
    rows = await _error_rows(store)
    # The refusal is strict validation's, from the catch-all, so the arm under test was reached.
    assert "strict-validation failed: parse error: list index out of range" in rows[0]["error"]


@pytest.mark.parametrize("ctype", [ConnectorType.MLLP, ConnectorType.HTTP])
async def test_an_msh12_version_mismatch_is_final(
    store: MessageStore, ctype: ConnectorType
) -> None:
    ic = _strict_ic(ctype)
    runner = _runner(store, ic)
    if ctype is ConnectorType.MLLP:
        ack = await runner._handle_inbound(ic, _WRONG_VERSION.encode("ascii"))
        assert ack is not None and "MSA|AR|" in ack
    else:
        receipt = await runner._handle_inbound_http(ic, _WRONG_VERSION.encode("ascii"))
        assert receipt.refusal is RefusalKind.PERMANENT
    rows = await _error_rows(store)
    assert "version mismatch" in rows[0]["error"]


# --- the timeout: did the validate begin? --------------------------------------------------------


class _QueuedAsyncio:
    """``asyncio`` as ``wiring_runner`` sees it, with the strict validate's ``to_thread`` on a pool
    of our choosing. Every other ``to_thread`` keeps the default executor, so a running runner's
    other off-loop work never queues behind the held worker."""

    def __init__(self, pool: ThreadPoolExecutor) -> None:
        self._pool = pool

    def __getattr__(self, name: str) -> Any:
        return getattr(asyncio, name)

    async def to_thread(self, func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        if not isinstance(func, wiring_runner._StrictValidateRun):
            return await asyncio.to_thread(func, *args, **kwargs)
        # As asyncio.to_thread does: the worker runs in a copy of the caller's context.
        loop = asyncio.get_running_loop()
        call = functools.partial(contextvars.copy_context().run, func, *args, **kwargs)
        return await loop.run_in_executor(self._pool, call)


class _OneWorker:
    """A one-worker pool behind the strict validate's ``to_thread``, and the calls of a validate
    that hangs until ``release`` is set."""

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


async def test_a_timeout_that_began_is_final_to_the_engines_mllp_outbound(
    store: MessageStore, tmp_path: Path, one_worker: _OneWorker
) -> None:
    """Owner ruling 2026-11-04: a timeout whose validate began is final on MLLP too. The worker is
    free, so the validate begins and hangs past the timeout. A 1 s timeout, so a thread slow to be
    scheduled under GIL contention still begins inside it. Mutation: answer every timeout AE, as
    before the ruling. Red: AE, not permanent."""
    nak = await _send_end_to_end(store, tmp_path, _ADT, timeout=1.0)
    assert nak.code == "AR"
    assert nak.permanent is True
    assert one_worker.calls == [1]
    rows = await _error_rows(store)
    assert rows[0]["error"].endswith("strict-validation timed out after 1.0s")


async def test_control_a_timeout_that_never_began_is_retried_by_the_engines_mllp_outbound(
    store: MessageStore, tmp_path: Path, one_worker: _OneWorker
) -> None:
    """Control: the same path with the one worker held, so the validate never begins. AE, which the
    outbound retries, so the AR above is the began timeout's own class, not every timeout's.
    Mutation: answer every timeout AR. Red: AR here."""
    held = one_worker.hold()
    try:
        nak = await _send_end_to_end(store, tmp_path, _ADT, timeout=0.1)
    finally:
        held.set()
    assert nak.code == "AE"
    assert nak.permanent is False
    rows = await _error_rows(store)
    assert "strict-validation timed out after 0.1s before the validate began" in rows[0]["error"]
    # The MSA-3 text is the same for both causes; only the code differs.
    assert "before the validate began" not in str(nak)


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
    and stays PERMANENT, with the text the dry-run mirrors."""
    ic = _strict_ic(ConnectorType.HTTP, timeout=1.0)
    receipt = await _runner(store, ic)._handle_inbound_http(ic, _ADT.encode("ascii"))
    assert receipt.refusal is RefusalKind.PERMANENT
    rows = await _error_rows(store)
    assert rows[0]["error"].endswith("strict-validation timed out after 1.0s")
    assert one_worker.calls == [1]


def test_an_abandoned_run_never_validates_and_a_begun_one_reports_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lock protocol on its own: abandon first and the run returns without validating; begin
    first and abandon reports that it began, with its result once it finished."""
    calls: list[int] = []

    def _validate(*_: Any, **__: Any) -> ValidationResult:
        calls.append(1)
        return _OK

    monkeypatch.setattr(wiring_runner, "validate", _validate)

    first = wiring_runner._StrictValidateRun()
    assert first.abandon() == (False, None)
    assert first(_ADT, "2.5.1") is None
    assert calls == []

    second = wiring_runner._StrictValidateRun()
    assert second(_ADT, "2.5.1") is _OK
    assert calls == [1]
    assert second.abandon() == (True, _OK)


async def test_a_validate_that_finished_in_time_is_not_a_timeout_when_the_loop_takes_it_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The validate finishes inside the timeout, but a callback stalls the event loop past the
    timeout, so the loop reaches the timeout before it takes the result. The run had finished, so its
    result is used: a valid body is not refused as a begun timeout, which is final (AR / 422).
    Mutation: drop the finished result from ``_validate_strictly``'s timeout arm. Red:
    ``_StrictValidateTimedOut``. Measured on CPython 3.14: the mutation times out 6 of 6 runs."""
    finished = threading.Event()

    def _fast(*_: Any, **__: Any) -> ValidationResult:
        time.sleep(0.1)  # finishes at about 0.1 s, inside the stall and the 0.3 s timeout
        finished.set()
        return _OK

    monkeypatch.setattr(wiring_runner, "validate", _fast)
    ic = _strict_ic(ConnectorType.MLLP, timeout=0.3)
    loop = asyncio.get_running_loop()
    # Synchronous work on the loop from 0.05 s to 0.55 s, scheduled before the worker finishes.
    loop.call_later(0.05, time.sleep, 0.5)
    result = await wiring_runner._validate_strictly(ic, _ADT)
    assert finished.is_set()
    assert result is _OK


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


async def test_a_strict_receipt_body_over_validates_own_cap_is_oversize(
    store: MessageStore,
) -> None:
    """The receipt half of the cap: OVERSIZE, which the HTTP listener answers ``413``."""
    ic = _strict_ic(ConnectorType.HTTP, max_message_bytes=2 * _STRICT_CAP)
    body = (_hl7_of_length(_STRICT_CAP + 1) + "\r").encode("ascii")
    receipt = await _runner(store, ic)._handle_inbound_http(ic, body)
    assert receipt.refusal is RefusalKind.OVERSIZE


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
