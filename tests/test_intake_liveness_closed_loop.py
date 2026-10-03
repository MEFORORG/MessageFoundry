# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1866: a closed-loop intake liveness test over the runner's whole path.

The load harness used to carry an intake floor, ``read >= sent // 2``, in
``harness/load/report.py`` ``_reconcile``. PR 1407 retired it, and by decision it STAYS retired: it
was a liveness detector wearing a loss label, and its wall-clock ratio tripped on slow hosts that
lost nothing. That comment block is the source of record for why.

It did catch one defect class nothing else in the harness catches: an INTAKE STALL AFTER THE FIRST
COMMIT. If the ingress commit hangs on message 2, a load run ACKs one message, strands the rest as
unconfirmed, and reconciles clean (``acked=1, timeouts=89, read=1, read_short=0``, and
``ack_path_dead`` is false because one reply came back).

This file covers that class without a ratio. It drives a real MLLP listener, wired through the
``Registry`` and ``RegistryRunner`` onto a real SQLite store, with the engine-wide ``IntakeGate``
the Engine injects, through routing, transform and a file delivery, and waits for EVERY ACK it is owed. The only clock is a hang bound: generous, never a
speed assertion, and far above what a healthy run takes on any host. A stalled intake cannot
satisfy "every message was answered", however long it is given.

SCOPE, so nobody reads more into a green than it carries: this is the runner, not ``Engine`` or
``messagefoundry serve``. The gate is wired open, but the Engine's bound monitor that pauses it is
not, so a stall that lives only in that wrapper, or only under non-default serve settings, is
outside it.

The planted control proves the test can go red. It blocks the second ingress commit call until
teardown, runs the SAME assertion body, and requires that body to fail. A liveness test that cannot
fail on the stall it exists for reports a healthy engine and a stalled one identically.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.transports.base import IntakeGate
from messagefoundry.transports.mllp import MLLPDecoder, frame

_INBOUND = "IB_LIVENESS_ADT"
_OUTBOUND = "OB_LIVENESS_SINK"

#: Messages per run. Enough that a stall on message 2 leaves a large, unmistakable shortfall.
_N = 25

#: The hang bound for a whole test: every ACK, then every delivery. A healthy run takes well under a
#: second. It sits under the per-test watchdog, which CI sets per leg in ``.github/workflows/ci.yml``
#: (``--timeout``, the tighter leg at 60 s) and pyproject ``addopts`` sets for a local run, so a
#: failure reads as this file's assertion rather than as a watchdog stack dump.
_HANG_BOUND_S = 40.0

#: The bound the planted control hands the shared body once the stall has fired. It bounds nothing
#: about speed: the stalled message cannot be answered at any speed, so the body fails however long
#: this is. A short value only keeps the control cheap.
_STALL_BODY_BOUND_S = 1.0

_ARMS = [
    # One socket, every frame written up front: harsher pipelining than the load harness's sender,
    # which writes and reads concurrently (harness/load/sender.py).
    pytest.param(1, id="one_connection"),
    # Concurrent intake across sockets on one listener. Messages are dealt round-robin.
    pytest.param(5, id="five_connections"),
]


class _ReplyError(Exception):
    """A reply the client could not read. Kept apart from ``AssertionError`` so a malformed ACK or
    a dropped socket never passes for the stall the planted control expects."""


def _control_id(i: int) -> str:
    return f"LIVE{i:04d}"


def _adt(control_id: str) -> str:
    """A synthetic ADT^A01 (never real PHI). No strict validation is configured, so the only thing
    between it and an AA is the ingress commit."""
    return (
        f"MSH|^~\\&|SENDAPP|SENDFAC|RECVAPP|RECVFAC|20260101||ADT^A01|{control_id}|P|2.5\r"
        "EVN|A01|20260101\r"
        f"PID|1||{control_id}^^^H^MR||DOE^JANE\r"
    )


def _msa(ack: bytes) -> tuple[str, str]:
    """``(MSA-1 code, MSA-2 control id)`` from one ACK frame's payload, split on the ACK's own
    MSH-1 field separator rather than an assumed one."""
    text = ack.decode("utf-8")
    if not text.startswith("MSH") or len(text) < 4:
        raise _ReplyError(f"reply did not open with an MSH segment: {ack!r}")
    separator = text[3]
    for segment in text.split("\r"):
        fields = segment.split(separator)
        if fields[0] == "MSA" and len(fields) >= 3:
            return fields[1], fields[2]
    raise _ReplyError(f"reply carried no usable MSA segment: {ack!r}")


def _registry(outdir: Path) -> Registry:
    """One MLLP inbound, a router that sends everything to one handler, and a file sink."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            _INBOUND,
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            _OUTBOUND,
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send(_OUTBOUND, m))
    return reg


async def _pipelined_client(port: int, control_ids: list[str], acks: dict[str, list[str]]) -> None:
    """Write every frame at once over ONE connection, then read replies until each is answered.

    Every frame goes out before the first reply is read, so the listener holds a full pipeline on
    the socket from the start. Replies land in ``acks`` as they arrive, so a caller that gives up
    early still sees exactly how far intake got.
    """
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"".join(frame(_adt(cid)) for cid in control_ids))
        await writer.drain()
        decoder = MLLPDecoder()
        owed = set(control_ids)
        while not owed.issubset(acks):
            chunk = await reader.read(65536)
            if not chunk:
                missing = len(owed - set(acks))
                raise _ReplyError(f"the listener closed the socket with {missing} unanswered")
            for payload in decoder.feed(chunk):
                code, cid = _msa(payload)
                acks.setdefault(cid, []).append(code)
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


class _StallSecondCommit:
    """Stand in for ``store.enqueue_ingress``: the second call blocks until released, every other
    call commits. Blocking BEFORE the real call holds no store lock, so the stall is "this one
    commit never finishes" and not a store-wide freeze -- the five-connection control measures that.
    """

    def __init__(self) -> None:
        self._real: Callable[..., Awaitable[Any]] | None = None
        self.calls = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    def install(self, store: MessageStore, monkeypatch: pytest.MonkeyPatch) -> None:
        self._real = store.enqueue_ingress
        monkeypatch.setattr(store, "enqueue_ingress", self)

    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        assert self._real is not None, "the stall was called before it was installed"
        self.calls += 1
        if self.calls == 2:
            self.entered.set()
            await self.release.wait()
        return await self._real(*args, **kwargs)


@dataclass
class _Run:
    """One started engine and the pipelined clients driving it."""

    store: MessageStore
    outdir: Path
    sent: list[str]
    shares: list[list[str]] = field(default_factory=list)
    acks: dict[str, list[str]] = field(default_factory=dict)
    clients: list[asyncio.Task[None]] = field(default_factory=list)

    async def wait_for_clients(self, timeout: float) -> None:
        """Wait until every client has its replies, or ``timeout`` passes, then re-raise the first
        client failure. A crashed client must name its own error, not read as a stalled intake."""
        if timeout > 0:
            await asyncio.wait(self.clients, timeout=timeout)
        for task in self.clients:
            error = task.exception() if task.done() else None
            if error is not None:
                raise error


@contextlib.asynccontextmanager
async def _engine_run(
    tmp_path: Path,
    connections: int,
    *,
    stall: _StallSecondCommit | None = None,
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> AsyncIterator[_Run]:
    """Start the engine, open ``connections`` pipelined clients over ``_N`` messages, and tear it
    all down afterwards.

    A ``stall`` goes in over ``store.enqueue_ingress`` before the first frame is sent, and is
    released first on teardown, so ``runner.stop()`` does not wait on a commit told never to finish.
    """
    outdir = tmp_path / "sink"
    outdir.mkdir()  # an absent directory is created on first delivery, with a WARNING we do not want
    store = await MessageStore.open(tmp_path / "engine.db")
    runner: RegistryRunner | None = None
    run: _Run | None = None
    try:
        runner = RegistryRunner(
            _registry(outdir),
            store,
            poll_interval=0.02,
            intake_gate=IntakeGate(),
            egress=EgressSettings(deny_by_default=False),
        )
        await runner.start()
        if stall is not None:
            assert monkeypatch is not None, "a planted stall needs monkeypatch to undo it"
            stall.install(store, monkeypatch)
        port = runner._sources[_INBOUND].sockport  # type: ignore[attr-defined]
        sent = [_control_id(i) for i in range(_N)]
        run = _Run(store, outdir, sent)
        for c in range(connections):
            share = sent[c::connections]
            run.shares.append(share)
            run.clients.append(asyncio.create_task(_pipelined_client(port, share, run.acks)))
        yield run
    finally:
        if stall is not None:
            stall.release.set()
        if run is not None:
            for task in run.clients:
                task.cancel()
            await asyncio.gather(*run.clients, return_exceptions=True)
        try:
            if runner is not None:
                await runner.stop()
        finally:
            await store.close()


async def _until(predicate: Callable[[], Awaitable[bool]], deadline: float) -> bool:
    """Poll ``predicate`` until it holds or the loop clock passes ``deadline``. Returns whether it
    held."""
    loop = asyncio.get_running_loop()
    while not await predicate():
        if loop.time() >= deadline:
            return False
        await asyncio.sleep(0.02)
    return True


async def _assert_closed_loop(run: _Run, deadline: float) -> None:
    """THE body both tests run: every message answered with AA, committed, and delivered, all
    before the loop clock passes ``deadline``. No rate and no ratio anywhere in it."""
    loop = asyncio.get_running_loop()
    await run.wait_for_clients(timeout=deadline - loop.time())

    answered = set(run.acks)
    assert answered == set(run.sent), (
        f"{len(set(run.sent) - answered)} of {_N} messages got no reply within the hang bound "
        f"(intake stalled): first few {sorted(set(run.sent) - answered)[:5]}"
    )
    # Every reply read is an AA, and no message was answered twice before its connection's last
    # reply came in. A duplicate arriving after that is not read, so it is not claimed here.
    wrong = {cid: codes for cid, codes in run.acks.items() if codes != ["AA"]}
    assert wrong == {}, f"a reply was not exactly one AA: {wrong}"

    # Every answered message has its ingress row: the exact bound `read_short` carries in the load
    # harness. It does not prove the ACK FOLLOWED the commit; tests/test_ack_after_commit_invariant.py
    # does that.
    assert await run.store.count_messages(channel_id=_INBOUND) == _N

    # Close the loop through routing, transform and delivery, under what remains of the bound.
    async def delivered() -> bool:
        processed = await run.store.count_messages(
            channel_id=_INBOUND, status=MessageStatus.PROCESSED.value
        )
        return processed == _N and await run.store.in_pipeline_depth() == 0

    assert await _until(delivered, deadline), (
        "not every message reached PROCESSED with an empty pipeline within the hang bound"
    )
    assert sorted(p.stem for p in run.outdir.glob("*.hl7")) == sorted(run.sent)


@pytest.mark.parametrize("connections", _ARMS)
async def test_every_pipelined_message_is_acked_committed_and_delivered(
    tmp_path: Path, connections: int
) -> None:
    """Closed loop: every message sent gets one AA, has an ingress row, and is delivered.

    The one clock is ``_HANG_BOUND_S``, and a healthy engine finishes far inside it on any host. An
    intake stall after the first commit leaves messages unanswered forever, so it fails here at any
    speed. The planted control below runs this same body under that stall and requires the failure.
    """
    async with _engine_run(tmp_path, connections) as run:
        await _assert_closed_loop(run, asyncio.get_running_loop().time() + _HANG_BOUND_S)


@pytest.mark.parametrize("connections", _ARMS)
async def test_a_planted_intake_stall_after_the_first_commit_is_caught(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, connections: int
) -> None:
    """POSITIVE CONTROL: plant the stall the retired floor used to catch, and require the SAME body
    the main test runs to fail on it.

    The second ingress commit call blocks until teardown. The listener answers only after a commit,
    so that message can never be answered, and on a pipelined connection everything behind it waits
    too. Before running the body, the control pins down WHY it will fail: the stall fired, every
    connection it did not touch finished, and exactly one client is still waiting rather than
    crashed or disconnected. Otherwise the body's failure could be a slow host or a broken client.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _HANG_BOUND_S
    stall = _StallSecondCommit()
    async with _engine_run(tmp_path, connections, stall=stall, monkeypatch=monkeypatch) as run:
        # Race the stall against the clients, so a client that crashes or is dropped before the
        # second commit names its own error instead of running out the clock.
        entered = asyncio.create_task(stall.entered.wait())
        try:
            await asyncio.wait(
                [entered, *run.clients],
                timeout=deadline - loop.time(),
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            entered.cancel()
        await run.wait_for_clients(timeout=0)
        assert stall.entered.is_set(), "the second ingress commit was never called"

        # The stalled connection holds at most ceil(_N / connections) messages, so the others must
        # deliver at least the rest. At least one reply must arrive in every arm, which is the
        # one-connection case: message 1 committed before message 2's commit was called. Wait on
        # the CLIENT TASKS finishing, not on the reply count alone, which is reached a moment
        # before the last untouched client returns.
        floor = max(1, _N - math.ceil(_N / connections))

        async def only_the_stalled_client_is_left() -> bool:
            unfinished = sum(not task.done() for task in run.clients)
            return len(run.acks) >= floor and unfinished <= 1

        assert await _until(only_the_stalled_client_is_left, deadline), (
            f"{len(run.acks)} replies arrived, and the stall cannot block the {floor} it leaves"
        )
        await run.wait_for_clients(timeout=0)  # a crashed client names its own error here
        waiting = [i for i, task in enumerate(run.clients) if not task.done()]
        assert len(waiting) == 1, f"{len(waiting)} clients still waiting; the stall blocks one"
        # Every unanswered message belongs to the stalled connection's share.
        unanswered = set(run.sent) - set(run.acks)
        assert unanswered == set(run.shares[waiting[0]]) - set(run.acks)

        # The detection itself: the main test's body, handed a short bound, now fails.
        with pytest.raises(AssertionError, match="got no reply within the hang bound"):
            await _assert_closed_loop(run, loop.time() + _STALL_BODY_BOUND_S)

        if connections == 1:
            # One pipelined connection: message 1 committed, message 2 hangs, 3 onward queue behind.
            assert sorted(run.acks) == [_control_id(0)]
