# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""P2a — MLLP connection-event emit-points + the runner's off-hot-path drain to the store (#46).

The transport tests inject a capturing sink straight onto the source and drive real client sockets,
asserting the lifecycle (established/closed) + the pre-ingress failure kinds fire with the right
metadata. The runner test proves the injected sink → bounded queue → drain task → store path lands
``connection_event`` rows end-to-end.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports import mllp as mllp_mod
from messagefoundry.transports.mllp import CR, EB, SB, MLLPSource, build_ack, frame
from messagefoundry.transports.tcp import TcpSource

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


class _Capture:
    def __init__(self) -> None:
        self.events: list[tuple[str, str | None, str | None]] = []

    async def __call__(self, kind: str, peer_host: str | None, reason: str | None) -> None:
        self.events.append((kind, peer_host, reason))

    def kinds(self) -> list[str]:
        return [k for k, _, _ in self.events]


async def _wait_for(predicate, timeout: float = 2.0) -> bool:  # type: ignore[no-untyped-def]
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


def _mllp(**extra: object) -> MLLPSource:
    return MLLPSource(
        Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0, **extra})
    )


async def _ack_handler(raw: bytes) -> str:
    return build_ack(raw, code="AA")


async def test_emits_established_then_closed() -> None:
    cap = _Capture()
    source = _mllp()
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(ADT))
        await writer.drain()
        await asyncio.wait_for(reader.read(100), 2.0)  # got the ACK → message handled
        assert await _wait_for(lambda: "established" in cap.kinds())
        writer.close()
        await writer.wait_closed()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert cap.kinds()[0] == "established"
    assert "closed" in cap.kinds()
    closed = next((p, r) for k, p, r in cap.events if k == "closed")
    assert closed == ("127.0.0.1", "eof")  # peer host captured; clean-EOF reason


async def test_no_sink_is_a_noop() -> None:
    # Capture off (the default): the listener path is byte-identical — no sink, no crash.
    source = _mllp()
    assert source.on_connection_event is None
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(frame(ADT))
        await writer.drain()
        assert await asyncio.wait_for(reader.read(100), 2.0)  # ACK still returned
        writer.close()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)


async def test_emits_peer_not_allowlisted() -> None:
    cap = _Capture()
    source = _mllp(source_ip_allowlist=["10.0.0.0/8"])  # 127.0.0.1 not allowed
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await asyncio.wait_for(reader.read(), 2.0) == b""  # refused → EOF
        writer.close()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert "peer_not_allowlisted" in cap.kinds()
    assert "established" not in cap.kinds() and "closed" not in cap.kinds()


async def test_emits_at_capacity() -> None:
    cap = _Capture()
    source = _mllp(max_connections=1)
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        _r1, w1 = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await _wait_for(lambda: source._active == 1)  # first client established
        r2, w2 = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await asyncio.wait_for(r2.read(), 2.0) == b""  # second refused → EOF
        assert await _wait_for(lambda: "at_capacity" in cap.kinds())
        w1.close()
        w2.close()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)


async def test_emits_frame_oversize() -> None:
    cap = _Capture()
    source = _mllp(max_frame_bytes=64)
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(bytes([SB]) + b"A" * 200)  # open frame past the cap
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 2.0) == b""  # dropped → EOF
        assert await _wait_for(lambda: "frame_oversize" in cap.kinds())
        writer.close()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)
    # the connection was accepted (established) then failed — no redundant clean 'closed'
    assert "established" in cap.kinds() and "closed" not in cap.kinds()


async def test_idle_timeout_close_reason() -> None:
    cap = _Capture()
    source = _mllp(receive_timeout=0.1)
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await asyncio.wait_for(reader.read(), 2.0) == b""  # idle close
        writer.close()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert await _wait_for(lambda: "closed" in cap.kinds())
    closed_reason = next(r for k, _, r in cap.events if k == "closed")
    assert closed_reason == "idle_timeout"


class _StalledPeer:
    """A sender that takes the ACK bytes and then never drains them.

    A fake rather than a real socket: wedging a real loopback peer means filling its receive window,
    which takes hundreds of KiB of a size the OS picks, so the wedge would be slow and
    platform-dependent. The bound under test is on ``drain()``, and this reproduces exactly that.
    """

    def __init__(self) -> None:
        self.closed = False

    def get_extra_info(self, name: str, default: object = None) -> object:
        # TEST-NET-2 (RFC 5737) — a documentation address, never a routable one.
        return ("198.51.100.7", 2575) if name == "peername" else default

    def write(self, data: bytes) -> None:
        pass

    async def drain(self) -> None:
        await asyncio.sleep(3600)  # the peer is not reading; nothing here ever completes

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


class _OneFrameThenSilent:
    """Hands over one framed message, then holds the connection open without reaching EOF."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self, _n: int) -> bytes:
        if self._data:
            chunk, self._data = self._data, b""
            return chunk
        await asyncio.sleep(3600)
        return b""


async def test_ack_write_drain_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A sender that stops reading must not pin the connection or the slot it holds (BACKLOG #1617).

    ``receive_timeout`` bounds the READ. The ACK write's ``drain()`` was unbounded, so a peer whose
    receive window filled while it kept the connection open would hold its ``max_connections`` slot
    for as long as it liked, with nothing to time it out.
    """
    # The release the fix rides on, asserted rather than assumed: were TimeoutError to stop being an
    # OSError, _on_client's existing arm would miss it and the slot would leak, while the outcome
    # assertions below could still pass on a cancelled task.
    assert issubclass(TimeoutError, OSError)

    cap = _Capture()
    source = _mllp(max_connections=1)
    source.on_connection_event = cap
    await source.start(_ack_handler)
    # Bound the ACK write ONLY. Shrinking _CLIENT_SHUTDOWN_GRACE instead would also shrink the
    # teardown measured at the end, and a stop() that returned fast because its own grace was 0.05 s
    # would say nothing about the connection.
    monkeypatch.setattr(mllp_mod, "_ACK_DRAIN_GRACE", 0.05)
    peer = _StalledPeer()
    try:
        client = asyncio.create_task(
            source._on_client(_OneFrameThenSilent(frame(ADT)), peer)  # type: ignore[arg-type]
        )
        # Unbounded, this never returns. The 2 s is how the regression FAILS, not the assertion.
        await asyncio.wait_for(client, timeout=2.0)
        assert peer.closed  # dropped, not left open on a peer that had stopped reading
        assert source._active == 0  # ... and the max_connections slot went back
        assert "peer_reset" in cap.kinds()
        assert "closed" not in cap.kinds()  # a failure kind is not also reported as a clean close
    finally:
        started = asyncio.get_running_loop().time()
        await asyncio.wait_for(source.stop(), timeout=5.0)
        elapsed = asyncio.get_running_loop().time() - started
    # Nothing was left in flight, so stop() must not have spent its shutdown grace waiting.
    #
    # A LITERAL ceiling, deliberately NOT _CLIENT_SHUTDOWN_GRACE -- do not "tidy" it back to the
    # constant. Deriving it from the shutdown grace is what made the previous version inert: the
    # grace is 5.0 and so is the wait_for above, so a stop() slow enough to matter raised
    # TimeoutError there before the assert was ever reached. It could only ever be evaluated in
    # worlds where it already held. Measured: with a 2.5 s stop() injected, `elapsed < 5.0` passed.
    # 2.0 sits far below that 5.0, so the assert is REACHED and can fail, and far above the 0.05 s
    # _ACK_DRAIN_GRACE plus scheduling slack on a loaded runner, so it is not flaky. PR 1122 uses
    # the same 2.0 for the same reason in the TCP/X12 twins of this test; keep the three in step.
    assert elapsed < 2.0


async def test_tcp_emits_established_then_closed() -> None:
    cap = _Capture()
    source = TcpSource(
        Source(
            type=ConnectorType.TCP, settings={"host": "127.0.0.1", "port": 0, "framing": "vt_fs"}
        )
    )
    source.on_connection_event = cap

    async def handler(raw: bytes) -> None:
        return None

    await source.start(handler)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await _wait_for(lambda: "established" in cap.kinds())
        writer.close()
        await writer.wait_closed()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert cap.kinds()[0] == "established"
    assert "closed" in cap.kinds()


async def test_runner_writes_connection_events_to_store(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "ce_runner.db")
    try:
        reg = Registry()
        reg.add_inbound(
            InboundConnection(
                "IB_T_ADT",
                ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
                router="r",
            )
        )
        reg.add_router("r", lambda m: [])
        runner = RegistryRunner(reg, store)
        await runner.start()
        try:
            port = runner._sources["IB_T_ADT"].sockport  # type: ignore[attr-defined]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(frame(ADT))
            await writer.drain()
            await asyncio.wait_for(reader.read(100), 2.0)
            writer.close()
            await writer.wait_closed()
        finally:
            # Bounded for the same #55 reason as the source-level tests above.
            await asyncio.wait_for(
                runner.stop(), timeout=5.0
            )  # stops the source (closed emitted) then flushes the drain queue
        events = await store.list_connection_events(connection="IB_T_ADT")
        kinds = {e.kind for e in events}
        assert "established" in kinds and "closed" in kinds
        assert all(e.direction == "inbound" and e.transport == "mllp" for e in events)
    finally:
        await store.close()


# --- BACKLOG #1725: the open-frame deadline and the per-host connection cap ----------------------
#
# `receive_timeout` is applied PER READ, so it resets on every byte received: it bounds a SILENT
# socket and says nothing about how long one frame may take to arrive. `max_connections` counts
# sockets rather than hosts, and `source_ip_allowlist` ships off, so on a default listener there was
# no peer-scoped term at all. A deploying site would therefore let one unauthenticated peer hold
# every slot of a listener, each socket pinning up to `max_frame_bytes` of decoder buffer, while
# never completing a message. Nothing is lost or dropped; the cost is availability.
#
# Three arms, and the third is not optional: a deadline that fires on a legitimate slow-but-
# progressing sender is an outage wearing a security control's clothes, and only that arm tells the
# two apart.


async def _wait_until_dropped(reader: asyncio.StreamReader, timeout: float = 3.0) -> None:
    """Wait for the listener to drop us, accepting either spelling of "dropped".

    A clean EOF reads as `b""`. On Windows, closing a socket that still has unread bytes in its
    receive buffer sends an abortive RST instead of a FIN, which surfaces here as
    `ConnectionResetError`. A peer that is still writing when the listener closes sits in exactly
    that window, so asserting `b""` alone makes the test flake on which of the two the OS chose —
    a detail of the teardown race, not of the bound under test.
    """
    with contextlib.suppress(ConnectionResetError):
        assert await asyncio.wait_for(reader.read(), timeout) == b""


async def _trickle(writer: asyncio.StreamWriter, count: int, interval: float) -> None:
    """Open a frame, then feed it one byte at a time — never silent, never finished.

    Stops quietly once the listener drops the connection: a refused write is the PASS condition here,
    not a failure of the sender.
    """
    try:
        writer.write(bytes([SB]))
        await writer.drain()
        for _ in range(count):
            await asyncio.sleep(interval)
            writer.write(b"A")
            await writer.drain()
    except OSError:
        pass  # the listener dropped us, which is what the test is waiting for


async def test_a_trickling_peer_is_dropped_at_the_frame_deadline() -> None:
    """The defect's own case: a byte every 0.05 s under a 0.5 s per-read timeout.

    The peer is never idle for 0.5 s, so `receive_timeout` provably cannot be what fires; before the
    deadline existed this connection was held for as long as the peer cared to trickle.
    """
    cap = _Capture()
    source = _mllp(receive_timeout=0.5, max_frame_seconds=0.3)
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        # 200 bytes at 0.05 s outlives the 3 s read window by a wide margin, so with no deadline this
        # peer is still trickling when the wait expires: the arm reds on the TIMEOUT as well as on
        # the reason. Measured with the deadline stubbed out — the drop then came at 2.5 s (the last
        # byte plus the idle bound) and read `idle_timeout`, which a shorter feed would have hidden
        # behind a passing `read()`.
        feeder = asyncio.create_task(_trickle(writer, count=200, interval=0.05))
        await _wait_until_dropped(reader)
        feeder.cancel()
        await asyncio.gather(feeder, return_exceptions=True)
        writer.close()
        # Awaited, so the socket is gone before the next test runs on this shared loop rather than
        # tearing down under it — the #55 Proactor wedge is attributed to whichever test is running
        # when it lands, not to the one that left the socket behind. Suppressed because the listener
        # dropped us first, and a reset peer raises here on Windows.
        with contextlib.suppress(ConnectionResetError):
            await writer.wait_closed()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert await _wait_for(lambda: "closed" in cap.kinds())
    reason = next(r for k, _, r in cap.events if k == "closed")
    assert reason == "frame_deadline", (
        f"a trickling peer was closed for {reason!r}; the per-read timeout was 0.5 s and the peer "
        "sent a byte every 0.05 s, so the idle bound cannot be what fired"
    )


async def test_an_idle_peer_still_hits_receive_timeout_while_a_frame_is_open() -> None:
    """The idle bound fires independently, on the case the frame deadline would NOT cover.

    A frame is open and its deadline is far away (5 s) while the per-read timeout is 0.1 s, so the two
    bounds are separable by their reasons. This is the arm that would red if the deadline had replaced
    `receive_timeout` rather than joining it, or if taking the smaller of the two lost the idle bound
    whenever a frame was open. `test_idle_timeout_close_reason` above covers the same bound with NO
    frame open, which is the other half of "independently".
    """
    cap = _Capture()
    source = _mllp(receive_timeout=0.1, max_frame_seconds=5.0)
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(bytes([SB]) + b"MSH|")  # open a frame, then say nothing more
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 2.0) == b""  # idle close
        writer.close()
        with contextlib.suppress(ConnectionResetError):
            await writer.wait_closed()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert await _wait_for(lambda: "closed" in cap.kinds())
    reason = next(r for k, _, r in cap.events if k == "closed")
    assert reason == "idle_timeout", (
        f"an idle peer with an open frame was closed for {reason!r}; the frame had 5 s of budget "
        "left, so the idle bound is the only one that should have fired"
    )


async def test_a_slow_but_progressing_peer_inside_both_bounds_is_acked() -> None:
    """The control arm: an over-tight deadline is an outage, and nothing else here would catch it.

    A real partner on a congested link sends one message in several TCP segments with pauses between
    them. This peer stays inside both bounds — each gap is under `receive_timeout` and the whole frame
    completes well inside `max_frame_seconds` — so it must be acknowledged exactly as before.
    """
    cap = _Capture()
    source = _mllp(receive_timeout=0.5, max_frame_seconds=1.0)
    source.on_connection_event = cap
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        blob = frame(ADT)
        step = max(1, len(blob) // 4)
        for offset in range(0, len(blob), step):
            writer.write(blob[offset : offset + step])
            await writer.drain()
            await asyncio.sleep(
                0.05
            )  # under receive_timeout; ~0.2 s total, under max_frame_seconds
        ack = await asyncio.wait_for(reader.read(200), 2.0)
        assert b"MSA|AA" in ack, f"the slow-but-progressing sender was not acknowledged: {ack!r}"
        writer.close()
        await writer.wait_closed()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)


async def test_a_pipelined_sender_gets_a_fresh_deadline_for_each_frame() -> None:
    """The deadline is PER FRAME, and the single-frame control arm above cannot show it.

    A pipelined sender's reads almost never end on a frame boundary, so `decoder.in_frame` stays True
    read after read across DIFFERENT frames. A stamp taken only when nothing was being timed would
    therefore measure every later frame from the FIRST frame's start byte, and drop a healthy feed
    once per `max_frame_seconds` for as long as it kept the socket busy.

    Here every frame is on the wire for microseconds while the connection stays continuously in-frame
    for far longer than `max_frame_seconds`, driven by a deliberately slow handler. Both counts are
    asserted: all frames acknowledged, and no `frame_deadline` anywhere.
    """
    cap = _Capture()
    # The deadline is 1.0 s against a 0.03 s write gap, so a frame has to lose about 0.97 s to a
    # scheduler stall before this test reds for a reason that is not the defect. An earlier 0.3 s
    # deadline left only 0.27 s of that margin, which a loaded CI runner can eat.
    source = _mllp(receive_timeout=5.0, max_frame_seconds=1.0)
    source.on_connection_event = cap

    async def _slow_ack(raw: bytes) -> str:
        await asyncio.sleep(0.01)
        return build_ack(raw, code="AA")

    await source.start(_slow_ack)
    # 60 chunks at 0.03 s is 1.8 s continuously in-frame against a 1.0 s deadline. `asyncio.sleep`
    # is a lower bound, so a loaded runner only lengthens that — the cumulative margin never shrinks,
    # which is why raising the per-frame margin above did not have to be paid for here. Under the
    # defect a clock running across frames closes this connection around chunk 33 of 60, which the
    # count assertion below reports.
    count = 60
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        # Every chunk ENDS by opening the next frame, so the decoder is in-frame at the end of every
        # read no matter how the reads happen to split. Relying on a 4096-byte read landing mid-frame
        # by luck does not reproduce this: a version of this test that wrote all the frames at once
        # passed against the defect, because two reads drained the lot and the clock never ran.
        body = ADT.encode()
        writer.write(bytes([SB]))
        await writer.drain()
        acks = bytearray()
        try:
            for i in range(count):
                # Slower than the handler, so the listener reads chunk by chunk.
                await asyncio.sleep(0.03)
                chunk = body + bytes([EB, CR])
                if i < count - 1:
                    # Open the next frame, except on the LAST chunk. A trailing start byte would
                    # leave an empty frame open with a fresh stamp, and the deadline would then be
                    # racing the ACK drain below — a slow drain would fire `frame_deadline` on the
                    # dangling frame and fail the final assertion while pointing at a defect that is
                    # not there. The last chunk closes cleanly instead.
                    chunk += bytes([SB])
                writer.write(chunk)
                await writer.drain()
        except OSError:
            # The listener dropped us mid-feed. Fall through to the count assertion, which says what
            # happened; a raw ConnectionResetError out of the write loop names only the symptom.
            pass
        deadline = asyncio.get_event_loop().time() + 5.0
        # Same reason as the write loop's `except OSError` above, for the read side: the reader
        # shares the transport, so a drop the write loop swallowed is re-raised HERE on Windows as
        # ConnectionAborted/Reset. Uncaught it replaces the count assertion with a bare WinError,
        # which is the symptom and not the finding. `TimeoutError` is deliberately not suppressed —
        # a hung listener must still fail loudly rather than read as a short ACK count.
        with contextlib.suppress(ConnectionResetError, ConnectionAbortedError):
            while acks.count(b"MSA|AA") < count and asyncio.get_event_loop().time() < deadline:
                block = await asyncio.wait_for(reader.read(65536), 5.0)
                if not block:
                    break  # the listener dropped us, which is the regression this test is for
                acks += block
        assert acks.count(b"MSA|AA") == count, (
            f"only {acks.count(b'MSA|AA')} of {count} pipelined frames were acknowledged; the "
            "connection was dropped mid-feed, so the frame clock is running across frames rather "
            "than being restarted for each one"
        )
        writer.close()
        await writer.wait_closed()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert "frame_deadline" not in [r for _, _, r in cap.events]


async def test_per_host_cap_refuses_a_further_connection_from_the_same_address() -> None:
    """`max_connections_per_host` refuses where `max_connections` cannot.

    The global cap is left OFF, so nothing but the per-host term can produce this refusal, and the
    `at_capacity` event carries the reason that says which budget it was.
    """
    cap = _Capture()
    source = _mllp(max_connections=0, max_connections_per_host=2)
    source.on_connection_event = cap
    assert (
        source.max_connections is None
    )  # 0 disables the global cap: only the per-host one is live
    await source.start(_ack_handler)
    try:
        _r1, w1 = await asyncio.open_connection("127.0.0.1", source.sockport)
        _r2, w2 = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await _wait_for(lambda: source._active == 2)
        r3, w3 = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await asyncio.wait_for(r3.read(), 2.0) == b""  # third from 127.0.0.1 refused -> EOF
        assert await _wait_for(lambda: "at_capacity" in cap.kinds())
        refused = next((p, r) for k, p, r in cap.events if k == "at_capacity")
        assert refused == ("127.0.0.1", "max_connections_per_host")
        # The slot comes back when one of that host's own connections ends — the refusal is
        # pre-ingress and momentary, not a ban.
        w1.close()
        await w1.wait_closed()
        assert await _wait_for(lambda: source._per_host.get("127.0.0.1", 0) == 1)
        _r4, w4 = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await _wait_for(lambda: source._active == 2)
        for w in (w2, w3, w4):
            w.close()
            with contextlib.suppress(ConnectionResetError):
                await w.wait_closed()
        # Checked BEFORE stop(), which clears the table itself: asserted after it, a `_release` that
        # left `{host: 0}` behind would still read as empty and this guard would prove nothing.
        assert await _wait_for(lambda: source._active == 0)
        assert source._per_host == {}, (
            "a peer address was left in the per-host table after every connection closed; a table "
            f"that only grows is the leak the cap would otherwise introduce: {source._per_host}"
        )
        assert source._host_capacity_warned == set()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)


async def test_the_global_cap_refusal_is_still_unqualified() -> None:
    """Both caps emit `at_capacity`, so the REASON is the only thing telling an operator which one
    refused. The global refusal must keep carrying none, or the discriminator is worthless."""
    cap = _Capture()
    source = _mllp(max_connections=1, max_connections_per_host=0)
    source.on_connection_event = cap
    assert source.max_connections_per_host is None  # 0 disables the per-host cap
    await source.start(_ack_handler)
    try:
        _r1, w1 = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await _wait_for(lambda: source._active == 1)
        r2, w2 = await asyncio.open_connection("127.0.0.1", source.sockport)
        assert await asyncio.wait_for(r2.read(), 2.0) == b""
        assert await _wait_for(lambda: "at_capacity" in cap.kinds())
        assert next(r for k, _, r in cap.events if k == "at_capacity") is None
        for w in (w1, w2):
            w.close()
            with contextlib.suppress(ConnectionResetError):
                await w.wait_closed()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)


def test_both_new_caps_ship_on_and_are_reachable_through_the_mllp_factory() -> None:
    """A cap nobody can configure is not a control, and one that ships off protects nobody.

    Pinned against the module constants rather than literals, so changing a default without the
    factory (or the factory without the connector) reds here instead of shipping a listener whose
    documented default is not the one it runs.
    """
    from messagefoundry.config.wiring import MLLP

    source = _mllp()
    assert source.max_frame_seconds == mllp_mod.DEFAULT_MAX_FRAME_SECONDS
    assert source.max_connections_per_host == mllp_mod.DEFAULT_MAX_CONNECTIONS_PER_HOST
    # An EIGHTH, which is the number the constant's own docstring and docs/CONNECTIONS.md both
    # commit to ("at least eight distinct source addresses to fill a default listener"). Pinned at
    # the documented ratio rather than a looser one: a `* 4` bound passes at 64 per host, which
    # would falsify all three statements while leaving this test green.
    assert source.max_connections_per_host * 8 <= mllp_mod.DEFAULT_MAX_CONNECTIONS

    settings = MLLP(port=2575).settings
    assert settings["max_frame_seconds"] == mllp_mod.DEFAULT_MAX_FRAME_SECONDS
    assert settings["max_connections_per_host"] == mllp_mod.DEFAULT_MAX_CONNECTIONS_PER_HOST
    # The same None/0-disables convention every other cap on this listener follows.
    assert MLLP(port=2575, max_frame_seconds=None).settings["max_frame_seconds"] is None
    assert _mllp(max_frame_seconds=0).max_frame_seconds is None


def test_a_negative_cap_is_refused_at_build_not_discovered_at_the_first_connection() -> None:
    """A negative value is TRUTHY, so it survives the `if value` that reads `0` as "off".

    Left unchecked, `max_connections_per_host=-1` is worse than a wrong number: `0 >= -1` is true,
    so every peer is refused including one holding no connections, and because nothing is ever
    admitted nothing ever clears `_host_capacity_warned` — one attacker-chosen key per source
    address, which is the unbounded table this control is not allowed to contain. `max_frame_seconds`
    negative would expire every frame the instant it opened. Both fail at build, where dry-run and
    `messagefoundry check` surface them, rather than at the first connection in production.
    """
    with pytest.raises(ValueError, match="max_connections_per_host must be at least 1"):
        _mllp(max_connections_per_host=-1)
    with pytest.raises(
        ValueError, match="max_frame_seconds must be a number of seconds, zero or more"
    ):
        _mllp(max_frame_seconds=-1.0)
    # NaN is truthy and fails every comparison, so a `< 0` test let it through as a live deadline.
    with pytest.raises(
        ValueError, match="max_frame_seconds must be a number of seconds, zero or more"
    ):
        _mllp(max_frame_seconds=float("nan"))
    # 0 stays the documented "off" spelling for both, and is NOT caught by the refusal above.
    assert _mllp(max_connections_per_host=0).max_connections_per_host is None
    assert _mllp(max_frame_seconds=0).max_frame_seconds is None


# --- the string "0", which is how an env() reference without a cast spells a disable -------------
#
# Why that spelling reaches a connector, and why deciding "off" before the conversion got it wrong,
# is on `_cap_setting` in transports/mllp.py. One arm per setting rather than one combined test,
# because the caps fail in several different ways and a combined test would stop at the first.


async def _write_then_read_ack(
    writer: asyncio.StreamWriter, reader: asyncio.StreamReader, payload: bytes
) -> bytes:
    """Write `payload` and return whatever comes back, or `b""` if the listener dropped us.

    Every defect these arms pin ends with the listener closing the connection, and on Windows that
    surfaces as `ConnectionResetError` out of the write OR the read rather than a clean empty read.
    Raised, it fails the test naming only the symptom; swallowed here, the caller's own assertion
    fires and can say which cap and which connection_event were responsible.
    """
    with contextlib.suppress(ConnectionResetError, BrokenPipeError):
        writer.write(payload)
        await writer.drain()
        return await asyncio.wait_for(reader.read(200), 2.0)
    return b""


async def test_a_string_zero_receive_timeout_is_off_not_a_zero_second_read_budget() -> None:
    """A live zero-second read budget closes every connection the instant it is accepted.

    Asserted behaviourally as well as on the attribute, because an attribute test passes against a
    connector that reads the value correctly and then arms the wait on something else.
    """
    source = _mllp(receive_timeout="0", max_frame_seconds=None)
    assert source.receive_timeout is None
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        # Say nothing at all for far longer than a zero-second budget tolerates. Under the
        # regression the listener has already closed by now and this frame goes nowhere. Kept
        # generous on purpose: shortening it would race the close on a loaded runner, and a race
        # here fails OPEN — the test would pass against the defect.
        await asyncio.sleep(0.25)
        ack = await _write_then_read_ack(writer, reader, frame(ADT))
        assert b"MSA|AA" in ack, (
            "a listener with receive_timeout='0' did not acknowledge a frame sent after a quiet "
            f"quarter-second: {ack!r}. Nothing came back, so the idle bound fired and the string "
            "was converted to a live zero-second budget instead of being read as off"
        )
        writer.close()
        await writer.wait_closed()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)


async def test_a_string_zero_max_frame_seconds_is_off_not_a_zero_second_deadline() -> None:
    """Same spelling, a different failure: a live `0.0` expires every frame that spans two reads.

    A frame delivered in one read is never re-examined, so this needs a SPLIT frame to show the
    defect — which is also the realistic case, since a partner on a congested link routinely sends
    one message in several segments. Under a live zero the second read finds the budget already
    spent and the connection closes with a `frame_deadline` reason instead of being acknowledged.
    """
    cap = _Capture()
    source = _mllp(receive_timeout=5.0, max_frame_seconds="0")
    source.on_connection_event = cap
    assert source.max_frame_seconds is None
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        blob = frame(ADT)
        writer.write(blob[: len(blob) // 2])  # opens the frame, does not close it
        await writer.drain()
        # Long enough that the two halves land in separate reads whatever the runner is doing. The
        # requirement is two reads, not a long gap, but a gap too short to guarantee them would fail
        # OPEN — one read never re-examines the deadline, so the test would pass against the defect.
        await asyncio.sleep(0.25)
        ack = await _write_then_read_ack(writer, reader, blob[len(blob) // 2 :])
        assert b"MSA|AA" in ack, (
            "a listener with max_frame_seconds='0' did not acknowledge a frame split across two "
            f"reads: {ack!r}. The string was converted to a live zero-second deadline rather than "
            "being read as off"
        )
        writer.close()
        await writer.wait_closed()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)
    assert not [e for e in cap.events if e[2] == "frame_deadline"], (
        f"a frame_deadline fired on a listener whose deadline is off: {cap.events}"
    )


def test_a_string_zero_max_connections_per_host_is_off_not_a_refused_build() -> None:
    """A third failure mode: not a wrong bound but a build that refuses the documented spelling.

    `int("0")` is `0`, and the negative-cap guard reads `0 < 1` as a typo — so the listener failed
    to build with a message telling the operator to write `0`, which is what they had written. The
    guard now sees only genuinely negative values, in either spelling.
    """
    assert _mllp(max_connections_per_host="0").max_connections_per_host is None
    with pytest.raises(ValueError, match="max_connections_per_host must be at least 1"):
        _mllp(max_connections_per_host="-1")
    # A string that is not a disable still configures the cap it names, on every one of the five, so
    # none of this can be passing by turning all text into None.
    assert _mllp(max_connections_per_host="8").max_connections_per_host == 8
    assert _mllp(max_connections="99").max_connections == 99
    assert _mllp(receive_timeout="30").receive_timeout == 30.0
    assert _mllp(max_frame_bytes="4096").max_frame_bytes == 4096
    assert _mllp(max_frame_seconds="45").max_frame_seconds == 45.0


def test_a_sub_one_cap_is_still_refused_and_is_not_swallowed_as_off() -> None:
    """ "Off" means the operator WROTE zero, not that the value truncates to zero.

    The narrow way to read a string zero as off is to convert first and test the result. On an `int`
    cap that also reads `-0.5` as off, because `int(-0.5)` is `0` — turning a refusal into a silently
    disabled security cap, and in the fail-open direction. `_cap_setting` tests a float view instead,
    so a sub-1 value still reaches the guard that was written for it.

    Only reachable from a hand-written Python kwarg: `connections.toml` refuses a float or a string
    on an integer key, and an uncast `env()` ref hands over text that `int()` rejects. Pinned anyway,
    because the whole subject of this group is a spelling nobody expected to be reachable either.
    """
    for bad in (-0.5, 0.5, -1):
        with pytest.raises(ValueError, match="max_connections_per_host must be at least 1"):
            _mllp(max_connections_per_host=bad)
    # The float cap has no truncation to hide behind, so its guard sees the value as written.
    with pytest.raises(ValueError, match="max_frame_seconds must be a number of seconds"):
        _mllp(max_frame_seconds=-0.5)
    # Negative zero is a way of writing zero, not a negative, and must not reach either guard.
    assert _mllp(max_connections_per_host=-0.0).max_connections_per_host is None
    assert _mllp(max_frame_seconds="-0.0").max_frame_seconds is None


@pytest.mark.parametrize("setting", ["max_connections", "max_frame_bytes"])
async def test_a_string_zero_on_the_two_older_caps_is_off_too(setting: str) -> None:
    """The two caps that predate the frame deadline read the STRING `"0"` the same way, and worse.

    A plain `0` has always meant off on both, and `test_emits_at_capacity` above relies on that. It
    is the string that used to survive the truthiness test and land as a LIVE zero, where
    `max_connections` refuses every connection (`self._active >= 0` on the first one) and
    `max_frame_bytes` makes `FrameDecoder` raise on any frame of one byte or more. Neither is a
    subtle mis-bound — each turns the listener off while the operator reads their own config as
    having disabled a cap, which is why they are covered here rather than left for a follow-up.

    One plain frame, acknowledged, separates both from their defective forms.
    """
    cap = _Capture()
    source = _mllp(**{setting: "0"})
    source.on_connection_event = cap
    assert getattr(source, setting) is None
    await source.start(_ack_handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        ack = await _write_then_read_ack(writer, reader, frame(ADT))
        assert b"MSA|AA" in ack, (
            f"a listener with {setting}='0' did not acknowledge one ordinary frame: {ack!r}. "
            f"The string was converted to a live zero rather than being read as off; "
            f"the events say which gate refused it: {cap.events}"
        )
        writer.close()
        await writer.wait_closed()
    finally:
        # Bound teardown so a listener-stop regression (the #55 Windows Proactor wedge) fails LOUD as a
        # fast timeout instead of silently hanging the shared session loop — mirrors test_connection_resilience.
        await asyncio.wait_for(source.stop(), timeout=5.0)
