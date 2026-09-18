# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Raw-TCP transport with configurable delimiter framing (tcp.py + framing.py).

Covers the shared frame codec (frame/deframe, reassembly across chunks, inter-frame noise, oversize
reject) for the STX/ETX and VT/FS presets, a TcpSource<->TcpDestination loopback round-trip over a
real port, opaque byte relay, the no-reply vs framed-reply paths, expect_reply on the destination,
the [egress].allowed_tcp allowlist, the Tcp(...) factory presets/guards, and that MLLP's existing
framing behavior is unchanged after refactoring it onto the shared codec."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Tcp,
    WiringError,
    inbound,
    outbound,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, check_egress_allowed
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports import tcp as tcp_mod
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.framing import (
    MLLP_CODEC,
    STX_ETX_CODEC,
    FrameCodec,
    FrameError,
    codec_for,
)
from messagefoundry.transports.mllp import MLLPDecoder, MLLPFrameError, frame
from messagefoundry.transports.tcp import TcpDestination, TcpSource

X12 = "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       ~GS*HC*S*R~"


# --- codec: framing + decoding -----------------------------------------------


def test_stx_etx_frame_wraps_with_delimiters() -> None:
    framed = STX_ETX_CODEC.frame("HELLO")
    assert framed[0] == 0x02
    assert framed[-1] == 0x03  # no trailer
    assert framed[1:-1] == b"HELLO"


def test_vt_fs_preset_equals_mllp_framing() -> None:
    # VT/FS is the same scheme MLLP uses; the preset must produce byte-identical framing.
    assert codec_for("vt_fs") is MLLP_CODEC
    assert FrameCodec(start=0x0B, end=0x1C, trailer=0x0D).frame("X") == frame("X")


def test_stx_etx_decoder_single_message() -> None:
    dec = STX_ETX_CODEC.decoder()
    assert list(dec.feed(STX_ETX_CODEC.frame("MSH|one"))) == [b"MSH|one"]


def test_decoder_splits_multiple_messages_in_one_chunk() -> None:
    data = STX_ETX_CODEC.frame("AAA") + STX_ETX_CODEC.frame("BBB")
    assert list(STX_ETX_CODEC.decoder().feed(data)) == [b"AAA", b"BBB"]


def test_decoder_reassembles_across_chunks_one_byte_at_a_time() -> None:
    full = STX_ETX_CODEC.frame("split me up")
    dec = STX_ETX_CODEC.decoder()
    out: list[bytes] = []
    for i in range(len(full)):
        out.extend(dec.feed(full[i : i + 1]))
    assert out == [b"split me up"]


def test_decoder_discards_inter_frame_noise() -> None:
    # Leading junk and bytes between frames (incl. a stray byte where a trailer-less scheme has none)
    # are ignored, matching tolerant receivers.
    data = b"garbage" + STX_ETX_CODEC.frame("AAA") + b"\r\n" + STX_ETX_CODEC.frame("BBB")
    assert list(STX_ETX_CODEC.decoder().feed(data)) == [b"AAA", b"BBB"]


def test_decoder_rejects_oversize_open_frame() -> None:
    dec = STX_ETX_CODEC.decoder(max_frame_bytes=4)
    with pytest.raises(FrameError):
        list(dec.feed(b"\x02" + b"toolong"))


def test_decoder_in_frame_tracks_the_open_frame() -> None:
    # in_frame is the ADR 0067 reuse-desync guard, so assert it directly rather than leaning on the
    # persistent-connection tests that only observe it through a desync verdict.
    dec = STX_ETX_CODEC.decoder()
    assert not dec.in_frame
    assert list(dec.feed(b"\x02MSH|par")) == []
    assert dec.in_frame  # start byte seen, end byte not yet: a partial payload is buffered
    assert list(dec.feed(b"tial\x03")) == [b"MSH|partial"]
    assert not dec.in_frame
    assert list(dec.feed(b"trailing noise")) == []
    assert not dec.in_frame


def test_decoder_resets_state_after_an_oversize_frame() -> None:
    dec = STX_ETX_CODEC.decoder(max_frame_bytes=4)
    with pytest.raises(FrameError):
        list(dec.feed(b"\x02" + b"toolong"))
    assert not dec.in_frame  # state reset on the raise, so the decoder is reusable
    assert list(dec.feed(STX_ETX_CODEC.frame("ok"))) == [b"ok"]


def test_decoder_is_split_invariant_at_every_read_boundary() -> None:
    # A frame must decode identically however the reads fall -- including a delimiter landing as the
    # last byte of one read, and a start byte inside a payload, which is content and not a new frame.
    payload = "first|" + chr(0x02) + "|a start byte inside a frame is payload"
    stream = (
        b"lead-in noise" + STX_ETX_CODEC.frame(payload) + b"\r\n" + STX_ETX_CODEC.frame("second")
    )
    expected = [payload.encode(), b"second"]
    assert list(STX_ETX_CODEC.decoder().feed(stream)) == expected
    for cut in range(len(stream) + 1):
        dec = STX_ETX_CODEC.decoder()
        out: list[bytes] = []
        out.extend(dec.feed(stream[:cut]))
        out.extend(dec.feed(stream[cut:]))
        assert out == expected, f"a read boundary at byte {cut} decoded differently"
        assert not dec.in_frame


def test_decoder_cap_admits_exactly_max_frame_bytes() -> None:
    # The cap bounds the payload: exactly max_frame_bytes is accepted and one byte more raises.
    # Pinned because checking a whole slice's length sits one byte away from the per-byte check.
    whole = STX_ETX_CODEC.decoder(max_frame_bytes=4).feed(STX_ETX_CODEC.frame("ABCD"))
    assert list(whole) == [b"ABCD"]
    with pytest.raises(FrameError):
        list(STX_ETX_CODEC.decoder(max_frame_bytes=4).feed(STX_ETX_CODEC.frame("ABCDE")))


def test_decoder_cap_ignores_an_end_delimiter_beyond_it() -> None:
    # The end delimiter is present in this read but sits past the cap. Locating it first must not
    # rescue an over-cap frame: the cap is charged against the payload before the frame closes.
    dec = STX_ETX_CODEC.decoder(max_frame_bytes=2)
    with pytest.raises(FrameError):
        list(dec.feed(b"\x02" + b"far beyond the cap" + b"\x03"))


def test_decoder_yields_earlier_frames_before_an_over_cap_frame_in_the_same_read() -> None:
    # Both inbound listeners iterate feed() lazily and await the handler plus the ACK between
    # frames, so a frame that completed earlier in the read must already be handed over when a
    # later frame in that same read blows the cap.
    dec = STX_ETX_CODEC.decoder(max_frame_bytes=4)
    seen: list[bytes] = []
    with pytest.raises(FrameError):
        for message in dec.feed(STX_ETX_CODEC.frame("AAA") + b"\x02" + b"far too long"):
            seen.append(message)
    assert seen == [b"AAA"]


def test_decoder_decodes_16_mib_without_a_per_byte_walk() -> None:
    """16 MiB in 4 KiB reads must cost a fraction of a per-byte walk over the same bytes.

    The budget is calibrated on the machine running the test rather than hard-coded, so a slow or
    loaded runner scales both halves together instead of flaking (BACKLOG #1728).
    """
    mib = 1024 * 1024
    framed = MLLP_CODEC.frame(b"A" * (16 * mib))

    # Baseline: the shape feed() used to have -- one Python loop step per inbound byte.
    sample = bytes(mib)
    buf = bytearray()
    started = time.perf_counter()
    for byte in sample:
        if byte == MLLP_CODEC.end:
            buf.clear()
        else:
            buf.append(byte)
    per_byte_one_mib = time.perf_counter() - started

    dec = MLLP_CODEC.decoder(max_frame_bytes=32 * mib)
    decoded = 0
    started = time.perf_counter()
    for offset in range(0, len(framed), 4096):
        for message in dec.feed(framed[offset : offset + 4096]):
            decoded += len(message)
    elapsed = time.perf_counter() - started

    assert decoded == 16 * mib
    assert not dec.in_frame
    # A per-byte decoder costs 16 baseline units to walk these 16 MiB. Half that is a loose ceiling
    # -- roughly 8x headroom on the measured slice-based cost, and still red on a per-byte relapse.
    budget = 8 * per_byte_one_mib
    assert elapsed < budget, (
        f"16 MiB in 4 KiB reads took {elapsed:.3f}s against a {budget:.3f}s budget "
        f"({per_byte_one_mib * 1000:.0f}ms per MiB per-byte baseline)"
    )


def test_codec_validates_bytes_and_distinct_delimiters() -> None:
    with pytest.raises(ValueError):
        FrameCodec(start=0x02, end=0x02)  # start == end
    with pytest.raises(ValueError):
        FrameCodec(start=300, end=0x03)  # out of range
    with pytest.raises(ValueError, match="not both"):
        codec_for("stx_etx", start=0x02)  # preset AND explicit
    with pytest.raises(ValueError, match="unknown framing preset"):
        codec_for("nope")
    with pytest.raises(ValueError):
        codec_for(None)  # neither preset nor bytes


# --- MLLP unchanged after refactor onto the shared codec ---------------------


def test_mllp_framing_still_intact() -> None:
    framed = frame("HELLO")
    assert framed[0] == 0x0B and framed[-2:] == bytes([0x1C, 0x0D])
    assert list(MLLPDecoder().feed(framed)) == [b"HELLO"]


def test_mllp_decoder_still_raises_mllpframeerror() -> None:
    # The MLLP decoder must still raise MLLPFrameError (a FrameError subclass) so existing
    # `except MLLPFrameError` handlers in mllp.py keep catching it.
    dec = MLLPDecoder(max_frame_bytes=2)
    with pytest.raises(MLLPFrameError):
        list(dec.feed(b"\x0b" + b"abc"))


# --- loopback round-trip + relay ---------------------------------------------


def _source(**settings: object) -> TcpSource:
    base: dict[str, object] = {"host": "127.0.0.1", "port": 0, "framing": "stx_etx"}
    base.update(settings)
    return TcpSource(Source(type=ConnectorType.TCP, settings=base))


def _dest(port: int, **settings: object) -> TcpDestination:
    base: dict[str, object] = {
        "host": "127.0.0.1",
        "port": port,
        "framing": "stx_etx",
        "timeout_seconds": 5,
    }
    base.update(settings)
    return TcpDestination(Destination(name="out", type=ConnectorType.TCP, settings=base))


async def test_round_trip_opaque_relay() -> None:
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)
        return None  # fire-and-forget (no reply)

    source = _source()
    await source.start(handler)
    try:
        await _dest(source.sockport).send(X12)
        # Give the listener a beat to deliver the framed payload to the handler.
        for _ in range(50):
            if received:
                break
            await asyncio.sleep(0.01)
    finally:
        await source.stop()
    # The bytes are relayed verbatim (opaque) — delimiters stripped, payload unchanged.
    assert received == [X12.encode("utf-8")]


async def test_destination_no_reply_returns_when_not_expecting_one() -> None:
    async def handler(raw: bytes) -> None:
        return None

    source = _source()
    await source.start(handler)
    try:
        # expect_reply defaults False → send returns after the write without waiting for a reply.
        await _dest(source.sockport).send(X12)
    finally:
        await source.stop()


async def test_destination_expect_reply_reads_framed_reply() -> None:
    received: list[bytes] = []

    async def handler(raw: bytes) -> str:
        received.append(raw)
        return "ACK-OPAQUE"  # the source frames + sends this back on the same connection

    source = _source()
    await source.start(handler)
    try:
        # With expect_reply the destination reads one framed reply and treats it as confirmation:
        # the frame is CONSUMED, not returned. capture_response (ADR 0013) is the knob that hands
        # one back as a DeliveryResponse.
        assert await _dest(source.sockport, expect_reply=True).send(X12) is None
    finally:
        await source.stop()
    # Settled by the time send() returns, because the source awaits the handler before writing the
    # reply: the payload reached the peer verbatim. That the destination BLOCKS for the reply is the
    # sibling test below, which raises DeliveryError when none is sent.
    assert received == [X12.encode("utf-8")]


async def test_destination_expect_reply_times_out_when_none_sent() -> None:
    async def handler(raw: bytes) -> None:
        return None  # no reply ever sent

    source = _source()
    await source.start(handler)
    try:
        dest = _dest(source.sockport, expect_reply=True, timeout_seconds=0.3)
        with pytest.raises(DeliveryError):
            await dest.send(X12)
    finally:
        await source.stop()


async def test_destination_connect_failure_raises_delivery_error() -> None:
    # Nothing is listening on this port.
    with pytest.raises(DeliveryError):
        await _dest(1).send(X12)


async def test_source_drops_oversize_frame() -> None:
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)
        return None

    source = _source(max_frame_bytes=8)
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(b"\x02" + b"way too long to fit")  # over-cap open frame, no end delimiter
        await writer.drain()
        # The connection is dropped (EOF) and nothing is delivered.
        assert await reader.read(1) == b""
        writer.close()
    finally:
        await source.stop()
    assert received == []


# --- the reply write is bounded ----------------------------------------------


class _StalledPeer:
    """A sender that takes the reply bytes and then never drains them.

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


async def test_reply_write_drain_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A sender that stops reading must not pin the connection or the slot it holds.

    ``receive_timeout`` bounds the READ. The reply write's ``drain()`` was unbounded, so a peer whose
    receive window filled while it kept the connection open would hold its ``max_connections`` slot
    for as long as it liked, with nothing to time it out. ``TcpDestination``'s own drains were
    already bounded by ``self.timeout``, so the inbound reply was the outlier, not the convention.
    ``MLLPSource`` carries the same defect and is fixed on PR 1117, which is **not merged** — do not
    read this test as covering it.
    """
    # The release the fix rides on, asserted rather than assumed: were TimeoutError to stop being an
    # OSError, _on_client's existing arm would miss it and the slot would leak, while the outcome
    # assertions below could still pass on a cancelled task.
    assert issubclass(TimeoutError, OSError)

    events: list[str] = []

    async def capture(kind: str, peer_host: str | None, reason: str | None) -> None:
        events.append(kind)

    async def reply_handler(raw: bytes) -> str:
        return "REPLY"

    source = _source(max_connections=1)
    source.on_connection_event = capture
    await source.start(reply_handler)
    # Bound the reply write ONLY. Shrinking _CLIENT_SHUTDOWN_GRACE instead would also shrink the
    # teardown measured at the end, and a stop() that returned fast because its own grace was 0.05 s
    # would say nothing about the connection.
    monkeypatch.setattr(tcp_mod, "_REPLY_DRAIN_GRACE", 0.05)
    peer = _StalledPeer()
    try:
        framed = STX_ETX_CODEC.frame("PING", "utf-8")
        client = asyncio.create_task(
            source._on_client(_OneFrameThenSilent(framed), peer)  # type: ignore[arg-type]
        )
        # Unbounded, this never returns. The 2 s is how the regression FAILS, not the assertion.
        await asyncio.wait_for(client, timeout=2.0)
        assert peer.closed  # dropped, not left open on a peer that had stopped reading
        assert source._active == 0  # ... and the max_connections slot went back
        # Pins the order and the absence of anything else; "established" is the only other kind on
        # this path, and a failure must not also be reported as a clean "closed".
        assert events == ["established", "peer_reset"]
    finally:
        started = asyncio.get_running_loop().time()
        await asyncio.wait_for(source.stop(), timeout=5.0)
        elapsed = asyncio.get_running_loop().time() - started
    # Nothing was left in flight, so stop() must not have spent its shutdown grace waiting. The
    # threshold is deliberately well UNDER _CLIENT_SHUTDOWN_GRACE (5.0) rather than equal to it:
    # the wait_for above already raises at 5.0, so `elapsed < 5.0` could never fail and would pin
    # nothing. 2 s leaves a wide margin for a slow runner while still catching a teardown that waits.
    assert elapsed < 2.0


# --- build via the registry --------------------------------------------------


def test_build_source_and_destination_via_registry() -> None:
    src = build_source(
        Source(
            type=ConnectorType.TCP, settings={"host": "127.0.0.1", "port": 0, "framing": "vt_fs"}
        )
    )
    assert isinstance(src, TcpSource) and src.codec is MLLP_CODEC
    dest = build_destination(
        Destination(
            name="o",
            type=ConnectorType.TCP,
            settings={"host": "127.0.0.1", "port": 9, "start": 0x02, "end": 0x03},
        )
    )
    assert isinstance(dest, TcpDestination)
    assert (dest.codec.start, dest.codec.end, dest.codec.trailer) == (0x02, 0x03, None)


def test_build_source_rejects_bad_framing() -> None:
    with pytest.raises(ValueError, match="framing"):
        build_source(Source(type=ConnectorType.TCP, settings={"port": 0, "framing": "bogus"}))


# --- factory + wiring guards -------------------------------------------------


def test_tcp_factory_default_preset_and_explicit_bytes() -> None:
    assert Tcp(port=5000).settings["framing"] == "stx_etx"
    spec = Tcp(port=5000, framing=None, start=0x01, end=0x04)
    assert spec.type is ConnectorType.TCP
    assert (spec.settings["start"], spec.settings["end"]) == (0x01, 0x04)


def test_inbound_tcp_rejects_host() -> None:
    reg = Registry()
    import messagefoundry.config.wiring as w

    w._active = reg
    try:
        with pytest.raises(WiringError, match="takes no host"):
            inbound("IB_X12", Tcp(host="203.0.113.1", port=5000), router="r")
    finally:
        w._active = None


def test_outbound_tcp_requires_host() -> None:
    reg = Registry()
    import messagefoundry.config.wiring as w

    w._active = reg
    try:
        with pytest.raises(WiringError, match="requires a host"):
            outbound("OB_X12", Tcp(port=5000))
    finally:
        w._active = None


# --- egress allowlist --------------------------------------------------------


def _tcp_dest(host: str, port: int) -> Destination:
    return Destination(name="OB", type=ConnectorType.TCP, settings={"host": host, "port": port})


def test_tcp_egress_empty_allowlist_is_unrestricted() -> None:
    check_egress_allowed(_tcp_dest("anywhere.example", 1234), EgressSettings())  # no raise


def test_tcp_egress_allowlist_enforced() -> None:
    e = EgressSettings(allowed_tcp=["x12.partner.org:5000", "10.0.0.9"])
    check_egress_allowed(_tcp_dest("x12.partner.org", 5000), e)  # exact host:port
    check_egress_allowed(_tcp_dest("10.0.0.9", 7777), e)  # host-only entry → any port
    with pytest.raises(WiringError, match="allowed_tcp"):
        check_egress_allowed(_tcp_dest("evil.example", 5000), e)
    with pytest.raises(WiringError, match="allowed_tcp"):
        check_egress_allowed(_tcp_dest("x12.partner.org", 6661), e)  # wrong port


async def test_tcp_inbound_listener_is_not_connect_gated(tmp_path: Path) -> None:
    # A TCP source is a local listener (binds bind_host), so it must build-check cleanly even when an
    # allowed_tcp list exists — the list governs only TCP destinations.
    store = await MessageStore.open(tmp_path / "x.db")
    try:
        reg = Registry()
        reg.add_inbound(
            InboundConnection(
                "IB_X12",
                ConnectionSpec(ConnectorType.TCP, {"port": 5000, "framing": "stx_etx"}),
                router="r",
                content_type=ContentType.X12,
            )
        )
        reg.add_router("r", lambda m: [])
        reg.add_outbound(
            OutboundConnection(
                "OB_X12",
                ConnectionSpec(
                    ConnectorType.TCP, {"host": "ok.org", "port": 5000, "framing": "stx_etx"}
                ),
            )
        )
        runner = RegistryRunner(reg, store, egress=EgressSettings(allowed_tcp=["ok.org:5000"]))
        runner.build_check(runner.registry)  # no raise — listener not gated, dest allowed
    finally:
        await store.close()
