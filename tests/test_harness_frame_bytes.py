# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The test harness never emits an MLLP frame whose payload holds a frame byte (ASVS 1.1.2).

ADR 0205 rule 1 made the engine refuse to deliver a payload holding its codec's start or end byte,
and made its listeners neutralise one in a reply. The harness cannot import ``transports/``
(``tests/test_dependency_boundaries.py``), so it framed with the leaf's bare ``frame``, which looks
at nothing: an echoed MSH-10 holding ``0x0B`` gave an ACK frame with three start bytes, and one
holding ``0x1C`` cut the ACK short. The check now lives in the leaf
(:meth:`messagefoundry.framing.FrameCodec.find_frame_byte`), the engine's delivery and reply framers
delegate to it, and every harness site that is not a deliberate hostile injector frames through it:

* an MLLP ACK is NEUTRALISED (each frame byte becomes a space), as the engine's listeners reply,
  so the peer always reads exactly one frame;
* a send is REFUSED with the reason: the Send tab before it dials, the load sender on its open
  connection, and the raw-TCP sink's configured reply when the sink is built.

The Compose tab (behind an opt-in checkbox only), the fuzzer and the scenario drivers still frame
unchecked, on purpose; each is named, with its reason and its number of bare uses, in
``_DELIBERATE`` below.

Each site is driven with an echoed or sent value holding ``0x0B``, ``0x1C`` and ``0x1C 0x0D``, and
each case has its positive control: the bare ``frame`` of the same bytes IS malformed, so a pass is
not a check that cannot fail. Synthetic data only.
"""

from __future__ import annotations

import ast
import asyncio
import io
import socket
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from harness.load.corpus import Outgoing
from harness.load.correlator import Correlator
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.sender import PersistentConnection
from harness.load.sink import CorrelationSink
from harness.reconcile.capture import CaptureSink
from harness.sinks import mllp as mllp_sink_module
from harness.sinks.mllp import MLLPSink
from harness.sinks.tcp import TcpSink
from messagefoundry.framing import (
    MLLP_CODEC,
    STX_ETX_CODEC,
    FrameByteFault,
    FrameCodec,
    FrameEncodeError,
    FramePayloadError,
)
from messagefoundry.mllpcodec import (
    CR,
    EB,
    SB,
    AckMode,
    MLLPDecoder,
    build_ack,
    frame,
    frame_checked,
    frame_neutralised,
)

_REPO = Path(__file__).resolve().parents[1]

#: The start byte, the end byte alone, and the end byte before the trailer CR. Why the end byte is
#: refused alone is stated at ``FrameCodec.find_frame_byte``.
_HOSTILE_IDS = {
    "start_byte": "A\x0bB",
    "end_byte": "A\x1cB",
    "end_then_cr": "A\x1c\rB",
}


def _message(control_id: str) -> str:
    return (
        f"MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A01^ADT_A01|{control_id}|P|2.5.1\r"
        "EVN|A01|20260101000000\r"
    )


def _is_one_clean_mllp_frame(wire: bytes) -> bool:
    """Exactly one MLLP frame, ``SB body EB CR``, with no frame byte inside the body, and a decoder
    reads back exactly that body."""
    if len(wire) < 3 or wire[0] != SB or wire[-2:] != bytes([EB, CR]):
        return False
    body = wire[1:-2]
    if SB in body or EB in body:
        return False
    return list(MLLPDecoder().feed(wire)) == [body]


@pytest.fixture(params=sorted(_HOSTILE_IDS))
def hostile_id(request: pytest.FixtureRequest) -> str:
    return _HOSTILE_IDS[str(request.param)]


# --- the leaf: one definition of a payload that breaks framing ---------------------------------


@pytest.mark.parametrize("control_id", sorted(_HOSTILE_IDS.values()))
def test_the_positive_control_bare_frame_of_an_echoing_ack_is_malformed(control_id: str) -> None:
    # The defect as executed: the bare frame of an ACK echoing the value is not one clean frame.
    ack = build_ack(_message(control_id), timestamp="1")
    assert not _is_one_clean_mllp_frame(frame(ack))
    assert _is_one_clean_mllp_frame(frame_neutralised(ack))


@pytest.mark.parametrize("control_id", sorted(_HOSTILE_IDS.values()))
def test_frame_checked_refuses_and_names_no_content(control_id: str) -> None:
    payload = _message(control_id)
    assert not _is_one_clean_mllp_frame(frame(payload))  # positive control
    with pytest.raises(FramePayloadError) as caught:
        frame_checked(payload)
    assert "SEND" not in str(caught.value)  # the byte and its position, never the content
    assert str(caught.value).startswith("MLLP: payload holds the frame ")


def test_frame_checked_passes_a_clean_payload_unchanged() -> None:
    payload = _message("CLEAN1")
    assert frame_checked(payload) == frame(payload)
    assert frame_neutralised(payload) == frame(payload)


def test_find_frame_byte_reports_the_start_byte_first_then_the_end_byte() -> None:
    assert MLLP_CODEC.find_frame_byte(b"ab") is None
    assert MLLP_CODEC.find_frame_byte(b"a\x1cb\x0b") == FrameByteFault("start", 0x0B, 3)
    assert MLLP_CODEC.find_frame_byte(b"a\x1c") == FrameByteFault("end", 0x1C, 1)
    # The trailer is not a frame byte to a decoder; CR is MLLP's segment terminator.
    assert MLLP_CODEC.find_frame_byte(b"a\rb") is None
    # Codec-specific: STX/ETX judges its own bytes, not MLLP's.
    assert STX_ETX_CODEC.find_frame_byte(b"a\x0b\x1c") is None
    assert STX_ETX_CODEC.find_frame_byte(b"a\x03") == FrameByteFault("end", 0x03, 1)


def test_neutralise_returns_the_same_object_when_clean() -> None:
    body = b"clean"
    assert MLLP_CODEC.neutralise(body) is body
    assert MLLP_CODEC.neutralise(b"a\x0bb\x1cc") == b"a b c"


@pytest.mark.parametrize(
    "payload", ["ok", "a\x0bb", "a\x1cb", "a\x1c\rb", "\x1c\x0b", "x\x02y\x03", "a\u00e9\x0b"]
)
@pytest.mark.parametrize("codec", [MLLP_CODEC, STX_ETX_CODEC, FrameCodec(start=0xC3, end=0xA9)])
def test_the_engine_delivery_check_is_the_leaf_check(codec: FrameCodec, payload: str) -> None:
    # One definition: the engine's refusal fires exactly where the leaf's does, with the same text,
    # and its reply framer neutralises exactly as the leaf does. Imported here only, never by harness.
    from messagefoundry.transports.base import NegativeAckError
    from messagefoundry.transports.framing import check_frame_bytes, frame_reply

    body = payload.encode("utf-8")
    fault = codec.find_frame_byte(body)
    if fault is None:
        assert check_frame_bytes(codec, payload, "utf-8", transport="T") == body
        assert codec.frame_checked(payload, transport="T") == codec.frame(body)
    else:
        with pytest.raises(NegativeAckError) as engine:
            check_frame_bytes(codec, payload, "utf-8", transport="T")
        with pytest.raises(FramePayloadError) as leaf:
            codec.frame_checked(payload, transport="T")
        assert str(engine.value) == str(leaf.value) == fault.describe("T")
        assert engine.value.permanent and engine.value.code == "framing"
    assert frame_reply(codec, payload, "utf-8") == codec.frame_neutralised(payload)


# --- site: the Receive tab's ACK (harness/mllp.py MllpReceiver._write_ack) ----------------------


class _QtSockDouble:
    def __init__(self) -> None:
        self.written = b""

    def write(self, data: bytes) -> None:
        self.written += data


def test_receive_tab_ack_is_one_clean_frame(hostile_id: str) -> None:
    receiver_mod = pytest.importorskip("harness.mllp")
    text = _message(hostile_id)
    sock = _QtSockDouble()
    receiver_mod.MllpReceiver._write_ack(sock, text, "AA", AckMode.ORIGINAL)
    assert _is_one_clean_mllp_frame(sock.written)
    # Positive control: the call this replaced.
    assert not _is_one_clean_mllp_frame(
        frame(build_ack(text, code="AA", ack_mode=AckMode.ORIGINAL, timestamp=""))
    )


# --- site: the Send and Compose tabs' send (harness/mllp.py SendWorker._send_one) ---------------


@pytest.fixture
def listener() -> Iterator[socket.socket]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    srv.settimeout(0.3)
    try:
        yield srv
    finally:
        srv.close()


def test_send_tab_refuses_before_any_dial(hostile_id: str, listener: socket.socket) -> None:
    receiver_mod = pytest.importorskip("harness.mllp")
    payload = _message(hostile_id)
    assert not _is_one_clean_mllp_frame(frame(payload))  # positive control
    item = receiver_mod.SendItem(1, "ADT", "A01", hostile_id, payload)
    port = listener.getsockname()[1]
    worker = receiver_mod.SendWorker("127.0.0.1", port, [item], timeout=1.0, rate=0)
    result = worker._send_one(item)
    assert result.ok is False
    assert result.error.startswith("not sent: MLLP: payload holds the frame ")
    with pytest.raises(TimeoutError):
        listener.accept()  # no connection was opened for the refused payload


def test_send_tab_still_sends_a_clean_payload(listener: socket.socket) -> None:
    receiver_mod = pytest.importorskip("harness.mllp")
    payload = _message("CLEAN1")
    item = receiver_mod.SendItem(1, "ADT", "A01", "CLEAN1", payload)
    port = listener.getsockname()[1]
    got: list[bytes] = []

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(2.0)
            decoder = MLLPDecoder()
            while not got:  # read until one whole frame, however the bytes were segmented
                chunk = conn.recv(65536)
                if not chunk:
                    return
                got.extend(decoder.feed(chunk))
            conn.sendall(frame(build_ack(payload)))

    listener.settimeout(2.0)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    worker = receiver_mod.SendWorker("127.0.0.1", port, [item], timeout=2.0, rate=0)
    result = worker._send_one(item)
    thread.join(timeout=3.0)
    assert result.ok, result.error
    assert got == [payload.encode()]


def test_compose_framer_still_sends_a_hostile_payload(listener: socket.socket) -> None:
    # The Compose tab passes the bare frame when the operator opts in; the worker must honour it.
    receiver_mod = pytest.importorskip("harness.mllp")
    payload = _message(_HOSTILE_IDS["start_byte"])
    item = receiver_mod.SendItem(1, "ADT", "A01", "X", payload)
    port = listener.getsockname()[1]
    got: list[bytes] = []

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(2.0)
            decoder = MLLPDecoder()
            while not got:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                got.extend(decoder.feed(chunk))

    listener.settimeout(2.0)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    worker = receiver_mod.SendWorker(
        "127.0.0.1", port, [item], timeout=1.0, rate=0, expect_ack=False, framer=frame
    )
    worker._send_one(item)
    thread.join(timeout=3.0)
    # The decoder keeps an embedded start byte as data, so the whole hostile body arrived as sent.
    assert got == [payload.encode()]


def test_an_unencodable_payload_is_refused_without_its_content() -> None:
    payload = "PID|||||M\u00fcller"
    with pytest.raises(FrameEncodeError) as caught:
        frame_checked(payload, "ascii")
    err = caught.value
    # Neither link of the chain may hold the UnicodeEncodeError, whose .object is the whole payload.
    assert err.__cause__ is None and err.__context__ is None
    for text in (str(err), repr(err), *map(str, err.args)):
        assert "ller" not in text and "PID" not in text and "\u00fc" not in text
        assert "\\xfc" not in text
    assert "at character 9" in str(err)  # positive control: the content-free fact is there
    with pytest.raises(FrameEncodeError):
        frame_neutralised("M\u00fcller", "ascii")


def test_frame_payload_error_pickles_and_copies() -> None:
    import copy
    import pickle

    err = FramePayloadError(FrameByteFault("start", 0x0B, 3), "MLLP")
    for clone in (pickle.loads(pickle.dumps(err)), copy.copy(err)):
        assert isinstance(clone, FramePayloadError)
        assert str(clone) == str(err) and clone.fault == err.fault


# --- site: the scenario MLLP sink's ACK (harness/sinks/mllp.py) ---------------------------------


class _ConnDouble:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.sent = b""

    def recv(self, _n: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def sendall(self, data: bytes) -> None:
        self.sent += data


class _WholeChunkDecoder:
    """Yields each chunk whole, so a value holding ``0x1C`` reaches the ACK echo. The real decoder
    cuts a frame at ``0x1C``, so over a socket only ``0x0B`` can; this stands in to drive the reply
    line with every shape."""

    def __init__(self, max_frame_bytes: int | None = None) -> None:
        del max_frame_bytes

    def feed(self, data: bytes) -> Iterator[bytes]:
        yield data


def test_mllp_sink_ack_is_one_clean_frame(hostile_id: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mllp_sink_module, "MLLPDecoder", _WholeChunkDecoder)
    payload = _message(hostile_id).encode()
    sink = MLLPSink()
    conn = _ConnDouble([payload])
    sink._handle(conn, "peer")  # type: ignore[arg-type]
    assert _is_one_clean_mllp_frame(conn.sent)
    assert [r.payload for r in sink.records()] == [payload]
    assert not _is_one_clean_mllp_frame(frame(build_ack(payload, code="AA")))  # positive control


def test_mllp_sink_ack_over_the_real_decoder_is_one_clean_frame() -> None:
    # The realistic shape: an MLLP frame keeps a start byte as data, and the sink echoes it.
    payload = _message(_HOSTILE_IDS["start_byte"]).encode()
    sink = MLLPSink()
    conn = _ConnDouble([frame(payload)])
    sink._handle(conn, "peer")  # type: ignore[arg-type]
    assert _is_one_clean_mllp_frame(conn.sent)


# --- site: the raw-TCP sink's configured reply (harness/sinks/tcp.py) ---------------------------


@pytest.mark.parametrize("reply", [b"A\x02B", b"A\x03B", b"A\x03\rB"])
def test_tcp_sink_refuses_a_reply_holding_a_frame_byte_at_build(reply: bytes) -> None:
    bare = STX_ETX_CODEC.frame(reply)  # positive control: framed bare it is not one frame
    assert bare.count(0x02) + bare.count(0x03) > 2
    with pytest.raises(FramePayloadError):
        TcpSink(reply=reply)


def test_tcp_sink_sends_a_clean_reply_as_one_frame() -> None:
    sink = TcpSink(reply=b"ACK")
    conn = _ConnDouble([STX_ETX_CODEC.frame(b"payload")])
    sink._handle(conn, "peer")  # type: ignore[arg-type]
    assert conn.sent == STX_ETX_CODEC.frame(b"ACK")


# --- site: the load correlation sink's ACK (harness/load/sink.py) -------------------------------


def _metrics() -> LiveMetrics:
    return LiveMetrics(Counters(), Histogram(), Histogram())


def test_load_sink_ack_is_one_clean_frame(hostile_id: str) -> None:
    m = _metrics()
    sink = CorrelationSink(
        ControlIds(prefix="LX", width=12), Correlator(capacity=8, metrics=m), m, ports=(0,)
    )
    payload = _message(hostile_id).encode()
    replies = bytearray()
    sink._handle(payload, 0, replies)
    assert _is_one_clean_mllp_frame(bytes(replies))
    assert not _is_one_clean_mllp_frame(frame(build_ack(payload, code="AA")))  # positive control


# --- site: the reconcile capture sink's ACK (harness/reconcile/capture.py) ----------------------


def test_capture_sink_ack_is_one_clean_frame(hostile_id: str, tmp_path: Path) -> None:
    sink = CaptureSink(tmp_path / "capture.jsonl", ports=(0,))
    sink._file = io.StringIO()
    payload = _message(hostile_id).encode()
    replies = bytearray()
    sink._handle(payload, replies)
    assert _is_one_clean_mllp_frame(bytes(replies))
    assert '"control_id"' in sink._file.getvalue()  # the delivery itself is still captured
    assert not _is_one_clean_mllp_frame(frame(build_ack(payload, code="AA")))  # positive control


# --- site: the load sender (harness/load/sender.py PersistentConnection._write_loop) ------------


class _WriterDouble:
    def __init__(self) -> None:
        self.written = b""

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        return None


def test_load_sender_refuses_and_releases_a_hostile_payload(hostile_id: str) -> None:
    m = _metrics()
    conn = PersistentConnection(
        "127.0.0.1", 9, Correlator(capacity=8, metrics=m), m, expect_ack=False
    )
    done: list[int] = []
    hostile = Outgoing(1, "ADT", hostile_id, _message(hostile_id))
    clean = Outgoing(2, "ADT", "CLEAN2", _message("CLEAN2"))
    writer = _WriterDouble()

    async def run() -> None:
        conn.submit_nowait(hostile, lambda: done.append(1))
        conn.submit_nowait(clean, lambda: done.append(2))
        conn._stop.set()  # drain what is queued, then return
        await conn._write_loop(writer)  # type: ignore[arg-type]

    asyncio.run(run())
    assert writer.written == frame(clean.payload)  # only the clean one went out
    assert done == [1, 2]  # the refused job was released, not stranded
    # Counted apart from transport errors: a harness-side refusal is not the engine's failure.
    assert m.counters.refused_sends == 1 and m.counters.sent == 1 and m.counters.errors == 0
    assert not _is_one_clean_mllp_frame(frame(hostile.payload))  # positive control


def test_load_sender_releases_an_unencodable_payload() -> None:
    m = _metrics()
    conn = PersistentConnection(
        "127.0.0.1", 9, Correlator(capacity=8, metrics=m), m, expect_ack=False
    )
    done: list[int] = []
    writer = _WriterDouble()

    async def run() -> None:
        conn.submit_nowait(Outgoing(1, "ADT", "X", "MSH|\ud800"), lambda: done.append(1))
        conn._stop.set()
        await conn._write_loop(writer)  # type: ignore[arg-type]

    asyncio.run(run())
    assert done == [1] and writer.written == b"" and m.counters.refused_sends == 1


# --- the static guard: no harness module frames unchecked, outside the hostile injectors ---------

#: Modules that frame hostile bytes ON PURPOSE: (exact number of bare uses, reason). The count is
#: exact, so a new bare use inside a listed module fails too and must be argued for here.
_DELIBERATE: dict[str, tuple[int, str]] = {
    # The fuzzer's whole job is malformed and hostile wire bytes.
    "harness/fuzz/mutate.py": (4, "the fuzzer mutates framing on purpose"),
    # The hostile scenarios inject MLLP frame bytes to drive the engine's ingress refusal (ADR 0205
    # rule 4), and assert the ERROR and the NAK.
    "harness/drivers/mllp.py": (1, "scenario injector; hostile.py sends frame bytes through it"),
    "harness/drivers/tcp.py": (1, "scenario injector; a scenario chooses what reaches the engine"),
    # The Compose tab frames through frame_checked by default, like the Send tab; it hands the
    # bare frame to SendWorker only when the operator ticks its opt-in checkbox.
    "harness/compose.py": (1, "opt-in only: operator-chosen malformed framing, on purpose"),
}

_FRAME_MODULES = frozenset(
    {
        "messagefoundry.mllpcodec",
        "messagefoundry.transports.mllp",
        "messagefoundry.framing",
        "messagefoundry.transports.framing",
    }
)


def _bare_frame_calls() -> list[tuple[str, int]]:
    """Every use of the unchecked ``frame`` under ``harness/``, called or passed as a value: a name
    imported as ``frame`` from a framing module (under any alias), or any ``.frame`` attribute
    (``codec.frame``, ``MLLP_CODEC.frame``, ``mllpcodec.frame``). It does not see bytes framed by
    hand (``bytes([SB]) + body``); nothing in the harness does that today."""
    found: list[tuple[str, int]] = []
    for path in sorted((_REPO / "harness").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        names = {
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module in _FRAME_MODULES
            for alias in node.names
            if alias.name == "frame"
        }
        rel = path.relative_to(_REPO).as_posix()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in names
            ) or (
                isinstance(node, ast.Attribute)
                and isinstance(node.ctx, ast.Load)
                and node.attr == "frame"
            ):
                found.append((rel, node.lineno))
    return found


def test_no_harness_module_frames_unchecked_outside_the_hostile_injectors() -> None:
    calls = _bare_frame_calls()
    # Floor before the absence: the injectors carry seven bare uses between them, so a walk that
    # finds fewer than five has gone blind, not clean.
    assert len(calls) >= 5, calls
    offenders = [f"{path}:{line}" for path, line in calls if path not in _DELIBERATE]
    assert not offenders, (
        "these harness sites frame with the unchecked frame(); use frame_checked() for a send or "
        f"frame_neutralised() for a reply (messagefoundry.mllpcodec / FrameCodec): {offenders}"
    )


def test_each_deliberate_injector_frames_unchecked_exactly_as_often_as_listed() -> None:
    # Exact both ways: an allowance must not outlive its site, and a listed module must not grow a
    # new bare use (an ACK writer added to compose.py, say) under an allowance argued for another.
    calls = _bare_frame_calls()
    assert len(calls) >= 5, calls
    counted = {path: sum(1 for p, _ in calls if p == path) for path in _DELIBERATE}
    assert counted == {path: n for path, (n, _) in _DELIBERATE.items()}, calls


def test_the_guard_sees_an_aliased_import_and_an_attribute_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The instrument's positive control: point it at a fake tree holding both spellings.
    (tmp_path / "harness").mkdir()
    (tmp_path / "harness" / "x.py").write_text(
        "from messagefoundry.mllpcodec import frame as f\n"
        "from messagefoundry.framing import MLLP_CODEC\n"
        "f(b'a')\nMLLP_CODEC.frame(b'b')\nuse(framer=f)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys.modules[__name__], "_REPO", tmp_path)
    assert sorted(_bare_frame_calls()) == [
        ("harness/x.py", 3),
        ("harness/x.py", 4),
        ("harness/x.py", 5),
    ]
