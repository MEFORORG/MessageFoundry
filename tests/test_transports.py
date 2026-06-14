"""Transports: MLLP framing/decoding, ACK building, file + MLLP connectors.

The MLLP source/destination talk to each other over a real loopback TCP socket (port 0)
so the framing and ACK round-trip are exercised end-to-end, not mocked."""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, Destination, Source
from messagefoundry.config.wiring import File, MLLP
from messagefoundry.parsing.peek import Peek
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.file import (
    DEFAULT_MAX_FILE_BYTES,
    FileSource,
    _claim_unique,
    render_filename,
)
from messagefoundry.transports.mllp import (
    CR,
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_FRAME_BYTES,
    DEFAULT_RECEIVE_TIMEOUT,
    EB,
    SB,
    MLLPDecoder,
    MLLPDestination,
    MLLPFrameError,
    MLLPSource,
    build_ack,
    frame,
)

ADT = (Path(__file__).resolve().parents[1] / "samples" / "messages" / "adt_a01.hl7").read_text(
    encoding="utf-8"
)


# --- framing -----------------------------------------------------------------


def test_frame_wraps_with_sb_eb_cr() -> None:
    framed = frame("HELLO")
    assert framed[0] == SB
    assert framed[-2:] == bytes([EB, CR])
    assert framed[1:-2] == b"HELLO"


def test_decoder_single_message() -> None:
    msgs = list(MLLPDecoder().feed(frame("MSH|one")))
    assert msgs == [b"MSH|one"]


def test_decoder_splits_multiple_messages_in_one_chunk() -> None:
    data = frame("AAA") + frame("BBB")
    assert list(MLLPDecoder().feed(data)) == [b"AAA", b"BBB"]


def test_decoder_reassembles_across_chunks() -> None:
    full = frame("MSH|split me up")
    dec = MLLPDecoder()
    out: list[bytes] = []
    # Feed one byte at a time — the worst-case fragmentation.
    for i in range(len(full)):
        out.extend(dec.feed(full[i : i + 1]))
    assert out == [b"MSH|split me up"]


def test_decoder_discards_inter_frame_noise() -> None:
    # Leading junk, and a stray CR/keepalive between frames, must be ignored.
    data = b"garbage" + frame("AAA") + b"\r\n" + frame("BBB")
    assert list(MLLPDecoder().feed(data)) == [b"AAA", b"BBB"]


# --- ACK building ------------------------------------------------------------


def test_build_ack_accept_swaps_sender_receiver_and_echoes_control() -> None:
    ack = build_ack(ADT, code="AA", timestamp="20260604120001")
    p = Peek.parse(ack)
    assert p.message_type == "ACK"
    assert p.field("MSA-1") == "AA"
    assert p.field("MSA-2") == "MSG00001"  # original control id
    # Inbound was SENDINGAPP->...->RECEIVINGFAC; the ACK reverses that.
    assert p.sending_app == "RECEIVINGAPP"
    assert p.receiving_facility == "SENDINGFAC"
    assert p.version == "2.5.1"


def test_build_ack_defaults_msh7_to_now() -> None:
    # An omitted timestamp must yield a populated MSH-7 (a 14-digit HL7 DTM), not an empty field a
    # strict sender would reject (low-6). An explicit timestamp is still honored (test above).
    ack = build_ack(ADT, code="AA")
    msh7 = Peek.parse(ack).field("MSH-7")
    assert msh7 is not None and len(msh7) == 14 and msh7.isdigit()


def test_build_ack_enhanced_mode_uses_commit_codes() -> None:
    ack = build_ack(ADT, code="AA", ack_mode=AckMode.ENHANCED)
    assert Peek.parse(ack).field("MSA-1") == "CA"


def test_build_ack_error_carries_reason_text() -> None:
    ack = build_ack(ADT, code="AE", text="PID missing")
    p = Peek.parse(ack)
    assert p.field("MSA-1") == "AE"
    assert p.field("MSA-3") == "PID missing"


def test_build_ack_for_unparseable_inbound_still_builds() -> None:
    # A garbage inbound must still yield a (negative) ACK, not crash the listener.
    ack = build_ack("not hl7 at all", code="AR", text="unparseable")
    p = Peek.parse(ack)
    assert p.message_type == "ACK"
    assert p.field("MSA-1") == "AR"


def test_build_ack_rejects_unknown_code() -> None:
    with pytest.raises(ValueError):
        build_ack(ADT, code="ZZ")


def test_build_ack_text_cannot_inject_extra_fields() -> None:
    # A NACK reason containing the field separator must not add MSA fields (HL7-3).
    ack = build_ack(ADT, code="AE", text="bad|field|MSA-99-injection")
    p = Peek.parse(ack)
    assert p.field("MSA-1") == "AE"
    assert p.field("MSA-4") is None  # the embedded '|' was escaped, not turned into new fields


def test_build_ack_text_cannot_inject_segments() -> None:
    # A CR in the reason text must not inject a new segment into the ACK (HL7-3).
    ack = build_ack(ADT, code="AR", text="line1\rZZZ|injected|segment")
    assert Peek.parse(ack).segments() == ["MSH", "MSA"]  # no stray ZZZ segment


# --- file destination --------------------------------------------------------


def test_render_filename_resolves_placeholders() -> None:
    assert render_filename("{MSH-10}.hl7", ADT, fallback="x") == "MSG00001.hl7"
    assert render_filename("{MSH-9.1}_{MSH-10}.hl7", ADT, fallback="x") == "ADT_MSG00001.hl7"


def test_render_filename_falls_back_when_unresolvable() -> None:
    assert render_filename("{PID-99}.hl7", ADT, fallback="fb") == "fb.hl7"
    assert render_filename("{MSH-10}.hl7", "garbage", fallback="fb") == "fb.hl7"


async def test_file_destination_writes_named_file(tmp_path: Path) -> None:
    dest = build_destination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "{MSH-10}.hl7"},
        )
    )
    await dest.send(ADT)
    out = tmp_path / "MSG00001.hl7"
    assert out.read_text(encoding="utf-8") == ADT
    assert not list(tmp_path.glob("*.part"))  # temp file cleaned up by atomic rename


async def test_file_destination_does_not_clobber(tmp_path: Path) -> None:
    dest = build_destination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "fixed.hl7"},
        )
    )
    await dest.send(ADT)
    await dest.send(ADT)
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == ["fixed-1.hl7", "fixed.hl7"]


def test_claim_unique_falls_back_to_copy_when_link_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On FAT/exFAT/SMB os.link raises a non-FileExistsError OSError; delivery must still land via an
    # exclusive-create copy, still claiming a unique name when the target exists (low-5).
    def _no_link(src: str, dst: str) -> None:
        raise OSError("hard links not supported on this filesystem")

    monkeypatch.setattr(os, "link", _no_link)
    src = tmp_path / "src.part"
    src.write_bytes(b"PAYLOAD")
    target = tmp_path / "out.hl7"
    target.write_bytes(b"existing")  # name already taken -> fallback must pick out-1.hl7

    claimed = _claim_unique(src, target)
    assert claimed.name == "out-1.hl7"
    assert claimed.read_bytes() == b"PAYLOAD"
    assert target.read_bytes() == b"existing"  # the pre-existing file is never clobbered


# --- file source -------------------------------------------------------------


async def test_file_source_reads_and_archives(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    # write_bytes (not write_text) so on-disk content is byte-exact across platforms.
    (inbox / "msg1.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)
        return None

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()
        await task
    assert received == [ADT.encode("utf-8")]
    assert (inbox / ".processed" / "msg1.hl7").exists()
    assert not (inbox / "msg1.hl7").exists()


async def test_file_source_keeps_persistently_failing_file_for_retry(tmp_path: Path) -> None:
    # M-15: a handler that keeps failing (a persistent store/infra outage) must NOT quarantine the
    # file to .error — that would drop a received message unrecorded. It stays in the inbox as
    # back-pressure and is retried until the store recovers.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "bad.hl7").write_text("MSH|^~\\&|A", encoding="utf-8")
    attempts = {"n": 0}

    async def handler(raw: bytes) -> None:
        attempts["n"] += 1
        raise RuntimeError("store unavailable")  # never recovers

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: attempts["n"] >= 3)  # retried across multiple scans
    finally:
        await src.stop()
        await task
    assert (inbox / "bad.hl7").exists()  # still in the inbox (back-pressure, not lost)
    assert not (inbox / ".error" / "bad.hl7").exists()  # never quarantined as accept-and-drop
    assert not (inbox / ".processed" / "bad.hl7").exists()


# --- MLLP source <-> destination round trip ----------------------------------


async def test_mllp_round_trip_positive_ack(tmp_path: Path) -> None:
    received: list[bytes] = []

    async def handler(raw: bytes) -> str:
        received.append(raw)
        return build_ack(raw, code="AA")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={"host": "127.0.0.1", "port": source.sockport, "timeout_seconds": 5},
            )
        )
        await dest.send(ADT)  # returns normally only on a positive ACK
    finally:
        await source.stop()
    assert received == [ADT.encode("utf-8")]


@pytest.mark.parametrize(
    ("ack_code", "expect_code", "expect_permanent"),
    [
        ("AR", "AR", True),  # application reject → permanent → fail-fast
        ("AE", "AE", False),  # application error → transient → retry
    ],
)
async def test_mllp_negative_ack_classifies_permanence(
    ack_code: str, expect_code: str, expect_permanent: bool
) -> None:
    # A negative ACK surfaces as NegativeAckError (a DeliveryError subclass) carrying the failure
    # classification the delivery worker keys its policy on: AR rejects fail-fast, AE retries.
    async def handler(raw: bytes) -> str:
        return build_ack(raw, code=ack_code, text="rejected")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={"host": "127.0.0.1", "port": source.sockport, "timeout_seconds": 5},
            )
        )
        with pytest.raises(NegativeAckError, match="negative ACK") as exc_info:
            await dest.send(ADT)
        assert exc_info.value.code == expect_code
        assert exc_info.value.permanent is expect_permanent
    finally:
        await source.stop()


async def test_mllp_connect_failure_raises_delivery_error() -> None:
    # Nothing is listening on this port.
    dest = MLLPDestination(
        Destination(
            name="out",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 1, "timeout_seconds": 2},
        )
    )
    with pytest.raises(DeliveryError):
        await dest.send(ADT)


# --- connector settings (Mirth-parity expansion) -----------------------------


def test_frame_honors_encoding() -> None:
    framed = frame("café", "latin-1")
    assert framed[1:-2] == "café".encode("latin-1")


async def test_file_destination_honors_encoding(tmp_path: Path) -> None:
    dest = build_destination(
        Destination(
            name="archive",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "out.txt", "encoding": "latin-1"},
        )
    )
    payload = "PID|1||X||café\r"
    await dest.send(payload)
    assert (tmp_path / "out.txt").read_bytes() == payload.encode("latin-1")


async def test_file_source_min_age_skips_recent_files(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "new.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "min_age_seconds": 3600,  # far in the future → the fresh file is "too new"
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await asyncio.sleep(0.1)  # several poll cycles
        assert received == []  # skipped — still being "written"
        assert (inbox / "new.hl7").exists()  # left in place for a later poll
    finally:
        await src.stop()
        await task


async def test_file_source_after_read_delete(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "m.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "after_read": "delete",
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()
        await task
    assert not (inbox / "m.hl7").exists()
    assert not (inbox / ".processed" / "m.hl7").exists()  # deleted, not moved


async def test_file_source_recursive_descends_subdirs(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    (inbox / "sub").mkdir(parents=True)
    (inbox / "sub" / "deep.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "recursive": True,
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()
        await task
    assert received == [ADT.encode("utf-8")]


def test_file_source_within_root_rejects_escaping_path(tmp_path: Path) -> None:
    # Path-confinement (3.2): a candidate that resolves outside the watch root is rejected, so a
    # recursive scan can't be walked out of its directory via a symlink.
    inbox = tmp_path / "in"
    inbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    inside = inbox / "ok.hl7"
    inside.write_bytes(b"MSH|x\r")
    secret = outside / "secret.hl7"
    secret.write_bytes(b"MSH|x\r")
    src = build_source(Source(type=ConnectorType.FILE, settings={"directory": str(inbox)}))
    assert isinstance(src, FileSource)
    assert src._within_root(inside) is True
    assert src._within_root(secret) is False


async def test_file_source_skips_symlink_escaping_watch_root(tmp_path: Path) -> None:
    # End-to-end: a symlinked subdir pointing outside the root must never let the poller deliver a
    # file from outside the configured directory (whether or not rglob follows the symlink).
    inbox = tmp_path / "in"
    inbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.hl7").write_bytes(ADT.encode("utf-8"))
    try:
        (inbox / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported / not permitted on this platform")

    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "recursive": True,
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await asyncio.sleep(0.1)  # several poll intervals; the escaping file must never arrive
    finally:
        await src.stop()
        await task
    assert received == []


async def test_file_destination_refuses_path_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Defence in depth (3.2): even if a filename slipped past sanitization with a path component,
    # the destination refuses to write outside its configured directory.
    out = tmp_path / "out"
    dest = build_destination(
        Destination(name="OB", type=ConnectorType.FILE, settings={"directory": str(out)})
    )
    monkeypatch.setattr(
        "messagefoundry.transports.file.render_filename", lambda *a, **k: "../escape.hl7"
    )
    with pytest.raises(DeliveryError, match="outside the destination directory"):
        await dest.send("MSH|x\r")
    assert not (tmp_path / "escape.hl7").exists()


async def test_file_source_sort_mtime_orders_by_time(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    # Name order is a,z; mtime order is z (older), a (newer) — so they disagree.
    (inbox / "z.hl7").write_bytes(b"MSH|z\r")
    (inbox / "a.hl7").write_bytes(b"MSH|a\r")
    now = time.time()
    os.utime(inbox / "z.hl7", (now - 100, now - 100))
    os.utime(inbox / "a.hl7", (now, now))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "sort": "mtime",
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: len(received) == 2)
    finally:
        await src.stop()
        await task
    assert received == [b"MSH|z\r", b"MSH|a\r"]  # mtime order, not name (a,z) order


async def test_mllp_max_connections_refuses_extra() -> None:
    async def handler(raw: bytes) -> str:
        return build_ack(raw, code="AA")

    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0, "max_connections": 1}
        )
    )
    await source.start(handler)
    try:
        _r1, w1 = await asyncio.open_connection("127.0.0.1", source.sockport)
        await asyncio.sleep(0.05)  # let the server register the first client
        r2, w2 = await asyncio.open_connection("127.0.0.1", source.sockport)
        data = await asyncio.wait_for(r2.read(), 2.0)  # second is refused → EOF
        assert data == b""
        w1.close()
        w2.close()
    finally:
        await source.stop()


async def test_mllp_receive_timeout_closes_idle_client() -> None:
    async def handler(raw: bytes) -> str:
        return build_ack(raw, code="AA")

    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0, "receive_timeout": 0.1},
        )
    )
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        data = await asyncio.wait_for(reader.read(), 2.0)  # closed after ~0.1s idle → EOF
        assert data == b""
        writer.close()
    finally:
        await source.stop()


# --- resource caps (DoS guards: MLLP-1/2/3/4, FILE-2) ------------------------


def test_decoder_rejects_oversized_frame() -> None:
    # An open frame (SB, no EB) that grows past the cap must raise rather than buffer forever.
    dec = MLLPDecoder(max_frame_bytes=10)
    with pytest.raises(MLLPFrameError):
        list(dec.feed(bytes([SB]) + b"A" * 20))


def test_decoder_unbounded_by_default() -> None:
    # No cap configured → the decoder buffers whatever arrives (back-compat).
    dec = MLLPDecoder()
    assert list(dec.feed(frame("A" * 1000))) == [b"A" * 1000]


def test_mllp_source_defaults_are_secure() -> None:
    src = MLLPSource(Source(type=ConnectorType.MLLP, settings={"port": 0}))
    assert src.host == "127.0.0.1"  # loopback, not 0.0.0.0
    assert src.max_connections == DEFAULT_MAX_CONNECTIONS
    assert src.receive_timeout == DEFAULT_RECEIVE_TIMEOUT
    assert src.max_frame_bytes == DEFAULT_MAX_FRAME_BYTES


def test_mllp_source_caps_can_be_disabled_explicitly() -> None:
    src = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"port": 0, "max_connections": 0, "receive_timeout": 0, "max_frame_bytes": 0},
        )
    )
    assert src.max_connections is None
    assert src.receive_timeout is None
    assert src.max_frame_bytes is None


def test_dsl_defaults_match_connector_constants() -> None:
    # The MLLP()/File() DSL literals must stay in sync with the connector DEFAULT_* constants.
    s = MLLP(port=1).settings
    assert (
        s["host"] is None
    )  # no authored host: the bind interface is service-level ([inbound].bind_host)
    assert s["max_connections"] == DEFAULT_MAX_CONNECTIONS
    assert s["receive_timeout"] == DEFAULT_RECEIVE_TIMEOUT
    assert s["max_frame_bytes"] == DEFAULT_MAX_FRAME_BYTES
    assert File(directory="x").settings["max_file_bytes"] == DEFAULT_MAX_FILE_BYTES


async def test_mllp_source_drops_oversized_frame() -> None:
    handled: list[bytes] = []

    async def handler(raw: bytes) -> str:
        handled.append(raw)
        return build_ack(raw, code="AA")

    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0, "max_frame_bytes": 64},
        )
    )
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(bytes([SB]) + b"A" * 200)  # open frame past the cap, never closed
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 2.0)  # server drops the connection → EOF
        assert data == b""
        writer.close()
    finally:
        await source.stop()
    assert handled == []  # no complete frame was ever delivered to the handler


async def test_mllp_stop_closes_established_clients() -> None:
    """An idle-but-connected peer must not hang stop()/reload: stop closes the connection and
    returns promptly, and the client then sees EOF (review H-2)."""

    async def handler(raw: bytes) -> str:
        return build_ack(raw, code="AA")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
    try:
        await _until(lambda: source._active == 1)  # connection established + registered
        await asyncio.wait_for(source.stop(), timeout=3.0)  # must NOT hang on the open connection
        assert await asyncio.wait_for(reader.read(), timeout=2.0) == b""  # client sees EOF
    finally:
        writer.close()


async def test_mllp_stop_lets_inflight_handler_finish() -> None:
    """A message being handled when stop() runs still finishes its commit (the body is durably
    stored before any ACK; only a not-yet-sent ACK is lost, which the sender retries) — review H-2."""
    started = asyncio.Event()
    release = asyncio.Event()
    committed: list[bytes] = []

    async def slow_handler(raw: bytes) -> str:
        started.set()
        await release.wait()  # block mid-handler
        committed.append(raw)  # stands in for the durable store commit
        return build_ack(raw, code="AA")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(slow_handler)
    reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
    try:
        writer.write(frame("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1"))
        await writer.drain()
        await asyncio.wait_for(started.wait(), timeout=2.0)  # handler is mid-flight
        stop_task = asyncio.ensure_future(source.stop())
        release.set()  # let the in-flight handler complete its commit
        await asyncio.wait_for(stop_task, timeout=3.0)
        assert committed  # the in-flight message was fully handled, not dropped/cancelled
    finally:
        writer.close()


async def test_file_source_routes_oversized_to_error(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "big.hl7").write_bytes(b"X" * 5000)
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                "max_file_bytes": 100,
            },
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        await _until(lambda: (inbox / ".error" / "big.hl7").exists())
    finally:
        await src.stop()
        await task
    assert received == []  # never read into memory
    assert (inbox / ".error" / "big.hl7").exists()


async def test_file_source_leaves_file_in_place_on_handler_failure(tmp_path: Path) -> None:
    # M-15: an exception escaping the handler is an infrastructure (store-write) failure — the file
    # must stay in place to retry, not be quarantined to .error as an unrecorded accept-and-drop.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg.hl7").write_bytes(b"MSH|^~\\&|A\r")
    attempts = {"n": 0}

    async def handler(raw: bytes) -> None:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("store write failed")  # transient infra failure on the first scan

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler))
    try:
        # The retry (store "recovered") eventually succeeds and the file moves to .processed.
        await _until(lambda: (inbox / ".processed" / "msg.hl7").exists())
    finally:
        await src.stop()
        await task
    assert attempts["n"] >= 2  # the first failure left it in place; a later scan retried it
    assert not (inbox / ".error" / "msg.hl7").exists()  # never quarantined


# --- file source: leader-gating (Track B Step 4b) ----------------------------


def test_file_source_declares_polls_shared_resource() -> None:
    # A directory is a shared external resource — the runner reads this flag to know the intake is
    # leader-gated (only the cluster leader polls it).
    assert FileSource.polls_shared_resource is True


async def test_file_source_skips_scan_when_gate_false(tmp_path: Path) -> None:
    # A follower (leader_gate() -> False) must NOT read or move a dropped file across a poll tick:
    # the directory is shared, so a non-leader ingesting it would duplicate intake.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg1.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler, leader_gate=lambda: False))
    try:
        # Give the loop several poll intervals; a follower must scan none of them.
        await asyncio.sleep(0.1)
    finally:
        await src.stop()
        await task
    assert received == []  # never delivered
    assert (inbox / "msg1.hl7").exists()  # file untouched (not read, not moved)
    assert not (inbox / ".processed" / "msg1.hl7").exists()


async def test_file_source_processes_when_gate_true(tmp_path: Path) -> None:
    # A leader (leader_gate() -> True) processes exactly as the un-gated default does.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg1.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler, leader_gate=lambda: True))
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()
        await task
    assert received == [ADT.encode("utf-8")]
    assert (inbox / ".processed" / "msg1.hl7").exists()


async def test_file_source_resumes_when_gate_flips_to_true(tmp_path: Path) -> None:
    # Reactive-by-polling: with the gate initially False the file is left untouched; once the gate
    # flips True (this node became leader) the very next tick scans it — no restart needed.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "msg1.hl7").write_bytes(ADT.encode("utf-8"))
    received: list[bytes] = []
    leader = {"on": False}

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.01},
        )
    )
    task = asyncio.create_task(src.start(handler, leader_gate=lambda: leader["on"]))
    try:
        await asyncio.sleep(0.05)
        assert received == []  # still a follower — nothing ingested
        leader["on"] = True  # this node wins leadership
        await _until(lambda: bool(received))  # the next tick scans it
    finally:
        await src.stop()
        await task
    assert received == [ADT.encode("utf-8")]
    assert (inbox / ".processed" / "msg1.hl7").exists()


# --- listen sources accept (and ignore) the leader_gate ----------------------


async def test_mllp_source_accepts_and_ignores_leader_gate() -> None:
    # A listen source runs on every node; passing leader_gate must be accepted without error and have
    # no effect (it still binds + serves). Even a False gate does not stop it listening.
    src = MLLPSource(Source(type=ConnectorType.MLLP, settings={"port": 0}))
    await src.start(_noop_handler, leader_gate=lambda: False)
    try:
        assert src.sockport > 0  # bound + listening despite a False gate
        assert MLLPSource.polls_shared_resource is False  # a listen source is not a poll source
    finally:
        await src.stop()


async def test_tcp_source_accepts_and_ignores_leader_gate() -> None:
    from messagefoundry.transports.tcp import TcpSource

    src = TcpSource(Source(type=ConnectorType.TCP, settings={"port": 0, "framing": "stx_etx"}))
    await src.start(_noop_handler, leader_gate=lambda: False)
    try:
        assert src.sockport > 0  # bound + listening despite a False gate
        assert TcpSource.polls_shared_resource is False
    finally:
        await src.stop()


# --- helpers -----------------------------------------------------------------


async def _noop_handler(raw: bytes) -> str | None:
    return None


async def _until(cond, timeout: float = 2.0) -> None:
    """Poll ``cond`` until true or timeout (avoids fixed sleeps in async tests)."""
    elapsed = 0.0
    while not cond():
        await asyncio.sleep(0.01)
        elapsed += 0.01
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")
