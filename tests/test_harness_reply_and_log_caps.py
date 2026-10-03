# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness bounds what the engine under test sends or writes back to it (ASVS 5.1.1).

Four kinds of read took that content with no stated maximum: the MLLP clients' ACK reads (the
scenario driver and the load sender), the load rig's whole-file reads of the engine node logs, the
failover node's log tail, and the two-box coordination files another host writes. Each cap here is
pinned at its edge: a read exactly at the cap passes whole, one byte over is refused and recorded,
and nothing is cut short to fit. The caps are monkeypatched small so the edge costs no 16 MiB socket
write; a separate assertion pins each module constant to its documented value.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

import harness.drivers.mllp as mllp_driver
import harness.load.coord as coord
import harness.load.sender as sender
import harness.load.shardcert_ladder as ladder
from harness.load.corpus import Outgoing
from harness.load.correlator import Correlator
from harness.load.failover import EngineNode
from harness.load.metrics import Counters, Histogram, LiveMetrics
from messagefoundry.mllpcodec import DEFAULT_MAX_FRAME_BYTES, frame

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\r"
_CAP = 256


def _ack_of(size: int) -> bytes:
    """An ACK payload of exactly ``size`` bytes: an MSA segment padded with a trailing field."""
    head = b"MSH|^~\\&|B|A|D|C|20260101||ACK|X1|P|2.5.1\rMSA|AA|X1|"
    assert size >= len(head)
    return head + b"x" * (size - len(head))


def test_the_caps_are_their_documented_values() -> None:
    for module in (mllp_driver, sender):
        assert vars(module)["DEFAULT_MAX_FRAME_BYTES"] == DEFAULT_MAX_FRAME_BYTES
    assert DEFAULT_MAX_FRAME_BYTES == 16 * 1024 * 1024
    assert ladder.MAX_NODE_LOG_BYTES == 1 << 30
    assert coord.MAX_COORD_MESSAGE_BYTES == 1 << 20


# --- the scenario MLLP driver -------------------------------------------------------------------


@pytest.fixture
def one_reply_server() -> Iterator[tuple[int, list[bytes]]]:
    """A one-shot MLLP peer: answers each connection with the next queued reply payload, framed."""
    replies: list[bytes] = []
    srv = socket.create_server(("127.0.0.1", 0))
    srv.settimeout(0.05)  # a closed listener does not wake a blocked accept on every platform
    port = srv.getsockname()[1]
    done = threading.Event()

    def serve() -> None:
        while not done.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(5.0)
            with conn:
                conn.recv(65536)
                if replies:
                    conn.sendall(frame(replies.pop(0)))

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield port, replies
    finally:
        done.set()
        t.join(timeout=5)
        srv.close()


def test_mllp_driver_takes_a_reply_exactly_at_the_cap(
    monkeypatch: pytest.MonkeyPatch, one_reply_server: tuple[int, list[bytes]]
) -> None:
    monkeypatch.setattr(mllp_driver, "DEFAULT_MAX_FRAME_BYTES", _CAP)
    port, replies = one_reply_server
    replies.append(_ack_of(_CAP))
    [out] = mllp_driver.MLLPDriver("127.0.0.1", port, timeout=5.0).inject([_MSG.encode()])
    assert out.error == ""
    assert out.reply == _ack_of(_CAP)  # whole, not cut to fit


def test_mllp_driver_refuses_a_reply_one_byte_over_the_cap(
    monkeypatch: pytest.MonkeyPatch, one_reply_server: tuple[int, list[bytes]]
) -> None:
    monkeypatch.setattr(mllp_driver, "DEFAULT_MAX_FRAME_BYTES", _CAP)
    port, replies = one_reply_server
    replies.append(_ack_of(_CAP + 1))
    [out] = mllp_driver.MLLPDriver("127.0.0.1", port, timeout=5.0).inject([_MSG.encode()])
    assert out.error.startswith("reply refused:")
    assert out.reply is None  # nothing of the over-cap frame is kept


# --- the load sender ----------------------------------------------------------------------------


async def _sender_against(reply: bytes) -> tuple[sender.PersistentConnection, LiveMetrics]:
    """Send one message to a peer that answers ``reply`` framed, and wait for the outcome."""
    got_ack = asyncio.Event()

    async def peer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(65536)
        writer.write(frame(reply))
        await writer.drain()
        await reader.read()  # hold the socket open; only the harness side may close it
        writer.close()

    server = await asyncio.start_server(peer, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    conn = sender.PersistentConnection("127.0.0.1", port, Correlator(10, metrics), metrics)
    try:
        conn.start()
        assert conn.submit_nowait(Outgoing(1, "ADT", "X1", _MSG), got_ack.set)
        await asyncio.wait_for(got_ack.wait(), timeout=5.0)
        await conn.stop(0.05)
    finally:
        server.close()
        await server.wait_closed()
    return conn, metrics


async def test_load_sender_takes_an_ack_exactly_at_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sender, "DEFAULT_MAX_FRAME_BYTES", _CAP)
    conn, metrics = await _sender_against(_ack_of(_CAP))
    assert metrics.counters.acked == 1
    assert (conn.frame_refusals, metrics.counters.errors) == (0, 0)


async def test_load_sender_refuses_an_ack_one_byte_over_the_cap(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(sender, "DEFAULT_MAX_FRAME_BYTES", _CAP)
    with caplog.at_level(logging.WARNING, logger=sender.__name__):
        conn, metrics = await _sender_against(_ack_of(_CAP + 1))
    # Refused and recorded, never counted as an ACK, and not blamed on the engine as a close.
    assert metrics.counters.acked == 0 and metrics.counters.nak == 0
    assert conn.frame_refusals == 1
    assert metrics.counters.errors == 1
    assert metrics.counters.timeouts == 1  # its in-flight send released, like any other close
    assert conn.drops == 0
    assert "over cap" in caplog.text


# --- the engine node logs -----------------------------------------------------------------------

_PHASE_LINE = "delivery phase timing"


def test_node_log_at_the_cap_is_read_whole(tmp_path: Path) -> None:
    log = tmp_path / "shard-0.log"
    log.write_bytes(b"a" * _CAP)
    assert ladder.read_node_log(log, max_bytes=_CAP) == "a" * _CAP


def test_node_log_over_the_cap_is_refused_and_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    log = tmp_path / "shard-0.log"
    log.write_bytes(b"a" * (_CAP + 1))
    with caplog.at_level(logging.WARNING, logger=ladder.__name__):
        assert ladder.read_node_log(log, max_bytes=_CAP) is None
    assert "refused" in caplog.text and str(log) in caplog.text
    assert "aaaa" not in caplog.text  # the refusal never quotes the log


def test_node_log_missing_or_not_a_file_contributes_nothing(tmp_path: Path) -> None:
    assert ladder.read_node_log(tmp_path / "absent.log") is None
    assert ladder.read_node_log(tmp_path) is None


@pytest.mark.parametrize(
    "aggregate",
    [ladder.aggregate_phase_timing, ladder.aggregate_claim_timing, ladder.aggregate_episode_timing],
)
def test_every_aggregate_reads_its_logs_under_the_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, aggregate: object
) -> None:
    # The three aggregators read only through read_node_log, so a log over the cap is skipped whole
    # rather than read; the call itself still returns, as for a missing log.
    seen: list[int | None] = []
    real = ladder.read_node_log

    def spy(path: Path, *, max_bytes: int | None = None) -> str | None:
        seen.append(max_bytes)
        return real(path, max_bytes=max_bytes)

    monkeypatch.setattr(ladder, "read_node_log", spy)
    monkeypatch.setattr(ladder, "MAX_NODE_LOG_BYTES", _CAP)
    big = tmp_path / "shard-0.log"
    big.write_text(f"{_PHASE_LINE}\n" * (_CAP // len(_PHASE_LINE) + 2), encoding="utf-8")
    assert big.stat().st_size > _CAP
    assert callable(aggregate)
    result = aggregate([big])
    assert seen == [None]  # each log went through the capped reader at its default
    assert result.windows == 0


def test_failover_log_tail_reads_only_the_tail(tmp_path: Path) -> None:
    node = EngineNode(
        "n", 9000, env={"MEFOR_BENCH_KEEP_NODE_LOGS": str(tmp_path)}, config_dir="cfg", cwd=tmp_path
    )
    try:
        node._log.write(b"x" * 10_000 + b"END")
        node._log.flush()
        assert node.log_tail(limit=8) == "xxxxxEND"
        assert node.log_tail(limit=20_000) == "x" * 10_000 + "END"
    finally:
        node._log.close()


# --- the two-box coordination files -------------------------------------------------------------


def _json_of(size: int) -> bytes:
    """A JSON object of exactly ``size`` bytes."""
    shell = json.dumps({"pad": ""}).encode()
    return json.dumps({"pad": "p" * (size - len(shell))}).encode()


def test_coord_message_at_the_cap_is_read(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(coord, "MAX_COORD_MESSAGE_BYTES", _CAP)
    c = coord.FileDropCoord(tmp_path, run_id="r")
    body = _json_of(_CAP)
    assert len(body) == _CAP
    (tmp_path / f"r.{coord.SHARDS_READY}.json").write_bytes(body)
    assert c.read(coord.SHARDS_READY) == json.loads(body)


def test_coord_message_over_the_cap_is_refused_not_polled_forever(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(coord, "MAX_COORD_MESSAGE_BYTES", _CAP)
    c = coord.FileDropCoord(tmp_path, run_id="r")
    (tmp_path / f"r.{coord.SHARDS_READY}.json").write_bytes(_json_of(_CAP + 1))
    with pytest.raises(coord.CoordMessageRefused, match="over the 256-byte cap"):
        c.read(coord.SHARDS_READY)
    with pytest.raises(coord.CoordMessageRefused):
        asyncio.run(c.await_message(coord.SHARDS_READY, timeout=5.0, interval=0.01))


def test_coord_message_not_posted_still_reads_none(tmp_path: Path) -> None:
    c = coord.FileDropCoord(tmp_path, run_id="r")
    assert c.read(coord.SHARDS_READY) is None
    c.post(coord.SHARDS_READY, {"ok": 1})
    assert c.read(coord.SHARDS_READY) == {"ok": 1}
