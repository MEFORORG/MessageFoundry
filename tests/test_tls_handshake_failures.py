# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A failed inbound TLS handshake the EVENT LOOP ran leaves a record (vault BACKLOG #3302).

Before #3302 the HTTP intake listener and the API recorded none on any loop, and the MLLP listener
none on uvloop, where the loop runs its handshakes. Each surface below fails a real handshake and
reads the record, and each has a control that completes one and reads none. The MLLP case runs on
uvloop where it is installed (CI's Linux legs) and, everywhere, on the stdlib loop forced onto the
same loop-run path uvloop takes.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import ssl
import sys
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api.tls import ApiHandshakeRecord
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.tls_handshake_failures import (
    HandshakeFailures,
    handshake_cause,
    watch_loop_handshakes,
)
from messagefoundry.transports import mllp as mllp_module
from messagefoundry.transports.http_listener import HttpSource
from messagefoundry.transports.mllp import MLLPDestination
from tests.test_mllp_tls import ADT, _ack, _cert, _close_raw, _Events, _tls_source, _until

_PLAINTEXT = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


def _server_ctx(tmp_path: Path) -> tuple[ssl.SSLContext, str]:
    cert, key = _cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx, cert


def _pinned_client(cert: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cert)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _refuse_the_certificate(port: int) -> bool:
    """A client that does not trust the listener's certificate, so it sends an alert the SERVER
    then fails its handshake on: the wrong-certificate case the row names. Blocking, run in a
    thread: asyncio's own client drops the socket without sending the alert, which the server
    reads as a hang-up. True when the client refused, as it must."""
    ctx = ssl.create_default_context()
    with socket.create_connection(("127.0.0.1", port), timeout=5.0) as raw:
        try:
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1"):
                return False
        except ssl.SSLCertVerificationError:
            return True


async def _plaintext_peer(port: int) -> None:
    """Send plaintext to a TLS port, then wait for the listener to drop the socket."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(_PLAINTEXT)
        await writer.drain()
        with contextlib.suppress(ConnectionError, TimeoutError):
            await asyncio.wait_for(reader.read(1024), timeout=5.0)
    finally:
        await _close_raw(writer)


async def _tls_peer(port: int, ctx: ssl.SSLContext) -> bool:
    """Open a TLS connection with ``ctx``; True when the handshake completed."""
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname="127.0.0.1"),
            timeout=5.0,
        )
    except (ssl.SSLError, ConnectionError):
        return False
    await _close_raw(writer)
    return True


# --- the hook and the throttle, without a socket ---------------------------------------------


def _handshake_in_memory(server: ssl.SSLObject, client: ssl.SSLObject, pipes: Any) -> None:
    """Drive both ends of a handshake over memory BIOs until both finish."""
    c_in, c_out, s_in, s_out = pipes
    done = {"client": False, "server": False}
    for _ in range(20):
        for side, obj in (("client", client), ("server", server)):
            if done[side]:
                continue
            try:
                obj.do_handshake()
                done[side] = True
            except ssl.SSLWantReadError:
                pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        if all(done.values()):
            return
    pytest.fail("the in-memory handshake did not finish")


def test_the_hook_reports_a_failed_handshake_and_not_a_completed_one(tmp_path: Path) -> None:
    server_ctx, cert = _server_ctx(tmp_path)
    seen: list[str] = []
    watch_loop_handshakes(server_ctx, seen.append)

    # The control: a completed handshake raises SSLWantReadError on the way, which both loops read
    # as "call again", and reports nothing.
    pipes = (ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO())
    c_in, c_out, s_in, s_out = pipes
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    client = _pinned_client(cert).wrap_bio(c_in, c_out, server_hostname="127.0.0.1")
    _handshake_in_memory(server, client, pipes)
    assert seen == []

    # Plaintext where a ClientHello belongs fails, and is reported with a cause, not the bytes.
    s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    s_in.write(_PLAINTEXT)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    with pytest.raises(ssl.SSLError):
        server.do_handshake()
    assert len(seen) == 1
    assert seen[0].startswith("SSLError")
    assert "GET" not in seen[0]


def test_a_fault_in_the_recorder_does_not_change_the_handshake_error(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    server_ctx, _cert_path = _server_ctx(tmp_path)

    def broken(_cause: str) -> None:
        raise RuntimeError("recorder fault")

    watch_loop_handshakes(server_ctx, broken)
    s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    s_in.write(_PLAINTEXT)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.tls_handshake_failures"),
        pytest.raises(ssl.SSLError),  # the handshake's own error, not the recorder's
    ):
        server.do_handshake()
    assert "recording a failed TLS handshake failed: RuntimeError" in caplog.text


def test_the_cause_keeps_only_an_openssl_mnemonic() -> None:
    err = ssl.SSLError(1, "boom")
    err.reason = "WRONG_VERSION_NUMBER"
    assert handshake_cause(err) == "SSLError WRONG_VERSION_NUMBER"
    err.reason = "not a mnemonic: peer bytes"
    assert handshake_cause(err) == "SSLError"
    assert handshake_cause(ConnectionAbortedError("bound")) == "ConnectionAbortedError"


async def test_note_soon_throttles_as_note_does() -> None:
    """``note_soon`` runs inside the loop's handshake, so it cannot await. The first failure is
    still reported at once and its window starts then, so a second in the same loop turn is held
    for the trailing report rather than reported twice."""
    sent: list[tuple[str | None, str]] = []

    async def emit(peer_host: str | None, reason: str) -> None:
        sent.append((peer_host, reason))

    failures = HandshakeFailures(emit)
    failures.note_soon("10.0.0.1", "SSLError")
    failures.note_soon("10.0.0.2", "SSLError")
    failures.note_soon("10.0.0.3", "SSLError")
    await _until(lambda: bool(sent), "no report was sent")
    await asyncio.sleep(0.05)
    assert sent == [("10.0.0.1", "1 failed handshake(s) since the last event; last cause SSLError")]
    assert failures.count == 3
    assert failures._timer is not None  # the trailing report is armed
    await failures.flush()
    assert sent[-1] == (None, "2 failed handshake(s) since the last event; last cause SSLError")
    assert failures._timer is None
    await failures.flush()
    assert len(sent) == 2  # nothing more was held, so nothing more is sent


# --- the HTTP intake listener -----------------------------------------------------------------


def _http_tls_source(tmp_path: Path) -> tuple[HttpSource, str]:
    cert, key = _cert(tmp_path)
    source = HttpSource(
        Source(
            type=ConnectorType.HTTP,
            settings={
                "host": "127.0.0.1",
                "port": 0,
                "tls": True,
                "tls_cert_file": cert,
                "tls_key_file": key,
            },
        )
    )
    return source, cert


async def _no_reply(_raw: bytes) -> str | None:
    return None


async def test_the_http_listener_records_a_failed_handshake(tmp_path: Path) -> None:
    source, cert = _http_tls_source(tmp_path)
    events = _Events()
    source.on_connection_event = events
    await source.start(_no_reply)
    try:
        # The control: a completed handshake is no failure.
        assert await _tls_peer(source.sockport, _pinned_client(cert))
        await asyncio.sleep(0.1)
        assert "tls_handshake_failed" not in events.kinds()
        assert source.tls_handshake_failures == 0

        await _plaintext_peer(source.sockport)
        await _until(lambda: "tls_handshake_failed" in events.kinds(), "no failure event")
        failed = [e for e in events.seen if e[0] == "tls_handshake_failed"]
        assert len(failed) == 1
        (_kind, peer, reason) = failed[0]
        assert peer is None  # the loop's TLS object knows no peer
        assert reason is not None and reason.startswith("1 failed handshake(s)")
        assert "GET" not in reason  # a cause, never the peer's bytes
        assert source.tls_handshake_failures == 1

        # A client that refuses the listener's certificate fails the SERVER's handshake too. Inside
        # the window it is held, and stop() reports it.
        assert await asyncio.to_thread(_refuse_the_certificate, source.sockport)
        await _until(lambda: source.tls_handshake_failures == 2, "the second failure not counted")
        assert len([k for k in events.kinds() if k == "tls_handshake_failed"]) == 1
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)
    failed = [e for e in events.seen if e[0] == "tls_handshake_failed"]
    assert len(failed) == 2
    assert failed[1][2] is not None and failed[1][2].startswith("1 failed handshake(s)")


# --- the MLLP listener where the loop runs the handshake --------------------------------------


async def _mllp_loop_run_scenario(tmp_path: Path) -> None:
    source, cert = _tls_source(tmp_path)
    events = _Events()
    source.on_connection_event = events
    await source.start(_ack)
    try:
        assert source._upgrade_tls is False  # the loop runs the handshake here
        # The control: a real TLS sender gets a message through and no failure is recorded.
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={
                    "host": "127.0.0.1",
                    "port": source.sockport,
                    "timeout_seconds": 5,
                    "tls": True,
                    "tls_ca_file": cert,
                    "tls_check_hostname": True,
                },
            )
        )
        try:
            await dest.send(ADT)
        finally:
            await dest.aclose()
        assert "tls_handshake_failed" not in events.kinds()
        assert source.tls_handshake_failures == 0

        await _plaintext_peer(source.sockport)
        await _until(lambda: "tls_handshake_failed" in events.kinds(), "no failure event")
        assert source.tls_handshake_failures == 1
        (_kind, peer, reason) = next(e for e in events.seen if e[0] == "tls_handshake_failed")
        assert peer is None  # the loop's TLS object knows no peer
        assert reason is not None and reason.startswith("1 failed handshake(s)")
        assert "MSH" not in reason and "GET" not in reason
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_mllp_records_a_failed_loop_run_handshake_on_the_stdlib_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The path uvloop takes, forced on the stdlib loop so it runs on every platform."""
    monkeypatch.setattr(mllp_module, "_upgrades_tls_itself", lambda _loop: False)
    await _mllp_loop_run_scenario(tmp_path)


@pytest.mark.skipif(sys.platform == "win32", reason="uvloop does not run on Windows")
def test_mllp_records_a_failed_handshake_on_uvloop(tmp_path: Path) -> None:
    """Vault BACKLOG #2613 item 3: the real loop, not a stand-in. It skips where uvloop is not
    installed."""
    uvloop = pytest.importorskip("uvloop")
    asyncio.run(_mllp_loop_run_scenario(tmp_path), loop_factory=uvloop.new_event_loop)


def test_a_listener_running_its_own_handshake_does_not_count_twice(tmp_path: Path) -> None:
    """On the stdlib loop the MLLP listener upgrades each socket itself and counts a failure in
    `_start_tls`, with the peer. The context hook must stay out of that count."""
    source, _cert_path = _tls_source(tmp_path)
    source._upgrade_tls = True
    source._note_loop_tls_failure("SSLError")
    assert source.tls_handshake_failures == 0


# --- the API ------------------------------------------------------------------------------------


def _api_records(caplog_records: list[logging.LogRecord]) -> list[str]:
    return [
        r.getMessage()
        for r in caplog_records
        if r.name == "messagefoundry.api.tls"
        and r.levelno == logging.WARNING
        and r.getMessage().startswith("TLS handshake failed on the API listener")
    ]


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.mark.usefixtures("bounded_warn_only_retention", "verified_log_forwarding")
def test_serve_records_a_failed_api_handshake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The context serve hands uvicorn, served the way uvicorn serves it (``loop.create_server``
    with ``ssl=``). The first failure is a WARNING at once; a second inside the window is held and
    logged when uvicorn returns."""
    from messagefoundry.__main__ import main
    from messagefoundry.api_tls_source import GENERATED_CERT_NAME
    from messagefoundry.store.crypto import generate_key
    from tests.test_api_tls import _SYNTHETIC_LOOPBACK_TOML, SAMPLES_CONFIG

    collect = _Collect()
    tls_log = logging.getLogger("messagefoundry.api.tls")
    during: dict[str, Any] = {}

    async def scenario(ctx: ssl.SSLContext) -> None:
        loop = asyncio.get_running_loop()
        server = await loop.create_server(asyncio.Protocol, "127.0.0.1", 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        try:
            pinned = _pinned_client(str(tmp_path / GENERATED_CERT_NAME))
            during["control_ok"] = await _tls_peer(port, pinned)
            await asyncio.sleep(0.1)
            during["after_control"] = _api_records(collect.records)
            await _plaintext_peer(port)
            await _until(lambda: bool(_api_records(collect.records)), "no WARNING line")
            during["after_failure"] = _api_records(collect.records)
            assert await asyncio.to_thread(_refuse_the_certificate, port)
            await asyncio.sleep(0.2)
            during["held"] = _api_records(collect.records)
        finally:
            server.close()
            await server.wait_closed()

    def fake_run(*_args: Any, **kwargs: Any) -> None:
        tls_log.addHandler(collect)
        tls_log.setLevel(logging.WARNING)
        asyncio.run(scenario(kwargs["ssl_context_factory"](None, None)))

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", fake_run)
    (tmp_path / "messagefoundry.toml").write_text(_SYNTHETIC_LOOPBACK_TOML, encoding="utf-8")
    try:
        assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
        after_close = _api_records(collect.records)
    finally:
        tls_log.removeHandler(collect)
        tls_log.setLevel(logging.NOTSET)

    assert during["control_ok"] is True
    assert during["after_control"] == []  # the control: a completed handshake logs nothing
    assert len(during["after_failure"]) == 1
    line = during["after_failure"][0]
    assert line.startswith("TLS handshake failed on the API listener: 1 failed handshake(s)")
    assert "GET" not in line
    assert during["held"] == during["after_failure"]  # the second is held inside the window
    assert len(after_close) == 2  # and logged once uvicorn returned
    assert after_close[1].startswith("TLS handshake failed on the API listener: 1 failed")


def test_the_api_record_logs_nothing_at_close_when_nothing_is_held(tmp_path: Path) -> None:
    ctx, _cert_path = _server_ctx(tmp_path)
    record = ApiHandshakeRecord(ctx)
    collect = _Collect()
    tls_log = logging.getLogger("messagefoundry.api.tls")
    tls_log.addHandler(collect)
    try:
        record.close()
    finally:
        tls_log.removeHandler(collect)
    assert _api_records(collect.records) == []
