# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Console API client, exercised against a real uvicorn server in a background thread.

This is an integration test: it starts the managed app (engine + API) on a free port with a
code-first config, drives it by dropping an HL7 file, and verifies the *synchronous* client sees
the same end-to-end behavior the GUI relies on."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import Iterator

import httpx
import pytest
import uvicorn

from messagefoundry.api import create_managed_app
from messagefoundry.console.client import ApiError, EngineClient

ADT = "MSH|^~\\&|APP|FAC|RAPP|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _write_config(config_dir: Path, inbox: Path, outdir: Path) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    src_dir, out_dir = inbox.as_posix(), outdir.as_posix()
    module = f'''\
from messagefoundry import File, Send, handler, inbound, outbound, router

inbound("in", File(directory="{src_dir}", pattern="*.hl7", poll_seconds=0.05), router="r")
outbound("archive", File(directory="{out_dir}", filename="{{MSH-10}}.hl7"))


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("archive", msg)
'''
    (config_dir / "cfg.py").write_text(module, encoding="utf-8")


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    _write_config(tmp_path / "config", inbox, outdir)
    app = create_managed_app(
        db_path=tmp_path / "console.db",
        config_dir=tmp_path / "config",
        poll_interval=0.05,
    )
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    uv = uvicorn.Server(config)
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not uv.started:
        time.sleep(0.05)
        if time.time() > deadline:
            raise RuntimeError("server did not start")
    try:
        yield f"http://127.0.0.1:{port}", inbox
    finally:
        uv.should_exit = True
        thread.join(timeout=10)


def _wait(predicate, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while not predicate():
        time.sleep(0.05)
        if time.time() > deadline:
            raise AssertionError("condition not met within timeout")


def test_health_and_connections(server: tuple[str, Path]) -> None:
    url, _ = server
    with EngineClient(url) as client:
        assert client.health().status == "ok"
        channels = client.list_channels()  # inbound connections
        assert [c.id for c in channels] == ["in"]
        assert channels[0].running is True  # the wired graph starts with the engine


def test_message_flow_list_detail_replay(server: tuple[str, Path]) -> None:
    url, inbox = server
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    with EngineClient(url) as client:
        _wait(lambda: client.list_messages().total >= 1)
        listing = client.list_messages()
        assert listing.total == 1
        mid = listing.messages[0].id
        assert listing.messages[0].message_type == "ADT^A01"

        # The ingress row is listed the instant it commits, but the staged pipeline
        # produces the outbound row asynchronously (ingress → routed → outbound). Wait for
        # delivery before reading the outbox, or a slow runner races the worker and sees [].
        _wait(lambda: client.get_message(mid).outbox)
        detail = client.get_message(mid)
        assert detail.raw == ADT
        assert detail.outbox[0].destination_name == "archive"
        # Fetching detail recorded a 'viewed' audit event.
        assert any(e.event == "viewed" for e in detail.events)

        result = client.replay(mid)
        assert result.requeued == 1


def test_dead_letters_and_reload(server: tuple[str, Path]) -> None:
    url, _ = server
    with EngineClient(url) as client:
        # A healthy graph has nothing dead-lettered; the list + bulk replay still answer cleanly.
        dead = client.list_dead_letters()
        assert dead.total == 0
        assert dead.dead_letters == []
        assert client.replay_dead_letters().requeued == 0

        # Reload the startup config dir (config_dir=None) and confirm the live graph is reported.
        result = client.reload_config()
        assert (result.inbound, result.outbound, result.routers, result.handlers) == (1, 1, 1, 1)
        assert result.running is True


def test_start_stop_connection(server: tuple[str, Path]) -> None:
    url, _ = server

    def status(client: EngineClient) -> str | None:
        return next((r.status for r in client.connections() if r.name == "in ▸ in"), None)

    with EngineClient(url) as client:
        client.stop_connection("in")
        _wait(lambda: status(client) == "stopped")
        client.start_connection("in")
        _wait(lambda: status(client) == "running")


def test_404_raises_apierror(server: tuple[str, Path]) -> None:
    url, _ = server
    with EngineClient(url) as client:
        with pytest.raises(ApiError) as excinfo:
            client.get_message("does-not-exist")
        assert excinfo.value.status == 404


def test_unreachable_server_raises_apierror() -> None:
    with EngineClient("http://127.0.0.1:1", timeout=1.0) as client:
        with pytest.raises(ApiError):
            client.health()


def test_integrity_check_uses_generous_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    # M-27: the DB integrity scan can exceed the blanket 5s timeout on a large store — it must use a
    # generous per-request timeout rather than be mis-reported as "could not reach engine".
    import httpx

    client = EngineClient("http://127.0.0.1:8765")
    captured: dict[str, object] = {}

    class _Resp:
        status_code = 200

        def json(self) -> dict[str, object]:
            return {"ok": True, "detail": "verified"}

    def fake_request(method: str, path: str, headers: object = None, **kw: object) -> _Resp:
        captured.update(kw)
        return _Resp()

    monkeypatch.setattr(client._http, "request", fake_request)
    assert client.integrity_check().ok
    assert isinstance(captured.get("timeout"), httpx.Timeout)


# --- decode contract (H2/L2): schema/JSON failures on a 2xx body become ApiError -------------


def test_decode_maps_schema_mismatch_to_apierror() -> None:
    from messagefoundry.api.models import EngineInfo
    from messagefoundry.console.client import _decode

    # EngineInfo has required fields (version/uptime_seconds/pid); a mismatched shape must error.
    # (Health is deliberately all-optional now — version is auth-gated — so it can't stand in here.)
    resp = httpx.Response(200, json={"unexpected": "shape"})  # missing required fields
    with pytest.raises(ApiError, match="invalid response"):
        _decode(resp, EngineInfo)


def test_decode_maps_malformed_json_to_apierror() -> None:
    from messagefoundry.api.models import Health
    from messagefoundry.console.client import _decode

    resp = httpx.Response(200, content=b"not json at all")
    with pytest.raises(ApiError):
        _decode(resp, Health)


def test_decode_list_maps_bad_payload_to_apierror() -> None:
    from messagefoundry.api.models import ChannelInfo
    from messagefoundry.console.client import _decode_list

    resp = httpx.Response(200, json={"not": "a list"})
    with pytest.raises(ApiError):
        _decode_list(resp, ChannelInfo)


# --- poll client (backlog #2): a separate read-only client for off-thread reads ----------------


def test_for_polling_is_a_distinct_readonly_client() -> None:
    # The dedicated poll client (background, off-thread reads) must be a SEPARATE httpx.Client that
    # shares the bearer token but carries NO step-up/MFA handlers, so worker threads never touch the
    # main-thread client's connection pool or its mutable auth state — the cross-thread-shared-client
    # hazard the off-thread conversion closes.
    client = EngineClient("http://127.0.0.1:8765", timeout=3.0)
    client._token = "tok-123"  # simulate an authenticated session
    client.set_step_up_handler(lambda: True)
    client.set_mfa_handler(lambda: True)

    poll = client.for_polling()
    try:
        assert poll is not client
        assert poll._http is not client._http  # its own connection pool
        assert poll.base_url == client.base_url
        assert poll.token == "tok-123"  # shares the bearer token at creation
        # read-only: it must never prompt, so the 403→prompt→retry branches stay inert
        assert poll._step_up_handler is None
        assert poll._mfa_handler is None
    finally:
        poll.close()
        client.close()
