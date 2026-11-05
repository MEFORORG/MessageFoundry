# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The API's IPv6 listening socket is IPv6-only on every loop the engine runs on (#3764 item 6).

``serve`` hands the bind to ``uvicorn.run`` with no ``loop`` argument, so uvicorn's ``"auto"``
default picks the loop: uvloop wherever it is importable, which the engine's own ``uvloop``
dependency in ``pyproject.toml`` makes every CPython install outside Windows. uvicorn then calls
the loop's ``create_server`` with ``[api].host``. The stdlib loop sets ``IPV6_V6ONLY`` on each IPv6
socket it creates; whether uvloop does was unverified when engine PR 2380 shipped, and Linux
defaults the option off.

It matters for ``[api].trusted_proxies``. With the option off, an ``[api].host`` of ``::`` would
also accept IPv4 peers, which reach the engine as ``::ffff:``-mapped addresses, so the
forwarded-client check would see a spelling the operator may not have listed. With it on, an IPv4
peer of a ``::`` bind is refused, so a mapped peer cannot come from a dual-stack socket.

The uvloop arm skips where uvloop is not importable, which is every Windows install, so it runs on
CI's Linux legs only. The stdlib arm is its control and runs everywhere IPv6 is enabled.
"""

from __future__ import annotations

import asyncio
import inspect
import socket
import sys
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from messagefoundry.__main__ import main

_SAMPLES_CONFIG = Path(__file__).resolve().parent.parent / "samples" / "config"


async def _app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    """An ASGI app that never needs to answer: the test reads the listening socket only."""


def _ipv6_loopback_enabled() -> bool:
    """Whether this host can bind ``::1``; an IPv6-disabled runner has nothing to measure."""
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        return False
    return True


def test_serve_leaves_the_loop_to_uvicorns_auto_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The premise of the uvloop arm: serve passes uvicorn no ``loop``, and uvicorn's own default is
    ``"auto"``. If either changes, the arm below no longer measures the loop the engine runs on."""
    from messagefoundry.store.crypto import generate_key

    captured: dict[str, Any] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: captured.update(k))
    # warn, so the start-up posture gates (the off-box log forwarding one among them) warn rather
    # than refuse: what reaches uvicorn.run is the subject, not those gates.
    (tmp_path / "messagefoundry.toml").write_text(
        'security.enforcement = "warn"\n'
        "security.block_unlisted_outbound = true\n"
        "security.allow_unencrypted_phi = true\n"
        "security.allow_unencrypted_phi_under_strict_enforcement = true\n"
        "alerts.security_notifications_required = false\n"
        "security.local_access_only = true\n",
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(_SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert captured, "serve did not reach uvicorn.run"
    assert "loop" not in captured
    assert inspect.signature(uvicorn.Config).parameters["loop"].default == "auto"


@pytest.mark.parametrize("loop_name", ["asyncio", "auto"])
def test_the_api_ipv6_listener_is_ipv6_only(loop_name: str) -> None:
    """RED when: the loop serve runs on binds an IPv6 API socket dual-stack. ``auto`` is the engine's
    own path, and on Linux it must resolve to uvloop for this arm to mean anything, so it asserts
    that first. ``asyncio`` is the stdlib control, which sets the option explicitly."""
    uvloop: Any = None
    if loop_name == "auto":
        if sys.platform == "win32":
            pytest.skip("uvloop does not run on Windows, so auto is the stdlib loop there")
        uvloop = pytest.importorskip("uvloop")
    if not _ipv6_loopback_enabled():
        pytest.skip("IPv6 is not enabled on this host")
    # The wildcard is the case dual stack changes, so read it where binding one prompts nobody. On
    # Windows a wildcard bind can raise a firewall prompt; the option is set per IPv6 socket, so
    # ::1 there still reads the same code path.
    host = "::1" if sys.platform == "win32" else "::"
    config = uvicorn.Config(
        _app, host=host, port=0, loop=loop_name, lifespan="off", log_config=None
    )

    async def scenario() -> None:
        if uvloop is not None:
            assert isinstance(asyncio.get_running_loop(), uvloop.Loop), (
                "uvicorn's auto loop is not uvloop, so this arm does not measure the engine's loop"
            )
        server = uvicorn.Server(config)
        task = asyncio.create_task(server.serve())
        try:
            for _ in range(500):
                if server.started or task.done():
                    break
                await asyncio.sleep(0.01)
            assert server.started, "uvicorn did not start"
            (listener,) = server.servers[0].sockets
            # A dup, so the read works the same through the stdlib's TransportSocket and
            # uvloop's PseudoSocket.
            with socket.fromfd(listener.fileno(), socket.AF_INET6, socket.SOCK_STREAM) as dup:
                assert dup.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1
                port = dup.getsockname()[1]
            if host == "::":
                # The behaviour the option stands for: an IPv4 peer of the wildcard is refused,
                # rather than arriving as a ::ffff:-mapped address.
                with pytest.raises(ConnectionRefusedError):
                    _reader, writer = await asyncio.wait_for(
                        asyncio.open_connection("127.0.0.1", port), 5.0
                    )
                    writer.close()
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 10.0)

    asyncio.run(scenario(), loop_factory=config.get_loop_factory())
