# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The API's IPv6 listening socket is IPv6-only on the loops the engine runs on (#3764 item 6).

``serve`` hands the bind to ``uvicorn.run`` by host and port with no ``loop`` argument, so
uvicorn's ``"auto"`` default picks the loop and that loop's ``create_server`` makes the socket.
``tests/test_api_tls.py::test_serve_forwarded_allow_ips_empty_when_no_proxy`` pins that premise.
``"auto"`` means uvloop wherever it imports, and the engine's own ``uvloop`` dependency in
``pyproject.toml`` installs it at least on Linux and macOS outside PyPy. The stdlib loop sets
``IPV6_V6ONLY`` on each IPv6 socket it creates; whether uvloop does was unverified when engine PR
2380 shipped, and Linux defaults the option off.

What it decides is which families an ``[api].host`` of ``::`` serves. With the option off, that
bind would also accept IPv4 peers, which reach the engine as ``::ffff:``-mapped addresses. That
does not widen ``[api].trusted_proxies``, which hands uvicorn each IPv4 entry in both spellings,
but it is a listener on a family the operator did not name.

The uvloop arm runs where the dependency's marker installs uvloop. There it fails if uvloop does
not import, and under CI it fails if IPv6 is off, so a green CI run on such a leg ran it. It skips
on every other platform, every Windows install included. The stdlib arm discriminates only where
the OS default is off, as on Linux: Windows already defaults the option on, so there it reads the
default too. The control test shows the read can return 0.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import platform
import socket
import sys
from typing import Any

import pytest
import uvicorn

#: Where ``pyproject.toml``'s ``uvloop`` marker installs it: outside PyPy, Windows and Cygwin.
_UVLOOP_INSTALLED_HERE = platform.python_implementation() != "PyPy" and sys.platform not in {
    "win32",
    "cygwin",
}


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


def _v6only(fileno: int) -> int:
    """``IPV6_V6ONLY`` on the socket behind ``fileno``, read through a dup, so the read is the same
    for the stdlib's TransportSocket, uvloop's PseudoSocket and a plain socket."""
    with socket.fromfd(fileno, socket.AF_INET6, socket.SOCK_STREAM) as dup:
        return dup.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY)


def test_the_read_sees_a_dual_stack_socket() -> None:
    """The control: the same read returns 0 for a socket with the option cleared, so a 1 below is
    the loop's doing and not the instrument's."""
    if not _ipv6_loopback_enabled():
        pytest.skip("IPv6 is not enabled on this host")
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as dual:
        dual.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        dual.bind(("::1", 0))
        assert _v6only(dual.fileno()) == 0


@pytest.mark.parametrize("loop_name", ["asyncio", "auto"])
def test_the_api_ipv6_listener_is_ipv6_only(loop_name: str) -> None:
    """RED when: the loop serve runs on binds an IPv6 API socket dual-stack. ``auto`` is the engine's
    own path, and where uvloop is installed it must resolve to uvloop for this arm to mean
    anything, so it asserts that first. ``asyncio`` is the stdlib control."""
    uvloop: Any = None
    if loop_name == "auto":
        if not _UVLOOP_INSTALLED_HERE:
            pytest.skip("pyproject.toml installs uvloop outside PyPy, Windows and Cygwin only")
        # A dependency here, so a missing one fails rather than skips.
        uvloop = importlib.import_module("uvloop")
    if not _ipv6_loopback_enabled():
        if uvloop is not None and os.environ.get("CI"):
            pytest.fail("IPv6 is off on a CI leg that installs uvloop, so it was not measured")
        pytest.skip("IPv6 is not enabled on this host")
    # The wildcard is the case dual stack changes, so it is read on Linux, where a bind prompts
    # nobody. Elsewhere a wildcard bind can raise a firewall prompt (Windows, and macOS with its
    # firewall on); the option is set per IPv6 socket, so ::1 reads the same code path.
    host = "::" if sys.platform == "linux" else "::1"
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
            # No tight start bound: pytest-timeout is the watchdog, and a loaded leg is slow.
            while not (server.started or task.done()):
                await asyncio.sleep(0.01)
            assert server.started, "uvicorn did not start"
            (listener,) = server.servers[0].sockets
            assert _v6only(listener.fileno()) == 1
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 10.0)

    asyncio.run(scenario(), loop_factory=config.get_loop_factory())
