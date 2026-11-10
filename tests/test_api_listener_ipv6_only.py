# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The API's IPv6 listening socket is IPv6-only on the loops the engine runs on (vault BACKLOG #3764
item 6).

``serve`` hands the bind to ``uvicorn.run`` by host and port with no ``loop`` argument, so
uvicorn's ``"auto"`` default picks the loop and that loop's ``create_server`` makes the socket.
``tests/test_api_tls.py::test_serve_forwarded_allow_ips_empty_when_no_proxy`` pins that premise.
``"auto"`` means uvloop wherever it imports, and the engine's own ``uvloop`` dependency installs
it wherever its environment marker holds; this file evaluates that marker from messagefoundry's
installed metadata rather than restating it. The stdlib loop's ``create_server`` sets
``IPV6_V6ONLY`` on each IPv6 socket it binds by host and port; whether uvloop's does was unverified
when engine PR 2380 shipped, and Linux defaults the option off.

What it decides is which families an ``[api].host`` of ``::`` serves. With the option off, that
bind would also accept IPv4 peers, which reach the engine as ``::ffff:``-mapped addresses. That
does not widen ``[api].trusted_proxies``, which hands uvicorn each IPv4 entry in both spellings,
but it is a listener on a family the operator did not name.

The uvloop arm runs where the marker installs uvloop. There it fails if uvloop does not import,
and under CI it fails if IPv6 is off or the host's default is already on, so a green CI run on
such a leg measured uvloop. It skips on every other platform, every Windows install included.
On Linux both arms first require a fresh IPv6 socket to read 0, so a 1 is the loop's doing; on
Windows the default is on, so there the stdlib arm reads the default too. The control test shows
the read itself can return 0.
"""

from __future__ import annotations

import asyncio
import functools
import importlib
import importlib.metadata
import os
import socket
import sys
from typing import Any

import pytest
import uvicorn
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


@functools.cache
def _uvloop_installed_here() -> bool:
    """Whether messagefoundry's own ``uvloop`` requirement applies on this interpreter, read from
    its installed metadata, so ``pyproject.toml``'s marker stays the one statement of where."""
    for line in importlib.metadata.requires("messagefoundry") or []:
        requirement = Requirement(line)
        if canonicalize_name(requirement.name) == "uvloop":
            return requirement.marker is None or requirement.marker.evaluate({"extra": ""})
    raise AssertionError("messagefoundry no longer declares uvloop; this file's premise is gone")


def _under_ci() -> bool:
    """Whether ``CI`` is set to a true value; ``CI=false`` and ``CI=0`` are not CI."""
    return os.environ.get("CI", "").strip().lower() in {"1", "true", "yes"}


async def _app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    """An ASGI app that never needs to answer: the test reads the listening socket only."""


@functools.cache
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


def _fresh_default() -> int:
    """``IPV6_V6ONLY`` on a fresh IPv6 socket nobody set it on: this host's default."""
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as fresh:
        return _v6only(fresh.fileno())


def test_the_read_sees_a_dual_stack_socket() -> None:
    """The control for the instrument: the same read returns 0 for a socket with the option
    cleared, so it can see a dual-stack socket. Whether the host's default is off is a separate
    precondition, checked by each arm below on Linux."""
    if not _ipv6_loopback_enabled():
        pytest.skip("IPv6 is not enabled on this host")
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as dual:
        dual.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        dual.bind(("::1", 0))
        assert _v6only(dual.fileno()) == 0


def _not_measurable(reason: str, *, fail_under_ci: bool) -> None:
    """Fail where a CI leg should have measured this arm, skip elsewhere."""
    if fail_under_ci and _under_ci():
        pytest.fail(f"{reason}, on a CI leg that installs uvloop, so uvloop was not measured")
    pytest.skip(reason)


@pytest.mark.parametrize("loop_name", ["asyncio", "auto"])
def test_the_api_ipv6_listener_is_ipv6_only(loop_name: str) -> None:
    """RED when: the loop serve runs on binds an IPv6 API socket dual-stack. ``auto`` is the engine's
    own path, and where uvloop is installed it must resolve to uvloop for this arm to mean
    anything, so it asserts that first. ``asyncio`` is the stdlib control."""
    uvloop: Any = None
    if loop_name == "auto":
        if not _uvloop_installed_here():
            pytest.skip("messagefoundry's uvloop requirement does not apply on this interpreter")
        # A dependency here, so a missing one fails rather than skips.
        uvloop = importlib.import_module("uvloop")
    if not _ipv6_loopback_enabled():
        _not_measurable("IPv6 is not enabled on this host", fail_under_ci=uvloop is not None)
    if sys.platform == "linux" and _fresh_default() != 0:
        # net.ipv6.bindv6only=1: every socket reads 1, so a 1 would not be the loop's doing.
        _not_measurable("this host defaults IPV6_V6ONLY on", fail_under_ci=uvloop is not None)
    # The wildcard is the case dual stack changes, so it is read on Linux, where a bind prompts
    # nobody. Elsewhere a wildcard bind can raise a firewall prompt (Windows, and macOS with its
    # firewall on); the option is set per IPv6 socket, so ::1 reads the same code path.
    host = "::" if sys.platform == "linux" else "::1"
    config = uvicorn.Config(
        _app, host=host, port=0, loop=loop_name, lifespan="off", log_config=None
    )

    async def scenario() -> tuple[bool, list[int]]:
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
            started = server.started
            readings = [_v6only(s.fileno()) for s in server.servers[0].sockets] if started else []
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 10.0)
        # Asserted after the shutdown, so a slow stop cannot hide what was read.
        return started, readings

    try:
        started, readings = asyncio.run(scenario(), loop_factory=config.get_loop_factory())
    except SystemExit as exc:  # uvicorn exits its start-up when the bind fails
        pytest.fail(f"uvicorn exited at start-up with code {exc.code}: the {host} bind failed")
    assert started, "uvicorn did not start"
    assert readings == [1]
