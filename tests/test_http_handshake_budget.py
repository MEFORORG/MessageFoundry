# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The HTTP listener bounds how many slots one address may hold in a TLS handshake (vault BACKLOG #4888).

On a loop that upgrades TLS itself (``_upgrades_tls_itself``, the stdlib loops) a socket is admitted
before its handshake, so it holds a ``max_connections`` slot until the handshake ends, up to the 10 s
handshake bound. ``max_connections_per_host`` ships off on ``Http()`` (vault BACKLOG #2606), so before
this row one address that never finished a handshake, at least an mTLS peer with no client
certificate, could have held every one of the 256 slots. ``max_handshakes_per_host`` bounds only the
handshake: a socket leaves the count the moment its handshake ends, so a completed connection never
counts against it, and the per-host cap stays off for established traffic behind an L4 load
balancer.

Each refusal test carries a control: a socket within the budget, or a completed handshake, admitted
by the same listener. Every wait has a generous deadline and the handshake bound is pinned far above
it, so only the budget can close a socket in time.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import Http
from messagefoundry.transports import http_listener as http_module
from messagefoundry.transports.admission import ListenerAdmission
from messagefoundry.transports.http_listener import DEFAULT_MAX_HANDSHAKES_PER_HOST, HttpSource
from messagefoundry.transports.receipt import receipt_handler
from tests.test_http_listener_tls_admission import _https_post, _Intake
from tests.test_listener_admission import _PeerWriter
from tests.test_mllp_tls import _close_raw, _closed_by_listener, _Events, _until
from tests.test_tls_handshake_failures import _http_tls_source as _tls_source
from tests.test_tls_handshake_failures import _pinned_client

HOST = "127.0.0.1"


async def _silent_socket(port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """A plain TCP socket that never sends a ClientHello, so it stays in its handshake."""
    return await asyncio.open_connection(HOST, port)


async def test_one_address_holds_at_most_the_budget_in_its_handshake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row's case: per-host cap off (the shipped default), so before #4888 a third silent
    socket was admitted like the first two and only ``max_connections`` bounded the address."""
    monkeypatch.setattr(http_module, "_TLS_HANDSHAKE_TIMEOUT", 60.0)
    source, _cert = _tls_source(tmp_path, max_handshakes_per_host=2)
    assert source.max_connections_per_host is None  # the #2606 default this row leaves alone
    events = _Events()
    source.on_connection_event = events
    await source.start(receipt_handler(_Intake()))
    opened: list[asyncio.StreamWriter] = []
    try:
        assert source._upgrade_tls is True
        for _ in range(2):
            opened.append((await _silent_socket(source.sockport))[1])
        await _until(lambda: source._admission.active == 2, "two silent sockets were not admitted")
        assert source._admission.handshaking == {HOST: 2}
        r3, w3 = await _silent_socket(source.sockport)
        opened.append(w3)
        # Closed with no bytes: a plaintext 503 is no answer a TLS client can read.
        await _closed_by_listener(r3, within=5.0)
        await _until(lambda: "at_capacity" in events.kinds(), "no at_capacity event")
        assert events.seen == [("at_capacity", HOST, "max_handshakes_per_host")]
        assert source._admission.active == 2
        # CONTROL: a slot the budget frees is taken again by the next socket from the same address.
        await _close_raw(opened.pop(0))
        await _until(lambda: source._admission.active == 1, "the handshake slot was not released")
        opened.append((await _silent_socket(source.sockport))[1])
        await _until(lambda: source._admission.active == 2, "a socket within budget was refused")
        assert events.kinds() == ["at_capacity"]
        # Every handshake that ends gives its count back while the listener runs, not only at the
        # reset a stop() makes.
        while opened:
            await _close_raw(opened.pop())
        await _until(lambda: source._admission.handshaking == {}, "a handshake count was kept")
    finally:
        for writer in opened:
            await _close_raw(writer)
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_a_completed_handshake_does_not_count_against_the_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The budget counts the handshake, not the connection, which is what keeps it apart from a
    per-host cap of 1: a peer past its handshake is still open here, and a silent socket from the
    same address is admitted beside it. The second silent socket is refused, so the budget is on."""
    monkeypatch.setattr(http_module, "_TLS_HANDSHAKE_TIMEOUT", 60.0)
    source, cert = _tls_source(tmp_path, max_handshakes_per_host=1)
    events = _Events()
    source.on_connection_event = events
    await source.start(receipt_handler(_Intake()))
    opened: list[asyncio.StreamWriter] = []
    try:
        _r, done = await asyncio.wait_for(
            asyncio.open_connection(
                HOST, source.sockport, ssl=_pinned_client(cert), server_hostname=HOST
            ),
            timeout=5.0,
        )
        opened.append(done)  # handshake complete; no request sent, so the connection stays open
        await _until(lambda: source._admission.active == 1, "the TLS connection was not admitted")
        await _until(lambda: source._admission.handshaking == {}, "its handshake still counts")
        opened.append((await _silent_socket(source.sockport))[1])
        await _until(lambda: source._admission.active == 2, "a socket within budget was refused")
        assert source._admission.handshaking == {HOST: 1}
        r3, w3 = await _silent_socket(source.sockport)
        opened.append(w3)
        await _closed_by_listener(r3, within=5.0)
        await _until(lambda: "at_capacity" in events.kinds(), "no at_capacity event")
        assert ("at_capacity", HOST, "max_handshakes_per_host") in events.seen
    finally:
        for writer in opened:
            await _close_raw(writer)
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_the_budget_is_inert_where_the_loop_runs_the_handshake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a loop that does not upgrade TLS itself (uvloop's path, forced here), a socket in its
    handshake takes no slot and is not counted. Two silent sockets from one address with a budget
    of 1 leave a real client from that address served. This pins behaviour, not wiring: on this path
    `_on_client` runs only after the loop's handshake, so no wiring change could make the budget
    count these sockets."""
    monkeypatch.setattr(http_module, "_upgrades_tls_itself", lambda _loop: False)
    monkeypatch.setattr(http_module, "_TLS_HANDSHAKE_TIMEOUT", 60.0)
    source, cert = _tls_source(tmp_path, max_handshakes_per_host=1)
    events = _Events()
    source.on_connection_event = events
    intake = _Intake()
    await source.start(receipt_handler(intake))
    opened: list[asyncio.StreamWriter] = []
    try:
        assert source._upgrade_tls is False
        for _ in range(2):
            opened.append((await _silent_socket(source.sockport))[1])
        assert await _https_post(source.sockport, cert) == 202
        assert "at_capacity" not in events.kinds()
        assert source._admission.handshaking == {}
    finally:
        for writer in opened:
            await _close_raw(writer)
        await asyncio.wait_for(source.stop(), timeout=10.0)
    assert intake.received == [b"hi"]


def _http(**settings: Any) -> HttpSource:
    return HttpSource(
        Source(
            type=ConnectorType.HTTP,
            settings={"host": HOST, "port": 0, **settings},
        )
    )


def test_the_budget_ships_on_and_can_be_turned_off() -> None:
    assert DEFAULT_MAX_HANDSHAKES_PER_HOST == 32
    # The factory's literal default and the listener's constant are one number.
    assert Http(port=1).settings["max_handshakes_per_host"] == DEFAULT_MAX_HANDSHAKES_PER_HOST
    source = _http()
    assert source.max_handshakes_per_host == DEFAULT_MAX_HANDSHAKES_PER_HOST
    assert source._admission.max_handshakes_per_host == DEFAULT_MAX_HANDSHAKES_PER_HOST
    # An eighth of the socket cap, the ratio the other listeners' per-host cap ships at.
    assert source.max_connections is not None
    assert source.max_connections == DEFAULT_MAX_HANDSHAKES_PER_HOST * 8
    assert _http(max_handshakes_per_host=0).max_handshakes_per_host is None
    assert _http(max_handshakes_per_host=None).max_handshakes_per_host is None
    assert _http(max_handshakes_per_host="0").max_handshakes_per_host is None
    with pytest.raises(ValueError, match="max_handshakes_per_host"):
        _http(max_handshakes_per_host=-1)


def _gate(budget: int | None) -> ListenerAdmission:
    return ListenerAdmission(
        transport="HTTP",
        name="IB_TEST",
        max_connections=10,
        max_connections_per_host=None,
        source_ip_allowlist=None,
        max_handshakes_per_host=budget,
    )


def test_admission_counts_only_sockets_in_their_handshake() -> None:
    host = "192.0.2.7"
    w: Any = _PeerWriter()
    gate = _gate(1)
    first = gate.admit(host)
    with gate.handshake(host, first):
        refused = gate.check(w, host, handshake=True)
        assert refused is not None and refused.reason == "max_handshakes_per_host"
        assert host in gate.handshake_capacity_warned
        # CONTROL: a socket that needs no handshake (a plaintext listener, or the loop's
        # handshake) is not measured against the budget at all.
        assert gate.check(w, host) is None
    assert gate.handshaking == {} and gate.handshake_capacity_warned == set()
    assert gate.per_host == {host: 1}, "ending the handshake gave back the connection slot"
    assert gate.check(w, host, handshake=True) is None
    # A handshake that fails by raising leaves the count too.
    with pytest.raises(OSError), gate.handshake(host, first):
        raise OSError("handshake failed")
    assert gate.handshaking == {}
    gate.release(host, first)
    assert gate.active == 0 and gate.per_host == {}
    # Off: no refusal however many are in their handshake.
    off = _gate(None)
    with contextlib.ExitStack() as stack:
        for _ in range(5):
            stack.enter_context(off.handshake(host, off.admit(host)))
        assert off.check(w, host, handshake=True) is None


def test_a_handshake_ending_after_a_restart_leaves_the_restarted_count_alone() -> None:
    """The epoch rule of vault BACKLOG #2939, applied to the handshake table."""
    host = "192.0.2.7"
    w: Any = _PeerWriter()
    gate = _gate(1)
    straggler = contextlib.ExitStack()
    straggler.enter_context(gate.handshake(host, gate.admit(host)))
    gate.stopping = True
    gate.reset()
    assert gate.handshaking == {}
    gate.stopping = False
    with gate.handshake(host, gate.admit(host)):
        straggler.close()  # the pre-restart handshake ends while the restarted one is running
        assert gate.handshaking == {host: 1}, "a pre-restart handshake freed the restarted slot"
        refused = gate.check(w, host, handshake=True)
        assert refused is not None and refused.reason == "max_handshakes_per_host"
    assert gate.handshaking == {}
