# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0021 connection events on the ISA/IEA-framed X12 listener (BACKLOG #1665).

``X12Source`` carried no ``_emit_event`` call at all, so an allow-list refusal, a capacity refusal,
an over-cap interchange and a peer reset recorded **nothing** -- while ``TcpSource``, the listener
X12 is otherwise a near-copy of, recorded a row for each. On a deploying site that would leave an
X12 feed's connects and refusals absent from the one stream an operator reads to answer "did the
sender connect, and why did it drop". MessageFoundry has zero deployments, so nothing is missing
from a live stream today.

``test_allowlist_refusal_is_recorded_by_both_listeners`` carries the **positive control**: it drives
the same refusal on ``TcpSource`` through the same capture sink in the same test. A zero on the X12
side means the listener is silent only because the identical drive is non-zero on the TCP side; a
capture harness that could not see an event at all would read as a clean X12 listener.

Its own file rather than a hunk in ``tests/test_x12_transport.py``: open PR 1214 is rewriting that
file's ``expect_reply`` round-trip tests, and a seven-test block landing in the middle of it would
conflict for no gain. Only the ``_interchange`` builder is borrowed from there, which 1214 does not
touch.

The listener is driven by calling ``_on_client`` with fakes rather than over a real socket. That is
how the two drain tests beside it already work, and it is what lets the ``peer_reset`` and
``at_capacity`` arms be driven at all -- neither is reachable by writing bytes at a loopback port.
No ``start()``/``stop()``, so nothing here binds a port.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports.tcp import TcpSource
from messagefoundry.transports.x12 import X12Source
from tests.test_x12_transport import _interchange

#: One complete synthetic PHI-free 270 eligibility interchange, as bytes on the wire.
EDI = _interchange().encode("utf-8")

#: TEST-NET-3 (RFC 5737) -- a documentation address, never a routable one.
PEER = ("203.0.113.9", 2710)


class _Peer:
    """A writer fake: reports a fixed peer address, takes the reply, and closes on demand."""

    def __init__(self) -> None:
        self.closed = False
        self.written: list[bytes] = []

    def get_extra_info(self, name: str, default: object = None) -> object:
        return PEER if name == "peername" else default

    def write(self, data: bytes) -> None:
        self.written.append(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


class _Eof:
    """A sender that hangs up immediately -- the clean-close path."""

    async def read(self, _n: int) -> bytes:
        return b""


class _Silent:
    """A sender that connects and then says nothing -- the idle-timeout path."""

    async def read(self, _n: int) -> bytes:
        await asyncio.sleep(3600)
        return b""


class _Reset:
    """A sender whose socket dies under the read."""

    async def read(self, _n: int) -> bytes:
        raise ConnectionResetError("connection reset by peer")


class _OnceThenSilent:
    """Hands over one payload, then holds the connection open without reaching EOF."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self, _n: int) -> bytes:
        if self._data:
            chunk, self._data = self._data, b""
            return chunk
        await asyncio.sleep(3600)
        return b""


Event = tuple[str, str | None, str | None]


def _sink(events: list[Event]) -> object:
    async def capture(kind: str, peer_host: str | None, reason: str | None) -> None:
        events.append((kind, peer_host, reason))

    return capture


async def _drive(
    source: X12Source | TcpSource,
    reader: object,
    writer: _Peer,
    handler: object = None,
) -> list[Event]:
    """Run one client against ``source`` and return the events it emitted, in order."""
    events: list[Event] = []
    source.on_connection_event = _sink(events)  # type: ignore[assignment]
    if handler is None:

        async def _noop(raw: bytes) -> None:
            return None

        handler = _noop
    source._handler = handler  # type: ignore[assignment]
    # 2 s is how a regression FAILS (the unbounded arms sleep 3600), not how it passes.
    await asyncio.wait_for(source._on_client(reader, writer), timeout=2.0)  # type: ignore[arg-type]
    return events


def _x12(**settings: object) -> X12Source:
    base: dict[str, object] = {"host": "127.0.0.1", "port": 0}
    base.update(settings)
    return X12Source(Source(type=ConnectorType.X12, settings=base))


def _tcp(**settings: object) -> TcpSource:
    base: dict[str, object] = {"host": "127.0.0.1", "port": 0, "framing": "stx_etx"}
    base.update(settings)
    return TcpSource(Source(type=ConnectorType.TCP, settings=base))


def _kinds(events: list[Event]) -> list[str]:
    return [kind for kind, _peer, _reason in events]


# --- the positive control ----------------------------------------------------


async def test_allowlist_refusal_is_recorded_by_both_listeners() -> None:
    """The refusal that was silent on X12 and recorded on TCP, driven identically on both.

    The TCP arm is the control. Without it a zero on the X12 side is indistinguishable from a
    capture sink that is never called for any listener -- which is the shape the original defect
    hid behind, since ``SourceConnector.on_connection_event`` legitimately stays ``None`` on a
    poll/file source.
    """
    allowlist = {"source_ip_allowlist": ["10.0.0.0/8"]}  # PEER is outside it

    tcp_events = await _drive(_tcp(**allowlist), _Eof(), _Peer())
    x12_events = await _drive(_x12(**allowlist), _Eof(), _Peer())

    assert _kinds(tcp_events) == ["peer_not_allowlisted"], (
        "the control failed: TcpSource records this refusal today, so a harness that sees nothing "
        "here proves nothing about X12"
    )
    assert x12_events == tcp_events, (
        "the X12 listener refuses an out-of-allowlist peer identically to TcpSource but records a "
        f"different event set: {_kinds(x12_events)} vs {_kinds(tcp_events)}"
    )
    assert x12_events[0][1] == PEER[0]  # the peer host, and no port


# --- the vocabulary the two listeners share ----------------------------------


def _emitted_kinds(module_path: Path) -> set[str]:
    """The literal ``_emit_event("kind")`` names in one transports module, by AST."""
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    kinds: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "_emit_event" or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            kinds.add(first.value)
    return kinds


def test_x12_emits_the_same_event_vocabulary_as_its_tcp_twin() -> None:
    """Derived from the emit sites, so neither listener can grow a kind the other lacks.

    The two listeners are near-copies: same accept path, same allow-list and capacity gates, same
    per-chunk decode loop, same outer ``OSError`` arm, same ``finally``. Every ``TcpSource`` kind
    therefore has an X12 analogue and none was dropped. A new kind on one side alone is either a
    real asymmetry that belongs in this assertion's exemption, or the omission this row fixed.

    A new *name* on either side is a separate failure, caught by
    ``test_connection_event_vocabulary_is_derived_from_the_emit_sites`` in the PHI inventory, which
    checks the shipped kinds against the documented row and the console's filter tuple.
    """
    transports = Path(__file__).resolve().parents[1] / "messagefoundry" / "transports"
    tcp_kinds = _emitted_kinds(transports / "tcp.py")
    x12_kinds = _emitted_kinds(transports / "x12.py")
    assert tcp_kinds, (
        "the AST walk found no TcpSource emit site -- the instrument broke, not x12.py"
    )
    assert x12_kinds == tcp_kinds, (
        f"the X12 and raw-TCP listeners disagree on their connection-event vocabulary: "
        f"{sorted(x12_kinds ^ tcp_kinds)}"
    )


# --- one test per kind, each driven ------------------------------------------


async def test_capacity_refusal_is_recorded() -> None:
    source = _x12(max_connections=1)
    source._active = 1  # the one slot is taken
    assert _kinds(await _drive(source, _Eof(), _Peer())) == ["at_capacity"]
    assert source._active == 1  # a refused client never took a slot


async def test_a_clean_connection_is_recorded_as_established_then_closed() -> None:
    events = await _drive(_x12(), _Eof(), _Peer())
    assert _kinds(events) == ["established", "closed"]
    assert events[1][2] == "eof"


async def test_an_idle_connection_closes_with_the_idle_timeout_reason() -> None:
    events = await _drive(_x12(receive_timeout=0.05), _Silent(), _Peer())
    assert _kinds(events) == ["established", "closed"]
    assert events[1][2] == "idle_timeout", (
        "an idle drop and a clean hangup are the same kind; only `reason` separates them"
    )


async def test_an_over_cap_interchange_is_recorded_as_frame_oversize() -> None:
    # Reuses TcpSource's kind name deliberately: X12's frame IS the interchange, and inventing
    # `interchange_oversize` would red the documented-vocabulary guard, the console filter tuple
    # and the docs/PHI.md row together.
    events = await _drive(_x12(max_interchange_bytes=64), _OnceThenSilent(EDI), _Peer())
    assert _kinds(events) == ["established", "frame_oversize"]
    assert events[1][2], "the over-cap event must carry a redacted reason, not an empty one"


async def test_an_unexpected_handler_failure_is_recorded_as_framing_error() -> None:
    async def explode(raw: bytes) -> None:
        raise ValueError("synthetic handler failure")

    events = await _drive(_x12(), _OnceThenSilent(EDI), _Peer(), handler=explode)
    assert _kinds(events) == ["established", "framing_error"]


async def test_a_peer_reset_is_recorded_and_not_also_reported_as_a_clean_close() -> None:
    source = _x12()
    events = await _drive(source, _Reset(), _Peer())
    assert _kinds(events) == ["established", "peer_reset"], (
        "a failed connection must not ALSO emit `closed` -- an operator counting clean closes "
        "would over-count them"
    )
    assert source._active == 0  # the slot went back
