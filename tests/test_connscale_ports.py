# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guards for the connscale port families (BACKLOG #1014, #1103).

#1103's test requirement, stated in the item: *"A test that probes one port and asserts it binds
cannot see this. The guard has to assert that EVERY port the sweep will use was reserved."* That is
what this module checks, in three layers:

1. the allocator really binds every port it hands back -- proved with a LIVE occupied port, so the
   check is not blind (an allocator that returned the range without probing would pass a
   probe-nothing test happily);
2. the API range the caller reserves is exactly the set of ports the runner then binds, driven
   through the real ``run_connscale`` loop with a stubbed step;
3. the runner refuses to step past the range it told the caller to reserve.
"""

from __future__ import annotations

import contextlib
import socket
from collections.abc import Iterator
from typing import Any

import pytest

import harness.load.connscale.runner as runner_mod
from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.runner import ConnScaleError, run_connscale, sweep_step_count
from tests._connscale_ports import (
    API_PORT_HI,
    API_PORT_LO,
    INBOUND_PORT_HI,
    INBOUND_PORT_LO,
    SINK_PORT_HI,
    SINK_PORT_LO,
    require_contiguous,
    reserve_api_and_sink_bases,
    reserve_contiguous_ports,
)

# Every family window must sit below the LOWEST OS ephemeral floor, or a kernel-assigned port can
# land inside a block after it was probed and the reservation means nothing (Linux defaults to
# 32768-60999; Windows and macOS start at 49152).
_LOWEST_EPHEMERAL_FLOOR = 32768

_WINDOWS = (
    ("inbound", INBOUND_PORT_LO, INBOUND_PORT_HI),
    ("api", API_PORT_LO, API_PORT_HI),
    ("sink", SINK_PORT_LO, SINK_PORT_HI),
)


@contextlib.contextmanager
def _occupy(port: int) -> Iterator[socket.socket]:
    """Hold ``port`` with a real LISTENING socket for the duration of the block."""
    s = socket.socket()
    # No SO_REUSEADDR: the occupier must genuinely deny the port to a second binder, which is the
    # whole point of using it as a positive control.
    s.bind(("127.0.0.1", port))
    s.listen(1)
    try:
        yield s
    finally:
        s.close()


def test_family_windows_are_disjoint_and_below_the_ephemeral_floor() -> None:
    # The three windows are carved out of one band and must not overlap: an API block landing inside
    # the inbound block would collide with the engine's own listeners.
    for name, lo, hi in _WINDOWS:
        assert lo < hi, (name, lo, hi)
        assert hi <= _LOWEST_EPHEMERAL_FLOOR, (name, hi)
    spans = sorted((lo, hi, name) for name, lo, hi in _WINDOWS)
    for (lo_a, hi_a, name_a), (lo_b, hi_b, name_b) in zip(spans, spans[1:], strict=False):
        assert hi_a <= lo_b, (name_a, (lo_a, hi_a), name_b, (lo_b, hi_b))


def test_reserved_block_is_contiguous_and_inside_its_window() -> None:
    ports = reserve_contiguous_ports(8, lo=API_PORT_LO, hi=API_PORT_HI)
    assert ports == list(range(ports[0], ports[0] + 8))
    assert ports[0] >= API_PORT_LO
    assert ports[-1] < API_PORT_HI


def test_allocator_binds_every_port_it_returns_not_just_the_base() -> None:
    # THE #1103 GUARD, with a live positive control. Occupy one port, then squeeze the window down to
    # a band so narrow that every candidate block must contain it: a base-only allocator (the
    # defect) would still hand back a range, and this must instead fail loudly. The occupied port is
    # NOT the base of every candidate block -- with n=4 in a 5-wide window the occupier sits at
    # offset 1 or 2 depending on the anchor -- so passing this genuinely requires probing past the
    # base.
    block = reserve_contiguous_ports(5, lo=API_PORT_LO, hi=API_PORT_HI)
    victim = block[2]
    lo, hi = block[0], block[0] + 5
    with _occupy(victim):
        with pytest.raises(RuntimeError, match="could not reserve") as exc:
            reserve_contiguous_ports(4, lo=lo, hi=hi, tries=50)
        # The message names the PORT, not merely the window. #1103's cost was a failure whose text
        # ("access forbidden", WinError 10013) pointed away from port allocation entirely.
        assert str(victim) in str(exc.value), str(exc.value)
    # ... and with the occupier released the very same call succeeds: the guard tracks the live
    # state of the port, it is not just permanently red on a narrow window.
    reopened = reserve_contiguous_ports(4, lo=lo, hi=hi, tries=50)
    assert len(reopened) == 4
    assert reopened[0] >= lo and reopened[-1] < hi


def test_allocator_dodges_an_occupied_port_when_the_window_has_room() -> None:
    # The complement of the test above: given room to move, the allocator must RELOCATE around a
    # live port rather than fail. The window is sized so the dodge is forced and observable -- 7
    # ports, blocks of 4, so the candidate anchors are lo+0..lo+3 and the victim at lo+1 sits inside
    # two of them. Against a base-only allocator (the #1103 defect) anchor lo+1 is still rejected
    # (its BASE is the victim) but anchor lo is accepted with the victim unchecked inside it, so each
    # iteration catches the defect with probability 1/3 and 25 of them leave a ~1-in-26,000 chance of
    # passing by luck. Sizing matters: the first draft of this test used the full 700-port window,
    # where the victim is rare enough that the base-only mutation sailed through it green.
    block = reserve_contiguous_ports(7, lo=SINK_PORT_LO, hi=SINK_PORT_HI)
    lo, hi = block[0], block[0] + 7
    victim = lo + 1
    with _occupy(victim):
        for _ in range(25):
            ports = reserve_contiguous_ports(4, lo=lo, hi=hi, tries=50)
            assert victim not in ports, (victim, ports)
            assert ports[0] in (lo + 2, lo + 3), (lo, ports)  # the only anchors that clear it


def test_allocator_fails_loud_when_unsatisfiable() -> None:
    # tries=0 hits the post-loop exhaustion branch deterministically (without occupying the whole
    # window) and must raise -- never fall back silently to a fixed port (BACKLOG #1014).
    with pytest.raises(RuntimeError, match="could not reserve"):
        reserve_contiguous_ports(8, lo=API_PORT_LO, hi=API_PORT_HI, tries=0)


def test_allocator_fails_loud_when_window_too_narrow() -> None:
    # The width guard fires BEFORE any probing when the requested block cannot fit the window at all:
    # asking for one more port than the window holds can never be satisfied, so it raises up front
    # rather than looping (BACKLOG #1014 -- fail loud, never a silent fallback).
    with pytest.raises(RuntimeError, match="cannot reserve"):
        reserve_contiguous_ports(API_PORT_HI - API_PORT_LO + 1, lo=API_PORT_LO, hi=API_PORT_HI)


def test_allocator_accepts_a_window_sized_to_hold_the_block_exactly() -> None:
    # The boundary the width guard used to get wrong: a window of exactly n ports HAS one valid
    # anchor (lo) and must be reserved, not rejected as too narrow. Found by driving the real smoke
    # run against a window narrowed to its own block -- the run failed with "cannot reserve", a
    # message about window size, when the actual condition was an occupied port.
    block = reserve_contiguous_ports(4, lo=SINK_PORT_LO, hi=SINK_PORT_HI)
    lo = block[0]
    exact = reserve_contiguous_ports(4, lo=lo, hi=lo + 4)
    assert exact == [lo, lo + 1, lo + 2, lo + 3]
    # One port narrower is genuinely unsatisfiable and still fails loud.
    with pytest.raises(RuntimeError, match="cannot reserve"):
        reserve_contiguous_ports(4, lo=lo, hi=lo + 3)


def test_require_contiguous_rejects_a_gapped_block() -> None:
    # The acquisition-site assertion has to be able to say no. A gapped block means some port in the
    # range was never reserved, which is exactly the state #1103 shipped in.
    assert require_contiguous([30010, 30011, 30012], 3, "API") == 30010
    with pytest.raises(RuntimeError, match="not 3 contiguous ports"):
        require_contiguous([30010, 30011, 30013], 3, "API")
    with pytest.raises(RuntimeError, match="not 1 contiguous ports"):
        require_contiguous([], 1, "sink")


def _stub_steps(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record the api_port of every step, without spawning an engine."""
    seen: list[int] = []

    async def _stub(_profile: object, *, api_port: int, **_kw: Any) -> object:
        seen.append(api_port)
        return object()

    monkeypatch.setattr(runner_mod, "_run_one_step", _stub)
    monkeypatch.setattr(runner_mod, "_evaluate_slos", lambda *_a, **_kw: [])
    monkeypatch.setattr(runner_mod, "build_comparison", lambda *_a, **_kw: None)
    monkeypatch.setattr(runner_mod, "build_fuse_comparison", lambda *_a, **_kw: None)
    monkeypatch.setattr(runner_mod, "build_batch_comparison", lambda *_a, **_kw: None)
    return seen


_MULTI_ARM = """
[connscale]
name = "port-width"
counts = [256, 512]
aggregate_rate = 400.0
sweep_mode = "both"
claim_modes = ["pooled"]
fuse_modes = [false, true]
trials = 3
"""


async def test_reserved_api_range_covers_every_port_the_sweep_binds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # THE ITEM'S CENTRAL CLAIM, driven through the real loop: reserve sweep_step_count(profile)
    # ports, run the sweep, and require the set of ports it actually bound to be EXACTLY the
    # reserved range -- no port outside it, and none of the range left over. A single-probe caller
    # (the shipped defect) reserves 1 and binds 24 here, so this test is red against it.
    profile = load_connscale_profile_text(_MULTI_ARM)
    seen = _stub_steps(monkeypatch)
    width = sweep_step_count(profile)
    assert width == 1 * 2 * 1 * 2 * 2 * 3, width  # claim × fuse × batch × mode × count × trials

    api_base, sink_base = reserve_api_and_sink_bases(profile, sink_ports=2)
    reserved = list(range(api_base, api_base + width))
    await run_connscale(profile, engine_api_port_base=api_base, sink_port=sink_base)

    assert sorted(seen) == reserved, (sorted(seen), reserved)
    assert reserved[0] >= API_PORT_LO and reserved[-1] < API_PORT_HI
    assert sink_base >= SINK_PORT_LO and sink_base + 1 < SINK_PORT_HI


async def test_runner_refuses_to_bind_past_the_range_it_asked_the_caller_to_reserve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # FAIL-ON-PURPOSE for the runner's own cardinality guard. Understating sweep_step_count is the
    # exact drift the guard exists to catch -- it is what a new sweep axis would do -- and the run
    # must stop with a message naming the unreserved port rather than binding it.
    profile = load_connscale_profile_text(_MULTI_ARM)
    _stub_steps(monkeypatch)
    monkeypatch.setattr(runner_mod, "sweep_step_count", lambda _p: 3)

    with pytest.raises(ConnScaleError) as exc:
        await run_connscale(profile, engine_api_port_base=30500, sink_port=31500)
    assert "30503" in str(exc.value), str(exc.value)  # base + 3, the first unreserved port
    assert "#1103" in str(exc.value)
