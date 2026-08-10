# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Contiguous port-block reservation for the connection-scale suites (BACKLOG #1014, #1103).

A connscale run consumes THREE port families, and every one of them is a contiguous RANGE that the
engine or the sink derives by increment from a base:

* **inbound** -- the engine binds ``base_port + i`` for each of the N connections;
* **API** -- the runner binds ``engine_api_port_base + step`` for each sweep step, and
  :func:`harness.load.connscale.runner.sweep_step_count` is the one definition of how many that is;
* **sink** -- the correlation sink binds ``sink_port + i`` for each of ``sink_ports``.

#1014 gave the INBOUND family a real reservation: probe a contiguous run of the required width,
anchor it at random so concurrent worktrees de-correlate, assert contiguity at the acquisition site,
and fail loudly rather than fall back to a fixed block. #1103 is the same defect one family over --
the API and sink bases were each drawn from a single ``bind(("127.0.0.1", 0))`` probe that was closed
before it returned, so exactly ONE port of each range was ever verified and every port after the base
was assumed. This module is the single definition all three families now share.

**Why fixed windows rather than kernel-assigned ephemeral ports.** A verified-then-released ephemeral
port is worth very little: the kernel hands out ports from that same range to unrelated sockets, so a
port probed at T can be taken at T+1 by something that had nothing to do with this suite. Every window
below therefore sits BELOW the OS ephemeral floors (Linux 32768; Windows/macOS 49152) and ABOVE the
sibling fixed-port MLLP band (11xxx-19xxx) -- the kernel will not hand one out, and no sibling test's
fixed listener is already sitting in one. That is the reasoning #1014 wrote for the inbound window;
the API and sink families now inherit it instead of contradicting it.

**The windows are disjoint**, so one family's block can never overlap another's -- the hazard the old
arrangement dodged only by keeping the API and sink ports numerically far above the inbound block.

Measured 2026-08-10 over ``tests/``, ``harness/``, ``samples/``, ``packaging/``, ``messagefoundry/``,
``ide/``, ``scripts/`` and ``.github/``: the band [20000, 32700) carries no fixed port bind anywhere in
the tree. The only literals in [30000, 32768) are a fake PID, a millisecond timeout, a LOINC code and
a GitHub issue number -- none of them ports.
"""

from __future__ import annotations

import random
import socket

from harness.load.connscale.profile import ConnScaleProfile
from harness.load.connscale.runner import sweep_step_count

# The three family windows. Upper bounds are EXCLUSIVE and every one of them is below 32768, the
# lowest OS ephemeral floor. See the module docstring for why the band was chosen and how it was
# measured; the disjointness is asserted by tests/test_connscale_ports.py rather than assumed.
INBOUND_PORT_LO = 20000
INBOUND_PORT_HI = 30000
API_PORT_LO = 30000
API_PORT_HI = 31000
SINK_PORT_LO = 31000
SINK_PORT_HI = 31700


def reserve_contiguous_ports(n: int, *, lo: int, hi: int, tries: int = 200) -> list[int]:
    """Reserve ``n`` contiguous free ports in ``[lo, hi)``, anchored at a RANDOM base.

    Every one of the ``n`` ports is bound before the block is accepted, so the returned range is
    verified in full rather than extrapolated from its base (BACKLOG #1103). The random anchor is
    #1014's concurrency fix: it de-correlates worktrees so two suites rarely pick overlapping blocks.
    Probe/bind-and-release only holds the block momentarily, so it cannot truly reserve it against a
    concurrent engine -- the random anchor over a wide window is the real defense, and a genuine
    collision surfaces as a RED rather than a masked retry.

    Raises ``RuntimeError`` if the window cannot hold ``n`` ports at all, or if no free block was
    found in ``tries`` attempts. It NEVER falls back to a fixed base.
    """
    if n < 1:
        raise ValueError(f"n must be >= 1, got {n}")
    # The last anchor that still leaves n ports inside the window is hi - n, so the window is
    # unsatisfiable only when that falls BELOW lo. #1014's inherited form of this guard tested
    # `hi - n <= lo`, which also rejected a window sized to hold the block EXACTLY -- satisfiable
    # with the single anchor lo. That off-by-one had no effect on the shipped windows (all far wider
    # than the blocks drawn from them) but it turned an exact fit into a fail-loud, and it reported
    # the "too narrow" message for a window that was not.
    if hi - n < lo:
        raise RuntimeError(
            f"cannot reserve {n} contiguous ports in [{lo},{hi}): the window holds {hi - lo}"
        )
    # The port that blocked the most recent attempt, carried into the failure message. A run that
    # exhausts its tries should name a port an operator can look up, not just a window -- the
    # diagnostic that was missing when this class last fired in CI (#1103: `WinError 10013` reads as
    # a permissions fault and names nothing).
    blocked: tuple[int, OSError] | None = None
    for _ in range(tries):
        base = random.randint(lo, hi - n)
        socks: list[socket.socket] = []
        try:
            for i in range(n):
                s = socket.socket()
                # No SO_REUSEADDR on purpose: honest free-detection. A live listener must make
                # bind FAIL here, unlike SO_REUSEADDR's Windows steal semantics. The block is
                # released before the engine binds, so REUSEADDR would only add false-frees.
                try:
                    s.bind(("127.0.0.1", base + i))
                except OSError as exc:
                    s.close()
                    blocked = (base + i, exc)
                    break
                socks.append(s)
            if len(socks) == n:
                return list(range(base, base + n))
        finally:
            for sock in socks:
                sock.close()
    detail = f"; last blocked on port {blocked[0]} ({blocked[1]})" if blocked is not None else ""
    raise RuntimeError(
        f"could not reserve {n} contiguous free ports in [{lo},{hi}) after {tries} tries{detail}"
    )


def require_contiguous(ports: list[int], n: int, family: str) -> int:
    """Check ``ports`` is exactly ``n`` ascending contiguous ports and return its base.

    This is the acquisition-site guard #1103 asks for, stated once for all three families: it is not
    enough that the allocator returned SOMETHING, the caller has to know the whole range it is about
    to hand to a process that will bind every port in it.
    """
    if not ports or ports != list(range(ports[0], ports[0] + n)):
        raise RuntimeError(
            f"{family} port block is not {n} contiguous ports: {ports} (BACKLOG #1103)"
        )
    return ports[0]


def reserve_api_and_sink_bases(
    profile: ConnScaleProfile, *, sink_ports: int = 1
) -> tuple[int, int]:
    """Reserve the API and sink RANGES a ``profile`` sweep will consume; return their two bases.

    The runner binds ``api_base + step`` for every one of :func:`sweep_step_count` sweep steps and the
    sink binds ``sink_base + i`` for every one of ``sink_ports``, so both ranges are reserved and
    verified in full here -- not just their bases (BACKLOG #1103). The two windows are disjoint, which
    is what retires the old ordering trick (draw the sink first so the API block increments away from
    it): that trick was correct only while both bases came from back-to-back ephemeral draws, an
    assumption about allocator behaviour rather than a checked property.
    """
    n_api = sweep_step_count(profile)
    api = reserve_contiguous_ports(n_api, lo=API_PORT_LO, hi=API_PORT_HI)
    sink = reserve_contiguous_ports(sink_ports, lo=SINK_PORT_LO, hi=SINK_PORT_HI)
    return (
        require_contiguous(api, n_api, "API"),
        require_contiguous(sink, sink_ports, "sink"),
    )
