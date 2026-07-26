# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shape parameters + the topology math for the estate-shape system-under-test graph (#216).

Loader skips ``_*`` modules, so this file is *imported* by :mod:`graph` rather than loaded as config.
It is the ONE authority on the estate topology: given a connection count and a "simple fraction" it
decides, deterministically, which connection indices are *simple* (1 inbound → 1 outbound, 2 events per
message) and which are *hubs* (1 inbound → ``hub_fanout`` outbounds, ``1 + hub_fanout`` events per
message). Both the code-first graph HERE and the load-side driver
(:mod:`harness.load.estate.driver`) import :func:`hub_flags` / :func:`events_per_msg`, so the graph the
engine serves and the per-connection rate the driver calibrates derive from the SAME assignment — the
driver never has to guess the served fan-out.

The assignment is **contiguous and reproducible**: indices ``[0, n_simple)`` are simple, the rest are
hubs. Contiguous (rather than a seeded shuffle) so the graph process and the driver process agree on
the class of every index WITHOUT sharing a random seed across a process boundary — the topology is a
pure function of ``(count, simple_fraction)`` alone.

Knobs (all optional, with CI-small defaults so ``serve`` works with none set):

* ``MEFOR_ESTATE_COUNT``           — number of inbound MLLP connections to declare (default 60, CI-safe).
* ``MEFOR_ESTATE_SIMPLE_FRACTION`` — fraction of connections that are simple pass-through (default 0.72).
* ``MEFOR_ESTATE_HUB_FANOUT``      — outbound destinations each HUB connection fans to (default 3).
* ``MEFOR_ESTATE_BASE_PORT``       — first inbound MLLP port; conn ``i`` binds ``base_port + i`` (default 2600).
* ``MEFOR_ESTATE_SINK_HOST``       — sink host every destination delivers to (default 127.0.0.1).
* ``MEFOR_ESTATE_SINK_PORT``       — base sink port (default 2700).
* ``MEFOR_ESTATE_SINK_PORTS``      — contiguous sink ports to round-robin destinations across (default 1).
* ``MEFOR_ESTATE_TRANSFORM``       — ``cheap`` | ``edit`` (default ``cheap`` — pass-through, cheapest graph).

Everything is **synthetic and generic** — it models the *shape* of a mixed estate, never a real site.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Transform cost modes (mirrors connscale): cheapest pass-through + an optional whole-field rewrite.
CHEAP = "cheap"  # pass-through: deliver the receipt unchanged (the cheapest possible graph)
EDIT = "edit"  # representative whole-field rewrites via the Message model (optional realism)
_TRANSFORMS = frozenset({CHEAP, EDIT})

# Guard rails so a misconfigured run fails loud (in _shape, before any listener binds).
_MAX_PORT = 65535
_MIN_COUNT = 1
_MAX_COUNT = 5000  # generous headroom over the 1500 ceiling; a typo of 50000 fails loud
_MAX_FANOUT = 256  # a hub fanning to hundreds of outbounds is already far past any real estate


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    if value > maximum:
        raise ValueError(f"{name} must be <= {maximum}, got {value}")
    return value


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be within [{minimum}, {maximum}], got {value}")
    return value


def simple_count(count: int, simple_fraction: float) -> int:
    """How many of ``count`` connections are simple (the rest are hubs). ``round`` to the nearest,
    clamped to ``[0, count]`` so a fraction of exactly 0.0/1.0 yields all-hub / all-simple. This is the
    SINGLE definition the graph and the driver both derive from."""
    if not 0.0 <= simple_fraction <= 1.0:
        raise ValueError(f"simple_fraction must be within [0, 1], got {simple_fraction}")
    n = round(count * simple_fraction)
    return max(0, min(count, n))


def hub_flags(count: int, simple_fraction: float) -> tuple[bool, ...]:
    """Per-index class assignment: ``True`` at index ``i`` iff connection ``i`` is a HUB. Indices
    ``[0, n_simple)`` are simple (``False``), the rest hubs — contiguous + reproducible so the graph
    process and the driver process agree without sharing a seed."""
    n_simple = simple_count(count, simple_fraction)
    return tuple(i >= n_simple for i in range(count))


def events_per_msg(is_hub: bool, hub_fanout: int) -> int:
    """Pipeline events a single received message produces on this connection: 1 inbound read + the
    outbound deliveries. A simple connection delivers to 1 destination (``2`` events); a hub delivers to
    ``hub_fanout`` (``1 + hub_fanout`` events). Events count in + out — the 45M/day yardstick semantics."""
    return (1 + hub_fanout) if is_hub else 2


@dataclass(frozen=True)
class EstateShape:
    """Resolved estate-graph parameters (read once from the environment at load time)."""

    count: int
    simple_fraction: float
    hub_fanout: int
    base_port: int
    sink_host: str
    sink_port: int
    sink_ports: int
    transform: str

    def hub_flags(self) -> tuple[bool, ...]:
        return hub_flags(self.count, self.simple_fraction)

    def sink_endpoint(self, index: int) -> tuple[str, int]:
        """Round-robin a destination index across the contiguous sink port range."""
        return self.sink_host, self.sink_port + (index % self.sink_ports)

    def conn_name(self, role: str, index: int, sub: int | None = None) -> str:
        """The registry name for connection ``index`` of ``role`` (``IB``/``R``/``H``), or one of a
        hub's fan-out outbounds when ``sub`` is given (``OB_00007_02``). A simple connection's single
        outbound uses ``sub=0``."""
        if sub is None:
            return f"{role}_ES_{index:05d}"
        return f"{role}_ES_{index:05d}_{sub:02d}"


def load_estate_shape() -> EstateShape:
    transform = os.environ.get("MEFOR_ESTATE_TRANSFORM", CHEAP).strip().lower() or CHEAP
    if transform not in _TRANSFORMS:
        raise ValueError(
            f"MEFOR_ESTATE_TRANSFORM must be one of {sorted(_TRANSFORMS)}, got {transform!r}"
        )
    count = _env_int("MEFOR_ESTATE_COUNT", 60, minimum=_MIN_COUNT, maximum=_MAX_COUNT)
    simple_fraction = _env_float("MEFOR_ESTATE_SIMPLE_FRACTION", 0.72, minimum=0.0, maximum=1.0)
    hub_fanout = _env_int("MEFOR_ESTATE_HUB_FANOUT", 3, minimum=1, maximum=_MAX_FANOUT)
    base_port = _env_int("MEFOR_ESTATE_BASE_PORT", 2600, minimum=1, maximum=_MAX_PORT)
    sink_port = _env_int("MEFOR_ESTATE_SINK_PORT", 2700, minimum=1, maximum=_MAX_PORT)
    sink_ports = _env_int("MEFOR_ESTATE_SINK_PORTS", 1, minimum=1, maximum=4096)
    # The N inbound ports occupy [base_port, base_port + count). Validate the block stays inside the
    # port space and does NOT overlap the sink port range — a collision would fight an inbound listener
    # and the correlation sink for the same port (a bind error deep in startup).
    inbound_hi = base_port + count - 1
    if inbound_hi > _MAX_PORT:
        raise ValueError(
            f"MEFOR_ESTATE_BASE_PORT={base_port} + COUNT={count} runs past port {_MAX_PORT} "
            f"(highest inbound port would be {inbound_hi})"
        )
    sink_lo, sink_hi = sink_port, sink_port + sink_ports - 1
    if base_port <= sink_hi and sink_lo <= inbound_hi:
        raise ValueError(
            f"inbound port block [{base_port}, {inbound_hi}] overlaps the sink port range "
            f"[{sink_lo}, {sink_hi}] — move MEFOR_ESTATE_BASE_PORT or MEFOR_ESTATE_SINK_PORT apart"
        )
    return EstateShape(
        count=count,
        simple_fraction=simple_fraction,
        hub_fanout=hub_fanout,
        base_port=base_port,
        sink_host=os.environ.get("MEFOR_ESTATE_SINK_HOST", "127.0.0.1") or "127.0.0.1",
        sink_port=sink_port,
        sink_ports=sink_ports,
        transform=transform,
    )
