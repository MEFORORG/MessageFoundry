# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shape parameters for the connection-scale system-under-test graph (B11).

Loader skips ``_*`` modules, so this file is *imported* by :mod:`graph` rather than loaded as config.
It centralizes the ``MEFOR_CONNSCALE_*`` env knobs (mirroring ``harness/config/load/_shape.py``'s
pattern) so the N-inbound graph reads them in one place — no copy-paste across registered modules.

The connection-scale harness sets ``MEFOR_CONNSCALE_COUNT=N`` (and the matching sink env) in the
engine subprocess environment **before each sweep step**, so ONE graph file serves every N (500 /
1000 / 1500 — or the CI smoke's 50 / 100) by env alone, with no per-N file generation. Each of the N
inbounds points at a trivial router → trivial handler → one outbound to the correlation sink, so the
measured cost is the engine's *per-connection machinery* (workers, wake events, pool, executor hops),
not transform CPU.

Knobs (all optional, with safe CI-small defaults so ``serve`` works with none set):

* ``MEFOR_CONNSCALE_COUNT``      — number of inbound MLLP connections to declare (default 50, CI-safe).
* ``MEFOR_CONNSCALE_BASE_PORT``  — first inbound MLLP port; conn ``i`` binds ``base_port + i`` (default 2600).
* ``MEFOR_CONNSCALE_SINK_HOST``  — sink host every destination delivers to (default 127.0.0.1).
* ``MEFOR_CONNSCALE_SINK_PORT``  — base sink port (default 2700).
* ``MEFOR_CONNSCALE_SINK_PORTS`` — contiguous sink ports to round-robin across (default 1).
* ``MEFOR_CONNSCALE_TRANSFORM``  — ``cheap`` | ``edit`` (default ``cheap`` — pass-through, cheapest graph).

Everything is **synthetic and generic** — it models the *shape* of a high-connection-count estate
(N inbound feeds each with one trivial route+handler), never a real site.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Transform cost modes (a subset of the load graph's — connscale only needs cheapest + a representative
# whole-field rewrite, never the CPU-spin SLOW mode; the wall here is per-connection machinery, not CPU).
CHEAP = "cheap"  # pass-through: deliver the receipt unchanged (the cheapest possible graph)
EDIT = "edit"  # representative whole-field rewrites via the Message model (optional realism)
_TRANSFORMS = frozenset({CHEAP, EDIT})

# Guard rails so a misconfigured sweep fails loud (in _shape, before any listener binds) rather than
# colliding the inbound port block with the sink ports or running off the top of the port space.
_MAX_PORT = 65535
_MIN_COUNT = 1
_MAX_COUNT = 5000  # generous headroom over the 1500 ceiling; a typo of 50000 fails loud


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


@dataclass(frozen=True)
class ConnScaleShape:
    """Resolved connection-scale graph parameters (read once from the environment at load time)."""

    count: int
    base_port: int
    sink_host: str
    sink_port: int
    sink_ports: int
    transform: str

    def sink_endpoint(self, index: int) -> tuple[str, int]:
        """Round-robin a destination index across the contiguous sink port range (mirrors the load
        graph's ``sink_endpoint``)."""
        return self.sink_host, self.sink_port + (index % self.sink_ports)


def load_connscale_shape() -> ConnScaleShape:
    transform = os.environ.get("MEFOR_CONNSCALE_TRANSFORM", CHEAP).strip().lower() or CHEAP
    if transform not in _TRANSFORMS:
        raise ValueError(
            f"MEFOR_CONNSCALE_TRANSFORM must be one of {sorted(_TRANSFORMS)}, got {transform!r}"
        )
    count = _env_int("MEFOR_CONNSCALE_COUNT", 50, minimum=_MIN_COUNT, maximum=_MAX_COUNT)
    base_port = _env_int("MEFOR_CONNSCALE_BASE_PORT", 2600, minimum=1, maximum=_MAX_PORT)
    sink_port = _env_int("MEFOR_CONNSCALE_SINK_PORT", 2700, minimum=1, maximum=_MAX_PORT)
    sink_ports = _env_int("MEFOR_CONNSCALE_SINK_PORTS", 1, minimum=1, maximum=4096)
    # The N inbound ports occupy [base_port, base_port + count). Validate the block stays inside the
    # port space and does NOT overlap the sink port range — a collision would have an inbound listener
    # and the correlation sink fight for the same port, surfacing as a bind error deep in startup.
    inbound_hi = base_port + count - 1
    if inbound_hi > _MAX_PORT:
        raise ValueError(
            f"MEFOR_CONNSCALE_BASE_PORT={base_port} + COUNT={count} runs past port {_MAX_PORT} "
            f"(highest inbound port would be {inbound_hi})"
        )
    sink_lo, sink_hi = sink_port, sink_port + sink_ports - 1
    if base_port <= sink_hi and sink_lo <= inbound_hi:
        raise ValueError(
            f"inbound port block [{base_port}, {inbound_hi}] overlaps the sink port range "
            f"[{sink_lo}, {sink_hi}] — move MEFOR_CONNSCALE_BASE_PORT or MEFOR_CONNSCALE_SINK_PORT apart"
        )
    return ConnScaleShape(
        count=count,
        base_port=base_port,
        sink_host=os.environ.get("MEFOR_CONNSCALE_SINK_HOST", "127.0.0.1") or "127.0.0.1",
        sink_port=sink_port,
        sink_ports=sink_ports,
        transform=transform,
    )
