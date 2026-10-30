# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shape parameters for the connection-scale system-under-test graph (B11).

Loader skips ``_*`` modules, so this file is *imported* by :mod:`graph` rather than loaded as config.
It centralizes the ``MEFOR_CONNSCALE_*`` env knobs (mirroring ``harness/config/load/_shape.py``'s
pattern) so the N-inbound graph reads them in one place — no copy-paste across registered modules.

Serving ``harness/config/connscale`` reads the shape from ``MEFOR_CONNSCALE_COUNT=N`` (and the
matching sink env), so ONE graph file serves every N by env alone. That env route reaches the engine
process only: a ``[sandbox].mode = "subprocess"`` worker never receives a ``MEFOR_`` name, so the
connscale sweep runner writes each step's shape into a generated config directory instead, validated
by the same :func:`make_connscale_shape` (BACKLOG #3132). Each of the N
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
* ``MEFOR_CONNSCALE_NAME_PREFIX``— an OPTIONAL per-engine tag inserted into every connection name
  (default empty = byte-identical to the single-engine graph). The multi-ENGINE store-contention
  orchestrator (``harness multishard``) sets a distinct prefix per engine so that on ONE shared store
  the same-index lanes across engines get DISTINCT connection identities — FIFO lanes are keyed by
  connection name, so identical names would share rows (cross-engine claim/steal), confounding the
  disjoint-lane isolation the gate needs. Restricted to ``[A-Za-z0-9_]`` (safe in a connection name).

Everything is **synthetic and generic** — it models the *shape* of a high-connection-count estate
(N inbound feeds each with one trivial route+handler), never a real site.
"""

from __future__ import annotations

import os
import re
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

# A per-engine name prefix must be safe inside a connection name (no HL7 separators / no whitespace /
# nothing the loader or the registry would choke on). Empty is allowed (the single-engine default).
_NAME_PREFIX_RE = re.compile(r"^[A-Za-z0-9_]*$")


def _env_int(name: str) -> int | None:
    """Parse one integer knob, or ``None`` when it is unset. Parsing only: the bounds live once, in
    :func:`make_connscale_shape`, so the env route and the generated route cannot disagree."""
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class ConnScaleShape:
    """Resolved connection-scale graph parameters (read once from the environment at load time)."""

    count: int
    base_port: int
    sink_host: str
    sink_port: int
    sink_ports: int
    transform: str
    name_prefix: str = (
        ""  # per-engine tag inserted into every connection name (empty = single-engine)
    )

    def sink_endpoint(self, index: int) -> tuple[str, int]:
        """Round-robin a destination index across the contiguous sink port range (mirrors the load
        graph's ``sink_endpoint``)."""
        return self.sink_host, self.sink_port + (index % self.sink_ports)

    def conn_name(self, role: str, index: int) -> str:
        """The registry name for connection ``index`` of ``role`` (``IB``/``OB``/``R``/``H``).

        With an empty ``name_prefix`` this is byte-identical to the historical single-engine names
        (e.g. ``IB_CS_00000``); with a prefix ``E0`` it becomes ``IB_E0_CS_00000`` — DISTINCT per
        engine so the shared-store FIFO lanes stay disjoint (each engine claims only its own rows)."""
        tag = f"{self.name_prefix}_" if self.name_prefix else ""
        return f"{role}_{tag}CS_{index:05d}"


def make_connscale_shape(
    *,
    count: int = 50,
    base_port: int = 2600,
    sink_host: str = "127.0.0.1",
    sink_port: int = 2700,
    sink_ports: int = 1,
    transform: str = CHEAP,
    name_prefix: str = "",
) -> ConnScaleShape:
    """Validate the knobs and build a :class:`ConnScaleShape`. The ONE validation both routes share:
    the env route (:func:`load_connscale_shape`) and the generated per-step config directory the
    connscale runner writes (``harness.load.connscale.stepconfig``, BACKLOG #3132), so a shape that
    one route refuses the other refuses too."""
    if transform not in _TRANSFORMS:
        raise ValueError(
            f"MEFOR_CONNSCALE_TRANSFORM must be one of {sorted(_TRANSFORMS)}, got {transform!r}"
        )
    _bounded("MEFOR_CONNSCALE_COUNT", count, minimum=_MIN_COUNT, maximum=_MAX_COUNT)
    _bounded("MEFOR_CONNSCALE_BASE_PORT", base_port, minimum=1, maximum=_MAX_PORT)
    _bounded("MEFOR_CONNSCALE_SINK_PORT", sink_port, minimum=1, maximum=_MAX_PORT)
    _bounded("MEFOR_CONNSCALE_SINK_PORTS", sink_ports, minimum=1, maximum=4096)
    if not _NAME_PREFIX_RE.match(name_prefix):
        raise ValueError(
            f"MEFOR_CONNSCALE_NAME_PREFIX must match [A-Za-z0-9_]* (safe in a connection name), "
            f"got {name_prefix!r}"
        )
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
        sink_host=sink_host or "127.0.0.1",
        sink_port=sink_port,
        sink_ports=sink_ports,
        transform=transform,
        name_prefix=name_prefix,
    )


def _bounded(name: str, value: int, *, minimum: int, maximum: int) -> None:
    # bool is an int; a True count is a typo, not 1.
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer, got {value!r}")
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    if value > maximum:
        raise ValueError(f"{name} must be <= {maximum}, got {value}")


def load_connscale_shape() -> ConnScaleShape:
    """The shape the ``MEFOR_CONNSCALE_*`` environment names. The env route reaches the engine only:
    a ``[sandbox].mode = "subprocess"`` worker's environment is an allowlist that never carries a
    ``MEFOR_`` name, so a worker that ran this would build the default shape (BACKLOG #3132). The
    connscale runner therefore writes the shape into a generated config directory instead."""
    # Only what is set is passed, so each default lives once, in make_connscale_shape's signature.
    knobs: dict[str, int | str] = {}
    for key, name in (
        ("count", "MEFOR_CONNSCALE_COUNT"),
        ("base_port", "MEFOR_CONNSCALE_BASE_PORT"),
        ("sink_port", "MEFOR_CONNSCALE_SINK_PORT"),
        ("sink_ports", "MEFOR_CONNSCALE_SINK_PORTS"),
    ):
        value = _env_int(name)
        if value is not None:
            knobs[key] = value
    for key, name in (
        ("sink_host", "MEFOR_CONNSCALE_SINK_HOST"),
        ("transform", "MEFOR_CONNSCALE_TRANSFORM"),
        ("name_prefix", "MEFOR_CONNSCALE_NAME_PREFIX"),
    ):
        text = os.environ.get(name, "").strip()
        if text:
            knobs[key] = text.lower() if key == "transform" else text
    return make_connscale_shape(**knobs)  # type: ignore[arg-type]
