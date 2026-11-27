# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shape parameters and wiring for the connection-scale system-under-test graph (B11).

Loader skips ``_*`` modules, so this file is *imported* by :mod:`graph` rather than loaded as config.
It centralizes the ``MEFOR_CONNSCALE_*`` env knobs (mirroring ``harness/config/load/_shape.py``'s
pattern) so the N-inbound graph reads them in one place — no copy-paste across registered modules.

It is imported two ways, so it imports nothing from the ``harness`` package. ``graph.py`` imports it
as the bare sibling helper ``_shape``, which the config loader serves from this directory, so
``serve --config harness/config/connscale`` works with only the engine installed (BACKLOG #5852).
The connscale runner, its tests, and the module the runner generates per sweep step import it as
``harness.config.connscale._shape``. :func:`wire_graph` lives here rather than in a second helper
for the same reason: a second helper would have to name this one, bare under the loader and
package-qualified everywhere else, and one import cannot be both.

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
import sys
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps

from messagefoundry import MLLP, Send, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.wiring import HandlerFn, RouterFn
from messagefoundry.parsing.message import Message, RawMessage

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


# A copy of harness/config/_refusal.py, because this file is served to its graph as a bare sibling
# helper and must not need the harness package (BACKLOG #5852).
# tests/test_harness_graph_engine_only.py holds the two equal.
def prints_its_refusal[R](read_shape: Callable[[], R]) -> Callable[[], R]:
    """Wrap ``read_shape`` so a ``ValueError`` it raises is printed to stderr, then raised as is."""

    @wraps(read_shape)
    def reading() -> R:
        try:
            return read_shape()
        except ValueError as exc:
            print(f"harness shape refused: {exc}", file=sys.stderr, flush=True)
            raise

    return reading


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
    # Each refusal names the knob both ways: the profile/CLI name the sweep runner sets, and the
    # MEFOR_CONNSCALE_* variable the env route reads.
    if transform not in _TRANSFORMS:
        raise ValueError(
            f"transform (MEFOR_CONNSCALE_TRANSFORM) must be one of {sorted(_TRANSFORMS)}, "
            f"got {transform!r}"
        )
    _bounded("count (MEFOR_CONNSCALE_COUNT)", count, minimum=_MIN_COUNT, maximum=_MAX_COUNT)
    _bounded("base_port (MEFOR_CONNSCALE_BASE_PORT)", base_port, minimum=1, maximum=_MAX_PORT)
    _bounded("sink port (MEFOR_CONNSCALE_SINK_PORT)", sink_port, minimum=1, maximum=_MAX_PORT)
    _bounded("sink ports (MEFOR_CONNSCALE_SINK_PORTS)", sink_ports, minimum=1, maximum=4096)
    if not _NAME_PREFIX_RE.match(name_prefix):
        raise ValueError(
            f"name prefix (MEFOR_CONNSCALE_NAME_PREFIX) must match [A-Za-z0-9_]* (safe in a "
            f"connection name), got {name_prefix!r}"
        )
    # The N inbound ports occupy [base_port, base_port + count). Validate the block stays inside the
    # port space and does NOT overlap the sink port range — a collision would have an inbound listener
    # and the correlation sink fight for the same port, surfacing as a bind error deep in startup.
    inbound_hi = base_port + count - 1
    if inbound_hi > _MAX_PORT:
        raise ValueError(
            f"base_port {base_port} + count {count} runs past port {_MAX_PORT} "
            f"(highest inbound port would be {inbound_hi})"
        )
    sink_lo, sink_hi = sink_port, sink_port + sink_ports - 1
    if base_port <= sink_hi and sink_lo <= inbound_hi:
        raise ValueError(
            f"inbound port block [{base_port}, {inbound_hi}] overlaps the sink port range "
            f"[{sink_lo}, {sink_hi}] — move base_port (MEFOR_CONNSCALE_BASE_PORT) or the sink "
            f"port (--sink-port, MEFOR_CONNSCALE_SINK_PORT) apart"
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


@prints_its_refusal
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


# -- Wiring ------------------------------------------------------------------------------------
# graph.py and the runner's generated per-step module both call wire_graph: one wiring, so the two
# routes cannot build different graphs for the same shape.

# A few attempts with brief backoff: the sink always AA's, so retries shouldn't fire — but a transient
# hiccup under heavy connection count should ride out rather than dead-letter and dirty the no-loss check.
_RETRY = RetryPolicy(
    max_attempts=5, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=5.0
)


def _apply_transform(
    msg: Message | RawMessage, shape: ConnScaleShape, index: int
) -> Message | RawMessage:
    """Apply the configured transform cost. ``cheap`` returns the receipt unchanged (cheapest graph);
    ``edit`` rewrites representative whole fields via the Message model (never string slicing). MSH-10
    is left intact — the correlation sink matches on the control id, so the delivered copy must carry
    the same one it arrived with."""
    if shape.transform == EDIT and isinstance(msg, Message):
        msg["MSH-4"] = "MEFOR_CONNSCALE"  # sending facility
        msg["MSH-6"] = f"SINK_{index:05d}"  # receiving facility = this destination
    return msg


def _make_passthrough(dest: str, shape: ConnScaleShape, index: int) -> HandlerFn:
    """A per-connection handler: apply the (trivial) transform, deliver to its own outbound. Each
    handler runs on its own fresh parse of the raw (one routed row per handler), so mutation is
    isolated."""

    def handle(msg: Message | RawMessage) -> Send:
        return Send(dest, _apply_transform(msg, shape, index))

    return handle


def _route_to(handler_name: str) -> RouterFn:
    """A trivial router: every received message goes to the one handler bound to this inbound."""

    def route(_msg: Message | RawMessage) -> list[str]:
        return [handler_name]

    return route


def wire_graph(shape: ConnScaleShape) -> None:
    """Register N independent inbound->router->handler->outbound chains by name. Conn i: IB_CS_{i}
    on base_port+i -> R_CS_{i} -> H_CS_{i} -> OB_CS_{i} -> the sink. Names run through
    ``ConnScaleShape.conn_name``, so a per-engine name prefix gives each engine DISTINCT names on a
    shared store (disjoint FIFO lanes); an empty prefix is byte-identical to the historical
    single-engine names."""
    for i in range(shape.count):
        dest = shape.conn_name("OB", i)
        host, port = shape.sink_endpoint(i)
        outbound(
            dest,
            MLLP(host=host, port=port, connect_timeout=2.0, timeout_seconds=5.0),
            retry=_RETRY,
        )
        hname = shape.conn_name("H", i)
        handler(hname)(_make_passthrough(dest, shape, i))
        rname = shape.conn_name("R", i)
        router(rname)(_route_to(hname))
        inbound(shape.conn_name("IB", i), MLLP(port=shape.base_port + i), router=rname)
