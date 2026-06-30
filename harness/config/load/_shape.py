# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared shape parameters + helpers for the load system-under-test graph.

Loader skips ``_*`` modules, so this file is *imported* by :mod:`graph` rather than loaded as config.
It centralizes the env-tunable knobs (fan-out factor, transform cost, sink endpoint) so the graph
reads them in one place — no copy-paste across the registered modules (CLAUDE.md §4).

Knobs (all optional, with safe defaults so ``serve`` works with none set):

* ``MEFOR_LOAD_FANOUT``         — sink destinations per ADT message (default 20).
* ``MEFOR_LOAD_RESULTS_FANOUT`` — destinations per results/other message (default 4).
* ``MEFOR_LOAD_TRANSFORM``      — ``cheap`` | ``edit`` | ``slow`` (default ``edit``).
* ``MEFOR_LOAD_TRANSFORM_MS``   — CPU spin per transform when ``slow`` (default 1.0 ms).
* ``MEFOR_LOAD_SINK_HOST``      — sink host every destination delivers to (default 127.0.0.1).
* ``MEFOR_LOAD_SINK_PORT``      — base sink port (default 2700).
* ``MEFOR_LOAD_SINK_PORTS``     — contiguous sink ports to round-robin across (default 1).
* ``MEFOR_LOAD_ADT_PORT``       — ADT hub inbound MLLP port (default 2600).
* ``MEFOR_LOAD_RESULTS_PORT``   — results hub inbound MLLP port (default 2601).
* ``MEFOR_LOAD_OTHER_PORT``     — other hub inbound MLLP port (default 2602).
* ``MEFOR_LOAD_SHARD_ADT``      — ``supervise`` shard id for the ADT hub (default unset → no tag).
* ``MEFOR_LOAD_SHARD_RESULTS``  — ``supervise`` shard id for the results hub (default unset → no tag).
* ``MEFOR_LOAD_SHARD_OTHER``    — ``supervise`` shard id for the other hub (default unset → no tag).

Shards (all optional): tagging a hub with ``shard=`` routes it to a named ``messagefoundry supervise``
subprocess. **Unset (the default) = no tag = a single implicit shard**, so the SAME load graph serves
both unsharded (default) and sharded (e.g. ``MEFOR_LOAD_SHARD_ADT=a`` / ``_RESULTS=b`` / ``_OTHER=b``
→ a 2-shard layout) with no other change. The tags never affect routing.

The graph is **synthetic and generic** — it models the *shape* of a high-fan-out estate (one big ADT
hub plus results/orders hubs), never a real site. See ``docs/LOAD-TESTING.md``.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from messagefoundry.parsing.message import Message, RawMessage

# Transform cost modes.
CHEAP = "cheap"  # pass-through: deliver the raw receipt unchanged
EDIT = "edit"  # representative whole-field rewrites via the Message model
SLOW = "slow"  # edit + a deterministic CPU spin, to find the transform-cost ceiling on one core
_TRANSFORMS = frozenset({CHEAP, EDIT, SLOW})


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_shard(name: str) -> str | None:
    """A shard id from the environment, or ``None`` when unset/blank (= no shard tag)."""
    raw = os.environ.get(name)
    raw = raw.strip() if raw else ""
    return raw or None


@dataclass(frozen=True)
class Shape:
    """Resolved load-graph parameters (read once from the environment at load time)."""

    fanout: int
    results_fanout: int
    transform: str
    transform_ms: float
    sink_host: str
    sink_port: int
    sink_ports: int
    adt_port: int
    results_port: int
    other_port: int
    shard_adt: str | None
    shard_results: str | None
    shard_other: str | None

    def sink_endpoint(self, index: int) -> tuple[str, int]:
        """Round-robin a destination index across the contiguous sink port range."""
        return self.sink_host, self.sink_port + (index % self.sink_ports)


def load_shape() -> Shape:
    transform = os.environ.get("MEFOR_LOAD_TRANSFORM", EDIT).strip().lower() or EDIT
    if transform not in _TRANSFORMS:
        raise ValueError(
            f"MEFOR_LOAD_TRANSFORM must be one of {sorted(_TRANSFORMS)}, got {transform!r}"
        )
    return Shape(
        fanout=_env_int("MEFOR_LOAD_FANOUT", 20, minimum=1),
        results_fanout=_env_int("MEFOR_LOAD_RESULTS_FANOUT", 4, minimum=1),
        transform=transform,
        transform_ms=_env_float("MEFOR_LOAD_TRANSFORM_MS", 1.0, minimum=0.0),
        sink_host=os.environ.get("MEFOR_LOAD_SINK_HOST", "127.0.0.1") or "127.0.0.1",
        sink_port=_env_int("MEFOR_LOAD_SINK_PORT", 2700, minimum=1),
        sink_ports=_env_int("MEFOR_LOAD_SINK_PORTS", 1, minimum=1),
        adt_port=_env_int("MEFOR_LOAD_ADT_PORT", 2600, minimum=1),
        results_port=_env_int("MEFOR_LOAD_RESULTS_PORT", 2601, minimum=1),
        other_port=_env_int("MEFOR_LOAD_OTHER_PORT", 2602, minimum=1),
        shard_adt=_env_shard("MEFOR_LOAD_SHARD_ADT"),
        shard_results=_env_shard("MEFOR_LOAD_SHARD_RESULTS"),
        shard_other=_env_shard("MEFOR_LOAD_SHARD_OTHER"),
    )


def _spin(ms: float) -> None:
    """Busy-loop for ``ms`` milliseconds — a CPU-bound transform on the event loop, *not* a sleep, so
    it models single-core transform contention (the durable-write wall is hit at the store; this finds
    the *transform* ceiling). Deterministic and side-effect-free, so a re-run is equivalent."""
    if ms <= 0.0:
        return
    deadline = time.perf_counter() + ms / 1000.0
    while time.perf_counter() < deadline:
        pass


def apply_transform(
    msg: Message | RawMessage, shape: Shape, lane: str, index: int
) -> Message | RawMessage:
    """Apply the configured transform cost and return what to deliver.

    Never touches MSH-10 — the correlation sink matches on the control id, so the delivered copy must
    carry the same one it arrived with. ``cheap`` returns the receipt unchanged; ``edit``/``slow``
    rewrite representative whole fields (and ``slow`` additionally burns CPU)."""
    if shape.transform == CHEAP or not isinstance(msg, Message):
        return msg
    if shape.transform == SLOW:
        _spin(shape.transform_ms)
    # Representative whole-field rewrites — the kind real-world feeds make. Whole-field sets
    # via the Message model (never string slicing); MSH-10 is deliberately left intact.
    msg["MSH-4"] = "MEFOR_LOAD"  # sending facility
    msg["MSH-6"] = f"SINK_{lane}_{index:02d}"  # receiving facility = this destination
    return msg
