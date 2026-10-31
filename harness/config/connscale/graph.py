# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Connection-scale system-under-test: N inbound MLLP connections, each a trivial route → handler →
one outbound to the correlation sink (B11).

Where ``harness/config/load`` models a high-FAN-OUT estate (3 hubs each fanning to many outbounds),
this models a high-CONNECTION-COUNT estate: ``MEFOR_CONNSCALE_COUNT`` inbound MLLP listeners, each
with its own trivial Router (returns the one handler) → Handler (filter-free pass-through, optionally
a representative whole-field ``edit``) → one outbound delivering to the harness correlation sink. The
graph is a **flat list of inbound()/outbound() registrations wired by name** — no bundling "channel"
object (CLAUDE.md §1) — and the router/handler logic stays code-first.

Serving this directory reads the shape from ``MEFOR_CONNSCALE_COUNT=N`` (+ the matching base/sink
env), so this ONE graph file serves any N by env alone. The connscale sweep runner no longer serves it:
it writes each step's shape into a generated config directory instead
(``harness.load.connscale.stepconfig``), because a ``[sandbox].mode = "subprocess"`` worker never
receives a ``MEFOR_`` variable and would build the default 50 (BACKLOG #3132). Both build the graph
through :func:`harness.config.connscale._wire.wire_graph`. The trivial route+handler keep
the measured cost the engine's *per-connection machinery* (workers, wake events, pool, executor hops),
not transform CPU. Serve it on its own::

    MEFOR_CONNSCALE_COUNT=500 MEFOR_CONNSCALE_BASE_PORT=2600 MEFOR_CONNSCALE_SINK_PORT=2700 \
      python -P -X disable-remote-debug -m messagefoundry serve --config harness/config/connscale --db ./connscale.db

Every value here is synthetic and generic — no real partner, site, host, or volume. See
``docs/LOAD-TESTING.md``.
"""

from __future__ import annotations

from harness.config.connscale._shape import load_connscale_shape
from harness.config.connscale._wire import wire_graph

wire_graph(load_connscale_shape())
