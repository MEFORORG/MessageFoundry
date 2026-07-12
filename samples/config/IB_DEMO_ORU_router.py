# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""IB_DEMO_ORU — Router (the *router* file of the per-feed **Hybrid** config layout).

The three concerns of one feed are split by role across flat, prefixed files (the loader globs
``*.py`` non-recursively, so prefixed flat files — not subdirs — see docs/CONNECTIONS.md
§"Decomposing by role"):

    connections.toml            IB_DEMO_ORU / OB_DEMO_ORU (transport config as data, ADR 0007)
    IB_DEMO_ORU_router.py       @router  — this file (Corepoint "E Process": decides forwarding)
    IB_DEMO_ORU_handler.py      @handler — filter → delegate → Send
    _demo_oru_transforms.py     the field-level transform steps (imported by the handler)

The inbound in ``connections.toml`` binds this router by name (``router = "demo_oru_router"``); the
router names its handler by string. Nothing bundles them into a "channel" object — the graph is wired
by name across the whole config dir.
"""

from messagefoundry import router


@router("demo_oru_router")
def route_demo_oru(msg):
    # Forward ORU results to the relay handler; anything else is logged UNROUTED (never dropped).
    if msg["MSH-9.1"] != "ORU":
        return []
    return ["demo_oru_relay"]
