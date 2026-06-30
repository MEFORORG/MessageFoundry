# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Store-once-deliver-many (L2b) system-under-test — the shape that actually triggers dedup.

The load graph (``harness/config/load``) fans out via N **separate** handlers (one ``Send`` each → N
``transform_handoff``s, each a single delivery → the body is stored **inline**), and its ``edit``
transform rewrites MSH-6 *per destination* → N **distinct** bodies. So the load graph never exercises
store-once-deliver-many.

This graph fans out via **one** handler returning ``list[Send]`` of the **identical** body to N
destinations — a single ``transform_handoff`` with N deliveries — which is exactly the shape that
triggers L2b: the body is content-addressed and written **once** to ``shared_body``, referenced by N
``queue.body_ref`` rows (instead of N inline copies). Serve it for §7 **J1/S7.1** (store-once
functional) and **J9/S7.6** (write-amplification)::

    MEFOR_LOAD_FANOUT=20 MEFOR_LOAD_SINK_PORT=2700 \
      python -m messagefoundry serve --config harness/config/store_once --db ./store_once.db

then inject a few ADT messages on the inbound port and inspect the store (``shared_body`` row count,
``queue.body_ref``). Synthetic + generic; reuses the load graph's ``_shape`` for ports/sink/fan-out so
``MEFOR_LOAD_FANOUT`` / ``MEFOR_LOAD_SINK_PORT`` / ``MEFOR_LOAD_ADT_PORT`` behave the same as there.
"""

from __future__ import annotations

from messagefoundry import MLLP, Send, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy
from messagefoundry.parsing.message import Message, RawMessage

from harness.config.load._shape import load_shape

_SHAPE = load_shape()

# A few attempts with brief backoff (the sink always AA's, so retries shouldn't fire) — a transient
# hiccup rides out rather than dead-lettering and dirtying the no-loss / store-once inspection.
_RETRY = RetryPolicy(
    max_attempts=5, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=5.0
)


def _register_dests(fanout: int) -> list[str]:
    """Declare ``fanout`` outbound destinations, all delivering to the harness correlation sink."""
    names: list[str] = []
    for i in range(fanout):
        dest = f"OB_StoreOnce_{i:02d}"
        host, port = _SHAPE.sink_endpoint(i)
        outbound(
            dest,
            MLLP(host=host, port=port, connect_timeout=2.0, timeout_seconds=5.0),
            retry=_RETRY,
        )
        names.append(dest)
    return names


_DESTS = _register_dests(_SHAPE.fanout)

inbound("IB_StoreOnce", MLLP(port=_SHAPE.adt_port), router="store_once_router")


@router("store_once_router")
def route(msg: Message | RawMessage) -> list[str]:
    return ["fanout_identical_body"]


@handler("fanout_identical_body")
def fanout_identical_body(msg: Message | RawMessage) -> list[Send]:
    # ONE handler → list[Send] of the SAME body to every destination. All N deliveries share this one
    # transform_handoff AND carry the identical body, so the store dedups: one content-addressed
    # shared_body row + N body_ref rows (not N inline copies). Deliberately NO per-destination
    # transform — that would make the bodies distinct and defeat dedup (see harness/config/load for the
    # realistic N-distinct-bodies shape).
    return [Send(dest, msg) for dest in _DESTS]
