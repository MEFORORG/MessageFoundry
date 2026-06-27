# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pass-through (PT) source — a deliberately inert *internal* inbound (ADR 0013, generalized).

A **pass-through inbound** (``PT_*`` in the Corepoint idiom) has **no listening or polling source**:
messages arrive *exclusively* via the engine-internal **pass-through handoff** — a Handler ``Send``\\ s
its transformed message *into* a PT inbound (naming it like any outbound), and the engine re-ingresses
that body as a **new, independent inbound message** on the PT inbound's channel, where the PT inbound's
own Router decides where it goes next. This lets one logical feed fan out across internal connectors and
re-route deeper without an external hop.

This generalizes the ADR 0013 Increment 2 re-ingress primitive. That primitive existed only for
**query→response capture** (a ``Loopback()`` inbound fed by a capturing outbound's reply, 1:1). A PT
inbound is the **1:N internal routing** sibling: any Handler may target it, the body is the *transformed*
message (not a captured partner reply), and the PT inbound carries a first-class Router/Handler graph.
Both share the atomic content-addressed re-ingress shape (a child INGRESS row produced in the *same*
transaction that consumes the parent's routed row), so a crash/re-run is an idempotent no-op.

Like :class:`~messagefoundry.transports.loopback.LoopbackSource`, this connector exists only to satisfy
the source-registry contract so the runner can build a PT inbound like any other (and so its
router/transform workers spawn — a PT inbound is an ordinary inbound *for routing purposes*). Its
``start`` records the handler and returns; its run loop never fires; routing a re-ingressed message
through the source/listener seam would be the bare-``enqueue_ingress`` double-injection trap (ADR 0013),
so this connector guards against that by never invoking the handler at all. A unit test pins that the
handler is never invoked.

Unlike :class:`~messagefoundry.transports.timer.TimerSource`, a PT source reads **no** shared external
resource, so ``polls_shared_resource = False`` — there is nothing to leader-gate at the source. The
pass-through work is part of the parent's ``transform_handoff`` transaction, leader-gated by the
active-passive graph gating that already runs the whole graph on the leader only.
"""

from __future__ import annotations

import logging
from typing import Callable

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports.base import InboundHandler, SourceConnector, register_source

logger = logging.getLogger(__name__)


class PassThroughSource(SourceConnector):
    """An inert internal inbound: no socket, no poll. A Send-into-PT delivers via the pass-through
    handoff (part of ``transform_handoff``), never through this seam."""

    # Reads no shared external resource → nothing to leader-gate at the source (the re-ingress is part
    # of the parent's transform handoff, gated by active-passive graph gating).
    polls_shared_resource = False

    def __init__(self, config: Source) -> None:
        # No settings to read — a PT inbound carries only its router/content_type on the inbound itself.
        self._config = config
        self._handler: InboundHandler | None = None

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        """Record the handler and return live. The handler is intentionally **never** invoked — a
        pass-through message reaches the pipeline via the internal handoff, not this seam."""
        self._handler = handler

    async def stop(self) -> None:
        return None


register_source(ConnectorType.PT, PassThroughSource)
