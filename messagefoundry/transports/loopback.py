# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Loopback source — a deliberately inert inbound (ADR 0013 Increment 2).

A loopback inbound has **no listening or polling source**: messages arrive *exclusively* via the
engine-internal ``ingress_handoff`` (a captured reply re-ingressed as a new inbound message). This
connector exists only to satisfy the source-registry contract so the runner can build a loopback
inbound like any other (and so its router/transform/**response** workers spawn). Its ``start`` records
the handler and returns; its run loop never fires; routing a re-ingressed message through the
source/listener seam would be the bare-``enqueue_ingress`` double-injection trap (ADR 0013), so this
connector guards against that by never invoking the handler at all.

Unlike :class:`~messagefoundry.transports.timer.TimerSource`, a loopback reads **no** shared external
resource, so ``polls_shared_resource = False`` — there is nothing to leader-gate at the source. The
re-ingress work is leader-gated at the *worker* (the per-lane claim owner), consistent with every other
stage.
"""

from __future__ import annotations

import logging
from typing import Callable

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports.base import InboundHandler, SourceConnector, register_source

logger = logging.getLogger(__name__)


class LoopbackSource(SourceConnector):
    """An inert inbound: no socket, no poll. Re-ingress delivers via ``ingress_handoff``, never here."""

    # Reads no shared external resource → nothing to leader-gate at the source (re-ingress is gated at
    # the worker's per-lane claim owner instead — see the re-ingress worker).
    polls_shared_resource = False

    def __init__(self, config: Source) -> None:
        # No settings to read — a loopback carries only its router/content_type on the inbound itself.
        self._config = config
        self._handler: InboundHandler | None = None

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        """Record the handler and return live. The handler is intentionally **never** invoked — a
        re-ingressed message reaches the pipeline via the internal ``ingress_handoff``, not this seam."""
        self._handler = handler

    async def stop(self) -> None:
        return None


register_source(ConnectorType.LOOPBACK, LoopbackSource)
