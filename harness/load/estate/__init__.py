# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Estate-shape load driver (#216).

Drives the heterogeneous estate SUT (:mod:`harness.config.estate`) — a majority of simple
1-in-1-out feeds plus a minority of fan-out hubs — at a calibrated **per-connection event rate** so the
aggregate converges on a target total events/sec (the 45M/day = ~520 ev/s demo shape). Where
:mod:`harness.load.connscale` meters every connection UNIFORMLY (the wrong axis for a heterogeneous
estate — hubs would over-contribute events), this driver weights each connection's message rate by its
served fan-out so every connection emits the same *event* rate. It reuses the connscale/load
scaffolding (PersistentConnection, CorrelationSink, EnginePoller, the CPU-per-event probe, the owned
EngineNode) rather than re-implementing it. See ``docs/LOAD-TESTING.md``.
"""
