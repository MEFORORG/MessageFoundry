# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale measurement harness (B11).

Spins up N inbound MLLP connections (500 / 1000 / 1500) at a low per-connection rate against a real
MessageFoundry engine the harness OWNS (subprocess), holds each connection count steady, and reads the
connection-scale walls vs connection count — executor saturation, server-DB pool acquire-wait, the
idle-poll/thundering-herd empty-claim storm, FD/socket count, config-reload latency, and ACK latency.

It is a **measurement tool**, not reliability-core: it reuses the existing ``harness/load`` rig
(PersistentConnection, CorrelationSink, EnginePoller, the metrics primitives, the EngineNode
subprocess spawn) and reads only the additive, read-only engine instrumentation. See
``docs/LOAD-TESTING.md``.
"""
