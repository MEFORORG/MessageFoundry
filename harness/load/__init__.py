# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless, asyncio load-testing engine for the MessageFoundry engine.

A separate, **Qt-free** layer of the test harness (sibling to :mod:`harness.scenarios`) that drives
the engine under heavy MLLP traffic and measures it. It saturates one or more inbound MLLP hubs from
a persistent, pipelined connection pool; a fast correlation sink absorbs the engine's outbound
fan-out and times each message end-to-end; an engine poller samples the HTTP API for throughput,
backlog, and drain. See ``docs/LOAD-TESTING.md``.

Like :mod:`harness.scenarios`, this package imports no PySide6, and drives the engine through the
**pure** surfaces a client is allowed to use: the MLLP framing primitives
(:mod:`messagefoundry.transports.mllp`), the parsing library, the generators, and the HTTP
:class:`~messagefoundry.apiclient.EngineClient`.

**The store carve-out, and it is not the client rule being bent.** The rigs that OWN the engine
subprocess they measure — they spawn it, hand it a store, and stop it — are test rigs rather than
clients, and some of their jobs are only doable against the store directly. In
:mod:`harness.load.connscale` that is at least emptying a shared server store between sweep steps
(``runner._reset_server_store``) and the BACKLOG #1292 intake audit's per-message read
(``runner._store_reader``); :mod:`harness.load.shardcert` provisions its own store the same way.
Each goes through the ``Store`` protocol via ``open_store``, lazily imported inside the function so
the import graph of everything else is unchanged, and each is a read/reset path on a store the rig
itself provisioned — never a shortcut around the API for something the API could answer. (Separately
and harmlessly, several modules import the ``AckMode`` enum from ``config``; that is a value type,
not engine state.) The Qt-free client rule itself is unchanged: nothing here imports PySide6, and
the monitoring path is still the HTTP API.
"""

from __future__ import annotations
