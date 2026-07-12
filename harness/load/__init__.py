# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless, asyncio load-testing engine for the MessageFoundry engine.

A separate, **Qt-free** layer of the test harness (sibling to :mod:`harness.scenarios`) that drives
the engine under heavy MLLP traffic and measures it. It saturates one or more inbound MLLP hubs from
a persistent, pipelined connection pool; a fast correlation sink absorbs the engine's outbound
fan-out and times each message end-to-end; an engine poller samples the HTTP API for throughput,
backlog, and drain. See ``docs/LOAD-TESTING.md``.

Like :mod:`harness.scenarios`, this package imports no PySide6 and never imports the engine's
``pipeline``/``store``/``config`` internals — only the **pure** surfaces the harness is allowed to
use: the MLLP framing primitives (:mod:`messagefoundry.transports.mllp`), the parsing library, the
generators, and the HTTP :class:`~messagefoundry.apiclient.EngineClient`.
"""

from __future__ import annotations
