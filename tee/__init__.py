# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Standalone MLLP **tee relay** — a small, separate application (no ``messagefoundry`` imports).

It repoints an ``Epic -> Corepoint`` feed through a relay that **always ACKs on receipt** and forwards
the *unchanged* message to **both** Corepoint (the live production path) **and** a shadow
MessageFoundry instance, so MEFOR can be validated against real traffic during a parallel-run cutover
without being in — or altering — the production path (backlog #14; see ``docs/TEE-RELAY.md``).

Deliberately minimal and dependency-light: it **vendors** a tiny MLLP codec (``tee.mllp``) rather than
importing the engine, and uses **SQLite** (via ``aiosqlite``) as its only store — for the NAK log and
an optional body capture. It is a relay, not a second engine.
"""

from __future__ import annotations

__all__ = ["RelayConfig", "TeeRelay"]
__version__ = "0.1.0"

from tee.relay import RelayConfig, TeeRelay
