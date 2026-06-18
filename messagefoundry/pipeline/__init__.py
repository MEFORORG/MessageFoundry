# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-message pipeline + connection supervision.

The inbound path (parse/validate → Router → Handler(s) → fan out to outbound outboxes →
ACK/NACK) and the per-outbound delivery workers live in :mod:`.wiring_runner`;
:mod:`.engine` supervises the :class:`RegistryRunner` over a shared store. Outbound
connections drain independently so one slow/failing destination never blocks the others.

Submodules:

* :mod:`.wiring_runner` — :class:`RegistryRunner` (runs a code-first wiring Registry)
* :mod:`.engine`        — :class:`Engine`
"""

from __future__ import annotations

from messagefoundry.pipeline.engine import ConfigReloadDenied, Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner

__all__ = ["Engine", "ConfigReloadDenied", "RegistryRunner"]
