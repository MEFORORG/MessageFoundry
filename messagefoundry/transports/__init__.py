# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Transport connectors (sources & destinations).

Each connector implements the small async interface in :mod:`.base` and is keyed by
:class:`~messagefoundry.config.models.ConnectorType` in a registry, so new transports
register without changes to the channel model or pipeline. Phase 1: MLLP + file.

Importing this package registers the built-in connectors (the ``mllp`` and ``file``
modules call ``register_source``/``register_destination`` at import time), so callers can
go straight to :func:`build_source` / :func:`build_destination`.
"""

from __future__ import annotations

from messagefoundry.transports import (  # noqa: F401  (import = registration)
    database,
    file,
    loopback,
    mllp,
    remotefile,
    rest,
    soap,
    tcp,
    timer,
    x12,
)
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    build_destination,
    build_source,
    register_destination,
    register_source,
)

__all__ = [
    "DeliveryError",
    "NegativeAckError",
    "DestinationConnector",
    "SourceConnector",
    "InboundHandler",
    "build_source",
    "build_destination",
    "register_source",
    "register_destination",
]
