# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Configuration: connector models + the code-first wiring layer.

Connectors are described by :class:`Source`/:class:`Destination` (type + free-form
``settings``). The message graph is authored code-first in
:mod:`messagefoundry.config.wiring` — declare ``inbound``/``outbound`` Connections and
decorate ``@router``/``@handler`` scripts; a directory of such modules loads via
``load_config`` into a :class:`~messagefoundry.config.wiring.Registry`.
"""

from __future__ import annotations

from messagefoundry.config.models import (
    AckMode,
    ConnectorType,
    Destination,
    RetryPolicy,
    Source,
    Validation,
)

__all__ = [
    "Source",
    "Destination",
    "Validation",
    "RetryPolicy",
    "ConnectorType",
    "AckMode",
]
