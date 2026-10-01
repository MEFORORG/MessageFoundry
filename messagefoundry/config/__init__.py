# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Configuration: connector models + the code-first wiring layer.

Connectors are described by :class:`Source`/:class:`Destination` (type + free-form
``settings``). The message graph is authored code-first in
:mod:`messagefoundry.config.wiring` — declare ``inbound``/``outbound`` Connections and
decorate ``@router``/``@handler`` scripts; a directory of such modules loads via
``load_config`` into a :class:`~messagefoundry.config.wiring.Registry`.
"""

from __future__ import annotations

# PEP 810 (BACKLOG #2514; inert on 3.14, see tests/test_startup_import_budget.py). Importing the
# leaf `config.tls_policy`, which every CLI command reaches through `logging_setup`, then no longer
# loads pydantic and the models: about 80 modules. A use of a re-exported name loads them.
__lazy_modules__ = ["messagefoundry.config.models"]

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
