# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Generate conformant HL7 v2.5.1 **RAS** (pharmacy/treatment administration) messages.

The required ADMINISTRATION group carries RXA; ORC/RXA/RXR are shared builders.
"""

from __future__ import annotations

from messagefoundry.generators import _core
from messagefoundry.generators._core import MessageSpec

_core.register(
    MessageSpec(
        code="RAS",
        trigger_to_structure={"O17": "RAS_O17"},
        optional_allowlist=frozenset({"PD1", "PV2", "AL1", "RXR"}),
        group_suffixes=frozenset({"_PATIENT", "_PATIENT_VISIT"}),
    )
)
