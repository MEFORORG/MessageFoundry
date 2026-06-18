# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Generate conformant HL7 v2.5.1 **ORU** (observation result) messages.

The required PATIENT_RESULT → ORDER_OBSERVATION groups give MSH + OBR; we include the optional
PATIENT (PID) and OBSERVATION (OBX) groups so results carry a patient and values.
"""

from __future__ import annotations

from messagefoundry.generators import _core
from messagefoundry.generators._core import MessageSpec

_core.register(
    MessageSpec(
        code="ORU",
        trigger_to_structure={"R01": "ORU_R01", "R30": "ORU_R30"},
        optional_allowlist=frozenset({"ORC", "PD1", "NK1"}),
        group_suffixes=frozenset({"_PATIENT", "_OBSERVATION"}),
    )
)
