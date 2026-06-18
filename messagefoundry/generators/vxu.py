# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Generate conformant HL7 v2.5.1 **VXU** (unsolicited vaccination update) messages.

RXA/RXR live in the shared core (also used by RAS), so this is just the spec.
"""

from __future__ import annotations

from messagefoundry.generators import _core
from messagefoundry.generators._core import MessageSpec

_core.register(
    MessageSpec(
        code="VXU",
        trigger_to_structure={"V04": "VXU_V04"},
        optional_allowlist=frozenset({"PD1", "PV2", "NK1", "RXR", "OBX"}),
        group_suffixes=frozenset({"_PATIENT", "_ORDER", "_OBSERVATION"}),
    )
)
