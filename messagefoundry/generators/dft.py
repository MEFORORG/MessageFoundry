# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Generate conformant HL7 v2.5.1 **DFT** (detailed financial transaction) messages.

DFT_P03/P11 require MSH + EVN + PID + a FINANCIAL group (→ FT1); we add an optional visit and
diagnoses for realism.
"""

from __future__ import annotations

from messagefoundry.generators import _core
from messagefoundry.generators._core import MessageSpec

_core.register(
    MessageSpec(
        code="DFT",
        trigger_to_structure={"P03": "DFT_P03", "P11": "DFT_P11"},
        optional_allowlist=frozenset({"PV1", "PV2", "DG1"}),
    )
)
