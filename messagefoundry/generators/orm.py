# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Generate conformant HL7 v2.5.1 **ORM** (general order) messages.

ORM_O01 only *requires* MSH + ORC; we include the optional PATIENT group (PID/PV1) for realism,
and an ORDER_DETAIL after each ORC. Its OBR/RQD/RQ1/RXO/ODS/ODT group is a choice, so the
generator emits exactly one alternative, OBR (see ``_core._pick_alternative``).
"""

from __future__ import annotations

from messagefoundry.generators import _core
from messagefoundry.generators._core import MessageSpec

_core.register(
    MessageSpec(
        code="ORM",
        trigger_to_structure={"O01": "ORM_O01"},
        optional_allowlist=frozenset({"PD1", "PV2"}),
        group_suffixes=frozenset({"_PATIENT", "_PATIENT_VISIT", "_ORDER_DETAIL"}),
    )
)
