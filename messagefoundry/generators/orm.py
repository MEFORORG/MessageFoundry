"""Generate conformant HL7 v2.5.1 **ORM** (general order) messages.

ORM_O01 only *requires* MSH + ORC; we include the optional PATIENT group (PID/PV1) for realism.
We deliberately omit ORDER_DETAIL: hl7apy models its OBR/RQD/RQ1/RXO/ODS/ODT subgroup as
all-required rather than a choice, so it can't be populated sensibly — OBR-based orders are
better expressed via OML (the modern lab order) instead.
"""

from __future__ import annotations

from messagefoundry.generators import _core
from messagefoundry.generators._core import MessageSpec

_core.register(
    MessageSpec(
        code="ORM",
        trigger_to_structure={"O01": "ORM_O01"},
        optional_allowlist=frozenset({"PD1", "PV2"}),
        group_suffixes=frozenset({"_PATIENT", "_PATIENT_VISIT"}),
    )
)
