"""Generate conformant HL7 v2.5.1 **BAR** (add/change billing account) messages.

BAR_Pxx require MSH + EVN + PID + a VISIT group; we add procedures (PR1), guarantor (GT1) and
insurance (IN1) for realistic billing accounts.
"""

from __future__ import annotations

from messagefoundry.generators import _core
from messagefoundry.generators._core import MessageSpec

_core.register(
    MessageSpec(
        code="BAR",
        # P10 omitted: requires GP1 (grouping/reimbursement), which we don't build.
        trigger_to_structure={
            "P01": "BAR_P01",
            "P02": "BAR_P02",
            "P05": "BAR_P05",
            "P06": "BAR_P06",
            "P12": "BAR_P12",
        },
        optional_allowlist=frozenset({"PV1", "PV2", "DG1", "GT1", "OBX", "AL1"}),
        group_suffixes=frozenset({"_PROCEDURE", "_INSURANCE"}),
    )
)
