# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Generate conformant HL7 v2.5.1 **SIU** (scheduling) messages.

Every SIU_Sxx structure in the reference is covered. Required SCH + RESOURCES(→RGS) plus the
optional PATIENT (PID) and SERVICE (AIS) groups give a realistic appointment message. The other
resource groups (general/location/personnel → AIG/AIL/AIP) are left out (not in the suffix set).
"""

from __future__ import annotations

import random

from hl7apy import v2_5_1 as _ref

from messagefoundry.generators import _core
from messagefoundry.generators import _hl7data as d
from messagefoundry.generators._core import Ctx, MessageSpec, next_seq, seg

# Every SIU structure: trigger "S12" -> "SIU_S12".
TRIGGER_TO_STRUCTURE: dict[str, str] = {
    k.split("_", 1)[1]: k for k in _ref.MESSAGES if k.startswith("SIU_")
}


def _build_sch(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.APPT_REASONS)
    return seg(
        "SCH",
        {
            1: d.ei(str(rng.randint(100_000, 999_999))),  # placer appointment id
            2: d.ei(str(rng.randint(100_000, 999_999)), "SCHED"),  # filler appointment id
            6: d.cwe(code, text, "L"),  # event reason (required)
            16: d.xcn(*rng.choice(d.CLINICIANS)),  # filler contact person (required)
            20: d.xcn(*rng.choice(d.CLINICIANS)),  # entered by person (required)
        },
    )


def _build_rgs(rng: random.Random, ctx: Ctx) -> str:
    return seg("RGS", {1: str(next_seq(ctx, "RGS")), 2: "A"})


def _build_ais(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.SERVICES)
    return seg(
        "AIS",
        {
            1: str(next_seq(ctx, "AIS")),
            3: d.cwe(code, text, "LN"),  # universal service id (required)
            4: d.ts(ctx.msg_dt),
        },
    )


_core.register(
    MessageSpec(
        code="SIU",
        trigger_to_structure=TRIGGER_TO_STRUCTURE,
        builders={"SCH": _build_sch, "RGS": _build_rgs, "AIS": _build_ais},
        optional_allowlist=frozenset({"PV1", "PV2", "DG1", "OBX"}),
        group_suffixes=frozenset({"_PATIENT", "_SERVICE"}),
    )
)
