# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Generate conformant HL7 v2.5.1 **MDM** (medical document management) messages.

MDM_T01/T02 require MSH + EVN + PID + PV1 + TXA (T02 adds an observation/OBX).
"""

from __future__ import annotations

import random

from messagefoundry.generators import _core
from messagefoundry.generators import _hl7data as d
from messagefoundry.generators._core import Ctx, MessageSpec, next_seq, seg


def _build_txa(rng: random.Random, ctx: Ctx) -> str:
    return seg(
        "TXA",
        {
            1: str(next_seq(ctx, "TXA")),
            2: rng.choice(d.DOCUMENT_TYPES),  # document type (required)
            12: d.ei(
                str(rng.randint(100_000, 999_999)), "DOC"
            ),  # unique document number (required)
            17: rng.choice(d.DOC_STATUSES),  # document completion status (required)
        },
    )


_core.register(
    MessageSpec(
        code="MDM",
        trigger_to_structure={"T01": "MDM_T01", "T02": "MDM_T02"},
        builders={"TXA": _build_txa},
        optional_allowlist=frozenset({"PD1", "PV2", "NK1", "OBX", "DG1", "AL1"}),
        group_suffixes=frozenset({"_COMMON_ORDER", "_OBSERVATION"}),
    )
)
