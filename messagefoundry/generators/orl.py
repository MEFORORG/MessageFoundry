"""Generate conformant HL7 v2.5.1 **ORL** (laboratory order response) messages.

ORL is an order acknowledgement: MSH + MSA, optionally echoing the patient/order. We emit an
AA acknowledgement plus the optional response patient block.
"""

from __future__ import annotations

import random

from messagefoundry.generators import _core
from messagefoundry.generators._core import Ctx, MessageSpec, seg


def _build_msa(rng: random.Random, ctx: Ctx) -> str:
    # MSA-1 acknowledgement code, MSA-2 the (fabricated) control id being acknowledged.
    return seg("MSA", {1: "AA", 2: f"REQ{rng.randint(10_000, 99_999)}"})


# ORL is an acknowledgement: MSH + MSA is conformant for every ORL structure. We don't echo the
# patient/order block — O34/O36 nest a required SPM-bearing order group we don't populate.
_core.register(
    MessageSpec(
        code="ORL",
        trigger_to_structure={"O22": "ORL_O22", "O34": "ORL_O34", "O36": "ORL_O36"},
        builders={"MSA": _build_msa},
    )
)
