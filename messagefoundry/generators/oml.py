"""Generate conformant HL7 v2.5.1 **OML** (laboratory order) messages — the modern,
cleanly-structured successor to ORM for OBR-based orders, with specimen (SPM) support.
"""

from __future__ import annotations

import random

from messagefoundry.generators import _core
from messagefoundry.generators import _hl7data as d
from messagefoundry.generators._core import Ctx, MessageSpec, next_seq, seg


def _build_spm(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.SPECIMEN_TYPES)
    return seg("SPM", {1: str(next_seq(ctx, "SPM")), 4: d.cwe(code, text, "HL70487")})


_core.register(
    MessageSpec(
        code="OML",
        # O35 omitted: requires SAC (specimen container), which we don't build.
        trigger_to_structure={"O21": "OML_O21", "O33": "OML_O33"},
        builders={"SPM": _build_spm},
        optional_allowlist=frozenset({"PD1", "PV2", "DG1", "OBX"}),
        group_suffixes=frozenset(
            {"_PATIENT", "_PATIENT_VISIT", "_OBSERVATION_REQUEST", "_OBSERVATION", "_SPECIMEN"}
        ),
    )
)
