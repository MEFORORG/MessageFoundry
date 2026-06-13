"""Generate conformant HL7 v2.5.1 **RDE** (pharmacy/treatment encoded order) messages.

hl7apy's parser greedily assigns a TQ1 to the optional ``RDE_O11_TIMING`` group (which precedes
RXE) and never to the *required* ``RDE_O11_TIMING_ENCODED`` group — so it false-flags
TIMING_ENCODED as missing even though the message carries a TQ1 in the right place. We emit the
correct segments (ORC/RXE/TQ1/RXR) and a narrow gate tolerates that one tool-limitation error
(a spec-correct message), failing on anything else. (Same spirit as ADT's two-block fallback.)
"""

from __future__ import annotations

import random

from messagefoundry.parsing import validate
from messagefoundry.generators import _core
from messagefoundry.generators import _hl7data as d
from messagefoundry.generators._core import Ctx, MessageSpec, next_seq, seg


def _build_rxe(rng: random.Random, ctx: Ctx) -> str:
    code, text = rng.choice(d.MEDICATIONS)
    return seg(
        "RXE",
        {
            2: d.cwe(code, text, "RxNorm"),  # give code (required)
            3: "1",  # give amount minimum (required)
            5: d.cwe("mg", "milligram", "UCUM"),  # give units (required)
        },
    )


def _build_tq1(rng: random.Random, ctx: Ctx) -> str:
    return seg("TQ1", {1: str(next_seq(ctx, "TQ1"))})


def _gate(msg: str, structure: str) -> tuple[bool, list[str]]:
    result = validate(msg, expected_version="2.5.1")
    # Tolerate only the known TIMING_ENCODED mis-grouping; any other error is a real failure.
    remaining = [e for e in result.errors if "TIMING_ENCODED" not in e]
    return (not remaining), remaining


_core.register(
    MessageSpec(
        code="RDE",
        trigger_to_structure={"O11": "RDE_O11"},
        builders={"RXE": _build_rxe, "TQ1": _build_tq1},
        optional_allowlist=frozenset({"PD1", "PV2"}),
        group_suffixes=frozenset({"_PATIENT", "_PATIENT_VISIT"}),
        gate=_gate,
    )
)
