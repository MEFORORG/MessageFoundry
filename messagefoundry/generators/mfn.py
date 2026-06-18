# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Generate conformant HL7 v2.5.1 **MFN** (master file notification) messages.

We cover the generic master-file structures (M01, M13) that need only MFI + MFE. The typed
variants (M02→STF, M04→CDM, M05→LOC/LDP, …) require master-file-specific segments we don't build.
"""

from __future__ import annotations

import random

from messagefoundry.generators import _core
from messagefoundry.generators import _hl7data as d
from messagefoundry.generators._core import Ctx, MessageSpec, seg


def _build_mfi(rng: random.Random, ctx: Ctx) -> str:
    return seg(
        "MFI",
        {
            1: d.cwe("PRA", "Practitioner master file", "HL70175"),  # master file id (required)
            3: "REP",  # file-level event code (required)
            6: "NE",  # response level code (required)
        },
    )


def _build_mfe(rng: random.Random, ctx: Ctx) -> str:
    return seg(
        "MFE",
        {
            1: rng.choice(("MAD", "MUP", "MDC")),  # record-level event code (required)
            4: d.cwe(f"KEY{rng.randint(100, 999)}", "Master record", "L"),  # primary key (required)
            5: "CWE",  # primary key value type (required)
        },
    )


_core.register(
    MessageSpec(
        code="MFN",
        trigger_to_structure={"M01": "MFN_M01", "M13": "MFN_M13"},
        builders={"MFI": _build_mfi, "MFE": _build_mfe},
    )
)
