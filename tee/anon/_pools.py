# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Surrogate value pools — the **tee seam** (ADR 0030 §1).

Mirror of ``messagefoundry/anon/_pools.py`` for the standalone tee, which cannot import
``messagefoundry``: it re-exports the same pool names from the **vendored** copy of the generator's
data tables (``tee/anon/_hl7data.py``, held byte-identical to the engine's by the parity test). The
shared ``surrogates.py`` only ever reaches pools through ``from . import _pools``, so the surrogate
logic stays byte-identical across both packages while this seam differs.
"""

from __future__ import annotations

from tee.anon._hl7data import (
    CITIES,
    CLINICIANS,
    FAMILY_NAMES,
    GIVEN_NAMES,
    MIDDLE_INITIALS,
    STREETS,
)

__all__ = [
    "CITIES",
    "CLINICIANS",
    "FAMILY_NAMES",
    "GIVEN_NAMES",
    "MIDDLE_INITIALS",
    "STREETS",
]
