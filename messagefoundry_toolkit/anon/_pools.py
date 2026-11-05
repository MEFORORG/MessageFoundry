# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Surrogate value pools — the **toolkit seam** (ADR 0030 §1/§3).

:mod:`messagefoundry_toolkit.anon.surrogates` draws fabricated names/streets/cities/clinicians
from these pools. On the toolkit side they are re-exported straight from the generator's
already-pure, dependency-free data tables (:mod:`messagefoundry_toolkit.generators._hl7data`, in
the same distribution since ADR 0201 slice 7) so there is **one** source of synthetic data —
surrogates and the synthetic ADT generator stay consistent and there is nothing extra to maintain.

This module is the deliberate **non-parity seam**: the standalone ``tee/anon/_pools.py`` re-exports
the *same* names from a vendored copy of ``_hl7data`` instead (the tee cannot import
``messagefoundry``). ``surrogates.py`` only ever touches ``_pools`` through ``from . import _pools``,
so the surrogate logic file itself stays byte-identical across both packages. The vendored pool
data is held identical by the parity test.
"""

from __future__ import annotations

from messagefoundry_toolkit.generators._hl7data import (
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
