# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fuzz a RUNNING engine through a harness driver, pure Python (``python -m harness --fuzz``).

The repository's top-level ``fuzz/`` package fuzzes parsers in-process under Atheris, which needs
a native toolchain and does not run on Windows. This package is the other half: it takes the
generators' synthetic HL7, applies seeded mutations at three layers -- bytes, fields (through the
parsed :class:`~messagefoundry.parsing.message.Message`, never by slicing raw text) and MLLP
frames -- sends each case to a live inbound, and after every batch checks the invariants a
deploying site would rely on (:mod:`harness.fuzz.invariants`).

Every case is a pure function of ``(seed, iteration)``, so a failure is reported as a seed and an
iteration plus a file holding the exact bytes sent, and ``--fuzz-replay FILE`` sends them again.

Always import this as ``harness.fuzz``: a bare ``fuzz`` is the Atheris package at the repo root.
"""

from __future__ import annotations

from harness.fuzz.campaign import CampaignResult, Failure, FuzzConfig, SetupError, replay, run
from harness.fuzz.mutate import LAYERS, Case, make_case
from harness.fuzz.transport import Exchange, Transport, build_transport

__all__ = [
    "LAYERS",
    "CampaignResult",
    "Case",
    "Exchange",
    "Failure",
    "FuzzConfig",
    "SetupError",
    "Transport",
    "build_transport",
    "make_case",
    "replay",
    "run",
]
