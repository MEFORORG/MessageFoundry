# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Deployment verifier — ``messagefoundry verify``.

Adopter-grade, **wheel-only** acceptance for a real deployment: host/environment checks, a store
connectivity check, and an end-to-end message smoke — using only the installed engine (no source
tree, no test suite). It answers "is *this* box set up right and does a message actually flow?", which
is the on-box complement to CI's engine-conformance suites.

The model deliberately marks host/domain steps it can't self-verify (AD login, NSSM, the visual
no-console-flash check) as ``MANUAL`` rather than faking a pass.
"""

from __future__ import annotations

from messagefoundry.verify.model import CheckResult, Status
from messagefoundry.verify.runner import run_verify

__all__ = ["CheckResult", "Status", "run_verify"]
