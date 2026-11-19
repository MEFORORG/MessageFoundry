# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared result model for the deployment verifier."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from messagefoundry.verify_leaf import DRIVER_DETAIL_LIMIT as DRIVER_DETAIL_LIMIT
from messagefoundry.verify_leaf import safe_detail_text as safe_detail_text
from messagefoundry.verify_leaf import safe_exc_detail as safe_exc_detail
from messagefoundry.verify_leaf import safe_exc_text as safe_exc_text


class Status(str, Enum):  # noqa: UP042
    """Outcome of a single verify check. ``str`` mix-in so it serialises as its value."""

    PASS = "PASS"  # nosec B105 — a check-status enum value, not a credential
    FAIL = "FAIL"
    SKIP = "SKIP"  # not applicable / not reachable here (e.g. driver extra not installed)
    MANUAL = "MANUAL"  # a human on the box must confirm it; not auto-checkable
    ERROR = "ERROR"  # the check itself broke


#: Statuses that make the overall run fail (exit 1). MANUAL/SKIP never fail a run.
FAILING: tuple[Status, ...] = (Status.FAIL, Status.ERROR)


# The detail scrub imported above lives in a stdlib-only leaf, so the acceptance harness can share it
# without loading this package's runner (BACKLOG #5389, #5395); it is re-exported for the checks.


@dataclass
class CheckResult:
    """One verify check and its outcome."""

    id: str
    title: str
    status: Status
    detail: str
    evidence: str = ""
