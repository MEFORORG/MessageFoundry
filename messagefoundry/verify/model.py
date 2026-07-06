# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared result model for the deployment verifier."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Status(str, Enum):
    """Outcome of a single verify check. ``str`` mix-in so it serialises as its value."""

    PASS = "PASS"  # nosec B105 — a check-status enum value, not a credential
    FAIL = "FAIL"
    SKIP = "SKIP"  # not applicable / not reachable here (e.g. driver extra not installed)
    MANUAL = "MANUAL"  # a human on the box must confirm it; not auto-checkable
    ERROR = "ERROR"  # the check itself broke


#: Statuses that make the overall run fail (exit 1). MANUAL/SKIP never fail a run.
FAILING: tuple[Status, ...] = (Status.FAIL, Status.ERROR)


@dataclass
class CheckResult:
    """One verify check and its outcome."""

    id: str
    title: str
    status: Status
    detail: str
    evidence: str = ""
