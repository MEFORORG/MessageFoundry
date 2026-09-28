# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rows an audit read leaves out, applied inside the store query (BACKLOG #1131).

The store only knows HOW to leave rows out. WHICH rows, and for whom, is decided in
:mod:`messagefoundry.auth.audit_visibility`, so the store stays free of any permission logic.

**The exclusion runs in SQL, before ``LIMIT``, on purpose.** Filtered after the fetch, a page asked
for N rows would come back short by exactly the number of hidden rows in it, and that shortfall is
itself the signal the exclusion exists to remove.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

__all__ = ["AuditExclusion"]


@dataclass(frozen=True)
class AuditExclusion:
    """``actions`` hides every row with one of those actions. ``rows`` hides a row only when both its
    action and its detail match one ``(action, detail)`` pair exactly: the lock refusals of the
    factor and directory legs share an action with ordinary failures, and differ only in detail."""

    actions: frozenset[str] = frozenset()
    rows: frozenset[tuple[str, str]] = frozenset()

    def __post_init__(self) -> None:
        # An empty detail would also match every NULL-detail row of that action (see ``clauses``).
        if any(not detail for _, detail in self.rows):
            raise ValueError("an excluded (action, detail) pair needs a non-empty detail")

    def clauses(self, bind: Callable[[str], str]) -> list[str]:
        """The WHERE clauses, to be ANDed. ``bind`` records one value as a query parameter and
        returns its placeholder, so no value is ever formatted into the SQL text. Sorted, so the SQL
        and its parameter order are the same on every call."""
        out: list[str] = []
        if self.actions:
            marks = ", ".join(bind(a) for a in sorted(self.actions))
            out.append(f"action NOT IN ({marks})")
        for action, detail in sorted(self.rows):
            # COALESCE, because ``detail = ?`` on a NULL detail is NULL and NOT NULL is NULL, which
            # WHERE reads as false: without it every NULL-detail row of that action would vanish.
            out.append(f"NOT (action = {bind(action)} AND COALESCE(detail, '') = {bind(detail)})")
        return out
