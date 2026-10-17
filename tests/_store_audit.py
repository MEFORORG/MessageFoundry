# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Audit arguments for store tests that are not about the audit row (vault BACKLOG #3217).

``cancel_queued`` and the four operator alert mutations take a REQUIRED ``audit``, so a test of the
mutation itself still has to pass one. These are the ones it passes. The row-and-change atomicity
is the subject of ``tests/_operator_audit_atomic_contract.py``, not of these tests. Extra-free.
"""

from __future__ import annotations

from messagefoundry.store.store import AuditAppend


def no_purge_audit(_cancelled: int) -> None:
    """A purge audit that records nothing, for a test about the cancel alone."""
    return None


#: The alert row a test about the alert mutation alone passes.
ALERT_AUDIT = AuditAppend("test.alert", actor="test")
