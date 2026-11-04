# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Audit arguments for store tests that are not about the audit row (vault BACKLOG #3217, #2624).

Store mutations that take a REQUIRED ``audit`` include at least ``cancel_queued``, the four
operator alert mutations, ``replay``, ``replay_dead``, ``resend_to`` and ``reingress``;
``tests/test_operator_audit_required.py`` walks the current set. A test of the mutation itself
still has to pass one. These are the ones it passes. The row-and-change atomicity
is the subject of ``tests/_operator_audit_atomic_contract.py``, not of these tests. Extra-free.
"""

from __future__ import annotations

from messagefoundry.store.store import AuditAppend


def no_operator_audit(_result: object) -> None:
    """An operator audit that records nothing, for a test about the replay, resend, re-ingress or
    cancel alone. It writes what the old ``audit=None`` default wrote: no row (BACKLOG #2624). The
    store now refuses ``None`` itself (BACKLOG #5069), so a test that wants no row passes this."""
    return None


#: The same audit under the name the purge tests use; one function, not two copies (BACKLOG #5071).
no_purge_audit = no_operator_audit


#: The alert row a test about the alert mutation alone passes.
ALERT_AUDIT = AuditAppend("test.alert", actor="test")
