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

from messagefoundry.store.store import AuditAppend, mutation_changed

#: The row :func:`no_operator_audit` records for a result that changed the store.
OPERATOR_AUDIT = AuditAppend("test.operator", actor="test")


def no_operator_audit(result: object) -> AuditAppend | None:
    """The least audit the store accepts, for a test about the replay, resend, re-ingress or cancel
    alone: no row for a result that changed nothing, and :data:`OPERATOR_AUDIT` for one that did.
    The store refuses ``None`` in place of the audit, and a ``None`` row for a change, since
    BACKLOG #5069, so a test that is not about the row passes this."""
    return OPERATOR_AUDIT if mutation_changed(result) else None


#: The same audit under the name the purge tests use; one function, not two copies (BACKLOG #5071).
no_purge_audit = no_operator_audit


#: The alert row a test about the alert mutation alone passes.
ALERT_AUDIT = AuditAppend("test.alert", actor="test")
