# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a store restore rolls back, said once (BACKLOG #5094).

``messagefoundry restore`` places the archive's whole store, so every change written to the store
after the archive was taken is gone from the one it places. The post-restore notices carry
:data:`RESTORE_ROLLBACK_NOTICE` whole, and the adopter guide's restore section names every class in
:data:`RESTORE_ROLLBACK_CLASSES`; ``tests/test_b5094_restore_rollback_notice.py`` pins them.

A leaf with no imports, because the CLI builds its parser from it and the CLI's startup import
budget (``tests/test_startup_import_budget.py``) names each engine module it loads. The same test
file refuses an import here.
"""

from __future__ import annotations

__all__ = ["RESTORE_ROLLBACK_CLASSES", "RESTORE_ROLLBACK_NOTICE"]

#: The account and security changes a restore undoes, worded as what an operator does about each.
#: Read off the store's account and approval tables (``users``, ``roles``, ``user_roles``,
#: ``ad_group_role_map``, ``ad_group_scope_map``, ``webauthn_credentials``,
#: ``pending_approvals``). The notice says "at least" because the restore replaces every other
#: table too, and a column added later joins none of these by itself.
RESTORE_ROLLBACK_CLASSES: tuple[str, ...] = (
    "account creations, disables, enables and deletes",
    "account locks and unlocks",
    "role changes and custom roles",
    "password resets and password changes, self-service ones included: force a reset where the "
    "user's own change cannot be replayed",
    "MFA and passkey enrolments and removals",
    "recovery codes issued or used: reissue them",
    "federated sign-in (OIDC) bindings and unbindings",
    "notify-email changes",
    "channel scopes",
    "AD group-to-role and AD group-to-scope maps",
    "dual-control approval decisions",
)

#: The statement every post-restore notice carries whole. It leads with the instruction, because
#: the alert instance's reason column keeps only about the first 200 characters of the alert's
#: detail, and the instruction must survive that cut.
RESTORE_ROLLBACK_NOTICE = (
    "Every change made after the archive's newest audit row is undone and must be re-applied by "
    "hand, at least: "
    + "; ".join(RESTORE_ROLLBACK_CLASSES)
    + ". Messages received after the archive was taken are not in the restored store either."
)
