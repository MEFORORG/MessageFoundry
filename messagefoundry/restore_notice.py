# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a store restore rolls back, said once (BACKLOG #5094).

``messagefoundry restore`` places the archive's whole store, so every change written to the store
after the archive was taken is gone from the one it places. Every notice an operator acts on after
a restore carries :data:`RESTORE_ROLLBACK_NOTICE` whole, and the adopter guide's restore section
names every class in :data:`RESTORE_ROLLBACK_CLASSES`; a test pins both.

A leaf with no imports, because the CLI builds its parser from it and the CLI's startup import
budget (``tests/test_startup_import_budget.py``) names each engine module it loads.
"""

from __future__ import annotations

__all__ = ["RESTORE_ROLLBACK_CLASSES", "RESTORE_ROLLBACK_NOTICE"]

#: The account and security changes a restore undoes, as an operator would re-apply them. Read off
#: the store's account tables (``users``, ``roles``, ``user_roles``, ``ad_group_role_map``,
#: ``ad_group_scope_map``, ``webauthn_credentials``). The notice says "at least" because the
#: restore replaces every other table too, and a later column joins none of these by itself.
RESTORE_ROLLBACK_CLASSES: tuple[str, ...] = (
    "account creations, disables, enables and deletes",
    "role changes and custom roles",
    "password resets and password changes, self-service ones included",
    "MFA and passkey enrolments and removals, and recovery codes issued or used",
    "notify-email changes",
    "channel scopes",
    "AD group-to-role and AD group-to-scope maps",
)

#: The one sentence every restore notice carries whole. It keeps "must be re-applied by hand"
#: because the operator's act is the point of it.
RESTORE_ROLLBACK_NOTICE = (
    "A restore puts back the archive's whole store, so every change made after its newest audit "
    "row is undone. These must be re-applied by hand, at least: "
    + "; ".join(RESTORE_ROLLBACK_CLASSES)
    + "."
)
