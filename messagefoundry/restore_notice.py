# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a store restore rolls back, said once (BACKLOG #5094).

``messagefoundry restore`` places the archive's whole store, so every change written to the store
after the archive was taken is gone from the one it places. Every restore notice carries
:data:`RESTORE_ROLLBACK_NOTICE` whole: the ones shown after a restore and the ones shown before
one, such as the age refusal and the ``--allow-old-archive`` help. The adopter guide's restore
section names every class in :data:`RESTORE_ROLLBACK_CLASSES`.
``tests/test_b5094_restore_rollback_notice.py`` pins all of that, and refuses an import here.

A leaf with no imports, because the CLI builds its parser from it on every run. The notice is
rendered as argparse help, so it must never hold a ``%``; the same test renders that help.
"""

from __future__ import annotations

__all__ = ["RESTORE_ROLLBACK_CLASSES", "RESTORE_ROLLBACK_NOTICE"]

#: The account and security changes a restore undoes, worded as what an operator does about each.
#: Drawn from the store's account and approval tables (``users``, ``roles``, ``user_roles``,
#: ``ad_group_role_map``, ``ad_group_scope_map``, ``webauthn_credentials``,
#: ``pending_approvals``). Not a census: the restore replaces every other table too, and a column
#: added later joins none of these by itself, hence the notice's "at least".
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
    "dual-control approval decisions: a request decided after the archive is pending again, so "
    "reject it rather than approve it a second time",
)

#: The statement every restore notice carries whole. Worded for a restore in general, because the
#: age refusal shows it before anything was written.
RESTORE_ROLLBACK_NOTICE = (
    "A restore undoes every change made to the store after the archive's newest audit row, and "
    "each must be re-applied by hand, at least: "
    + "; ".join(RESTORE_ROLLBACK_CLASSES)
    + ". Re-apply the removals before users can reach the restored engine. Messages received "
    "after the archive was taken, later reference-set syncs and later transform state are not in "
    "a restored store either."
)
