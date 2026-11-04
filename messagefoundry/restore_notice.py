# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a store restore rolls back, said once (BACKLOG #5094).

``messagefoundry restore`` places the archive's whole store, so every change written to the store
after the archive was taken is gone from the one it places. :data:`RESTORE_ROLLBACK_NOTICE` is the
statement. The ``restore`` summary, its ``--json`` payload, the ``restore --help`` epilog and the
``store_restored`` alert's ``rollback_notice`` key carry it whole. The places too short for it, the
alert's ``detail`` and the age refusal, carry :data:`RESTORE_NOTICE_POINTER` instead, which names
the command that prints it on an installed engine. The adopter guide's restore section names every
class in :data:`RESTORE_ROLLBACK_CLASSES`. ``tests/test_b5094_restore_rollback_notice.py`` pins all
of that, and refuses an import here.

A leaf with no imports, because the CLI builds its parser from it on every run. The notice is
rendered as argparse help, so it must never hold a ``%``; the same test renders that help.
"""

from __future__ import annotations

__all__ = ["RESTORE_NOTICE_POINTER", "RESTORE_ROLLBACK_CLASSES", "RESTORE_ROLLBACK_NOTICE"]

#: The account and security changes a restore undoes, worded as what an operator does about each.
#: Drawn from the store's account, approval and attestation tables (``users``, ``roles``,
#: ``user_roles``, ``ad_group_role_map``, ``ad_group_scope_map``, ``webauthn_credentials``,
#: ``pending_approvals``, ``transit_bound_attestation``). Not a census: the restore replaces every
#: other table too, and a column added later joins none of these by itself, hence the notice's
#: "at least".
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
    "the vault_transit bound attestation: one withdrawn since (store withdraw-transit-bound) is "
    "live again, and one recorded since (store attest-transit-bound) is gone, so serve refuses "
    "under [security].enforcement = enforce until it is recorded again",
)

#: The statement every restore notice that has the room carries whole. Worded for a restore in
#: general, because ``restore --help`` shows it before anything was written. The audited changes
#: are bounded by the archive's newest audit row, which the ``restore`` summary, the age refusal
#: and the alert print beside it; anything unaudited written between that row and the snapshot is
#: in the archive and is not undone.
RESTORE_ROLLBACK_NOTICE = (
    "A restore undoes every change made to the store after the archive was taken. Each audited "
    "change after the archive's newest audit row must be re-applied by hand, at least: "
    + "; ".join(RESTORE_ROLLBACK_CLASSES)
    + ". Re-apply the removals before users can reach the restored engine: keep "
    "[security].local_access_only = true, its default, with any reverse proxy in front of the "
    "engine stopped, or keep the API port behind a closed firewall, until they are done. They "
    "need the web console or the API of a serving engine: the offline commands, at least "
    "admin-unlock, admin-reset-totp, admin-set-notify-email and admin-revoke-sessions, act on the "
    "store without one, but none of them disables or deletes an account, removes a passkey or "
    "changes a role. A restore can also send again: messages still queued when the archive was "
    "taken are processed and delivered again, those delivered since included, and an inbound that "
    "leaves files in place (after_read = leave), local or remote, ingests again the files it took "
    "since, so a partner can receive duplicates. Serving the restored store starts its "
    "connections at once, so those go out before any re-apply can finish. Where "
    "[integrity].audit_anchor_file holds an anchor taken after the archive, the start-up audit "
    "walk, where it runs, reports the restored log as truncated (an integrity_drift alert on "
    "audit-chain-truncated): expect it, and take a new anchor "
    "once the restore is confirmed. Messages received after the archive was taken, later "
    "reference-set syncs and later transform state are not in a restored store either."
)

#: Where to read :data:`RESTORE_ROLLBACK_NOTICE` from a place too short to hold it. ``restore
#: --help`` builds its parser only, so it prints the notice on any installed engine, with no
#: config, store or running engine.
RESTORE_NOTICE_POINTER = "messagefoundry restore --help lists what a restore rolls back."
