- **A directory role change now commits with its audit row.** The `auth.ad_roles_resynced` row
  that a directory sign-in or a directory reconciler pass writes, and the reconciler's
  `auth.ad_session_revoked` row, now commit in the role write's or the revoke's own transaction.
  If the store refuses the row there, the write is applied again without it and the row is then
  written on its own. A row the store refuses on its own too is lost and pages
  `audit_write_failed`, keyed `directory-sign-in:<action>` for a sign-in and
  `directory-reconciler:<action>` for a pass. A pass that ends without raising also pages the
  other audit rows the store refused during it, which it used to only log. On a directory
  sign-in, any error from writing the roles and their row still leaves the engine trying to end
  the account's other sessions and sending the roles-changed notice before the error is raised,
  and when the sync gave the account Administrator, `administrator_granted` pages before the
  sign-in fails. (`BACKLOG #2221`, `BACKLOG #3018`)
