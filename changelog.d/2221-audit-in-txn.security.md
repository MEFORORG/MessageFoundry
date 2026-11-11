- **A directory role change now commits with its audit row.** The `auth.ad_roles_resynced` row
  that a directory sign-in or a directory reconciler pass writes, and the reconciler's
  `auth.ad_session_revoked` row, now commit in the role write's or the revoke's own transaction.
  If the store refuses the row there, the write is applied again without it and the row is then
  written on its own. On a sign-in, a row the store refuses on its own too is lost and pages
  `audit_write_failed`, keyed `directory-sign-in:<action>`. A reconciler pass that ends without
  raising pages it once for each action whose row the store refused during the pass, keyed
  `directory-reconciler:<action>`; a pass used to only log a refused row. A store that is not the
  shape the row needs, such as one missing a table, is not taken as a refusal: the write is still
  applied again without the row, and the error is then raised as a defect's is rather than paged
  as a refused row. On a directory sign-in,
  any error from writing the roles and their row still leaves the engine trying to end the
  account's other sessions and sending the roles-changed notice before the error is raised, and
  when the account's directory groups newly map it to Administrator, `administrator_granted`
  pages before the sign-in fails. (`BACKLOG #2221`, `BACKLOG #3018`)
