- **A directory account whose channel scope the directory narrowed can no longer step up with the
  old scope.** The code, passkey, enrolment, IdP and password re-bind step-up legs compared the
  account's roles with its current directory groups, but not its channel scope, so an account
  that lost a scope-mapped group renewed its window, or was minted an action-bound grant, with
  channels it no longer held until the reconciliation pass revoked it. Once the roles pass, each
  leg now refuses an account whose scope the groups would narrow, by the reconciliation pass's own
  scope rule, audited as `directory_scope_narrowed`. It charges nothing, writes no scope, and is
  answered as a demotion: sign out and sign in again, which writes the scope the groups grant now.
  An account whose groups grant Administrator is not asked. When the AD group-to-channel map fails
  its seal, an account holding a scope is refused as `directory_scope_map_unsealed` instead and is
  told to try again later or ask an administrator, as for a failing role map. A new sign-in
  reads the same failing map: it keeps a scope an administrator set, so that refusal stands, and
  withdraws a directory-set scope to NULL, which grants no channel, so the step-up then passes
  with no channels. See
  [SECURITY.md](../docs/SECURITY.md). (`vault BACKLOG #3081`)
