- **A directory account whose channel scope the directory narrowed can no longer step up with the
  old scope.** The code, passkey, enrolment, IdP and password re-bind step-up legs compared the
  account's roles with its current directory groups, but not its channel scope, so an account
  that lost a scope-mapped group renewed its window, or was minted an action-bound grant, with
  channels it no longer held until the reconciliation pass revoked it. Once the roles pass, each
  leg now refuses an account whose scope the groups would narrow, by the reconciliation pass's own
  scope rule, audited as `directory_scope_narrowed`. It charges nothing, writes no scope, and is
  answered as a demotion: sign out and sign in again, which writes the scope the groups grant now.
  An Administrator is not asked. See [SECURITY.md](../docs/SECURITY.md). (`vault BACKLOG #3081`)
