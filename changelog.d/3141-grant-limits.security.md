- **The 0.5.2 notes listed only some of the directory grants of Administrator that raise no
  `administrator_granted` alert.** The directory can make an account an Administrator by adding it
  to a group already mapped to that role. Its next sign-in, or a directory reconciler pass when the
  account holds a live session, raises the alert, but at least these cases raise none. A sign-in
  that sees the grant first and fails with a server error after the role write loses the alert,
  because the retry gains nothing. A reconciler pass that the mass-revoke breaker aborts writes no
  roles. An account that never signs in again raises nothing when no pass reaches it, for example
  because it holds no live session or `[auth].ad_session_recheck_seconds` is 0. The 0.5.2 entries
  for vault BACKLOG #2610 and #3141 both missed the `ad_session_recheck_seconds = 0` case. A site
  that relies on this alert should also watch membership of the mapped group in the directory
  itself. The list is kept in
  [SECURITY.md](../docs/SECURITY.md#dual-control-approval-for-high-value-actions-wp-l3-04-asvs-235),
  *A directory grant*. No behaviour changed. (`vault BACKLOG #3141`)
