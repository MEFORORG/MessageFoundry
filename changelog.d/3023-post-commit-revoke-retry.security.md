- **The session revoke that follows a committed auth change is retried, and a miss is audited.**
  A password change or reset, an MFA reset, a disable, a role, scope or custom-role change, a
  directory map save or resync and the `provision-admin` repair each end the account's sessions
  after their own change commits. A store refusal there, such as a pool shortage, a statement
  timeout or a lost connection, is now run again, up to three attempts. One refused every time is
  logged at ERROR and written as an `auth.sessions_revoke_failed` row naming the account and the
  change; before, the request failed with the change committed, the other sessions live and nothing
  recorded. A cancellation is not covered. See [SECURITY.md](../docs/SECURITY.md).
  (`vault BACKLOG #3023`)
