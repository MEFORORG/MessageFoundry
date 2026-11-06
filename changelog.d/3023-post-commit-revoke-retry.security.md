- **The session revoke that follows a committed auth change is retried, and a miss is audited.**
  At least a password change or reset, an MFA reset, a disable, a role, scope or custom-role edit,
  a directory map save or resync and the `provision-admin` repair end the account's sessions after
  their own change commits. A store refusal there, such as a pool shortage, a statement
  timeout or a lost connection, is now run again, up to three attempts within 15 seconds. One it gives up on is
  logged at ERROR and written as an `auth.sessions_revoke_failed` row naming the account and the
  change; before, the request failed with the change committed, the other sessions live and nothing
  recorded. A custom-role delete, which revokes before it deletes, the directory reconciler's
  demotion and a cancellation are not covered. See [SECURITY.md](../docs/SECURITY.md).
  (`vault BACKLOG #3023`)
