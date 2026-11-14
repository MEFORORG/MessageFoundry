- **`provision-admin` waits out store refusals on its repair revokes.** On the repair branch, at
  least the session revoke before it sets the password and the one after a successful
  Administrator grant each re-run for up to about five minutes, since the command has no request
  deadline; request callers keep the 15-second request budget. A revoke it gives up on after a
  successful grant tries to page the `administrator_granted` alert, and the command exits with an
  error naming `messagefoundry admin-revoke-sessions`. A refused run may leave the account's
  sessions live, so after any refused run, run `messagefoundry admin-revoke-sessions`, which ends
  the sessions it finds, of every account.
