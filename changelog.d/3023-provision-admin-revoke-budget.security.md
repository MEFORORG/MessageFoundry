- **`provision-admin` waits out store refusals on its repair revokes.** Its repair branch's
  session revokes re-run for up to five minutes, since the command has no request deadline;
  request callers keep the 15-second budget. A revoke it gives up on after the Administrator grant
  still raises the `administrator_granted` alert, then refuses the command with text naming
  `messagefoundry admin-revoke-sessions`, the host command that ends the earlier holder's session;
  one given up on before the grant refuses it with no password or role written. A run refused
  after it set the password also ends the account's sessions.
