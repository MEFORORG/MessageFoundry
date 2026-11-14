- **`provision-admin` waits out store refusals on its repair revokes.** Its repair branch's
  revoke before it sets the password, and its revoke after the grant, each re-run for up to five
  minutes, since the command has no request deadline. When a run is refused after it set the
  password, because an authenticator stage or enable step was refused or the grant was refused,
  the revoke it then makes runs on the 15-second request budget of up to three attempts, as request
  callers' revokes do; a repaired run refused for an unexpected grant outcome revokes on the
  five-minute budget instead. A revoke it gives up on after a successful Administrator grant
  still raises the `administrator_granted` alert, then refuses the command with text naming
  `messagefoundry admin-revoke-sessions`, the host command that ends the earlier holder's session;
  one given up on before the grant refuses it with no password or role written. A run refused
  after it set the password also tries to end the account's sessions, except a fresh account's run
  refused for an unexpected grant outcome; a revoke the store refuses is named in the refusal text.
