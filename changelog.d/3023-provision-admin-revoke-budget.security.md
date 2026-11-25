- **`provision-admin` re-runs some of its repair revokes for longer when the store refuses them.**
  On the repair branch, at least the session revoke before it sets the password and the one after
  an Administrator grant the store reported as made each re-run on a five-minute budget, since the
  command has no request deadline; request callers keep the 15-second request budget. A revoke it
  gives up on after such a grant still tries to page the `administrator_granted` alert, as a
  granted run does, and the command exits with an error naming
  `messagefoundry admin-revoke-sessions`. A run refused after it wrote to the account may leave that
  account's sessions live; `messagefoundry admin-revoke-sessions`, run once the store answers, with
  the `--service-config` or `--db` the command used, ends the sessions it finds, of any account.
  (`vault BACKLOG #3023`)
