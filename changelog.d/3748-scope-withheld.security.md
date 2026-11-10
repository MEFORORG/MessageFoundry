- **An account's channel scope, and who owns it, go only to a `users:manage` holder in the audit
  trail too.** `GET /audit`, its console page and `GET /audit/export` withhold from a reader
  without `users:manage` the channel lists and scope sources in the detail of four actions:
  `user.channel_scope_changed`, `auth.ad_scope_resynced`, `auth.ad_session_revoked` (its
  `scope_from` and `scope_to`) and `user.channel_scope_change_refused` (its `owner`,
  `read_source`, `expected_source` and `reason`), as `GET /users` already withholds every
  account's scope. Those four are what a census of the writers found; a new action that names a
  scope is shown whole until it is added to the list. The engine's user summary now withholds the scope unless its
  caller asks for it, the console's copy needs every page to say which, and the console's Approvals
  note for `requester_not_authorized` names the causes it covers, a deleted requester and an
  unbound auth service among them.
