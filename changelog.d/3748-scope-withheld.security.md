- **The audit trail withholds the stored channel lists and scope sources of four actions from a
  reader without `users:manage`.** `GET /audit`, its console page and `GET /audit/export` narrow
  these four: `user.channel_scope_changed`, `auth.ad_scope_resynced`, `auth.ad_session_revoked` (its
  `scope_from` and `scope_to`) and `user.channel_scope_change_refused` (its `owner`, `read_source`,
  `expected_source` and `reason`), as `GET /users` already withholds every account's scope. Those
  four are what a census of the writers found; a new action that names a scope is shown whole until
  it is added to the list. Rows left whole can still let such a reader infer a scope, at least
  `auth.channel_denied` and channel-attributed access rows, and `/me/security-events` is not
  narrowed; `docs/SECURITY.md` names what is left open. The engine's user summary now withholds the
  scope unless its caller asks for it, the console's copy needs every page to say which, and the
  console's Approvals note for `requester_not_authorized` names the causes it covers, a deleted
  requester and an unbound auth service among them.
