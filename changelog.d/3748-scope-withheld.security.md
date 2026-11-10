- **A scope change's channel list goes only to a `users:manage` holder in the audit trail too.**
  `GET /audit`, its console page and `GET /audit/export` show a reader without `users:manage` a
  `user.channel_scope_changed` or `auth.ad_scope_resynced` row with its detail cut to the
  account id, where the row has one, and `"channels": "withheld"`, as `GET /users` already
  withholds every account's scope. The engine's user summary now withholds the scope unless its
  caller asks for it, the console's copy needs every page to say which, and the console's Approvals
  note for `requester_not_authorized` names the causes it covers, a deleted requester and an
  unbound auth service among them.
