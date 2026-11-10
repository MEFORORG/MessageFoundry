- **SQL Server now has every `users(id)` foreign key the other two stores have, and trusts them.**
  `sessions.user_id` and `user_roles.user_id` gain the keys SQLite and Postgres already declare, so
  a sign-in there can no longer write a session for an account that does not exist.
  `fk_webauthn_credentials_user`, which an earlier release added `WITH NOCHECK`, is rebuilt
  `WITH CHECK`. On the first open after an upgrade, the store deletes the passkey, session and role
  grant rows that name an account that no longer exists, then adds each key; nothing can use such
  a row. A sign-in that commits while an account is being deleted now makes the delete fail and
  roll back whole, rather than leave the session behind. (`vault BACKLOG #2733`)
