- **SQL Server now has every `users(id)` foreign key the other two stores have, and trusts them.**
  `sessions.user_id` and `user_roles.user_id` gain the keys SQLite and Postgres already declare, so
  a sign-in there can no longer write a session for an account that does not exist.
  `fk_webauthn_credentials_user`, which an earlier release added `WITH NOCHECK`, is rebuilt
  `WITH CHECK`. On the first open after an upgrade, the store deletes the passkey, session and role
  grant rows that name an account that no longer exists, logs a warning with how many it deleted
  from each table it deleted any from, naming no account, then adds each key; nothing can use such
  a row. A sign-in started while an account is being deleted waits for the delete, and its session
  write then fails on the session key, rather than leave a session behind or fail the delete.
  (`vault BACKLOG #2733`)
