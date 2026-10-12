- **Session rows carry an integrity seal on a store that holds a key.** Each `sessions` row now
  stores an HMAC-SHA256 seal (`mfseal:v1:<key id>:<mac>`) over every column except `last_used_at`,
  under a key derived from the store key for this purpose alone. The engine writes the seal in one
  helper per backend and checks it in one place, `AuthService._load_session`. A row whose seal does
  not verify resolves to no session and is revoked. The refusal writes an
  `integrity.authority_seal_failed` audit row and raises an `integrity_drift` alert under the
  subject `authority-seal`, and the engine keeps running. A row sealed under a retired store key is
  ended with an INFO line instead, since that is a key change and not an integrity failure.
  Revoking a session blanks its seal. Ending every session of an account also raises that
  account's session epoch, and a session minted under an older epoch resolves to nothing.
  `rotate-key` now ends every session, so every operator signs in again after a rotation. New
  columns `sessions.user_epoch`, `sessions.seal` and `users.session_epoch` on SQLite, Postgres and
  SQL Server. A session row written before this change, or before the store had a local key, has
  no seal, so a keyed store refuses, reports and ends it once. A session that carries an older
  epoch than its account is ended and reported the same way. A keyless store, and the `vault_transit` provider, write and check no
  seal yet. (vault BACKLOG #2592)
