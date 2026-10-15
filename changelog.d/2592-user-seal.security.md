- **Each account's authorization record carries an integrity seal on a store that holds a key.**
  One HMAC-SHA256 seal (`users.authz_seal`, `mfseal:v1:<key id>:<mac>`) covers every other column
  of the account's `users` row, the TOTP secret's stored bytes included, its `user_roles` rows and
  a digest of its passkeys (`users.cred_digest`), under the same purpose-derived key the session
  seal uses. Every INSERT or UPDATE of those tables goes through one helper per backend, with at
  least two named exceptions: the passkey sign-count update, which the digest leaves out, and the
  one-time column backfills of the schema migration. Deletes need no key and stay plain. The
  helper checks the seal it read before it writes, refuses the write and re-seals nothing when the
  check fails, and writes the whole record back with a compare on the old seal. `AuthService`
  checks the seal in one loader before it acts on an account, and the identity build, the
  password, TOTP and recovery-code checks take the checked type. An account whose record fails is
  refused, writes an `integrity.authority_seal_failed` audit row and raises `integrity_drift` under
  the `authority-seal` subject, and the engine keeps running; an API write the store refuses for
  that reason answers 409. A passkey set that no longer matches its digest refuses every passkey
  ceremony for that account the same way. The account's session epoch is now inside the seal, and
  the last-administrator guard counts only administrators whose record passes. A record sealed
  under a retired store key still verifies, and `rotate-key` re-encrypts each account's TOTP secret
  and re-seals the account under the active key in one write, so removing the retired key
  afterwards signs nobody out. New columns `users.cred_digest` and `users.authz_seal` on SQLite,
  Postgres and SQL Server. An account written before this change, or before the store had a local
  key, has no seal, so a keyed store refuses it: nothing seals a blank record automatically. A
  keyed open names how many such accounts there are, and `provision-admin` under a new username is
  the way back in. A keyless store, and the `vault_transit` provider, write and check no seal yet.
  (vault BACKLOG #2592)
