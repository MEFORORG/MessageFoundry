- **Dual-control approval requests carry an integrity seal on a store that holds a key.** Each
  `pending_approvals` row has its own HMAC-SHA256 seal (`pending_approvals.seal`) over every other
  column, under the same purpose-derived key the user, session and role seals use. That binds what a
  release acts on: the captured params, a held config reload's digest among them, and the requester
  id the self-approval refusal compares. Every INSERT and UPDATE of the table goes through one helper
  per backend. A new request is sealed as it is inserted; a status change reads the row, checks its
  seal, and writes the moved row and a new seal only while the row still carries the seal it read,
  so a row changed outside the store is never re-sealed. The approval gate reads requests only
  through its own seal check. A request that fails is left out of the pending and interrupted
  lists, and approving, rejecting or resolving it answers 409, so it runs nothing and expires where
  it stands. A repeat request never joins an open one that fails; it is filed on its own, and the store logs
  the skipped row at WARNING, with the audit row and alert following when the gate next reads it. A row
  changed while its operation runs is left `executing`, and the restart reconcile leaves it so. Each
  failure writes an `integrity.authority_seal_failed` audit row and raises `integrity_drift`, once
  per request per five minutes, and the engine keeps running. A keyed open names how many open
  requests carry no seal; nothing seals one automatically, so a request filed before this change
  can no longer be released and is requested again. `rotate-key` re-seals each request under the
  active key after checking it, and leaves one that fails as it is. A seal stops a request forged or
  edited outside the store, not an older sealed copy put back: a writer who kept a `pending` row
  with its seal can restore it after the request was decided. New column `pending_approvals.seal` on
  SQLite, Postgres and SQL Server. A keyless store, and the `vault_transit` provider, write and check
  no seal yet. (vault BACKLOG #2592)
