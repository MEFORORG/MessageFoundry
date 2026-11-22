- **`provision-admin` would now tell a refusal before its first account write from one after
  it, and the store commands would say what an open may have left.** `provision-admin` counted
  the write as started before the account reads that come first, so a cipher refusal from those
  reads exited 1 and never said to delete the authenticator entry it showed; it now exits 2 and
  says to delete it. A refused first INSERT of a new account also says to delete it, since no
  seed was stored. Once the write has started, the refusals that report it in words, at least a
  key-resolution, hop, integrity or SQLite store refusal such as "database is locked", now say
  to keep that entry until a later run of the command completes. A SQLite store refusal after
  the store opened no longer reads as "cannot open the store". A `StoreKeylessError` or `CipherError` raised once the
  write has started still reaches the command's last-resort exit 1, which names no entry.
- **A refusal that follows a store open no longer says "nothing was written" where the open may
  already have run its own writing steps**, in at least `provision-admin`, `admin-reset-totp`,
  `admin-unlock` and `admin-set-notify-email`: a `StoreKeylessError`, `CipherError`,
  keyless-chain or unauditable-write refusal, `admin-unlock`'s refused account read,
  `admin-set-notify-email`'s refused audit append, in `admin-reset-totp` a store failure raised
  after an open returned, and in `provision-admin` a key-resolution, hop or SQLite store refusal
  raised after its pre-check or write open returned. A store keyed by the `vault_transit` cipher
  counts as keyed here. It says the change the command makes did not land, and names at least what the open
  may have changed, such as the schema, the salt record, the audit chain's genesis record and, on
  SQL Server under `[store].schema_management = auto`, the snapshot options; where it can name
  none, it says the open's own steps may have written. At least a store pin refusal under the
  host key provider, and a refusal about the account itself, such as a disabled Administrator,
  still say nothing was written. (`BACKLOG #5067`)
