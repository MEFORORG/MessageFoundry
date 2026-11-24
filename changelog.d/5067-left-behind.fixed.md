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
- **These store refusals that follow a store open no longer say "nothing was written" where the
  open may already have run its own writing steps**, in `provision-admin`, `admin-reset-totp`,
  `admin-unlock` and `admin-set-notify-email`: a `StoreKeylessError`, `CipherError`,
  keyless-chain or unauditable-write refusal, `admin-unlock`'s refused account read,
  `admin-set-notify-email`'s refused audit append, in `admin-reset-totp` a store failure raised
  after an open returned, and in `provision-admin` a key-resolution, hop or SQLite store refusal
  raised after its pre-check or write open returned. A store keyed by the `vault_transit` cipher
  counts as keyed here. It says the change the command makes did not land, and names what the open may have
  changed, such as the schema, the salt record, the audit chain's genesis record and, on SQL
  Server under `[store].schema_management = auto`, the snapshot options. Where the command
  cannot tell whether the open reached its writing steps, as for a cipher refusal that can come
  before the open connects, it says the open may or may not have reached them and names those
  changes only as possible. The same holds for `provision-admin`'s OS-user and authenticator-enrolment refusals
  over an existing store, `admin-reset-totp`'s OS-user, enrolment and code-mismatch refusals, and
  `admin-unlock`'s refused row seal. A keyless-chain, keyless-provision or unauditable-write
  refusal is raised only after a full open, so it says the open may already have changed the
  database. In `admin-reset-totp` a store refusal or store failure raised at the
  replacement's own open, or after it but before the replacement is tried, names the earlier
  open, the one that checked the account before the key was shown, apart from the replacement's
  own, and names the open's one-time steps, such as the genesis record, for the earlier open
  alone. `provision-admin` now does the same over an existing store, naming its pre-check's
  open as the earlier one, for a key-resolution, hop, short-schema, key, cipher, keyless-chain,
  keyless-provision or unauditable-write refusal at or after its write's open, and for a
  SQLite store failure after that open returned. Other refusals after an open still say nothing was written,
  at least a store pin refusal under the host key provider, a refusal about the account itself
  such as a disabled Administrator, and `admin-reset-totp`'s refusals of the replacement itself. (`BACKLOG #5067`)
- **`provision-admin` would now keep its result when the store fails to close after the grant
  committed.** The failed close is a warning, so the recovery codes are still shown and the
  administrator_granted page still sent. (`BACKLOG #5067`)
