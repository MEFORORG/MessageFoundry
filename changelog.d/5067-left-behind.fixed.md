- **`provision-admin` would now tell a refusal before its first account write from one after
  it, and say what a key-decryption or keyless-chain refusal may have left.** It counted the
  write as started before the account reads that come first, so a cipher refusal from those
  reads exited 1 and never said to delete the authenticator entry it showed; it now exits 2 and
  says to delete it. Once the write has started, the refusals that report it in words, at least
  a key-resolution, hop, schema, keyless or integrity refusal, now say to keep that entry until
  a later run of the command completes. A key or cipher refusal raised once the write has
  started still reaches the command's last-resort exit 1, which names no entry. A
  `StoreKeylessError`, `CipherError` or keyless-chain refusal in `provision-admin` and
  `admin-reset-totp`, one that `admin-unlock`'s store open raises, and in `provision-admin` a key-resolution, hop, schema
  or keyless refusal raised after the write's store open returned, no longer says "nothing was written" where the open may already
  have run its own writing steps: it says the change the command makes did not land, and names
  at least what the open may have changed, such as the schema and, on SQL Server under
  `[store].schema_management = auto`, the snapshot options. At least a store pin refusal under
  the host key provider still says nothing was written. (`BACKLOG #5067`)
