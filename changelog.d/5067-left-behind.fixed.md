- **`provision-admin` would now tell a refusal before its first write from one after it, and
  say what a key or cipher refusal may have left.** It counted the write as started before the
  account reads that come first, so a cipher refusal from those reads exited 1 and never said to
  delete the authenticator entry it showed; it now exits 2 and says so. A refusal once the write
  has started now names that entry too: keep it until a later run of the command completes. A
  key, cipher or keyless-chain refusal in `provision-admin`, `admin-reset-totp` and
  `admin-unlock` no longer says "nothing was written" where the open may already have run its
  own writing steps: it says the command's own writes did not run, and names at least what the
  open may have changed, such as the schema and, on SQL Server under
  `[store].schema_management = auto`, the snapshot options. (`BACKLOG #5067`)
