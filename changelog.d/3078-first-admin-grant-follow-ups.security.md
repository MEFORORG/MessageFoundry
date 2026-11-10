- **The first-administrator grant refuses an account holding a passkey, and on SQLite it takes the
  write lock before it reads.** `provision-admin` enrols no passkey and clears an earlier holder's
  before it writes, so a passkey on the account when the role is granted was enrolled by that holder
  meanwhile; the grant now writes no role beside it, on all three stores, and a re-run clears it.
  On SQLite the grant opens with `BEGIN IMMEDIATE`, so a `provision-admin` run waits for a busy
  engine's write rather than failing busy at once and using up its re-runs. (`vault BACKLOG #3078`)
