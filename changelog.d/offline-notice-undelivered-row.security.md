- **`provision-admin` and `admin-reset-totp` now record a security notice whose send failed.** The
  notifier these offline commands build had no audit sink, so a takeover or authenticator notice
  that the relay refused left only a WARNING on stderr, while `provision-admin`'s audit row still
  read `holder_notice: dispatched`. Both commands now pass their store, and a failed send writes
  the `auth.security_notice_undelivered` row the running engine writes, with the account's username
  as the actor. `admin-reset-totp`, whose store has closed by then, opens it again for that row, and only
  when a send failed.
