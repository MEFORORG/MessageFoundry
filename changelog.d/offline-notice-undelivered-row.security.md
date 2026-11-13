- **`provision-admin` and `admin-reset-totp` now record a security notice whose send failed.** The
  notifier these offline commands build had no audit sink, so a takeover or authenticator notice
  that the relay refused left only a WARNING on stderr, while `provision-admin`'s audit row still
  read `holder_notice: dispatched`. Both commands now pass their store, and a failed send writes
  the `auth.security_notice_undelivered` row the running engine writes, with the recipient as the
  actor. `admin-reset-totp` opens its store again for the notice, because the swap's store is
  closed by then.
