- **`provision-admin` and `admin-reset-totp` now record a security notice whose send failed.** The
  notifier these offline commands build had no audit sink, so a takeover or authenticator notice
  that the relay refused left only a WARNING on stderr, while `provision-admin`'s audit row still
  read `holder_notice: dispatched`. Both commands now give it an audit sink, and a failed send
  writes the `auth.security_notice_undelivered` row the running engine writes, with the account's
  username as the actor. `provision-admin` passes the store it holds open. `admin-reset-totp`,
  whose store has closed by then, passes a sink that opens the store again for that row, and only
  when a send failed. `provision-admin` also says in its result when the send of the notice it
  queued raised, so its delivery is unconfirmed: a new `holder_notice_send_failed` field in
  `--json`, and a WARNING line in text output.
