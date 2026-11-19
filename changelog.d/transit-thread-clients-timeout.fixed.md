- **The `vault_transit` cipher gives each thread its own Vault client, and closes their
  connections.** The store calls the cipher on the event loop and in worker threads, and all of
  them used to share one hvac client and its one `requests` session. Each thread now builds its own
  client on its first Transit call, with the same address, token and CA anchor as the first. A
  thread's client is closed on that thread, never from another one, so a Transit call in flight
  on one thread is not cut off by a close on another. Closing a SQLite, SQL Server or Postgres
  store, even when an earlier close step raised, closes the closing thread's client and marks
  every other thread's stale: each of those threads closes its own on its next call, which builds
  a fresh one, or when it ends. The cipher stays usable, because more than one store can share it. A cipher no store holds is not closed this
  way. Building a client sends no request to Vault, so a build failure is never a failure of a
  request to Vault. A thread whose client cannot be built gets, on a read, the no-verdict outage
  error, since Vault was never asked about the value. On a write it gets the error the cipher's
  failure classifier reads the build failure as, which is the outage error only where that
  classifier reads it as an outage. A stage handoff does not read which of the two it is.
  (`BACKLOG #5963`)
- **Every Transit request the cipher sends now times out at 5 seconds to connect and 30 seconds
  per socket read,** set by the engine rather than left at hvac's 30-second default for both; the
  read figure is unchanged and only the connect bound is tighter. This does not
  bound how long a stalled Vault can hold the event loop, which the cipher still runs on: at least
  name resolution is untimed, the read figure applies to each socket read, and one cipher call can
  send several requests. A request the timeout ends is an outage that gave no verdict on the
  value. (`BACKLOG #5983`)
