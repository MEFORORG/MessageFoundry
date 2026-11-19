- **The `vault_transit` cipher gives each thread its own Vault client.** The event loop and the
  store's worker threads used to share one hvac client and its one `requests` session. The thread
  that opened the store uses the client built at startup; any other thread builds its own on its
  first Transit call, with the same address, token and CA anchor. No thread closes another
  thread's client. Closing a SQLite, SQL Server or Postgres store, even after an earlier close
  step raised, closes the closing thread's client and marks the others stale. Each other thread
  releases its own at least on its next call, which builds a fresh one, or when it ends. A client
  not released that way is left to garbage collection. The cipher stays usable, since stores can
  share it. A thread whose client cannot be built gets, on a read, the no-verdict outage error; on
  a write, the error the cipher's failure classifier reads the build failure as. (`BACKLOG #5963`)
- **Every Transit request the cipher sends now times out at 5 seconds to connect and 30 seconds
  per socket read,** set by the engine rather than left at hvac's 30-second default for both; the
  read figure is unchanged and only the connect bound is tighter. This does not
  bound how long a stalled Vault can hold the event loop, which the cipher still runs on: at least
  name resolution is untimed, the read figure applies to each socket read, and one cipher call can
  send several requests. A request the timeout ends is an outage that gave no verdict on the
  value. (`BACKLOG #5983`)
