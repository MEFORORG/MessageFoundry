- **The `vault_transit` cipher gives each thread its own Vault client.** The event loop and the
  store's worker threads used to share one hvac client and its one `requests` session. The thread
  that builds the cipher uses the client built with it; any other thread builds its own when it
  first needs one, with the same address, token and CA anchor. The cipher never closes a thread's
  client from another thread. Closing a SQLite, SQL Server or Postgres store, even after an
  earlier close step raised, closes the closing thread's client and marks the others stale. Each
  other thread releases its own at least on its next Transit request, which builds a fresh client,
  or when it ends before interpreter shutdown; until then a stale client stays open. The cipher
  stays usable, since stores can share it.
  Where a thread's client cannot be built, a data-key decrypt gets the no-verdict outage error and
  a data-key encrypt the error the cipher's failure classifier reads the build failure as.
  (`BACKLOG #5963`)
- **Every Transit request the cipher sends now times out at 5 seconds to connect and 30 seconds
  per socket read,** set by the engine rather than left at hvac's 30-second default for both; the
  read figure is unchanged and only the connect bound is tighter. This does not
  bound how long a stalled Vault can hold the event loop, which the cipher still runs on: at least
  name resolution is untimed, the read figure applies to each socket read, and one cipher call can
  send several requests. A request the timeout ends is an outage that gave no verdict on the
  value. (`BACKLOG #5983`)
