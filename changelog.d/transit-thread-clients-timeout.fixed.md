- **The `vault_transit` cipher gives each thread its own Vault client, and closes their
  connections.** The store calls the cipher on the event loop and in worker threads, and all of
  them used to share one hvac client and its one `requests` session. Each thread now builds its own
  client on its first Transit call, from the same inputs as the first, read once when the cipher is
  built. A thread's client is closed when the thread ends, and closing a SQLite, SQL Server or
  Postgres store closes the rest, even when an earlier close step raised; the cipher stays usable,
  because more than one store can share it. A thread whose client cannot be built gets the
  no-verdict outage error, not a refusal of the value. (`BACKLOG #5963`)
- **Every Transit request the cipher sends now times out at 5 seconds to connect and 10 seconds
  per socket read,** set by the engine rather than left at hvac's 30-second default. This does not
  bound how long a stalled Vault can hold the event loop, which the cipher still runs on: at least
  name resolution is untimed, the read figure applies to each socket read, and one cipher call can
  send several requests. A request the timeout ends is an outage that gave no verdict on the
  value. (`BACKLOG #5983`)
