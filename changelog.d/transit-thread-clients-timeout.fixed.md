- **The `vault_transit` cipher gives each thread its own Vault client, and closing a store closes
  their connections.** The store calls the cipher on the event loop and in worker threads, and all
  of them used to share one hvac client and its one `requests` session. Each thread now builds its
  own client, through the same construction as the first, on its first Transit call. Closing a
  SQLite, SQL Server or Postgres store now closes the pooled Vault sockets of every client the
  cipher built; the cipher stays usable, because more than one store can share it.
  (`BACKLOG #5963`)
- **Every Transit request the cipher sends now times out at 5 seconds to connect and 10 seconds
  per socket read,** set by the engine rather than left at hvac's 30-second default. The cipher
  still runs on the event loop, so a stalled Vault would still hold the loop, now for at most that
  long per request; a reply that keeps trickling bytes is not cut off by the read figure. A request
  the timeout ends is an outage that gave no verdict on the value. (`BACKLOG #5983`)
