- **Under `vault_transit`, a bulk walk no longer queues the auth path's row seal checks.** Before,
  a store call that makes many Transit round trips in one go ran on the same pool of 8 threads as
  the row seal checks on sign-in and session reads, holding one thread for the whole walk: at least
  an audit chain walk, a Postgres or SQL Server reference cache decode, SQL Server's state cache
  load and each at-open seal batch. A few such walks at once would leave a seal check waiting for
  a thread for as long as the walks ran. They now run on a separate bulk pool, so the seal pool
  stays free for seal checks and single cell calls. Its size is the new
  `[store].transit_bulk_workers` (`MEFOR_STORE_TRANSIT_BULK_WORKERS`), default `2`, from `1` to
  `64`; any other value is refused when the settings load. The default is a judgement, not a
  measurement. Past that bound a bulk walk waits behind the others, with no deadline. The engine
  stop now shuts both pools down after the store closes, waiting off the event loop for any call
  still running. Nothing changes under `aesgcm`. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md). (`BACKLOG #3929`)
