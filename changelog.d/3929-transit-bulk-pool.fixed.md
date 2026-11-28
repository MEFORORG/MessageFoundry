- **Under `vault_transit`, a bulk walk no longer queues the auth path's row seal checks.** Before,
  a store call that makes many Transit round trips in one go ran on the same pool of 8 threads as
  the row seal checks on sign-in and session reads, holding one thread for the whole walk: at least
  an audit chain walk, a Postgres or SQL Server reference cache decode, SQL Server's state cache
  load at open and each at-open seal batch. Eight such walks at once, the seal pool's size, would
  leave a seal check waiting for a thread for as long as the walks ran; fewer took that many
  threads from the checks and from single cell calls. They now run on a separate bulk pool, so none
  holds a seal pool thread; single cell calls still share that pool with the seal checks. Its size is the new
  `[store].transit_bulk_workers` (`MEFOR_STORE_TRANSIT_BULK_WORKERS`), default `2`, from `1` to
  `64`; any other value is refused when the settings load. The default is a judgement, not a
  measurement. Past that bound a bulk walk waits behind the others, with no deadline, so at most
  that many run at once where up to 8 could before. When the last engine in the process
  stops, it now shuts both pools down after its store closes: queued calls are cancelled, and it
  waits off the event loop up to 2 seconds, or what is left of its stop budget, for calls still
  running, then leaves them to finish. Nothing changes under `aesgcm`. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md). (`BACKLOG #3929`)
