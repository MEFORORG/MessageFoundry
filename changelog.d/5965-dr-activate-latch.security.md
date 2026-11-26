- **`[dr].activate` is removed, and a DR box always starts passive.** With `[dr].enabled` it
  latched the DR run-profile at engine construction and bound the priority feeds without the
  seed verification, the takeover hook (when one is set) or the `dr.activate` audit row that
  `POST /dr/activate` runs. The key is now refused at load as a removed key, `true` or `false`,
  from the file, the environment (`MEFOR_DR_ACTIVATE`) or code, and its refusal names
  `POST /dr/activate` as the route. The engine and the DR coordinator no longer read any setting
  to start active, so under `serve` a DR box always starts passive. A box that was activated and
  restarts comes back passive, logs at ERROR and raises the new `dr_restarted_passive` alert,
  critical unless a matching rule names its own severity, which closes the open `dr_activated`.
  It never re-activates itself: `POST /dr/activate` brings it back, and `POST /dr/release` on
  the passive box records that it stays passive. Each engine shard reads its own `dr.activate`
  and `dr.release` rows, which now name the host and the shard, and alerts on its own; the DR
  alerts' label adds the shard on an engine shard. No DR box runs a scheduled backup pass any
  more, activated included, so a later re-activation of the same restore still passes the
  `[dr].restore_token` vintage check.
  (`BACKLOG #5965`)
