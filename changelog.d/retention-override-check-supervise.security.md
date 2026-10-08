- **BREAKING -- `messagefoundry check` and `supervise` now refuse a connection's own keep-forever
  retention override that `serve` refuses.** An inbound `messages_days = 0` or an outbound
  `dead_letter_days = 0` with no `[security].allow_keeping_phi_indefinitely = true` is refused by
  an enforcing engine when it loads the graph. `check` passed that graph. A new required check,
  `retention-overrides`, now fails it in the engine's words. `supervise` did not look either, so
  on a first deployment each engine shard would have refused the graph and been restarted. It now
  refuses once, before it starts an engine shard, with exit code 2. Under `enforcement = warn`,
  or with the acknowledgement, both pass the graph; `check` shows the line the engine would
  write, and neither writes the warning or the `AUDIT:` line itself.
  **Who this would bite on first deployment:** a config repository whose CI runs `check` on a
  graph with such an override and no acknowledgement. **Remedy:** the failure names each
  connection and the switch. Read *Per-connection overrides* in
  [CONFIGURATION.md](../docs/CONFIGURATION.md#retention) before setting it. (`BACKLOG #2368`)
