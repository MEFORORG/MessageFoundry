- **`GET /status` marks a log sink the flap latch alone holds.** Each entry in `log_sinks` gains
  `latch_only`, true when the sink reads `unwritable` only through the flap latch while its own
  state is `rolled`. [ADR 0162](../docs/adr/0162-fail-closed-application-log-write-guard-detect-roll-and-stop.md)
  amendment D says when it is set. (`BACKLOG #5812`)
