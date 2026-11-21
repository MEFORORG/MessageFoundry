- **`GET /status` marks a log sink the flap latch alone holds.** Each entry in `log_sinks` gains
  `latch_only`, defined in [ADR 0162](../docs/adr/0162-fail-closed-application-log-write-guard-detect-roll-and-stop.md)
  amendment D. (`BACKLOG #5812`)
