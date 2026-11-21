- **At least `RetryPolicy` `max_attempts`, `ActiveWindow` `days` and `BatchConfig` `max_wait_ms`
  refuse a boolean when validated in code-first config, where main read it as 0 or 1.** A boolean
  in a `connections.toml` schedule window's `days` is refused too, where it was read as a weekday.
  (`BACKLOG #5509`)
