- **At least `RetryPolicy`, `ActiveWindow` and `BatchConfig` refuse a boolean where a number is
  meant when built in Python config, which earlier code read as 0 or 1.** A boolean in a
  `connections.toml` schedule window's `days` is refused too, where it was read as a weekday.
  (`BACKLOG #5509`)
