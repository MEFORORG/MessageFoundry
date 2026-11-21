- **A boolean where a number is meant is refused, in `messagefoundry.toml` and in the connection
  models.** pydantic read `true` as 1 and `false` as 0, so `delete_message_bodies_after_days =
  false` in `messagefoundry.toml` read as 0, and a code-first `RetryPolicy(max_attempts=False)` as a
  permanent no-retry failure. The settings sections now refuse a boolean on a numeric key at load,
  naming the key, for example `delete_message_bodies_after_days = false` or an `[[alerts.rules]]`
  `cooldown_seconds = true`. So do the numeric fields of `RetryPolicy`, `BuildupThreshold`,
  `StallThreshold`, `SaturationThreshold`, `ActiveWindow`, `BatchConfig`, `Validation` and
  `Destination`, built in code or from `connections.toml`; a boolean in a schedule window's `days`
  array is now refused rather than read as a weekday. The buildup and stall thresholds already refused a boolean, and the
  strict `connections.toml` tables a wrong-typed value; their refusal now names the field, and on
  the retry and batch tables says it was a boolean.
  (`BACKLOG #5509`)
