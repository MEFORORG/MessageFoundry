- **`messagefoundry dryrun` and `messagefoundry check` now apply an inbound's strict-validation
  timeout, as the listener does.** A strict validate that takes longer than
  `validation.strict_timeout_s` previews as `ERROR` with the listener's own text,
  `strict-validation timed out after <N>s`, where before the preview reported whatever hl7apy found.
  The preview validates inline and measures the time, so a slow fixture still runs its full validate
  time rather than being abandoned at the timeout, and a validate that raises after the timeout
  previews as the timeout too, as on the listener. A `strict_timeout_s` of zero or below still
  validates with no timeout. (`BACKLOG #1689`)
- **A streaming inbound's body at or over `stream_threshold_bytes` is no longer strict-validated
  whole in a preview.** The listener validates only such a body's header, which the parse already
  covers, so a preview could refuse, or time out on, a message the engine takes. (`BACKLOG #1689`)
- **A Router, `accepts=` predicate or Handler that calls `sys.exit()` previews as `ERROR`.** The
  `SystemExit` used to leave the dry run, so `messagefoundry check` could exit with the script's own
  code, 0 included. The error names an integer exit code and nothing else. (`BACKLOG #1689`)
- **A dry run logs a warning when it skips a file-backed reference set.** A set whose file did not
  load is left out of the preview, as before, and a WARNING now names the set, once per set per
  process, without quoting the file's content or guessing the cause. Before, a later read of the set
  reported it missing with nothing to say why. (`BACKLOG #3340`)
