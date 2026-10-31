- **`messagefoundry dryrun` and `messagefoundry check` now apply an inbound's strict-validation
  timeout, as the listener does.** A strict validate that runs past `validation.strict_timeout_s`
  previews as `ERROR` with the listener's own text, `strict-validation timed out after <N>s`, where
  before the preview waited it out and reported whatever hl7apy found. An expired validate cannot
  be stopped and runs on in the background; at most four run at once, and once all four are still
  running when the next one's timeout passes, that message previews as `ERROR` with
  `strict-validation not run: ...` rather than passing. A `strict_timeout_s` of zero or below
  still validates with no timeout. (`BACKLOG #1689`)
- **A streaming inbound's body at or over `stream_threshold_bytes` is no longer strict-validated
  whole in a preview.** The listener validates only such a body's header, which the parse already
  covers, so a preview could refuse, or time out on, a message the engine takes. (`BACKLOG #1689`)
- **A dry run logs a warning when it skips a file-backed reference set.** A set whose file is
  missing, malformed or unreadable is left out of the preview, as before, and a WARNING now names
  the set and says whether its file is missing or malformed or unreadable, without quoting the
  file's content. Before, a later read of the set reported it missing with nothing to say why. (`BACKLOG #3340`)
