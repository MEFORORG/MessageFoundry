- **The shipped Kubernetes manifests set `enableServiceLinks: false`.** The engine reads no
  service-link variable, and a Service named `mefor` or `mefor-<section>` would otherwise inject
  names the settings loader refuses at start. Cluster DNS is unaffected. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md). (`vault BACKLOG #2600`)
- **`messagefoundry security show` says why a report is partial.** The new
  `loosenings_partial_reason` field carries the settings-load failure as every other command
  renders it: the refused input is hidden, and each validator's message is shown as written. It
  is `null` when the report is complete. A mistyped `MEFOR_<SECTION>_<KEY>` variable in the
  shell is one cause, and the reason names it and not its value. (`vault BACKLOG #2600`)
- **The `[backup]` and `[dr]` cloud-URL refusals quote the scheme and no longer the URL.** A URL
  can carry a credential, and a load failure is printed to stderr, to a service log and now to
  `security show`'s JSON. (`vault BACKLOG #2600`)
- **`serve` logs the unread-`MEFOR_*`-variable warnings again once logging is configured,** so
  they reach the log file and the off-box forwarder, not only stderr. Every command now logs them
  before any settings refusal, so one refused key does not hide a mistyped variable.
  (`vault BACKLOG #2600`)
- **On Windows, a secret reference written in another letter case still spares its variable.**
  Under `[secrets].provider = "env"` the unknown-variable refusal compares the two names as the
  platform does: ignoring case on Windows, exactly elsewhere. (`vault BACKLOG #2600`)
