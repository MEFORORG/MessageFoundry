- **The shipped Kubernetes manifests set `enableServiceLinks: false`.** The engine reads no
  service-link variable, and a Service named `mefor` or `mefor-<section>` would otherwise inject
  names the settings loader refuses at start. Cluster DNS is unaffected. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md). (`vault BACKLOG #2600`)
- **`messagefoundry security show` says why a report is partial.** The new
  `loosenings_partial_reason` field carries the settings-load failure, rendered without any
  configured value, and is `null` when the report is complete. A mistyped `MEFOR_<SECTION>_<KEY>`
  variable in the shell is one cause, and the reason names it. (`vault BACKLOG #2600`)
- **On Windows, a secret reference written in another letter case still spares its variable.**
  Under `[secrets].provider = "env"` the unknown-variable refusal compares the two names as the
  platform does: ignoring case on Windows, exactly elsewhere. (`vault BACKLOG #2600`)
