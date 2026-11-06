- **The `url_query_credential` reading now reads an `env()` URL.** It read a literal `url` only, so
  a credential in the query of a URL given as `env()` was missing from `messagefoundry check` and
  from `GET /security/posture`, even when the `env()` carried a literal `default=`. The posture
  entry now reads it against the values the graph builds with, falling back to the `default=`. The
  `check` line does not load the instance's environment values, so it reads the `default=` only. A
  `deployed=False` outbound with an `env()` URL is skipped by both, since its values are never
  resolved. See [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md). (`BACKLOG #3766`)
