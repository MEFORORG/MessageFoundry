- **The `url_query_credential` reading now reads an `env()` URL.** It read a literal `url` only, so
  a credential in the query of a URL given as `env()` was missing from `messagefoundry check` and
  from `GET /security/posture`, even when the `env()` carried a literal `default=`. The posture
  entry now reads it against the values the graph builds with, and `check`, which has none, reads
  its `default=`. A URL the environment alone supplies, with no default, is still named only by the
  construction WARNING. See [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md).
  (`BACKLOG #3766`)
