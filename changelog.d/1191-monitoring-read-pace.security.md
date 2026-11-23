- **Six `monitoring:read` GETs are paced per account.** `GET /graph/edges`, `/status`, `/stats`,
  `/metrics`, `/metrics/history` and `/connections` share one budget per account: past 600 reads per
  60 s across the six, the shipped default of the new `[auth].monitoring_read_rate_limit_*`
  settings, a read is answered 429 with a `Retry-After`. The budget is per API process, so N engine
  shards multiply it by N; the all-accounts count ships off. The web console's in-process reads of
  the same handlers are not charged, and neither are `/ws/stats`, `/events`,
  `/connections/{name}/events` or `/config/provenance`. The key and the basis of the default are in
  [SECURITY.md](../docs/SECURITY.md), *Monitoring-read pacing*. (vault `BACKLOG #1191`)
