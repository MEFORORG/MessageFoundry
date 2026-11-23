- **The cost-bearing `monitoring:read` GETs are paced per account.** `GET /graph/edges`, `/status`,
  `/stats`, `/metrics`, `/metrics/history` and `/connections` answer 429 with a `Retry-After` past
  600 reads per 60 s per account, the shipped default of the new `[auth].monitoring_read_rate_limit_*`
  settings; the all-accounts count ships off. The web console's in-process reads of the same
  handlers are not charged. The routes, the key and the basis of the default are in
  [SECURITY.md](../docs/SECURITY.md), *Monitoring-read pacing*. (vault `BACKLOG #1191`)
