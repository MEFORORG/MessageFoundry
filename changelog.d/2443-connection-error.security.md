- **A connection's start-failure reason on the dashboard is masked until a per-connection reveal**
  (ASVS 14.2.6, owner ruling R12). `ConnectionRow.error` joins the per-property map on the
  `messages:view_summary` tier. `GET /connections` returns it as `****` to a holder, and `null` to a
  caller without that permission, until a `reveal=<connection name>` query parameter asks for one
  connection. That reveal needs `messages:view_summary`, charges the PHI-read budget, and writes a
  `connection_error_reveal` audit row. The `status` word, the `errored` count and every other field
  stay readable under `monitoring:read`. `EngineClient.connections()` takes the same `reveal`.
  `ConnectionMetadata.error` on `GET /connections/{name}/metadata` carries the same text and is not
  masked yet. See [SECURITY.md](../docs/SECURITY.md) and [PHI.md](../docs/PHI.md) section 2.
  (`BACKLOG #2443`)
