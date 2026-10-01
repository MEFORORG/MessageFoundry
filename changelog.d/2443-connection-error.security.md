- **A connection's start-failure reason is masked until the operator reveals it** (ASVS 14.2.6,
  owner ruling R12). `ConnectionRow.error` and `ConnectionMetadata.error` join the per-property
  map on the `messages:view_summary` tier. `GET /connections` and
  `GET /connections/{name}/metadata` return the error as `****` to a holder, and `null` to a caller
  without that permission. `reveal=<connection name>` on the dashboard, or `reveal=true` on the
  metadata route, returns it whole. That reveal needs `messages:view_summary`, is refused for a
  connection outside a scoped caller's channels, charges the PHI-read budget, and writes a
  `connection_error_reveal` audit row. The `status` word, the `errored` count and every other field
  stay readable under `monitoring:read`. The metadata route gains an ungated `fault` field
  (`failed` or `filtered`), so a role that sees `error` as `null` can still tell that the connection
  is down. `EngineClient.connections()` takes the same `reveal`.
- **Each gated response model now gets a serializer over its own gated properties only.** The
  shared one covered every field with a gateable name, gated or not, so a model whose `metadata`
  is a dict could not be gated. The published schema of every other model is unchanged. See
  [SECURITY.md](../docs/SECURITY.md) and [PHI.md](../docs/PHI.md) section 2. (`BACKLOG #2443`)
