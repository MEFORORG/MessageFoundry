- **BREAKING: `[api].trusted_proxies` refuses a zoned entry, matches an IPv4 entry in both
  spellings, and two `[api]` lists split their env form on commas.** An IPv6 entry with a zone
  such as `fe80::1%eth0` is refused, because a peer is reported without its zone; list `fe80::1`.
  uvicorn ignores a network's zone, so a zoned network is refused too. uvicorn compares a mapped
  `X-Forwarded-For` hop such as `::ffff:10.0.0.1` only with a mapped entry, so behind a dual-stack
  proxy that writes mapped hops the entry `10.0.0.1` would have resolved the client to that hop
  rather than to the real client. The engine now hands uvicorn each IPv4 entry, and each mapped
  entry, in both its plain and IPv4-mapped spellings, so `::ffff:0:0/96` also trusts every plain
  IPv4 peer; the `trusted_proxies` row of `docs/CONFIGURATION.md` says how.
  `MEFOR_API_TRUSTED_PROXIES`
  and `MEFOR_API_WS_ALLOWED_ORIGINS` now split on `,` on every platform, as
  `MEFOR_SECURITY_ALLOWED_CLIENT_NETWORKS` does. They split on the path separator before, `:` on
  Linux and macOS, which broke an IPv6 entry or an origin's port apart; on Windows, a `;` list
  must be rewritten with `,`. (`BACKLOG #3042`)
