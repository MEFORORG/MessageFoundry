- **BREAKING: `[api].trusted_proxies` refuses two more forms that would match no peer, and two
  `[api]` lists split their env form on commas.** An IPv4-mapped entry such as `::ffff:10.0.0.1`
  is refused, because the engine reports an IPv4 peer in its plain form; list `10.0.0.1`. An IPv6
  entry with a zone such as `fe80::1%eth0` is refused, because a peer is reported without its zone;
  list `fe80::1`. uvicorn ignores a network's zone, so a zoned network is refused too.
  `MEFOR_API_TRUSTED_PROXIES`
  and `MEFOR_API_WS_ALLOWED_ORIGINS` now split on `,` on every platform, as
  `MEFOR_SECURITY_ALLOWED_CLIENT_NETWORKS` does. They split on the path separator before, `:` on
  Linux and macOS, which broke an IPv6 entry or an origin's port apart; on Windows, a `;` list
  must be rewritten with `,`. (`BACKLOG #3042`)
