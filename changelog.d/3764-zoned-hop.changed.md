- **The refusal of a zoned `[api].trusted_proxies` host now says what its advice leaves open.**
  After `List 'fe80::1' instead.` it adds that a hop an inner proxy writes into `X-Forwarded-For`
  with its zone, such as `fe80::1%eth0`, will not match that entry: the hop is untrusted and
  becomes the client address. That fails closed, degrading attribution and widening no trust. The
  `trusted_proxies` row of [CONFIGURATION.md](../docs/CONFIGURATION.md) says the same. The `serve`
  startup line for a TLS-terminating proxy now says which entries gain a twin spelling: an IPv4
  entry its `::ffff:`-mapped one, and an entry inside `::ffff:0:0/96` its plain IPv4 one. ADR 0151
  D-1 is amended to match. (`BACKLOG #3764`)
