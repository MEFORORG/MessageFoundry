- **The refusal of a zoned `[api].trusted_proxies` host now says what its advice leaves open.**
  After advising the zoneless host, such as `fe80::1`, both refusal paths add that a hop an inner
  proxy writes into `X-Forwarded-For` with a zone will not match that entry and becomes the client
  address. The `trusted_proxies` row of [CONFIGURATION.md](../docs/CONFIGURATION.md) says what that
  costs and which entry matches such a hop. The `serve` startup line for a TLS-terminating proxy
  now says which entries gain a twin spelling: an IPv4 entry its `::ffff:`-mapped one, and an entry
  inside `::ffff:0:0/96` its plain IPv4 one. ADR 0151 D-1 is amended to match. (`BACKLOG #3764`)
