- **An address draws one sign-in limiter bucket in its IPv4-mapped and plain spellings.** The
  per-address sign-in limiter, the passkey sign-in's begin leg and the repeated-credential audit
  budget now key a client through the same folding as the new-address signals: an IPv4-mapped
  address such as `::ffff:203.0.113.5` shares the bucket of `203.0.113.5`. Before this, one engine
  process that saw a host in both spellings, for example as a dual-stack direct peer and as a
  trusted proxy's plain forwarded hop, would have given it the per-address budget twice. Every
  loopback address now shares one bucket too, so `127.0.0.1` and `::1` together get one budget,
  which is stricter than before. A request with no address still counts as `"unknown"`. At least
  these still split one host: an IPv6 host that changes address, a zone id on an address that is
  neither loopback nor IPv4-mapped, and the IPv4-compatible form `::203.0.113.5`; the sign-in
  failure-burst signal and the HTTP intake limiter key the raw address. ([SECURITY.md](../docs/SECURITY.md), *Per-IP limiter caveat*)
  (`BACKLOG #3764`)
