- **One host draws one sign-in limiter bucket, whatever the spelling of its address.** The per-address
  sign-in limiter, the passkey sign-in's begin leg and the repeated-credential audit budget now key
  a client by its host: an IPv4-mapped address such as `::ffff:203.0.113.5` shares the bucket of
  `203.0.113.5`. Before this, a host that reached the engine in both spellings, for example across
  a bind change between `0.0.0.0` and `::`, would have had the per-address budget twice. Every
  loopback address now shares one bucket too, so `127.0.0.1` and `::1` together get one budget,
  which is stricter than before. A request with no address still counts as `"unknown"`.
  ([SECURITY.md](../docs/SECURITY.md), *Per-IP limiter caveat*) (`BACKLOG #3764`)
