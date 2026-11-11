- **The inbound HTTP listener's failed-attempt budget can key on the client behind a proxy.**
  `Http(trusted_proxies=[...])`, under `intake_auth = "api_key"` or `"bearer"` only, names the
  HTTP reverse proxies in front of the listener. From a listed peer the per-peer budget keys on the
  client address in `X-Forwarded-For`, read right to left as uvicorn reads it, so one client's
  failed attempts no longer `429` every partner behind the same proxy. The default is an empty
  list, which keys on the socket peer. On every HTTP listener, `mtls_subject` included, an IPv6
  socket peer now keys on its `/64` and an IPv4-mapped one on its IPv4 address, as a forwarded
  client does, except in a prefix that carries an IPv4 client, such as NAT64's, where it keys on
  that IPv4 client or on the whole address. Hosts that share a `/64` therefore share one budget,
  among them link-local peers and the clients of a network-specific NAT64 gateway. At least these
  are refused at load: the setting under `none` and `mtls_subject`, with either budget off or not
  an integer of at least 1, and for `'*'`, entries that together span a whole address family
  or more than a `/16` of IPv4 or a `/48` of IPv6, and each form `[api].trusted_proxies` refuses.
  See [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #5525`)
