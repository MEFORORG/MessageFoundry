- **The inbound HTTP listener's failed-attempt budget can key on the client behind a proxy.**
  `Http(trusted_proxies=[...])`, under `intake_auth = "api_key"` or `"bearer"` only, names the
  HTTP reverse proxies in front of the listener. From a listed peer the per-peer budget keys on the
  client address in `X-Forwarded-For`, read right to left as uvicorn reads it, so one client's
  failed attempts no longer `429` every partner behind the same proxy. The default is an empty
  list, which keys on the socket peer as before. The setting is refused under `none` and
  `mtls_subject`, with the global budget off, and for `'*'` or any entries that together span a
  whole address family. See [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #5525`)
