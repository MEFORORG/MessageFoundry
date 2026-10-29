- **`[api].ws_allowed_origins` entries are checked at load.** Each entry must be a bare origin,
  `scheme://host[:port]` with `http` or `https` and no path, query or fragment. A `;`-joined list,
  which used to load as one origin that no browser's `Origin` matched, is now refused with a
  message naming the comma-separated form. At least `*`, `null`, userinfo (never quoted in the
  refusal), a bad port, an IPv6 zone, a non-ASCII host and an IPv4 address in a form a browser
  rewrites are refused too. An accepted entry is normalized for the handshake's exact match: lower
  case, no trailing `/`, no default port, and an IPv6 literal in the hex form a browser writes.
  See [CONFIGURATION.md](../docs/CONFIGURATION.md). (`BACKLOG #3764`)
