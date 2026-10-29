- **`[api].ws_allowed_origins` entries are checked at load.** Each entry must be a bare origin,
  `scheme://host[:port]` with `http` or `https` and no path, query or fragment. A `;`-joined list,
  which used to load as one origin that no browser's `Origin` matched, is now refused with a
  message naming the comma-separated form, and so is any other entry that could never match, at
  least `*`, `null`, userinfo, a bad port and an IPv6 zone. An accepted entry is stored the way a
  browser sends `Origin`: lower case, no trailing `/`, no default port, and an IPv6 literal in its
  short form. See [CONFIGURATION.md](../docs/CONFIGURATION.md). (`BACKLOG #3764`)
