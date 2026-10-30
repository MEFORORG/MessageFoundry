- **`[api].ws_allowed_origins` entries are checked at load.** The handshake compares each entry
  to the `Origin` header exactly, so an entry in another form used to load and match nothing. A
  `;`-joined list loaded as one such origin. Now an entry must be spelled as a browser sends
  `Origin`, or the engine refuses to load. A `;` list is refused with a message naming the
  comma-separated form. A real origin in another spelling, such as `https://ops.example:443/`, is
  refused with the spelling to list. A refusal names the entry by position and never quotes it
  whole, on the message or on the exception chain. [CONFIGURATION.md](../docs/CONFIGURATION.md) lists what is refused. (`BACKLOG #3764`)
