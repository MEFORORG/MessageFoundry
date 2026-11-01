- **An inbound connection's `encoding` must be a literal codec name; an `env()` reference is
  refused when the config loads.** The ingress decode reads the inbound's own settings, where an
  `env()` reference is never resolved, so a text inbound would have refused every message. The
  refusal applies to a binary inbound too, names the connection and the reference's key, and
  resolves nothing, so it covers a not-deployed inbound and `connections.toml` too. Set an inbound
  encoding per environment by editing the connection. An outbound connection, a lookup and a
  reference set still take an `env()` encoding. (`BACKLOG #2431`)
- **An `encoding` of `None` is refused everywhere but on an inbound connection.** An inbound reads
  `None` as `utf-8`; most outbound connectors read the value as the codec name, so `None`, or an
  `env()` value resolving to `None` or an empty string, would have failed every send on them.
  Config load refuses a literal `None`. The build check refuses an `env()` value resolving to one,
  at a reload, a connection upsert, and the `build-check` line of `messagefoundry check`, which
  that line skips on a config dir with no service settings. (`BACKLOG #2431`)
- **An inbound `encoding` naming no text codec is a temporary refusal, not a permanent one.** Such a
  name refuses every body until it is fixed, and the body is not at fault. The MLLP listener answers
  `AE`, where a body invalid in a usable charset gets `AR`, and `Http()` answers `503` with
  `Retry-After`, naming the `ERROR` row as `refused_message_id`, where that body gets `422`. Each
  refused attempt is still its own `ERROR` row. (`BACKLOG #2431`)
