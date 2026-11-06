- **An `MLLP()` listener with `tls = true` admits each socket before its TLS handshake on every
  event loop, uvloop included.** Under uvloop the loop used to run the handshake, so
  `source_ip_allowlist`, `max_connections` and `max_connections_per_host` applied only after it,
  and a socket that never sent a ClientHello sat outside them for up to the 10 s handshake bound.
  On a loop other than the stdlib's own, the listener now runs its own accept loop: it refuses or
  admits each socket in plain TCP, then hands an admitted one to the loop's TLS layer before
  anything reads it. stop() closes a socket still in its handshake at once there too, and a failed
  handshake is reported with its peer. The stdlib path is unchanged. For the `MLLP()` listener, a
  loop that subclasses a stdlib loop now takes the same path as an unknown loop. The `Http()`
  listener takes the same accept loop since BACKLOG #2479; its own entry says what that changes.
  See
  [CONNECTIONS.md](../docs/CONNECTIONS.md). (`BACKLOG #1606`, `vault BACKLOG #4552`)
