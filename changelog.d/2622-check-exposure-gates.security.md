- **`messagefoundry check` now runs the four inbound TLS exposure gates.** The MLLP, DICOM, raw TCP
  and HTTP listener gates ran only when the engine started a listener. So the commit/CI gate passed
  a cleartext off-loopback listener that `serve` would then refuse to bind, starting the rest of the
  graph without it. The `build-check` leg now runs them with the instance's derived posture and the
  `[security].require_encryption_for_remote` escape. `check` has no `--allow-insecure-bind`, so a
  site that relies on that flag under `enforcement = "warn"` would see `check` refuse what `serve`
  admits. The gates run only on a listener the engine would bind: deployed and `auto_start`. On a
  running engine, a reload and a flag toggle also skip one the DR run-profile parks, and gate one an
  operator started. A listener outside its schedule window is gated, because the scheduler binds it
  when the window opens. A listener left unbound meets the same gates when it is started. **One
  exposed listener the engine would bind refuses the whole config at build check**, where engine
  start isolates only that listener. While it stands, a reload, dry-run reload, promote, connection
  edit, connection-flag toggle and DR activation are all refused. The refusal names the listener,
  and says that `deployed = false`, or `auto_start = false` with the listener stopped, leaves it
  unbound. The HTTP intake-authentication start gate (ADR 0154 D7) is not filtered this way and
  still runs on every deployed HTTP listener. A reload, a dry-run reload and a flag toggle pass the
  running engine's own escape, so they do not refuse a listener the engine bound under it. (vault
  `BACKLOG #2622` item 1)
