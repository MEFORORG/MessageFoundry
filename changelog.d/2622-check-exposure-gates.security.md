- **`messagefoundry check` now runs the four inbound TLS exposure gates.** The MLLP, DICOM, raw TCP
  and HTTP listener gates ran only when the engine started a listener. So the commit/CI gate passed
  a cleartext off-loopback listener that `serve` would then refuse to bind, starting the rest of the
  graph without it. The `build-check` leg now runs them with the instance's derived posture and the
  `[security].require_encryption_for_remote` escape. `check` has no `--allow-insecure-bind`, so a
  site that relies on that flag under `enforcement = "warn"` would see `check` refuse what `serve`
  admits. The gates run only on a listener that would be bound: deployed and `auto_start`. On a
  running engine, a reload also skips a listener the DR run-profile parks or its schedule window
  keeps closed, and gates one an operator started. A listener left unbound meets the same gates when
  an operator starts it. **One exposed listener that would be bound refuses the whole config at
  build check**, where engine start isolates only that listener. While it stands, a reload, dry-run
  reload, promote, connection edit, connection-flag toggle and DR activation are all refused. The
  refusal names the listener and says that `deployed = false` or `auto_start = false` leaves it
  unbound. A reload, a dry-run reload and a flag toggle pass the running engine's own escape, so
  they do not refuse a listener the engine bound under it. (vault `BACKLOG #2622` item 1)
