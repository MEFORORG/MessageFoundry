- **`messagefoundry check` now runs the four inbound TLS exposure gates.** The MLLP, DICOM, raw TCP
  and HTTP listener gates ran only when the engine started a listener, so the commit/CI gate passed
  a cleartext off-loopback listener that `serve` then refused. The `build-check` leg now runs them
  with the instance's derived posture and the `[security].require_encryption_for_remote` escape.
  `check` has no `--allow-insecure-bind`, so a site that relies on that flag under
  `enforcement = "warn"` would see `check` refuse what `serve` admits. A reload, a dry-run reload
  and a connection-flag toggle pass the running engine's own escape, so they never refuse a
  listener the engine already accepted. (vault `BACKLOG #2622` item 1)
