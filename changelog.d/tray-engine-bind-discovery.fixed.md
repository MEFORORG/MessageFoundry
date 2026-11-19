- **The tray finds the engine bind in more places.** It now takes the host and port the engine's own settings
  file sets (`[security].listen_address` with `local_access_only = false`, and
  `[api].port`) when `serve --host`/`--port` in the service entry leave them unset, keeps the engine's
  default for a part nothing sets, and probes a wildcard bind (`0.0.0.0`, `::`) on loopback. Each of
  those used to probe the wrong or an unconnectable URL and show a running engine as down.
  (`BACKLOG #5936`)
