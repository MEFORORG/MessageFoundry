- **The tray probes a partly named or wildcard engine bind.** When `serve` in the service entry names
  only one of `--host` and `--port`, the tray now keeps the engine's default for the other, and it
  follows the engine's scheme when neither is named. Each of those used to probe the wrong URL and show
  a running engine as down. A wildcard `--host` (`0.0.0.0`, `::`) is now probed on loopback rather
  than on an address no client can connect to, and the tray stays monitor-only for it. That probe
  verifies the engine's certificate against the loopback address, so it needs a certificate that
  names it; the one the engine mints names only the bind address. A relative `--service-config` now
  resolves under `--project-root`, as `serve` resolves it, so the tray reads the scheme from the
  settings file the engine loads. Known limit: the tray takes no host or port from that file, so a LAN
  bind set only through `[security].listen_address` is still probed on the loopback default and keeps
  service control. (`BACKLOG #5936`)
