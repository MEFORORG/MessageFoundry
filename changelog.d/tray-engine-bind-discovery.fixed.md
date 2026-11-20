- **The tray probes a partly named or wildcard engine bind.** When `serve` in the service entry names
  only one of `--host` and `--port`, the tray now keeps the engine's default for the other, and it
  follows the engine's scheme when neither is named. Before, a port-only bind was probed on the
  default port, a host-only bind on a non-loopback, non-wildcard address was probed on loopback, and
  an engine serving http with neither part named was probed over https, so each showed a running
  engine as down. A wildcard `--host` (`0.0.0.0`, `::`) is now probed on loopback, and the tray is
  monitor-only for it; with `--port` also named, the tray used to probe the wildcard address, which
  no client can connect to. Service control tightens for a host-only bind: a `--host` naming a
  non-loopback address, a wildcard included, with no `--port`, is now monitor-only, where the tray
  used to fall back to the loopback default and keep service control. A relative
  `--service-config` now resolves under `--project-root`, as `serve` resolves it, so the tray reads
  the scheme from the settings file the engine loads. Known limit: the tray takes no host or port
  from that file, so a LAN bind set only through `[security].listen_address` is still probed on the
  loopback default and keeps service control. (`BACKLOG #5936`)
