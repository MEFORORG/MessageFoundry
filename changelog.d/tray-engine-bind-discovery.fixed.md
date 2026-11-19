- **The tray probes a partly named engine bind.** When `serve` in the service entry names only one of
  `--host` and `--port`, the tray now keeps the engine's default for the other, and it follows the
  engine's scheme when neither is named. It used to probe the default URL, which missed a non-default
  port, a non-default host, and the http of a declared upstream terminator. A relative
  `--service-config` now resolves under `--project-root`, as `serve` resolves it, so the tray reads
  the scheme from the settings file the engine loads. (`BACKLOG #5936`)
