- **`serve` and `supervise` refuse to start as a Windows service without an absolute
  `--service-config`.** With no flag, or a relative one and no `--project-root`, a service would
  read a `messagefoundry.toml` from its working directory. The engine knows it is the service when
  `nssm.exe` is the first process above it other than Python and the `messagefoundry` launcher. A
  start from a shell, the developer loop, needs no flag. `install-service.ps1` refuses when it has
  no settings file to register. [SERVICE.md](../docs/SERVICE.md#install) says how to register one.
  (`BACKLOG #2626`)
