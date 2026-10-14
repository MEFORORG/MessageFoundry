- **`serve` and `supervise` refuse to start as a Windows service with no `--service-config`.**
  Without the flag, a service would read whatever `messagefoundry.toml` sits in its working
  directory. The engine knows it is the service when an `nssm.exe` is the first non-Python
  process above it. A start from a shell, the developer loop, needs no flag.
  [SERVICE.md](../docs/SERVICE.md#install) says how to register the file. (`BACKLOG #2626`)
