- **A `MEFOR_VALUE_*` variable in the Windows service's NSSM environment now refuses the start,
  where the engine finds its service and reads its lists.** Every one is refused, an empty one and
  a host name as well as a password, since the engine cannot tell which `env()` value is a secret: `serve`,
  `supervise`, `create_app` and `create_managed_app` refuse on it as they already do on an engine
  secret setting there, under every `[security].enforcement` setting. The refusal counts them
  without printing a name, and sends each to the secrets directory, as a file named as its
  variable, or a value that is not a secret and is the same for every instance to the active
  environment's value file. See [SERVICE.md](../docs/SERVICE.md). (`BACKLOG #8212`)
