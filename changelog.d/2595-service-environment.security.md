- **A store key in the Windows service's NSSM environment now refuses the start.** NSSM keeps the
  service's `AppEnvironmentExtra` and `AppEnvironment` lists in the service's registry key, which
  any local user can read on a default Windows install. `serve` and `supervise` now read their own
  service's list at start and refuse when `MEFOR_STORE_ENCRYPTION_KEY` or
  `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED` is in it, under every `[security].enforcement` setting. Keep
  the key in a DPAPI key file, which [SERVICE.md](../docs/SERVICE.md) now lists first. Another
  engine secret in that list is named as the loosening `service_environment_secret`, a store key
  that reaches the service through its environment as `store_key_in_service_environment`, and a
  list the engine could not read as `service_environment_unobservable`. The Windows service smoke
  and the store-access measurement now pass the key through a DPAPI key file. (`BACKLOG #2595`,
  `#2601`)
