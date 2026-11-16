- **The sandbox worker no longer receives `MEFOR_ALLOW_INSECURE_CONFIG_SOURCE` or the
  `MEFOR_SECURITY_ENFORCEMENT` dial.** The engine decides the config-source check when it reads the
  config, and the worker runs those bytes with no check of its own, so no `MEFOR_*` variable is in
  its environment now. Config code that read either variable in a sandbox worker, under
  `[sandbox].mode` `"subprocess"` or `"isolated"`, finds it unset. (`BACKLOG #2587`)
