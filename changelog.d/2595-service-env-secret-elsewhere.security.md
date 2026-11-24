- **An engine secret that reaches the Windows service from outside its own environment lists now
  refuses the start under `[security].enforcement = "enforce"`, and is named as
  `secret_from_outside_service_lists` under `"warn"`.** This applies where the engine finds its
  service and reads its lists, and the secret, such as `MEFOR_STORE_PASSWORD`, is in the
  engine's environment but not in those lists, so it came from somewhere else, such as the
  machine-wide environment. `serve`, `supervise`, `create_app` and `create_managed_app` apply it.
  Where the engine finds its service but cannot read its lists, such a secret in its environment
  now refuses the start under every enforcement setting, as a store key there already did. Move
  it to the secrets directory. See [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md).
  (`BACKLOG #2595`)
