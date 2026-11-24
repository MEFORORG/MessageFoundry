- **An engine secret other than a store key that the machine-wide environment sets now refuses
  the start of a Windows service under `[security].enforcement = "enforce"`, and is named as
  `secret_from_outside_service_lists` under `"warn"`.** This applies where the engine finds its
  service and reads its lists, and the secret, such as `MEFOR_STORE_PASSWORD`, is in the
  engine's environment, not in those lists, and set in the machine-wide environment's registry
  key. `serve`, `supervise`, `create_app` and `create_managed_app` apply it. Such a secret from
  anywhere else, such as a service-start wrapper, is named and not refused, and a store key from
  outside the lists is still named as `store_key_in_service_environment` and not refused.
  Where the engine finds its service but cannot read its lists, such a secret in its environment
  now refuses the start under every enforcement setting, as a store key there already did. Move
  it to the secrets directory. See [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md).
  (`BACKLOG #2595`)
