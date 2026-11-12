- **An engine secret setting in the Windows service's NSSM environment now refuses the start,
  where the engine finds its service and reads its lists.** At least the store password, the AD
  bind password, the OIDC client secret, an inline OIDC signing key and its passphrase, the SMTP
  password, the API TLS key passphrase, both Vault tokens and the AI key joined the store key:
  where the engine finds its service and reads its `AppEnvironmentExtra`, `AppEnvironment` and
  `Environment` values, `serve` and `supervise` refuse to start when one is in any of them, under
  every `[security].enforcement` setting. For these settings the refusal names the secrets
  directory as the way in. Where the engine knows its service but cannot read those values, they
  refuse only a store key or retired store key found in their own environment, never another
  secret setting. The `service_environment_secret` loosening, which only named them, is gone. An
  app built without either command, such as one built with `create_app(engine)`, is not refused.
  Where it finds its service, it names what they refuse as the loosening
  `secret_in_service_environment` instead. See [SERVICE.md](../docs/SERVICE.md). (`BACKLOG #2595`)
