- **An engine secret setting in the Windows service's NSSM environment now refuses the start.**
  At least the store password, the AD bind password, the OIDC client secret, an inline OIDC
  signing key and its passphrase, the SMTP password, the API TLS key passphrase, both Vault tokens
  and the AI key joined the store key: `serve` and `supervise` refuse to start when one is in the
  service's `AppEnvironmentExtra`, `AppEnvironment` or `Environment` value, under every
  `[security].enforcement` setting. The refusal names the secrets directory as the way in. The
  `service_environment_secret` loosening, which only named them, is gone. An app built without
  either command, such as one built with `create_app(engine)`, is not refused and names what they refuse as the loosening
  `secret_in_service_environment` instead. See
  [SERVICE.md](../docs/SERVICE.md). (`BACKLOG #2595`)
