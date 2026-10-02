- **Federated sign-in can authenticate to the token endpoint with `private_key_jwt`.** Set
  `[auth].oidc_token_endpoint_auth_method = "private_key_jwt"` and supply
  `[auth].oidc_client_private_key` (inline PEM via `MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY`, a PEM
  file path, or `oidc_client_private_key_ref`). The token request then carries a short-lived
  signed assertion (RFC 7523) and no client secret. The default stays `client_secret_post`, and
  the request is unchanged unless you opt in. A missing or unusable key refuses startup, and
  `messagefoundry verify --section federation` loads it the same way. For an IdP that registers a
  certificate (Entra ID), `oidc_client_certificate` adds its `x5t#S256` thumbprint to each assertion. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md) and ADR 0142 Amendment D. (`BACKLOG #296`)
