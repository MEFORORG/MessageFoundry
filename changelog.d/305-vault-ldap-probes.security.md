- **`messagefoundry check-privileges` now probes the Vault tokens and the AD bind account.** It
  used to print those hops as not probed. For each Vault token the engine uses, it now reads the
  token's policies, TTL and renewability, and its capabilities on each path the engine calls and on
  seven administrative paths. It reports the token over-granted on a `root` policy, a capability
  beyond what the engine's call needs, any grant on an administrative path, or one token serving
  both the store and the connector secrets. The token, its id and its accessor are never printed.
  It reads only the token in `MEFOR_STORE_VAULT_TOKEN` or `MEFOR_SECRETS_VAULT_TOKEN`, never
  `VAULT_TOKEN` or `~/.vault-token`. For the AD bind account it runs the LDAP "Who am I?"
  operation and reads the account's own groups, and reports an administrative group as an
  over-grant. Each run binds as the service account, so a wrong bind password counts toward the
  AD lockout threshold every time. That proves identity and group membership, not rights: delegated directory ACLs are
  not read, and the output says so. Each probe goes through the client the engine already builds
  for that hop. A probe that cannot run is reported as not observed. **The command now exits 4
  in cases where it used to exit 0:** when a Vault or AD probe cannot read its principal, for
  example when run without the service's environment. It already did that for the store. Before,
  those two hops were printed as not probed and never changed the exit code. These
  findings are reported only; unlike the store's, they never stop `serve` from starting. SMTP and
  the identity provider are still printed, not probed. See
  [SECURITY.md](../docs/SECURITY.md). (`BACKLOG #305`)
