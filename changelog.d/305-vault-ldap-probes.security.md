- **`messagefoundry check-privileges` now probes the Vault tokens and the AD bind account.** It
  used to print those hops as not probed.
  - For each Vault token the engine uses, it reads the token's policies, TTL and renewability. It
    then reads the token's capabilities on each path the engine calls, and on paths it never needs.
  - A token is over-granted when it carries the `root` policy or holds more than the engine's calls
    need. So is a token that can write a policy, mint a token, or export a store key.
  - One token serving both the store and the connector secrets is judged on both grants together.
  - The check reads only the token in `MEFOR_STORE_VAULT_TOKEN` or `MEFOR_SECRETS_VAULT_TOKEN`. It
    sends it only to the address in `MEFOR_STORE_VAULT_ADDR` or `MEFOR_SECRETS_VAULT_ADDR`. It never
    uses `VAULT_TOKEN`, `~/.vault-token` or `VAULT_ADDR`, which the engine itself still falls back
    to. It never prints the token, its id or its accessor.
  - For the AD bind account, it runs the LDAP "Who am I?" operation and reads the account's own
    groups. Membership of an administrative group it knows is an over-grant.
  - That proves identity and group membership, not rights. Delegated directory ACLs are not read,
    and the output says so.
  - Each run binds to AD as the service account. A wrong bind password counts toward the AD lockout
    threshold every time.
  - Each probe goes through the client the engine already builds for that hop. A probe that cannot
    run is reported as not observed.
  - **The command now exits 4 where it used to exit 0:** when a Vault or AD probe cannot read its
    principal, for example when run without the service's environment. Before, those hops were
    printed as not probed and never changed the exit code. The store hop already worked this way.
  - These findings are reported only. Unlike the store's, they never stop `serve` from starting.
  - SMTP and the identity provider are still printed, not probed. See
    [SECURITY.md](../docs/SECURITY.md). (`BACKLOG #305`)
