- **`messagefoundry check-privileges` now probes the Vault tokens and the AD bind account.** It
  used to print those hops as not probed. For each Vault token the engine uses, it now reads the
  token's policies, TTL and renewability, and its capabilities on each path the engine calls and on
  four administrative paths. It reports the token over-granted on a `root` policy, a capability
  beyond what the engine's call needs, or any grant on an administrative path. The token, its id
  and its accessor are never printed. For the AD bind account it runs the LDAP "Who am I?"
  operation and reads the account's own groups, and reports an administrative group as an
  over-grant. That proves identity and group membership, not rights: delegated directory ACLs are
  not read, and the output says so. Each probe goes through the client the engine already builds
  for that hop. A probe that cannot run is reported as not observed, so the command now exits 4
  when a Vault or AD probe cannot read its principal, as it already did for the store. These
  findings are reported only; unlike the store's, they never stop `serve` from starting. SMTP and
  the identity provider are still printed, not probed. See
  [SECURITY.md](../docs/SECURITY.md). (`BACKLOG #305`)
