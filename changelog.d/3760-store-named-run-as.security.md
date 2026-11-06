- **A SQLite store in a hardened data directory now admits one named run-as user account.** An
  install with `-ServiceAccount` naming a local user or a gMSA left a data directory the store
  refused, so the store fell back and the service and the operator who provisions the
  first Administrator would have locked each other out on first deployment. The store now admits a
  per-service virtual account as before, or an account with a machine- or domain-relative SID
  (`S-1-5-21-...`) that `LookupAccountSid` resolves to a user with a RID of 1000 or more. It does
  not check that this account is the one the service runs as. What is still refused, and what a
  refused directory gets, are stated in ADR 0163, *Note (2026-11-05)*. What a gMSA resolves
  to is unmeasured. See [SERVICE.md](../docs/SERVICE.md), "Restrict the service token".
  (`vault BACKLOG #3760`, `vault BACKLOG #2234`)
