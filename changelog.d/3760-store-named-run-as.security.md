- **A SQLite store in a hardened data directory now admits one named run-as user account.** An
  install with `-ServiceAccount` naming a local user or a gMSA left a data directory the store
  refused, so the store fell back to owner-only and the service and the operator who provisions the
  first Administrator would have locked each other out on first deployment. The store now shares
  its files with at most one principal beyond SYSTEM and Administrators: a per-service virtual
  account as before, or an account `LookupAccountSid` resolves to a user with a RID of 1000 or
  more. It does not check that this account is the one the service runs as. A failed lookup, a group, a built-in account, a second principal, a deny entry, a wrong
  right or inheritance and a foreign owner are all still refused. What a gMSA resolves to is
  unmeasured. See [SERVICE.md](../docs/SERVICE.md), "Restrict the service token". (`vault BACKLOG #3760`,
  `vault BACKLOG #2234`)
