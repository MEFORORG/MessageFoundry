- **Windows SSO now resolves a ticket only to the account it proves.** The ticket's realm was
  checked against `[auth].kerberos_realm` and dropped, and the directory was then asked the
  password sign-in's wider question. So in the shipped code, under a forest-wide base or the global
  catalog, `alice@CORP.EXAMPLE` would have signed in as a child domain's `alice`; one entry holding
  only the UPN `alice@<ad_domain>` would have answered a ticket for `alice`; and a machine's ticket
  (`WS01$`) was looked up like a person's. The Kerberos lookup now asks for a person account whose
  own `sAMAccountName` is the ticket's name and whose DN's whole trailing run of `DC=` RDNs equals
  the realm's domain, and looks up no name ending in `$`. A realm whose users are not under its own
  `DC=` RDNs, as on a directory other than Active Directory, now finds no account, and neither does
  a ticket naming the account by an implicit UPN, which a client that does not ask for name
  canonicalization may present. The password sign-in is unchanged. See
  [SECURITY.md](../docs/SECURITY.md#local-vs-active-directory). (`BACKLOG #4846`)
