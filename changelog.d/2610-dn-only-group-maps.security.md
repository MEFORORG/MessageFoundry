- **The AD group maps take a full distinguished name only; a short name is no longer accepted.**
  `PUT /ad-group-map` and `PUT /ad-group-scope-map`, and the web console's AD group page, refuse a
  key that is not a full DN, such as `CN=MF-Admins,OU=Groups,DC=example,DC=com`, with a 400. A
  user's groups are now read as DNs only. Before, the engine also matched each direct group's first
  CN and each nested group's `sAMAccountName`, so a map key written as a short name matched a
  same-named group in any unit. On a first deployment
  that mapped a short name, anyone able to create such a group and add an account to it would have
  given that account the mapped roles, Administrator included. A short-name key already stored
  matches nothing, and there is no compatibility path; re-enter it as a DN. `SECURITY.md` said the
  short form was the group's `sAMAccountName`; it now states the DN-only rule. (vault
  `BACKLOG #2610`)
- **A Windows SSO step names a client only when the Kerberos context that checked the ticket
  finished.** For SSPI and native GSSAPI that is the context's own `complete` flag. pyspnego's own
  Negotiate wrapper, used where GSSAPI offers no native SPNEGO, can stay incomplete after one step
  while the Kerberos context inside it finished, so there that inner context is read, and only a
  Kerberos one counts. This is defence in depth; no provider is known to name a client on an
  unfinished context. Kerberos realm handling is unchanged. (vault `BACKLOG #2610`)
