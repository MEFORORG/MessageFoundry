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
- **Group map keys and a user's groups are compared in one canonical DN form.** Each side is
  parsed, lower-cased, unescaped and escaped again one way, with the parts of a multi-valued RDN
  sorted. So `CN=C# Developers,...`, which Active Directory writes with the `#` unescaped,
  `CN=C\# Developers,...` and `CN=C\23 Developers,...` all name the same group, and a space after a
  comma is ignored. The maps store the canonical form, which is what `GET` now returns. (vault
  `BACKLOG #2610`)
- **A Windows SSO step names a client only when the Kerberos context that checked the ticket
  finished.** On Windows that is the SSPI context's own `complete` flag. On Linux every sign-in
  goes through pyspnego's own Negotiate wrapper, because pyspnego 0.12's GSSAPI proxy offers
  Kerberos only and never Negotiate. That wrapper can stay incomplete after one step while the
  Kerberos context inside it finished, so there the inner context is read, and only a Kerberos one
  counts. This is defence in depth; no provider is known to name a client on an unfinished context.
  Kerberos realm handling is unchanged. (vault `BACKLOG #2610`)
