- **An `[api].trusted_proxies` entry that covers more than one address is now named as a security
  loosening.** Every host inside a trusted range may set `X-Forwarded-For`, so each one can declare
  its own source address. That poisons the audit trail, the per-address sign-in limit and the
  new-client-IP step-up signal. Before this, only entries covering a whole address family were
  named, and a `/8` or a `/31` was silent. Any entry wider than one host is named now, IPv4 or IPv6,
  a `/31` or `/127` included. Entries that cover a whole family keep their own wording. The check is
  advisory, so the load still accepts a range. The serve-time warning, `messagefoundry security show`
  and `GET /security/posture` all list it.
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md) says what it gives up. (`BACKLOG #1131`)
