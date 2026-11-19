- **A Direct destination's `recipient_cert` that names any `rfc822Name` is now bound to those
  mailboxes alone; a `dNSName` beside them no longer names every other mailbox at that domain.** In
  the shipped code a cert a CA issued to `recipient@hisp.example` that also carried the `dNSName`
  `hisp.example` was accepted for any `hisp.example` recipient, so a deploying site would have
  encrypted mail for another subscriber to that subscriber's key. A `dNSName` still names a domain's
  mailboxes on an organisation certificate, one that carries no `rfc822Name`. Construction refuses
  the bound case and names the address's position, as before.
  [CONNECTIONS.md](../docs/CONNECTIONS.md) *Recipient trust* lists the checks. (`BACKLOG #5631`)
