- **[SECURITY.md](../docs/SECURITY.md) corrects its record of the single sign-on gap in the sign-in
  time floors.** A retry would avoid the floor too: a callback refused as too early has already
  signed in at the identity provider, so a new flow started a second later rides that sign-on. The
  sign-in rate limit that still applies counts per client address and globally, not per account.
  The 0.5.2 entry left out both. No behaviour changed. (`BACKLOG #1115`)
