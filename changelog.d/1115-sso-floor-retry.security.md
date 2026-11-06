- **[SECURITY.md](../docs/SECURITY.md) corrects its record of the single sign-on gap in the sign-in
  time floors.** A retry could avoid the floor too: a callback refused as too early has already
  signed in at the identity provider, so where the provider keeps that sign-on, a new flow started
  a second later could ride it. Setting `[auth].oidc_prompt = "login"` would close both routes at a
  provider that honours it. The sign-in rate limit that still applies counts per client address and
  globally, not per account. The 0.5.2 entry left these out. No behaviour changed.
  (`BACKLOG #1115`)
