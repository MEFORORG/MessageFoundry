- **An OAuth2 or SMART token hop behind an ECH sidecar posts through a plain opener.** (`BACKLOG
  #2977`) The engine sends the token request to the loopback sidecar, not to the token host, but
  the opener it went through kept the trust anchor and CRL resolved for the token host, so an `https://`
  sidecar would have been verified against that host's CA. It now uses the opener the REST
  destination's own ECH hop uses. The token hop's revocation refusal is unchanged.
