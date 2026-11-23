- **The `vault_transit` store cipher now renews its Vault token.** It read the token once, when the
  store opened, and never renewed it, so in a long-running engine a periodic token, or a renewable
  token with a TTL, would lapse and every store encrypt and decrypt would then be refused. The
  cipher now reads the token's TTL when the store opens (`auth/token/lookup-self`) and renews a
  renewable token (`auth/token/renew-self`) on the first store call made after half its TTL has
  passed. There is no timer, so an engine that makes no store call in that window still lets the
  token lapse. A token that is not renewable is logged at WARNING with its TTL. A failed renewal
  is logged and tried again; it does not fail the store call that ran it. Vault's max TTL still
  ends a token, and a renewal that grants less than the one before is logged at WARNING.
