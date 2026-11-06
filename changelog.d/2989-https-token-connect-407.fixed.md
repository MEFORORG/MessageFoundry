- **A web proxy's 407 to an `https://` token endpoint's `CONNECT` stops the lane instead of
  retrying.** (`BACKLOG #2989`) The OAuth2 and SMART token hops now raise the
  `auth-challenge-refused` configuration fault for it, as they already did for a refused proxy
  Digest challenge. urllib cannot answer a challenge to a `CONNECT`, so each retry sent the same
  `CONNECT` and met the same 407. Any other `CONNECT` refusal still retries. An `https://`
  destination's own `CONNECT` 407 is unchanged.
  [ADR 0095](../docs/adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)
  Amendment B.1 has the detail.
