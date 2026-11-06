- **A Digest web proxy's 407 to an `https://` token endpoint's `CONNECT` stops the lane instead
  of retrying.** (`BACKLOG #2989`) The OAuth2 and SMART token hops now raise the
  `auth-challenge-refused` configuration fault for it, as they already did for a challenge the
  proxy Digest handler refused on an `http://` token endpoint. The handler never sees a
  `CONNECT` 407, so each retry met the same one. A `CONNECT` 407 on a proxy with no Digest set
  up, and any other `CONNECT` refusal, still retry.
  [ADR 0095](../docs/adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)
  Amendment B.1 has the detail.
