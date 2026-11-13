- **A Digest web proxy's 407 to an `https://` token endpoint's `CONNECT` stops the lane instead
  of retrying.** (`BACKLOG #2989`) The OAuth2 and SMART token hops now raise the
  `auth-challenge-refused` configuration fault for it. urllib cannot answer a `CONNECT` challenge,
  so each retry met the same 407. A `CONNECT` 407 on a proxy with no Digest set up, and any other
  `CONNECT` refusal, still retry. Its text names the web proxy's 407 to the `CONNECT` and the two
  remedies, and the match reads the status of the proxy's reply and whether the token hop's proxy
  was built for Digest, never `http.client`'s message text or what the opener exposes.
  [ADR 0095](../docs/adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)
  Amendment B.1 has the detail and the remedy.
