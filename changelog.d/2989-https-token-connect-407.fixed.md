- **An OAuth2 or SMART connection whose `https://` token endpoint sits behind a web proxy set up
  for Digest is refused when it is built.** (`BACKLOG #2989`) urllib cannot answer a proxy's 407
  to the `CONNECT` with Digest, so that setup could never answer a challenge there; such a
  connection is now a configuration error at load instead of a lane that stops at its first send. The refusal keys on
  the proxy resolved for the token host, so a token host the proxy bypasses still builds. A
  `CONNECT` 407 on a proxy with no Digest set up, and any other `CONNECT` refusal, still retry.
  [ADR 0095](../docs/adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)
  Amendment B.1 has the detail and the remedy.
