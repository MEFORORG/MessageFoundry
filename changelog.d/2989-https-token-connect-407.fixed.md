- **An OAuth2 or SMART connection whose `https://` token endpoint sits behind a web proxy set up
  for Digest is refused when it is built.** (`BACKLOG #2989`) urllib cannot answer a proxy's 407
  to the `CONNECT` with Digest, so that setup could never answer a challenge there. Before, such a
  connection built: its lane stopped at the first send if the proxy challenged the `CONNECT`, and
  it minted tokens if the proxy let the `CONNECT` through unchallenged. Both cases are now refused
  at load. The refusal keys on the proxy resolved for the token host, so a token host the proxy
  bypasses still builds. It runs before the proxy credential's hop is judged, so it comes before
  any record of that credential crossing. The static-credential report no longer lists the proxy
  hop of a Digest proxy the build refuses. A `CONNECT` 407 on a proxy with no Digest set up, and any
  other `CONNECT` refusal, still retry.
  [ADR 0095](../docs/adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)
  Amendment B.1 has the detail and the remedy.
