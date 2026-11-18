- **An OAuth2 or SMART connection whose `https://` token endpoint sits behind a web proxy set up
  for Digest is refused when it is built.** (`BACKLOG #2989`) urllib cannot answer a proxy's 407
  to the `CONNECT` with Digest, so that setup could never answer a challenge there. Before, such a
  connection built: its lane stopped at the first send if the proxy challenged the `CONNECT`, and
  it minted tokens if the proxy let the `CONNECT` through unchallenged. Both cases are now refused
  at load. The refusal keys on the proxy resolved for the token host. On some REST and FHIR outbounds it runs before the proxy credential's hop
  is judged; the docstring of `refuse_a_digest_proxy_on_the_token_hop` says which. The static-credential report no longer lists the proxy hop of a Digest proxy on a
  connection whose own `url` is `https`, or on one that mints a bearer from a literal token URL with
  no `env()` value turning a token provider on or off; the docstring of `_digest_proxy_refused` says
  why. Other Digest proxy hops are listed as before. A `CONNECT` 407 on a proxy with no Digest set
  up, and any other `CONNECT` refusal, still retry.
  [ADR 0095](../docs/adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)
  Amendment B.1 has the detail and the remedy.
