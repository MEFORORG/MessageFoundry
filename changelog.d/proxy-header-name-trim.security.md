- **The send-time proxy credential rule reads a header name with its edge whitespace removed.**
  The opener matched a caller-set header's name against `Proxy-Authorization` in any letter case,
  but did not trim it. `http.client` sends a name that ends in a space or a tab as written, so on
  a connection with no `proxy_user`, a static header keyed `Proxy-Authorization` plus trailing
  whitespace would have reached a cleartext proxy, or the destination on a direct send, without a
  refusal. The name is now trimmed before it is matched, by one function that the message-metadata
  rule uses too. The rule is stated on
  [`ProxyCredentialsRefusedError`](../messagefoundry/transports/bounded_read.py).
