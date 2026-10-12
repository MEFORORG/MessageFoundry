- **The send-time proxy credential rule reads a header name however it is spelled.** The opener
  matched a caller-set header's name against `Proxy-Authorization` in any letter case, but did
  not trim it. `http.client` sends a name that ends in a space, a tab or a control character as
  written, so on a connection with no `proxy_user`, a static header keyed `Proxy-Authorization`
  plus trailing whitespace would have reached a cleartext proxy, or the destination on a direct
  send, without a refusal. One function now reads the name: it ignores the letter case and every
  character at either end that a header name cannot hold. The message-metadata rule calls it
  too. A connection's admission of its own `proxy_user` header covers the plain spelling only,
  and the opener reads every matching header on a request, so one cannot hide another. The rule
  is stated on [`ProxyCredentialsRefusedError`](../messagefoundry/transports/bounded_read.py).
