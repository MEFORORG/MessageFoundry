- **A Digest web proxy's 407 to an `https://` token endpoint's `CONNECT` names the proxy.** The
  `auth-challenge-refused` text for that case said a non-SHA-256 or unanswerable challenge was
  met, though the engine never screened one. It now says the web proxy answered the `CONNECT`
  with 407, which Digest cannot answer, and names Basic proxy auth or a bypass as the remedy. The
  match no longer reads `http.client`'s message text: the strict https connection raises
  `ProxyTunnelRefusedError` with the status of the proxy's reply, and the token hop decides when
  it is built whether its proxy is set up for Digest, so an opener with no `handlers` attribute no
  longer reads as a different fault and retries. The code, the permanence and the lane stop are
  unchanged. (BACKLOG #2989)
