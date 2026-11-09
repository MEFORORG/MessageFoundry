- **The engine refuses `accept()` on a WebSocket no gate admitted.** A WebSocket gate records on
  the handshake whether it admitted the caller, and the engine refuses `accept()`, and any denial
  response, on a socket whose gate refused, and on one with no recorded answer that no gate
  dependency or `public_route` mark declares. The client gets a bodyless 403. See [`docs/SECURITY.md`](../docs/SECURITY.md). (vault `BACKLOG #2955`)
