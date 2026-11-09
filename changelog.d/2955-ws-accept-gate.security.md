- **The engine refuses `accept()` on a WebSocket whose latest recorded gate answer is a refusal, or one with no recorded answer and neither a gate dependency nor a `public_route` mark.** The in-body WebSocket gates
  record on the handshake whether they admitted the caller, and the engine refuses `accept()`, and
  any denial response, on a socket whose latest recorded answer is a refusal, and on one with no
  recorded answer that no gate dependency or `public_route` mark declares. The client gets a
  bodyless 403. See [`docs/SECURITY.md`](../docs/SECURITY.md). (vault `BACKLOG #2955`)
