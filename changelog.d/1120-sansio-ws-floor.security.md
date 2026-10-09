- **The protocol header floor now covers uvicorn's sans-I/O WebSocket protocol, and the uvicorn cap
  moves from `<0.50` to `<0.55`.** From uvicorn 0.50, `ws="auto"` resolves to that protocol. The
  floor refused it, so `serve` exited with code 2 on any newer uvicorn, and the cap held uvicorn at
  0.49. The floor now adds `nosniff` and the framing policy to every handshake answer that protocol
  writes: the websockets library's own rejection of a bad handshake, uvicorn's `500`, its `403` for
  an app that closes before accepting, an app's own denial, and the `101`. It does so in one place,
  the `send_response` of the connection object the protocol hands each answer to. The legacy
  websockets server stays covered as before. wsproto is still refused. The lock moves uvicorn to
  0.54.0. `websockets` gains an upper bound, `<18`, because the floor wraps two of its internals;
  the lock stays at 17.1. The startup self-test drives whichever WebSocket class is served, and
  gains two drives: an app that closes before accepting, and an upgrade the websockets parser
  rejects. For that last one the floor also writes the answer. uvicorn 0.54.0 leaves it unwritten
  and the connection open, and then raises at server stop, before the engine's own shutdown runs.
  The floored class writes the queued `414` or `431` and closes. (`BACKLOG #1120`)
