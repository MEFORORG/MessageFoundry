- **The protocol header floor now covers uvicorn's sans-I/O WebSocket protocol, and uvicorn moves
  past its `<0.50` cap.** From uvicorn 0.50, `ws="auto"` resolves to that protocol. The
  floor refused it, so `serve` exited with code 2 on any newer uvicorn, and the cap held uvicorn at
  0.49. The floor now adds `nosniff` and the framing policy to the handshake answers that protocol
  writes. At uvicorn 0.54.0 those are at least: the websockets library's own rejection of a bad
  handshake, uvicorn's `500`, its `403` for an app that closes before accepting, an app's own
  denial, and the `101`. It does so in one place,
  the `send_response` of the connection object the protocol hands each answer to. The legacy
  websockets server stays covered as before. wsproto is still refused. uvicorn and
  `websockets` are now pinned exactly; the entry on the pins names the versions.
  The startup self-test drives whichever WebSocket class is served, and
  gains two drives: an app that closes before accepting, and an upgrade the websockets parser
  rejects. On this protocol the floor also does two things beyond adding headers, each a
  workaround for uvicorn 0.54.0 behaviour its legacy server did not have. It writes what the
  websockets parser queued for a request it rejected, a `414` or `431` or nothing at all, and
  closes; uvicorn leaves that unwritten and the connection open. And it drops a second handshake
  answer on a connection that has already ended its stream; uvicorn sends one at server stop,
  websockets asserts on it, and the stop would raise before the engine's own shutdown ran.
  (`BACKLOG #1120`)
