- **websockets moves to 17.2 under the protocol header floor, and the floor refuses at start when
  a flag its two uvicorn workarounds read is gone.** The floor wraps websockets internals, so its
  wire suite names the exact version it measured and fails on any other. The 17.2 files the floor
  depends on were compared with 17.1 and are byte-identical: `server.py`, `protocol.py`,
  `http11.py`, `datastructures.py`, and the legacy `server.py`, `protocol.py` and `handshake.py`.
  The wire suite, the startup self-test and every knock-out control pass on 17.2. Separately, the
  class build now requires `eof_sent` and `handshake_exc` on the websockets connection and
  `handshake_initiated` on uvicorn's protocol. Each was read with a default that switched its
  workaround off, so a rename upstream would have done so with no error. `serve` now names the
  missing flag and exits with code 2. (`BACKLOG #1120`)
