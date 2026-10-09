- **websockets moves to 17.2 under the protocol header floor, and the floor refuses at start when
  a flag its two uvicorn workarounds read is gone.** The floor wraps websockets internals, so its
  wire suite names the exact version it measured and fails on any other. The installed 17.1 and
  17.2 packages were compared file by file. At least these are byte-identical: `server.py`,
  `protocol.py`, `http11.py`, `datastructures.py`, and the legacy `server.py`, `protocol.py` and
  `handshake.py`. These changed and were read: `legacy/http.py`, which the legacy handshake uses
  to read a request, now stores a header it has just validated without validating it again;
  `extensions/permessage_deflate.py` no longer supports a compression window of 8 bits, which
  can change whether an accepted handshake's `101` carries `Sec-WebSocket-Extensions`; `frames.py` changes how a frame is rendered for a log line. None
  of them changes how a rejection is written or how any handshake answer gets the floor's
  headers. The compiled `speedups` module was not compared. The wire suite, the startup
  self-test and every knock-out control pass on 17.2. Separately, the class build now requires
  every attribute the floor's two uvicorn workarounds read or write: `eof_sent` and
  `handshake_exc` on the websockets connection, and `handshake_initiated`, `handshake_complete`,
  `close_sent` and `transport` on uvicorn's protocol. A rename upstream would otherwise have
  switched a workaround off, or left it setting a dead name, with no error. `serve` now names the
  missing one and exits with code 2. The check sees a name that is no longer assigned, not one
  uvicorn still assigns and has stopped reading. Not refreshed here: `security/risky-component-readings.json`
  and `security/bundled-code-survey.json` still describe websockets 17.1. They are dated
  snapshots made by hand with network access. (`BACKLOG #1120`)
