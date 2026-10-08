- **`serve` and `supervise` now test the protocol header floor at every start, and refuse on a
  failure.** The floor adds `nosniff` and the framing policy to the responses uvicorn writes
  itself. Until now the start-up check read only the shape of the uvicorn and websockets hooks the
  floor overrides. A new self-test, `messagefoundry/api/protocol_floor_selftest.py`, drives the
  built classes in memory: a malformed request, an app error, a WebSocket handshake with no key,
  and a WebSocket app error. It reads the headers off each answer. If one is missing, the engine
  names the response and the header and exits with code 2, before it mints a certificate or opens
  the store. It opens no socket and added about 7 ms to a start when measured. It covers those
  four response families only. There is no opt-out. (`BACKLOG #1120`)
