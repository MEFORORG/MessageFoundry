- **Corrected: the 0.5.2 entry "websockets moves to 17.2 under the protocol header floor"
  understated a test.** It said no test covers a name uvicorn still assigns and has stopped
  reading. A shutdown test covers one such read, of `close_sent`; the module docstring of
  `messagefoundry/api/protocol_headers.py`, under "Refuse at startup", says what it does and does
  not catch. (`BACKLOG #1120`)
