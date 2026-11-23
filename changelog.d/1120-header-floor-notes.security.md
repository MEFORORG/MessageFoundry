- **Corrected: the 0.5.2 entry on the protocol header floor understated one test.** That entry
  said no test covers a name uvicorn still assigns and has stopped reading. For `close_sent`, a
  wire test in `tests/test_header_floor_wire.py` fails when uvicorn's `shutdown` drops its
  `close_sent` check and sends a close frame on a parser-rejected connection, and a new control
  test shows it. It does not catch a `shutdown` that stops reading `close_sent` and returns early
  some other way. The module docstring in `messagefoundry/api/protocol_headers.py` is corrected
  the same way. The wire test now also asserts that uvicorn's `handle_connect` never ran on a
  parser-rejected upgrade, and that a later `data_received` does not call the parser-rejection
  step again, each with a positive control. (`BACKLOG #1120`)
