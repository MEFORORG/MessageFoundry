- **Corrected: the 0.5.2 entry on the protocol header floor understated one test.** That entry
  said no test covers a name uvicorn still assigns and has stopped reading. For `close_sent`, the
  shutdown test in `tests/test_header_floor_wire.py` fails if uvicorn's `shutdown` drops its
  `close_sent` check on a parser-rejected connection. A `shutdown` that stops reading the flag some
  other way need not fail it. The module docstring in `messagefoundry/api/protocol_headers.py` is
  corrected the same way. (`BACKLOG #1120`)
