- **Corrected: a test does catch one name the header floor's attribute check cannot.** The 0.5.2
  entry on the protocol header floor said no test covers a name uvicorn still assigns and has
  stopped reading. The shutdown test in `tests/test_header_floor_wire.py` fails if uvicorn's
  `shutdown` stops reading `close_sent`. The module docstring and a comment in
  `messagefoundry/api/protocol_headers.py` said the same and are corrected. That test now also
  asserts that uvicorn's `handle_connect` never ran on a parser-rejected upgrade, and that a later
  `data_received` does not run the parser-rejection step a second time. (`BACKLOG #1120`)
