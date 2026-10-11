- **`serve` pins the API's HTTP parser to httptools (llhttp), and pyproject pins it exactly, to
  `httptools==0.8.0`.** uvicorn's `http="auto"` picks httptools when it imports and falls back to
  h11 when it does not, with no log line. The two parsers frame some ambiguous requests
  differently, and h11 answers shapes llhttp refuses. `serve` now names the httptools protocol
  itself, refuses to start when httptools does not import, and logs which parser it serves at
  startup. A new suite sends those shapes over a real socket and checks each gets one `400`. It
  drives only the pinned version, so the declared range `httptools>=0.8.0` became an exact pin.
  A test holds the pin equal to the version the suite measured.

  The pin has the same cost as the uvicorn and websockets pins. A site cannot take a newer
  httptools, a security fix included, without a new MessageFoundry release. Dependabot gained an
  ignore range for httptools at `>=0.9.0`, the next minor after the pin, and opens no security PR
  in it. `pip-audit` over the lock still reports an advisory. (`BACKLOG #1125`)
