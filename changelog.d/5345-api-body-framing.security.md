- **The API's request body limit reads every `Transfer-Encoding` line, not only the first.** A
  request carrying `Transfer-Encoding: gzip` and then a second `Transfer-Encoding: chunked` line is
  framed as chunked by the llhttp parser `serve` pins, but the limit read only the first line and
  saw `gzip`. With no `Content-Length` it admitted the chunked body at any size, so a public route
  that reads a body, such as `POST /auth/login`, would read it unbounded before any
  authentication; a gated route refuses a caller with no identity before reading the body. With a
  `Content-Length`, the limit skipped its ambiguous-framing 400 on a server other than llhttp. Such
  a request is now refused **411** without a `Content-Length`, and **400** with one, as a single
  `chunked` line is. [SECURITY.md](../docs/SECURITY.md) now also says that under `serve`
  malformed chunked framing gets llhttp's own 400, and
  [DEPLOYMENT.md](../docs/DEPLOYMENT.md) no longer lists every repeated `Transfer-Encoding` among
  the shapes llhttp refuses. (vault `BACKLOG #5345`, added items 1 and 2)
