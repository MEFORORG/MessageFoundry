- **The API's request body limit refuses any `Transfer-Encoding`, and a `Content-Length` that is not
  one plain number.** The limit matched `chunked` in the first `Transfer-Encoding` line only. A
  request carrying `Transfer-Encoding: gzip` and then a second `Transfer-Encoding: chunked` line is
  framed as chunked by the llhttp parser `serve` pins, so with no `Content-Length` the limit admitted
  the chunked body at any size: a public route that reads a body, such as `POST /auth/login`, would
  read it unbounded before any authentication; a gated route refuses a caller with no identity
  before reading the body. Under `serve`, an empty `Transfer-Encoding` ahead of a `Content-Length`
  also reached a route. On a server other than the one `serve` pins, which refuses these first, the
  limit also took `+2`, `-5` and `0_2` as lengths through `int()`, and read only the first of
  several `Content-Length` lines. Now the limit refuses, and closes
  the connection on, any request carrying `Transfer-Encoding` and any `Content-Length` that is not
  one line of plain decimal digits, where llhttp under `serve` has not refused them first; the
  cap on the declared length is unchanged, and its 413 now closes the connection too.
  [SECURITY.md](../docs/SECURITY.md) control 5 states the rule and its statuses, and [DEPLOYMENT.md](../docs/DEPLOYMENT.md) tells a proxy in front of the
  engine to refuse a `Transfer-Encoding` on more than one line. (vault `BACKLOG #5345`)
