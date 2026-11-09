- **The API's request body limit refuses any `Transfer-Encoding`, and a `Content-Length` that is not
  one plain number.** The limit matched `chunked` in the first `Transfer-Encoding` line only. A
  request carrying `Transfer-Encoding: gzip` and then a second `Transfer-Encoding: chunked` line is
  framed as chunked by the llhttp parser `serve` pins, so with no `Content-Length` the limit admitted
  the chunked body at any size: a public route that reads a body, such as `POST /auth/login`, would
  read it unbounded before any authentication; a gated route refuses a caller with no identity
  before reading the body. Under `serve`, an empty `Transfer-Encoding` beside a `Content-Length`
  also reached a route. The limit also read the length with `int()`, which takes `+2`, `-5` and
  `0_2`, and read only the first of several `Content-Length` lines. Now any `Transfer-Encoding`
  line, whatever its value, is refused **411**, or **400** beside a `Content-Length`; a
  `Content-Length` must be one line of plain decimal digits or the request is refused **400**; and
  the 1 MiB cap on the declared length is unchanged. [SECURITY.md](../docs/SECURITY.md) control 5
  states the rule. (vault `BACKLOG #5345`)
